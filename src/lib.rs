pub mod error;
mod node;
#[cfg(test)]
mod test;
mod utils;

use crypter::{openssl::Aes256Ctr, Crypter};
use embedded_io::{
    blocking::{Read, Seek, Write},
    SeekFrom,
};
use error::Error;
use kms::KeyManagementScheme;
use node::{Child, Node};
use rand::{rngs::ThreadRng, CryptoRng, RngCore};
use std::{collections::HashSet, marker::PhantomData, mem};
use storage::{
    dir::{self, DirectoryStorage},
    Storage,
};

const DEFAULT_DEGREE: usize = 2;
const AES256CTR_KEY_SZ: usize = 32;

pub(crate) type Key<const N: usize> = [u8; N];
pub(crate) type BlockId = u64;
pub(crate) type NodeId = u64;

pub struct BKeyTree<
    R = ThreadRng,
    S = DirectoryStorage,
    C = Aes256Ctr,
    const KEY_SZ: usize = AES256CTR_KEY_SZ,
> {
    len: usize,
    degree: usize,
    updated: HashSet<NodeId>,
    updated_blocks: HashSet<BlockId>,
    key: Key<KEY_SZ>,
    root: Node<KEY_SZ>,
    storage: S,
    rng: R,
    pd: PhantomData<C>,
}

impl BKeyTree<ThreadRng, DirectoryStorage, Aes256Ctr, AES256CTR_KEY_SZ> {
    pub fn new(
        path: impl AsRef<str>,
        key: Key<AES256CTR_KEY_SZ>,
    ) -> Result<Self, Error<dir::Error>> {
        Self::with_degree(path, key, DEFAULT_DEGREE)
    }

    pub fn load(
        root_id: u64,
        path: impl AsRef<str>,
        key: Key<AES256CTR_KEY_SZ>,
    ) -> Result<Self, Error<dir::Error>> {
        Self::load_with_storage(root_id, DirectoryStorage::new(path.as_ref())?, key)
    }

    pub fn with_degree(
        path: impl AsRef<str>,
        key: Key<AES256CTR_KEY_SZ>,
        degree: usize,
    ) -> Result<Self, Error<dir::Error>> {
        Self::with_storage_and_degree(DirectoryStorage::new(path.as_ref())?, key, degree)
    }
}

impl<R, S, C, const KEY_SZ: usize> BKeyTree<R, S, C, KEY_SZ>
where
    R: RngCore + CryptoRng + Default,
    S: Storage<Id = u64>,
    C: Crypter,
{
    pub fn with_storage(storage: S, key: Key<KEY_SZ>) -> Result<Self, Error<S::Error>> {
        Self::with_storage_and_degree(storage, key, DEFAULT_DEGREE)
    }

    pub fn with_storage_and_degree(
        mut storage: S,
        key: Key<KEY_SZ>,
        degree: usize,
    ) -> Result<Self, Error<S::Error>> {
        Ok(Self {
            len: 0,
            degree,
            updated: HashSet::new(),
            updated_blocks: HashSet::new(),
            key,
            root: Node::new(storage.alloc_id()?, utils::generate_key(&mut R::default())),
            storage,
            rng: R::default(),
            pd: PhantomData,
        })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn root_id(&self) -> u64 {
        self.root.id
    }

    pub fn load_with_storage(
        id: NodeId,
        mut storage: S,
        key: Key<KEY_SZ>,
    ) -> Result<Self, Error<S::Error>> {
        // Load the root node.
        let root = Node::load::<C, S>(id, key, &mut storage)?;

        // To load with the extra metadata at the end.
        let mut len_raw = [0; mem::size_of::<u64>()];
        let mut degree_raw = [0; mem::size_of::<u64>()];

        {
            let mut reader = storage.read_handle(&root.id)?;
            reader
                .seek(SeekFrom::End(-2 * mem::size_of::<u64>() as i64))
                .map_err(|_| Error::Seek)?;
            reader.read_exact(&mut len_raw).map_err(|_| Error::Read)?;
            reader
                .read_exact(&mut degree_raw)
                .map_err(|_| Error::Read)?;
        }

        Ok(Self {
            len: u64::from_le_bytes(len_raw) as usize,
            degree: u64::from_le_bytes(degree_raw) as usize,
            updated: HashSet::new(),
            updated_blocks: HashSet::new(),
            key,
            root,
            rng: R::default(),
            storage,
            pd: PhantomData,
        })
    }

    pub fn persist(&mut self) -> Result<(NodeId, Key<KEY_SZ>), Error<S::Error>> {
        // Persist the root node.
        self.root.persist::<C, S>(self.key, &mut self.storage)?;

        // Acquire a write handle.
        let mut writer = self.storage.write_handle(&self.root.id)?;

        // Append extra metadata to the end.
        writer.seek(SeekFrom::End(0)).map_err(|_| Error::Seek)?;
        writer
            .write_all(&(self.len as u64).to_le_bytes())
            .map_err(|_| Error::Write)?;
        writer
            .write_all(&(self.degree as u64).to_le_bytes())
            .map_err(|_| Error::Write)?;

        Ok((self.root.id, self.key))
    }

    pub fn contains(&mut self, k: &BlockId) -> Result<bool, Error<S::Error>> {
        Ok(self.get(k)?.is_some())
    }

    pub fn get(&mut self, k: &BlockId) -> Result<Option<&Key<KEY_SZ>>, Error<S::Error>> {
        Ok(self
            .root
            .get::<C, S>(k, &mut self.storage)?
            .map(|(idx, node)| &node.vals[idx]))
    }

    pub fn get_mut(&mut self, k: &BlockId) -> Result<Option<&mut Key<KEY_SZ>>, Error<S::Error>> {
        Ok(self
            .root
            .get_mut::<C, S>(k, &mut self.storage)?
            .map(|(idx, node)| &mut node.vals[idx]))
    }

    pub fn get_key_value(
        &mut self,
        k: &BlockId,
    ) -> Result<Option<(&BlockId, &Key<KEY_SZ>)>, Error<S::Error>> {
        Ok(self
            .root
            .get::<C, S>(k, &mut self.storage)?
            .map(|(idx, node)| (&node.keys[idx], &node.vals[idx])))
    }

    pub fn insert(
        &mut self,
        k: BlockId,
        v: Key<KEY_SZ>,
    ) -> Result<Option<Key<KEY_SZ>>, Error<S::Error>> {
        if self.root.is_full(self.degree) {
            let mut new_root =
                Node::new(self.storage.alloc_id()?, utils::generate_key(&mut self.rng));

            mem::swap(&mut self.root, &mut new_root);

            self.root.children.push(Child::Loaded(new_root));
            self.root.split_child(
                0,
                self.degree,
                &mut self.storage,
                false,
                &mut self.rng,
                &mut self.updated,
            )?;
        }

        let res = self.root.insert_nonfull::<C, R, S>(
            k,
            v,
            self.degree,
            &mut self.storage,
            false,
            &mut self.rng,
            &mut self.updated,
        )?;

        if res.is_none() {
            self.len += 1;
        }

        Ok(res)
    }

    pub fn insert_for_update(
        &mut self,
        k: BlockId,
        v: Key<KEY_SZ>,
    ) -> Result<Option<Key<KEY_SZ>>, Error<S::Error>> {
        if self.root.is_full(self.degree) {
            let mut new_root =
                Node::new(self.storage.alloc_id()?, utils::generate_key(&mut self.rng));

            self.updated.insert(self.root.id);
            self.updated.insert(new_root.id);

            mem::swap(&mut self.root, &mut new_root);

            self.root.children.push(Child::Loaded(new_root));
            self.root.split_child(
                0,
                self.degree,
                &mut self.storage,
                true,
                &mut self.rng,
                &mut self.updated,
            )?;
        }

        let res = self.root.insert_nonfull::<C, R, S>(
            k,
            v,
            self.degree,
            &mut self.storage,
            true,
            &mut self.rng,
            &mut self.updated,
        )?;

        if res.is_none() {
            self.len += 1;
        }

        Ok(res)
    }

    pub fn remove(&mut self, k: &BlockId) -> Result<Option<Key<KEY_SZ>>, Error<S::Error>> {
        Ok(self.remove_entry(k)?.map(|(_, val)| val))
    }

    pub fn remove_entry(
        &mut self,
        k: &BlockId,
    ) -> Result<Option<(BlockId, Key<KEY_SZ>)>, Error<S::Error>> {
        // We do this to make it easier to mark updated nodes when removing.
        if !self.contains(k)? {
            return Ok(None);
        }

        if let Some(entry) =
            self.root
                .remove::<C, S>(k, self.degree, &mut self.storage, &mut self.updated)?
        {
            if !self.root.is_leaf() && self.root.is_empty() {
                self.root = self.root.children.pop().unwrap().as_option_owned().unwrap();
            }
            self.len -= 1;
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    pub fn clear(&mut self) -> Result<NodeId, Error<S::Error>> {
        self.len = 0;
        self.root.clear::<C, S>(&mut self.storage)?;
        self.root = Node::new(self.storage.alloc_id()?, utils::generate_key(&mut self.rng));
        Ok(self.root.id)
    }

    fn generate_key(&mut self) -> Key<KEY_SZ> {
        let mut key = [0; KEY_SZ];
        self.rng.fill_bytes(&mut key);
        key
    }
}

impl<R, S, C, const KEY_SZ: usize> KeyManagementScheme for BKeyTree<R, S, C, KEY_SZ>
where
    R: RngCore + CryptoRng + Default,
    S: Storage<Id = u64>,
    C: Crypter,
{
    type Key = Key<KEY_SZ>;
    type KeyId = BlockId;
    type Error = Error<S::Error>;

    fn derive(&mut self, block_id: Self::KeyId) -> Result<Self::Key, Self::Error> {
        if let Some(key) = self.get(&block_id)? {
            return Ok(*key);
        }
        let key = self.generate_key();
        self.insert(block_id, key)?;
        Ok(key)
    }

    fn update(&mut self, block_id: Self::KeyId) -> Result<Self::Key, Self::Error> {
        let key = self.generate_key();
        self.insert_for_update(block_id, key)?;

        self.updated_blocks.insert(block_id);

        Ok(key)
    }

    // TODO: Fix in key management trait that commit can be fallible.
    fn commit(&mut self) -> Vec<Self::KeyId> {
        self.root
            .commit::<C, R, S>(&mut self.storage, &mut self.rng, &mut self.updated)
            .unwrap();
        self.updated.clear();
        self.updated_blocks.drain().collect()
    }
}
