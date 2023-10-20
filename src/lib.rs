pub mod error;
pub mod node;
#[cfg(test)]
mod test;
mod utils;

pub use storage; // For re-export

use crypter::{openssl::Aes256Ctr, Crypter};
use embedded_io::{
    blocking::{Read, Seek, Write},
    SeekFrom,
};
use error::Error;
use kms::KeyManagementScheme;
use node::{Child, Node};
use rand::{rngs::ThreadRng, CryptoRng, RngCore};
use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
    mem,
};
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
    in_flight_blocks: HashMap<BlockId, Key<KEY_SZ>>,
    root: Node<KEY_SZ>,
    storage: S,
    rng: R,
    pd: PhantomData<C>,
}

impl BKeyTree<ThreadRng, DirectoryStorage, Aes256Ctr, AES256CTR_KEY_SZ> {
    pub fn new(path: impl AsRef<str>) -> Result<Self, Error<dir::Error>> {
        Self::with_degree(path, DEFAULT_DEGREE)
    }

    pub fn reload(
        root_id: u64,
        path: impl AsRef<str>,
        key: Key<AES256CTR_KEY_SZ>,
    ) -> Result<Self, Error<dir::Error>> {
        Self::reload_with_storage(root_id, DirectoryStorage::new(path.as_ref())?, key)
    }

    pub fn with_degree(path: impl AsRef<str>, degree: usize) -> Result<Self, Error<dir::Error>> {
        Self::with_storage_and_degree(DirectoryStorage::new(path.as_ref())?, degree)
    }
}

impl<R, S, C, const KEY_SZ: usize> BKeyTree<R, S, C, KEY_SZ>
where
    R: RngCore + CryptoRng + Default,
    S: Storage<Id = u64>,
    C: Crypter,
{
    pub fn with_storage(storage: S) -> Result<Self, Error<S::Error>> {
        Self::with_storage_and_degree(storage, DEFAULT_DEGREE)
    }

    pub fn with_storage_and_degree(mut storage: S, degree: usize) -> Result<Self, Error<S::Error>> {
        Ok(Self {
            len: 0,
            degree,
            updated: HashSet::new(),
            updated_blocks: HashSet::new(),
            in_flight_blocks: HashMap::new(),
            root: Node::new(storage.alloc_id()?),
            storage,
            rng: R::default(),
            pd: PhantomData,
        })
    }

    pub fn reload_with_storage(
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
            in_flight_blocks: HashMap::new(),
            root,
            rng: R::default(),
            storage,
            pd: PhantomData,
        })
    }

    pub fn load(&mut self, id: NodeId, key: Key<KEY_SZ>) -> Result<(), Error<S::Error>> {
        // Load the root node.
        let root = Node::load::<C, S>(id, key, &mut self.storage)?;

        // Load length and degree from the end.
        let (len, degree) = {
            let mut len_raw = [0; mem::size_of::<u64>()];
            let mut degree_raw = [0; mem::size_of::<u64>()];

            let mut reader = self.storage.read_handle(&root.id)?;

            reader
                .seek(SeekFrom::End(-2 * mem::size_of::<u64>() as i64))
                .map_err(|_| Error::Seek)?;
            reader.read_exact(&mut len_raw).map_err(|_| Error::Read)?;
            reader
                .read_exact(&mut degree_raw)
                .map_err(|_| Error::Read)?;

            let len = u64::from_le_bytes(len_raw) as usize;
            let degree = u64::from_le_bytes(len_raw) as usize;

            (len, degree)
        };

        // Update state after the fallible operations.
        self.root = root;
        self.len = len;
        self.degree = degree;

        Ok(())
    }

    pub fn persist(&mut self, key: Key<KEY_SZ>) -> Result<(), Error<S::Error>> {
        // Persist the root node.
        self.root.persist::<C, S>(key, &mut self.storage)?;

        // Persist length and degree at the end.
        let mut writer = self.storage.write_handle(&self.root.id)?;
        writer.seek(SeekFrom::End(0)).map_err(|_| Error::Seek)?;
        writer
            .write_all(&(self.len as u64).to_le_bytes())
            .map_err(|_| Error::Write)?;
        writer
            .write_all(&(self.degree as u64).to_le_bytes())
            .map_err(|_| Error::Write)?;

        Ok(())
    }

    pub fn persist_block(
        &mut self,
        block: &BlockId,
        key: Key<KEY_SZ>,
    ) -> Result<bool, Error<S::Error>> {
        // If the block is in-flight, insert without marking nodes in the path as updated.
        if let Some(block_key) = self.in_flight_blocks.remove(block) {
            self.insert(*block, block_key)?;
        }

        // Persist the block, persisting any nodes along the way.
        let res = self
            .root
            .persist_block::<C, S>(block, key, &mut self.storage)?;

        // Persist length and degree at the end if we persisted the block.
        if res {
            let mut writer = self.storage.write_handle(&self.root.id)?;
            writer.seek(SeekFrom::End(0)).map_err(|_| Error::Seek)?;
            writer
                .write_all(&(self.len as u64).to_le_bytes())
                .map_err(|_| Error::Write)?;
            writer
                .write_all(&(self.degree as u64).to_le_bytes())
                .map_err(|_| Error::Write)?;
        }

        Ok(res)
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

    pub fn contains(&mut self, k: &BlockId) -> Result<bool, Error<S::Error>> {
        Ok(self.get(k)?.is_some())
    }

    pub fn get(&mut self, k: &BlockId) -> Result<Option<&Key<KEY_SZ>>, Error<S::Error>> {
        Ok(self
            .root
            .get::<C, S>(k, &mut self.storage)?
            .map(|(idx, node)| &node.vals[idx]))
    }

    pub fn get_node(&mut self, k: &BlockId) -> Result<Option<&Node<KEY_SZ>>, Error<S::Error>> {
        Ok(self
            .root
            .get::<C, S>(k, &mut self.storage)?
            .map(|(_, node)| node))
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

    /// Inserts a key without marking any of the nodes touched on the way down as updated.
    pub fn insert(
        &mut self,
        k: BlockId,
        v: Key<KEY_SZ>,
    ) -> Result<Option<Key<KEY_SZ>>, Error<S::Error>> {
        if self.root.is_full(self.degree) {
            let mut new_root = Node::new(self.storage.alloc_id()?);
            let new_root_key = self.generate_key();

            mem::swap(&mut self.root, &mut new_root);

            self.root.children.push(Child::Loaded(new_root));
            self.root.children_keys.push(new_root_key);

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

    /// Inserts a key while marking any of the nodes touched on the way down as updated.
    pub fn insert_for_update(
        &mut self,
        k: BlockId,
        v: Key<KEY_SZ>,
    ) -> Result<Option<Key<KEY_SZ>>, Error<S::Error>> {
        if self.root.is_full(self.degree) {
            let mut new_root = Node::new(self.storage.alloc_id()?);

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
        self.root = Node::new(self.storage.alloc_id()?);
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

        if let Some(key) = self.in_flight_blocks.get(&block_id) {
            return Ok(*key);
        }

        let key = self.generate_key();
        self.in_flight_blocks.insert(block_id, key);

        Ok(key)
    }

    fn update(&mut self, block_id: Self::KeyId) -> Result<Self::Key, Self::Error> {
        let key = self.derive(block_id)?;
        self.updated_blocks.insert(block_id);
        Ok(key)
    }

    // TODO: Fix in key management trait that commit can be fallible.
    fn commit(&mut self) -> Vec<Self::KeyId> {
        // Add any in-flight blocks that haven't been updated.
        let inflight_blocks = self
            .in_flight_blocks
            .iter()
            .filter_map(|(k, v)| (!self.updated_blocks.contains(k)).then_some((*k, *v)))
            .collect::<Vec<_>>();

        for (block, key) in inflight_blocks.into_iter() {
            self.insert_for_update(block, key).unwrap();
        }

        // This will commit our changes, changing keys as necesssary to updated nodes as blocks.
        self.root
            .commit::<C, R, S>(
                &mut self.storage,
                &mut self.rng,
                &self.updated,
                &self.updated_blocks,
            )
            .unwrap();

        // Clear out our cached updates.
        self.updated.clear();
        self.in_flight_blocks.clear();
        self.updated_blocks.drain().collect()
    }
}
