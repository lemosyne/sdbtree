pub mod error;
pub mod node;
mod persist;
#[cfg(test)]
mod test;
mod utils;

pub use storage; // For re-export

use crypter::{aes::Aes256Ctr, Crypter};
use error::Error;
use kms::KeyManagementScheme;
use node::{Child, Node};
use rand::{rngs::ThreadRng, CryptoRng, RngCore};
use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
    mem,
};
use storage::{dir::DirectoryStorage, Storage};

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
    root: Node<KEY_SZ>,
    storage: S,
    rng: R,
    pd: PhantomData<C>,

    // Degree metadata
    degree: usize,
    degree_dirty: bool,

    // Length metadata
    len: usize,
    len_dirty: bool,

    // Updated node metadata
    updated: HashSet<NodeId>,
    updated_dirty: bool,

    // Updated block metadata
    updated_blocks: HashSet<BlockId>,
    updated_blocks_dirty: bool,

    cached_keys: HashMap<BlockId, Key<KEY_SZ>>,
}

impl BKeyTree<ThreadRng, DirectoryStorage, Aes256Ctr, AES256CTR_KEY_SZ> {
    pub fn new(path: impl AsRef<str>) -> Result<Self, Error> {
        Self::with_degree(path, DEFAULT_DEGREE)
    }

    pub fn reload(
        root_id: u64,
        path: impl AsRef<str>,
        key: Key<AES256CTR_KEY_SZ>,
    ) -> Result<Self, Error> {
        Self::reload_with_storage(
            root_id,
            DirectoryStorage::new(path.as_ref()).map_err(|_| Error::Storage)?,
            key,
        )
    }

    pub fn with_degree(path: impl AsRef<str>, degree: usize) -> Result<Self, Error> {
        Self::with_storage_and_degree(
            DirectoryStorage::new(path.as_ref()).map_err(|_| Error::Storage)?,
            degree,
        )
    }
}

impl<R, S, C, const KEY_SZ: usize> BKeyTree<R, S, C, KEY_SZ>
where
    R: RngCore + CryptoRng + Default,
    S: Storage<Id = u64>,
    C: Crypter,
{
    pub fn with_storage(storage: S) -> Result<Self, Error> {
        Self::with_storage_and_degree(storage, DEFAULT_DEGREE)
    }

    pub fn with_storage_and_degree(mut storage: S, degree: usize) -> Result<Self, Error> {
        Ok(Self {
            root: Node::new(storage.alloc_id().map_err(|_| Error::Storage)?),
            storage,
            rng: R::default(),
            pd: PhantomData,
            degree,
            degree_dirty: true,
            len: 0,
            len_dirty: true,
            updated: HashSet::new(),
            updated_dirty: true,
            updated_blocks: HashSet::new(),
            updated_blocks_dirty: true,
            cached_keys: HashMap::new(),
        })
    }

    pub fn reload_with_storage(
        id: NodeId,
        mut storage: S,
        key: Key<KEY_SZ>,
    ) -> Result<Self, Error> {
        // Load the root node.
        let root = Node::load::<C, S>(id, key, &mut storage)?;

        // Load the metadata.
        let meta = Self::load_meta(key, &mut storage)?;

        Ok(Self {
            root,
            storage,
            rng: R::default(),
            pd: PhantomData,
            degree: meta.degree,
            degree_dirty: false,
            len: meta.len,
            len_dirty: false,
            updated: meta.updated,
            updated_dirty: false,
            updated_blocks: meta.updated_blocks,
            updated_blocks_dirty: false,
            cached_keys: HashMap::new(),
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

    pub fn contains(&mut self, k: &BlockId) -> Result<bool, Error> {
        Ok(self.get(k)?.is_some())
    }

    pub fn get(&mut self, k: &BlockId) -> Result<Option<&Key<KEY_SZ>>, Error> {
        Ok(self
            .root
            .get::<C, S>(k, &mut self.storage)?
            .map(|(idx, node)| &node.vals[idx]))
    }

    pub fn get_node(&mut self, k: &BlockId) -> Result<Option<&Node<KEY_SZ>>, Error> {
        Ok(self
            .root
            .get::<C, S>(k, &mut self.storage)?
            .map(|(_, node)| node))
    }

    pub fn get_mut(&mut self, k: &BlockId) -> Result<Option<&mut Key<KEY_SZ>>, Error> {
        Ok(self
            .root
            .get_mut::<C, S>(k, &mut self.storage)?
            .map(|(idx, node)| &mut node.vals[idx]))
    }

    pub fn get_key_value(
        &mut self,
        k: &BlockId,
    ) -> Result<Option<(&BlockId, &Key<KEY_SZ>)>, Error> {
        Ok(self
            .root
            .get::<C, S>(k, &mut self.storage)?
            .map(|(idx, node)| (&node.keys[idx], &node.vals[idx])))
    }

    /// Inserts a key while marking any of the nodes touched on the way down as updated.
    pub fn insert(&mut self, k: BlockId, v: Key<KEY_SZ>) -> Result<Option<Key<KEY_SZ>>, Error> {
        if self.root.is_full(self.degree) {
            let mut new_root = Node::new(self.storage.alloc_id().map_err(|_| Error::Storage)?);
            let new_root_key = self.generate_key();

            self.updated.insert(self.root.id);
            self.updated.insert(new_root.id);

            mem::swap(&mut self.root, &mut new_root);

            self.root.children.push(Child::Loaded(new_root));
            self.root.children_keys.push(new_root_key);

            self.root.split_child(
                0,
                self.degree,
                &mut self.storage,
                &mut self.rng,
                &mut self.updated,
                true,
            )?;
        }

        let res = self.root.insert_nonfull::<C, R, S>(
            k,
            v,
            self.degree,
            &mut self.storage,
            &mut self.rng,
            &mut self.updated,
            true,
        )?;

        if res.is_none() {
            self.len += 1;
            self.len_dirty = true;
        }

        self.updated_dirty = true;

        Ok(res)
    }

    /// Inserts a key without marking any of the nodes touched on the way down as updated.
    /// NOTE: Currently unused
    pub fn insert_no_update(
        &mut self,
        k: BlockId,
        v: Key<KEY_SZ>,
    ) -> Result<Option<Key<KEY_SZ>>, Error> {
        if self.root.is_full(self.degree) {
            let mut new_root = Node::new(self.storage.alloc_id().map_err(|_| Error::Storage)?);
            let new_root_key = self.generate_key();

            mem::swap(&mut self.root, &mut new_root);

            self.root.children.push(Child::Loaded(new_root));
            self.root.children_keys.push(new_root_key);

            self.root.split_child(
                0,
                self.degree,
                &mut self.storage,
                &mut self.rng,
                &mut self.updated,
                false,
            )?;
        }

        let res = self.root.insert_nonfull::<C, R, S>(
            k,
            v,
            self.degree,
            &mut self.storage,
            &mut self.rng,
            &mut self.updated,
            false,
        )?;

        if res.is_none() {
            self.len += 1;
        }

        Ok(res)
    }

    /// Removes and marks nodes as updated.
    pub fn remove(&mut self, k: &BlockId) -> Result<Option<Key<KEY_SZ>>, Error> {
        Ok(self.remove_entry(k)?.map(|(_, val)| val))
    }

    /// Removes an entry and marks nodes as updated.
    pub fn remove_entry(&mut self, k: &BlockId) -> Result<Option<(BlockId, Key<KEY_SZ>)>, Error> {
        // We do this to make it easier to mark updated nodes when removing.
        if !self.contains(k)? {
            return Ok(None);
        }

        if let Some(entry) =
            self.root
                .remove::<C, S>(k, self.degree, &mut self.storage, &mut self.updated, true)?
        {
            if !self.root.is_leaf() && self.root.is_empty() {
                self.root = self.root.children.pop().unwrap().as_option_owned().unwrap();
            }

            self.len -= 1;
            self.len_dirty = true;

            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    /// Removes without marking nodes as updated.
    /// NOTE: Currently unused
    pub fn remove_no_update(&mut self, k: &BlockId) -> Result<Option<Key<KEY_SZ>>, Error> {
        Ok(self.remove_entry_no_update(k)?.map(|(_, val)| val))
    }

    /// Removes an entry without marking nodes as updated.
    /// NOTE: Currently unused
    pub fn remove_entry_no_update(
        &mut self,
        k: &BlockId,
    ) -> Result<Option<(BlockId, Key<KEY_SZ>)>, Error> {
        if !self.contains(k)? {
            return Ok(None);
        }

        if let Some(entry) =
            self.root
                .remove::<C, S>(k, self.degree, &mut self.storage, &mut self.updated, false)?
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

    pub fn clear(&mut self) -> Result<NodeId, Error> {
        self.root.clear::<C, S>(&mut self.storage)?;
        self.root = Node::new(self.storage.alloc_id().map_err(|_| Error::Storage)?);

        self.len = 0;
        self.len_dirty = true;

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
    type Error = Error;

    fn derive(&mut self, block_id: Self::KeyId) -> Result<Self::Key, Self::Error> {
        if let Some(key) = self.cached_keys.get(&block_id) {
            // eprintln!("found cached key for {block_id}");
            return Ok(*key);
        }

        if let Some(key) = self.get(&block_id)? {
            // eprintln!("found existing key for {block_id}");
            return Ok(*key);
        }

        let key = self.generate_key();
        self.cached_keys.insert(block_id, key);

        // eprintln!("add key for {block_id}");
        self.insert(block_id, key)?;

        Ok(key)
    }

    fn update(&mut self, block_id: Self::KeyId) -> Result<Self::Key, Self::Error> {
        let key = self.derive(block_id)?;

        self.updated_blocks.insert(block_id);
        self.updated_blocks_dirty = true;

        Ok(key)
    }

    fn commit(
        &mut self,
        _rng: impl RngCore + CryptoRng,
    ) -> Result<Vec<(Self::KeyId, Self::Key)>, Self::Error> {
        // Build our vector of blocks and pre-commit keys.
        let mut res = vec![];
        for block in self.updated_blocks.clone() {
            let key = self.derive(block)?;
            res.push((block, key));
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
        self.cached_keys.clear();

        self.updated.clear();
        self.updated_dirty = true;

        self.updated_blocks.clear();
        self.updated_blocks_dirty = true;

        Ok(res)
    }
}
