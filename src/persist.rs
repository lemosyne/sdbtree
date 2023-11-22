use crate::{error::Error, node::Node, utils, BKeyTree, BlockId, Key, NodeId, AES256CTR_KEY_SZ};
use crypter::Crypter;
use embedded_io::adapters::FromStd;
use rand::{CryptoRng, RngCore};
use std::{collections::HashSet, fs::File};
use storage::Storage;

pub struct BKeyTreeMeta<const KEY_SZ: usize = AES256CTR_KEY_SZ> {
    pub degree: usize,
    pub len: usize,
    pub updated: HashSet<NodeId>,
    pub updated_blocks: HashSet<BlockId>,
}

impl<R, S, C, const KEY_SZ: usize> BKeyTree<R, S, C, KEY_SZ>
where
    R: RngCore + CryptoRng + Default,
    S: Storage<Id = u64>,
    C: Crypter,
{
    fn len_path(&self) -> String {
        format!("{}/len", self.storage.root_path())
    }

    fn len_path_in<T: Storage>(storage: &T) -> String {
        format!("{}/len", storage.root_path())
    }

    fn degree_path(&self) -> String {
        format!("{}/degree", self.storage.root_path())
    }

    fn degree_path_in<T: Storage>(storage: &T) -> String {
        format!("{}/degree", storage.root_path())
    }

    fn updated_path(&self) -> String {
        format!("{}/updated", self.storage.root_path())
    }

    fn updated_path_in<T: Storage>(storage: &T) -> String {
        format!("{}/updated", storage.root_path())
    }

    fn updated_blocks_path(&self) -> String {
        format!("{}/updated_blocks", self.storage.root_path())
    }

    fn updated_blocks_path_in<T: Storage>(storage: &T) -> String {
        format!("{}/updated_blocks", storage.root_path())
    }

    fn new_rw_io(path: &str) -> Result<FromStd<File>, Error> {
        Ok(FromStd::new(
            File::options()
                .read(true)
                .write(true)
                .create(true)
                .open(path)?,
        ))
    }

    pub fn load_meta(_key: Key<KEY_SZ>, storage: &mut S) -> Result<BKeyTreeMeta<KEY_SZ>, Error>
    where
        S: Storage<Id = u64>,
    {
        let degree = {
            let mut reader = Self::new_rw_io(&Self::degree_path_in(storage))?;
            utils::read_u64(&mut reader)? as usize
        };

        let len = {
            let mut reader = Self::new_rw_io(&Self::len_path_in(storage))?;
            utils::read_u64(&mut reader)? as usize
        };

        let updated = {
            let mut reader = Self::new_rw_io(&Self::updated_path_in(storage))?;
            let updated_raw = utils::read_length_prefixed_bytes_clear(&mut reader)?;
            bincode::deserialize(&updated_raw).map_err(|_| Error::Deserialization)?
        };

        let updated_blocks = {
            let mut reader = Self::new_rw_io(&Self::updated_blocks_path_in(storage))?;
            let updated_blocks_raw = utils::read_length_prefixed_bytes_clear(&mut reader)?;
            bincode::deserialize(&updated_blocks_raw).map_err(|_| Error::Deserialization)?
        };

        Ok(BKeyTreeMeta {
            len,
            degree,
            updated,
            updated_blocks,
        })
    }

    pub fn persist_meta(&mut self, _key: Key<KEY_SZ>) -> Result<(), Error> {
        if self.degree_dirty {
            let mut writer = Self::new_rw_io(&self.degree_path())?;
            utils::write_u64(&mut writer, self.degree as u64)?;
            self.degree_dirty = false;
            // eprintln!("newly persisted degree");
        } else {
            // eprintln!("already persisted degree");
        }

        if self.len_dirty {
            let mut writer = Self::new_rw_io(&self.len_path())?;
            utils::write_u64(&mut writer, self.len as u64)?;
            self.len_dirty = false;
            // eprintln!("newly persisted len");
        } else {
            // eprintln!("already persisted len");
        }

        if self.updated_dirty {
            let mut writer = Self::new_rw_io(&self.updated_path())?;
            let updated_raw =
                bincode::serialize(&self.updated).map_err(|_| Error::Serialization)?;
            utils::write_length_prefixed_bytes_clear(&mut writer, &updated_raw)?;
            self.updated_dirty = false;
            // eprintln!("newly persisted updated");
        } else {
            // eprintln!("already persisted updated");
        }

        if self.updated_blocks_dirty {
            let mut writer = Self::new_rw_io(&self.updated_blocks_path())?;
            let updated_blocks_raw =
                bincode::serialize(&self.updated_blocks).map_err(|_| Error::Serialization)?;
            utils::write_length_prefixed_bytes_clear(&mut writer, &updated_blocks_raw)?;
            self.updated_blocks_dirty = false;
            // eprintln!("newly persisted updated blocks");
        } else {
            // eprintln!("already persisted updated blocks");
        }

        Ok(())
    }

    pub fn persist_meta_to<T: Storage<Id = u64>>(
        &mut self,
        _key: Key<KEY_SZ>,
        storage: &mut T,
    ) -> Result<(), Error> {
        let mut writer = Self::new_rw_io(&Self::degree_path_in(storage))?;
        utils::write_u64(&mut writer, self.degree as u64)?;

        let mut writer = Self::new_rw_io(&Self::len_path_in(storage))?;
        utils::write_u64(&mut writer, self.len as u64)?;

        let mut writer = Self::new_rw_io(&Self::updated_path_in(storage))?;
        let updated_raw = bincode::serialize(&self.updated).map_err(|_| Error::Serialization)?;
        utils::write_length_prefixed_bytes_clear(&mut writer, &updated_raw)?;

        let mut writer = Self::new_rw_io(&Self::updated_blocks_path_in(storage))?;
        let updated_blocks_raw =
            bincode::serialize(&self.updated_blocks).map_err(|_| Error::Serialization)?;
        utils::write_length_prefixed_bytes_clear(&mut writer, &updated_blocks_raw)?;

        Ok(())
    }

    pub fn load(&mut self, id: NodeId, key: Key<KEY_SZ>) -> Result<(), Error> {
        // Load the root node.
        let root = Node::load::<C, S>(id, key, &mut self.storage)?;

        // Load the metadata.
        let meta = Self::load_meta(key, &mut self.storage)?;

        // Update state after the fallible operations.
        self.root = root;
        self.degree = meta.degree;
        self.len = meta.len;
        self.updated = meta.updated;
        self.updated_blocks = meta.updated_blocks;

        Ok(())
    }

    pub fn persist(&mut self, key: Key<KEY_SZ>) -> Result<(), Error> {
        // Persist the root node.
        self.root
            .persist::<C, S>(key, &mut self.storage)
            .map_err(|_| Error::Storage)?;

        // Persist the metadata.
        self.persist_meta(key)?;

        Ok(())
    }

    pub fn persist_to<T: Storage<Id = u64>>(
        &mut self,
        key: Key<KEY_SZ>,
        storage: &mut T,
    ) -> Result<(), Error> {
        // Persist the root node.
        self.root
            .persist::<C, T>(key, storage)
            .map_err(|_| Error::Storage)?;

        // Persist the metadata.
        self.persist_meta_to(key, storage)?;

        Ok(())
    }

    pub fn persist_block(&mut self, block: &BlockId, key: Key<KEY_SZ>) -> Result<bool, Error> {
        // if let Some(block_key) = self.in_flight_blocks.remove(block) {
        //     // eprintln!("block {block} inflight");
        //     self.insert(*block, block_key)?;
        // } else {
        //     // eprintln!("block {block} not inflight");
        // }

        // Persist the block, persisting any dirty nodes along the way.
        let res = self
            .root
            .persist_block::<C, S>(block, key, &mut self.storage)?;

        // Persist the metadata if we persisted the block.
        if res {
            // eprintln!("persisted block: {block}");
            self.persist_meta(key)?;
        } else {
            // eprintln!("not persisting block: {block}");
        }

        Ok(res)
    }

    pub fn persist_block_to<T: Storage<Id = u64>>(
        &mut self,
        block: &BlockId,
        key: Key<KEY_SZ>,
        storage: &mut T,
    ) -> Result<bool, Error> {
        // // If the block is in-flight, insert it.
        // if let Some(block_key) = self.in_flight_blocks.remove(block) {
        //     self.insert_no_update(*block, block_key)?;
        // }

        // Persist the block, persisting any nodes along the way.
        let res = self.root.persist_block::<C, T>(block, key, storage)?;

        // Persist the metadata if we persisted the block.
        if res {
            self.persist_meta_to(key, storage)?;
        }

        Ok(res)
    }
}
