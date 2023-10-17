pub mod error;
mod iter;
mod node;

use embedded_io::{
    blocking::{Read, Seek, Write},
    SeekFrom,
};
use error::Error;
use iter::{Iter, Keys, Values};
use node::{Child, Node};
use serde::{Deserialize, Serialize};
use std::mem;
use storage::{
    dir::{self, DirectoryStorage},
    Storage,
};

const DEFAULT_DEGREE: usize = 2;

pub struct BKeyTree<K, V, S = DirectoryStorage>
where
    S: Storage,
{
    len: usize,
    degree: usize,
    root: Node<K, V>,
    storage: S,
}

impl<K, V> BKeyTree<K, V, DirectoryStorage>
where
    for<'de> K: Ord + Serialize + Deserialize<'de>,
    for<'de> V: Serialize + Deserialize<'de>,
{
    pub fn new(path: impl AsRef<str>) -> Result<Self, Error<dir::Error>> {
        Self::with_degree(path, DEFAULT_DEGREE)
    }

    pub fn with_degree(path: impl AsRef<str>, degree: usize) -> Result<Self, Error<dir::Error>> {
        Self::with_storage_and_degree(DirectoryStorage::new(path.as_ref())?, degree)
    }
}

impl<K, V, S> BKeyTree<K, V, S>
where
    for<'de> K: Ord + Serialize + Deserialize<'de>,
    for<'de> V: Serialize + Deserialize<'de>,
    S: Storage<Id = u64>,
{
    pub fn with_storage(storage: S) -> Result<Self, Error<S::Error>> {
        Self::with_storage_and_degree(storage, DEFAULT_DEGREE)
    }

    pub fn with_storage_and_degree(mut storage: S, degree: usize) -> Result<Self, Error<S::Error>> {
        Ok(Self {
            len: 0,
            degree,
            root: Node::new(storage.alloc_id()?),
            storage,
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

    pub fn load(id: u64, mut storage: S) -> Result<Self, Error<S::Error>> {
        // Load the root node.
        let root = Node::load(id, &mut storage)?;

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
            root,
            storage,
        })
    }

    pub fn persist(&mut self) -> Result<u64, Error<S::Error>> {
        // Persist the root node.
        self.root.persist(&mut self.storage)?;

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

        Ok(self.root.id)
    }

    pub fn contains(&mut self, k: &K) -> Result<bool, Error<S::Error>> {
        Ok(self.get(k)?.is_some())
    }

    pub fn get(&mut self, k: &K) -> Result<Option<&V>, Error<S::Error>> {
        Ok(self
            .root
            .get(k, &mut self.storage)?
            .map(|(idx, node)| &node.vals[idx]))
    }

    pub fn get_mut(&mut self, k: &K) -> Result<Option<&mut V>, Error<S::Error>> {
        Ok(self
            .root
            .get_mut(k, &mut self.storage)?
            .map(|(idx, node)| &mut node.vals[idx]))
    }

    pub fn get_key_value(&mut self, k: &K) -> Result<Option<(&K, &V)>, Error<S::Error>> {
        Ok(self
            .root
            .get(k, &mut self.storage)?
            .map(|(idx, node)| (&node.keys[idx], &node.vals[idx])))
    }

    pub fn insert(&mut self, k: K, v: V) -> Result<Option<V>, Error<S::Error>>
    where
        K: Ord,
    {
        if self.root.is_full(self.degree) {
            let mut new_root = Node::new(self.storage.alloc_id()?);
            mem::swap(&mut self.root, &mut new_root);
            self.root.children.push(Child::Loaded(new_root));
            self.root.split_child(0, self.degree, &mut self.storage)?;
        }

        let res = self
            .root
            .insert_nonfull(k, v, self.degree, &mut self.storage)?;

        if res.is_none() {
            self.len += 1;
        }

        Ok(res)
    }

    pub fn remove(&mut self, k: &K) -> Result<Option<V>, Error<S::Error>>
    where
        K: Ord,
    {
        Ok(self.remove_entry(k)?.map(|(_, val)| val))
    }

    pub fn remove_entry(&mut self, k: &K) -> Result<Option<(K, V)>, Error<S::Error>>
    where
        K: Ord,
    {
        if let Some(entry) = self.root.remove(k, self.degree, &mut self.storage)? {
            if !self.root.is_leaf() && self.root.is_empty() {
                self.root = self.root.children.pop().unwrap().as_option_owned().unwrap();
            }
            self.len -= 1;
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    pub fn clear(&mut self) -> Result<u64, Error<S::Error>> {
        self.len = 0;
        self.root.clear(&mut self.storage)?;
        self.root = Node::new(self.storage.alloc_id()?);
        Ok(self.root.id)
    }

    pub fn iter(&mut self) -> Result<Iter<'_, K, V, S>, Error<S::Error>> {
        Iter::new(&mut self.root, &mut self.storage)
    }

    pub fn keys(&mut self) -> Result<Keys<'_, K, V, S>, Error<S::Error>> {
        self.iter().map(Keys::new)
    }

    pub fn values(&mut self) -> Result<Values<'_, K, V, S>, Error<S::Error>> {
        self.iter().map(Values::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use std::fs;

    #[test]
    fn it_works() -> Result<()> {
        let mut tree = BKeyTree::new("bkeytreedir")?;

        for i in 0..10 {
            assert_eq!(tree.insert(i, i + 1)?, None);
        }

        for i in 0..10 {
            assert_eq!(tree.remove_entry(&i)?, Some((i, i + 1)));
        }

        let _ = fs::remove_dir_all("bkeytreedir");

        Ok(())
    }
}
