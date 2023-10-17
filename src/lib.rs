pub mod error;
mod node;

use embedded_io::{
    blocking::{Read, Seek, Write},
    SeekFrom,
};
use error::Error;
use node::{Child, Node};
use serde::{Deserialize, Serialize};
use std::mem;
use storage::{dir::DirectoryStorage, Storage};

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

impl<K, V, S> BKeyTree<K, V, S>
where
    for<'de> K: Ord + Serialize + Deserialize<'de>,
    for<'de> V: Serialize + Deserialize<'de>,
    S: Storage<Id = u64>,
{
    pub fn new(storage: S) -> Result<Self, Error> {
        Self::with_degree(storage, DEFAULT_DEGREE)
    }

    pub fn with_degree(mut storage: S, degree: usize) -> Result<Self, Error> {
        Ok(Self {
            len: 0,
            degree,
            root: Node::new(storage.alloc_id().map_err(|_| Error::Storage)?),
            storage,
        })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn load(id: u64, mut storage: S) -> Result<Self, Error> {
        // Load the root node.
        let root = Node::load(id, &mut storage)?;

        // To load with the extra metadata at the end.
        let mut len_raw = [0; mem::size_of::<u64>()];
        let mut degree_raw = [0; mem::size_of::<u64>()];

        {
            let mut reader = storage.read_handle(&root.id).map_err(|_| Error::Storage)?;

            reader
                .seek(SeekFrom::End(-2 * mem::size_of::<u64>() as i64))
                .map_err(|_| Error::Storage)?;
            reader
                .read_exact(&mut len_raw)
                .map_err(|_| Error::Storage)?;
            reader
                .read_exact(&mut degree_raw)
                .map_err(|_| Error::Storage)?;
        }

        Ok(Self {
            len: u64::from_le_bytes(len_raw) as usize,
            degree: u64::from_le_bytes(degree_raw) as usize,
            root,
            storage,
        })
    }

    pub fn persist(&mut self) -> Result<u64, Error> {
        // Persist the root node.
        self.root.persist(&mut self.storage)?;

        // Acquire a write handle.
        let mut writer = self
            .storage
            .write_handle(&self.root.id)
            .map_err(|_| Error::Storage)?;

        // Append extra metadata to the end.
        writer.seek(SeekFrom::End(0)).map_err(|_| Error::Storage)?;
        writer
            .write_all(&(self.len as u64).to_le_bytes())
            .map_err(|_| Error::Storage)?;
        writer
            .write_all(&(self.degree as u64).to_le_bytes())
            .map_err(|_| Error::Storage)?;

        Ok(self.root.id)
    }

    pub fn contains(&mut self, k: &K) -> Result<bool, Error> {
        Ok(self.get(k)?.is_some())
    }

    pub fn get(&mut self, k: &K) -> Result<Option<&V>, Error> {
        Ok(self
            .root
            .get(k, &mut self.storage)?
            .map(|(idx, node)| &node.vals[idx]))
    }

    pub fn get_mut(&mut self, k: &K) -> Result<Option<&mut V>, Error> {
        Ok(self
            .root
            .get_mut(k, &mut self.storage)?
            .map(|(idx, node)| &mut node.vals[idx]))
    }

    pub fn get_key_value(&mut self, k: &K) -> Result<Option<(&K, &V)>, Error> {
        Ok(self
            .root
            .get(k, &mut self.storage)?
            .map(|(idx, node)| (&node.keys[idx], &node.vals[idx])))
    }

    pub fn insert(&mut self, k: K, v: V) -> Result<Option<V>, Error>
    where
        K: Ord,
    {
        if self.root.is_full(self.degree) {
            let mut new_root = Node::new(self.storage.alloc_id().map_err(|_| Error::Storage)?);
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

    pub fn remove(&mut self, k: &K) -> Result<Option<V>, Error>
    where
        K: Ord,
    {
        Ok(self.remove_entry(k)?.map(|(_, val)| val))
    }

    pub fn remove_entry(&mut self, k: &K) -> Result<Option<(K, V)>, Error>
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

    // pub fn clear(&mut self) {
    //     self.len = 0;
    //     self.root = Node::new();
    // }

    // pub fn iter(&self) -> Iter<'_, K, V> {
    //     Iter::new(&self.root)
    // }

    // pub fn keys(&self) -> Keys<'_, K, V> {
    //     Keys::new(self.iter())
    // }

    // pub fn values(&self) -> Values<'_, K, V> {
    //     Values::new(self.iter())
    // }
}

// impl<K, V> Debug for BKeyTree<K, V>
// where
//     K: Debug,
//     V: Debug,
// {
//     fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
//         write!(f, "{:?}", self.root)
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn it_works() -> Result<()> {
        let mut tree = BKeyTree::new(DirectoryStorage::new("bkeytreedir")?)?;

        for i in 0..10 {
            assert_eq!(tree.insert(i, i + 1)?, None);
        }

        for i in 0..10 {
            assert_eq!(tree.remove_entry(&i)?, Some((i, i + 1)));
        }

        Ok(())
    }
}
