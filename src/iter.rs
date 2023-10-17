use std::marker::PhantomData;

use crate::{error::Error, node::Node};
use serde::Deserialize;
use storage::Storage;

pub struct Iter<'a, K, V, S> {
    nodes: Vec<u64>,
    indices: Vec<usize>,
    storage: &'a mut S,
    pd: PhantomData<(K, V)>,
}

impl<'a, K, V, S> Iter<'a, K, V, S>
where
    for<'de> K: Deserialize<'de>,
    for<'de> V: Deserialize<'de>,
    S: Storage<Id = u64>,
{
    pub(crate) fn new(
        mut root: &'a mut Node<K, V>,
        storage: &'a mut S,
    ) -> Result<Self, Error<S::Error>> {
        let mut nodes = vec![];
        let mut indices = vec![];

        if !root.is_empty() {
            while !root.is_leaf() {
                nodes.push(root.id);
                indices.push(0);
                root = root.access_child(0, storage)?;
            }
            nodes.push(root.id);
            indices.push(0);
        }

        Ok(Self {
            nodes,
            indices,
            storage,
            pd: PhantomData,
        })
    }
}

impl<'a, K, V, S> Iterator for Iter<'a, K, V, S>
where
    for<'de> K: Deserialize<'de> + 'a,
    for<'de> V: Deserialize<'de> + 'a,
    S: Storage<Id = u64>,
{
    type Item = (K, V);

    fn next(&mut self) -> Option<Self::Item> {
        if self.nodes.is_empty() {
            return None;
        }

        let mut node = Node::load(*self.nodes.last().unwrap(), self.storage).ok()?;
        let mut idx = *self.indices.last().unwrap();

        idx += 1;
        *self.indices.last_mut().unwrap() = idx;

        if idx == node.len() {
            self.nodes.truncate(self.nodes.len() - 1);
            self.indices.truncate(self.indices.len() - 1);
        }

        if idx < node.children.len() {
            let mut n = node.access_child(idx, self.storage).ok()?;

            while !n.is_leaf() {
                self.nodes.push(n.id);
                self.indices.push(0);
                n = n.access_child(0, self.storage).ok()?;
            }

            self.nodes.push(n.id);
            self.indices.push(0);
        }

        let key = node.keys.remove(idx - 1);
        let val = node.vals.remove(idx - 1);

        Some((key, val))
    }
}

pub struct Keys<'a, K, V, S> {
    inner: Iter<'a, K, V, S>,
}

impl<'a, K, V, S> Keys<'a, K, V, S> {
    pub(crate) fn new(inner: Iter<'a, K, V, S>) -> Self {
        Self { inner }
    }
}

impl<'a, K, V, S> Iterator for Keys<'a, K, V, S>
where
    for<'de> K: Deserialize<'de> + 'a,
    for<'de> V: Deserialize<'de> + 'a,
    S: Storage<Id = u64>,
{
    type Item = K;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(k, _)| k)
    }
}

pub struct Values<'a, K, V, S> {
    inner: Iter<'a, K, V, S>,
}

impl<'a, K, V, S> Values<'a, K, V, S> {
    pub(crate) fn new(inner: Iter<'a, K, V, S>) -> Self {
        Self { inner }
    }
}

impl<'a, K, V, S> Iterator for Values<'a, K, V, S>
where
    for<'de> K: Deserialize<'de> + 'a,
    for<'de> V: Deserialize<'de> + 'a,
    S: Storage<Id = u64>,
{
    type Item = V;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(_, v)| v)
    }
}
