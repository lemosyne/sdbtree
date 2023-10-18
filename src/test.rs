use super::*;
use anyhow::Result;
use std::{collections::HashMap, fs};

#[test]
fn simple() -> Result<()> {
    let mut rng = ThreadRng::default();
    let mut map = HashMap::new();
    let mut tree = BKeyTree::new("/tmp/bkeytreedir-simple", utils::generate_key(&mut rng))?;

    for block in 0..1000 {
        let key = utils::generate_key(&mut rng);
        map.insert(block, key);
        assert_eq!(tree.insert(block, key)?, None);
        assert_eq!(tree.len(), block as usize + 1);
    }

    for block in 0..1000 {
        let key = map.remove(&block).unwrap();
        assert_eq!(tree.remove_entry(&block)?, Some((block, key)));
        assert_eq!(tree.len(), 999 - block as usize);
    }

    let _ = fs::remove_dir_all("/tmp/bkeytreedir-simple");

    Ok(())
}

#[test]
fn reloading() -> Result<()> {
    let mut rng = ThreadRng::default();
    let mut map = HashMap::new();
    let mut tree = BKeyTree::new("/tmp/bkeytreedir-reload", utils::generate_key(&mut rng))?;

    for block in 0..1000 {
        let key = utils::generate_key(&mut rng);
        map.insert(block, key);
        assert_eq!(tree.insert(block, key)?, None);
        assert_eq!(tree.len(), block as usize + 1);
    }

    let (id, key) = tree.persist()?;
    let mut tree = BKeyTree::load(id, "/tmp/bkeytreedir-reload", key)?;

    for block in 0..1000 {
        let key = map.remove(&block).unwrap();
        assert_eq!(tree.get_key_value(&block)?, Some((&block, &key)));
    }

    let _ = fs::remove_dir_all("/tmp/bkeytreedir-reload");

    Ok(())
}
