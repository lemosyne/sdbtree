use super::*;
use anyhow::Result;
use std::{collections::HashMap, fs};

#[test]
fn simple() -> Result<()> {
    let mut rng = ThreadRng::default();
    let mut map = HashMap::new();
    let mut tree = BKeyTree::new("/tmp/bkeytreedir-simple")?;

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
    let mut tree = BKeyTree::new("/tmp/bkeytreedir-reload")?;

    for block in 0..1000 {
        let key = utils::generate_key(&mut rng);
        map.insert(block, key);
        assert_eq!(tree.insert(block, key)?, None);
        assert_eq!(tree.len(), block as usize + 1);
    }

    let key = utils::generate_key(&mut rng);
    let root_id = tree.root_id();
    tree.persist(key)?;

    let mut tree = BKeyTree::reload(root_id, "/tmp/bkeytreedir-reload", key)?;

    for block in 0..1000 {
        let key = map.remove(&block).unwrap();
        assert_eq!(tree.get_key_value(&block)?, Some((&block, &key)));
    }

    let _ = fs::remove_dir_all("/tmp/bkeytreedir-reload");

    Ok(())
}

#[test]
fn correctness() -> Result<()> {
    let mut tree = BKeyTree::new("/tmp/bkeytreedir-correctness")?;

    // We'll check that we can re-derive this after commit.
    let key4 = tree.derive(4)?;

    // Keys updated/derived during the same epoch should be the same.
    let key5 = tree.derive(5)?;
    let key5_updated = tree.update(5)?;
    assert_eq!(key5, key5_updated);
    assert_eq!(tree.commit(), vec![5]);

    // Should still be able to derive old keys, but not updated keys.
    let key4_rederived = tree.derive(4)?;
    let key5_rederived = tree.derive(5)?;
    assert_eq!(key4, key4_rederived);
    assert_ne!(key5, key5_rederived);

    let _ = fs::remove_dir_all("/tmp/bkeytreedir-correctness");

    Ok(())
}
