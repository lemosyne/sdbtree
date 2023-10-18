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

#[test]
fn correctness() -> Result<()> {
    let mut rng = ThreadRng::default();
    let mut tree = BKeyTree::new(
        "/tmp/bkeytreedir-correctness",
        utils::generate_key(&mut rng),
    )?;
    // A mix of updates and derives.
    let key1 = tree.update(1)?;
    let key2 = tree.update(2)?;
    let key4 = tree.derive(4)?;

    // Committing should yield the two updated keys.
    let mut commit = tree.commit();
    commit.sort();
    assert_eq!(vec![1, 2], commit);

    // We should be able to derive the previously derived/updated keys.
    let key1_updated = tree.derive(1)?;
    let key2_updated = tree.derive(2)?;
    let key4_rederived = tree.derive(4)?;
    assert_eq!(key1, key1_updated);
    assert_eq!(key2, key2_updated);
    assert_eq!(key4, key4_rederived);

    // Just a derive, no updates.
    let key11 = tree.derive(11)?;

    // Committing should yield no keys.
    assert!(tree.commit().is_empty());

    let key15 = tree.update(15)?;
    let key15_derived = tree.derive(15)?;
    let key13 = tree.derive(13)?;
    assert_eq!(key15, key15_derived);

    // Committing should yield the one update key.
    assert_eq!(vec![15], tree.commit());

    // We can still derive the old stuff.
    let key11_rederived = tree.derive(11)?;
    let key13_rederived = tree.derive(13)?;
    let key15_rederived = tree.derive(15)?;
    assert_eq!(key11, key11_rederived);
    assert_eq!(key13, key13_rederived);
    assert_eq!(key15, key15_rederived);

    // One more check on appending.
    let key16 = tree.derive(16)?;

    // Committing should yield no keys.
    assert!(tree.commit().is_empty());

    let key16_rederived = tree.derive(16)?;
    assert_eq!(key16, key16_rederived);

    Ok(())
}
