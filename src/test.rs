use super::*;
use anyhow::Result;
use rand::Rng;
use std::{collections::HashSet, fs};

const KEY_SZ: usize = 32;

#[test]
fn random_commit() -> Result<()> {
    fn all_keys(tree: &mut BKeyTree) -> Vec<[u8; KEY_SZ]> {
        (0..100).map(|i| tree.derive(i).unwrap()).collect()
    }

    let mut rng = ThreadRng::default();
    let mut tree = BKeyTree::new("/tmp/sdbtree-random-commit")?;

    for _ in 0..10000 {
        let old = all_keys(&mut tree);

        let ks: HashSet<u64> = HashSet::from_iter((0..10).map(|_| {
            let k = rng.gen_range(0..100);
            tree.update(k).unwrap();
            tree.commit(&mut rng).unwrap();
            k
        }));

        let new = all_keys(&mut tree);

        for (i, (o, n)) in old.iter().zip(&new).enumerate() {
            if !ks.contains(&(i as u64)) {
                assert_eq!(o, n);
            }
        }
    }

    Ok(())
}

#[test]
fn simple() -> Result<()> {
    let mut rng = ThreadRng::default();
    let mut map = HashMap::new();
    let mut tree = BKeyTree::new("/tmp/bkeytreedir-simple")?;

    for block in 0..1000 {
        let key = utils::generate_key(&mut rng);
        map.insert(block, key);
        assert_eq!(tree.insert_no_update(block, key)?, None);
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

    // let _ = fs::remove_dir_all("/tmp/bkeytreedir-reload");

    Ok(())
}

// #[test]
// fn correctness() -> Result<()> {
//     let mut rng = ThreadRng::default();
//     let mut tree = BKeyTree::new("/tmp/bkeytreedir-correctness")?;

//     // We'll check that we can re-derive this after commit.
//     let key4 = tree.derive(4)?;

//     // Keys updated/derived during the same epoch should be the same.
//     let key5 = tree.derive(5)?;
//     let key5_updated = tree.update(5)?;
//     assert_eq!(key5, key5_updated);
//     assert_eq!(tree.commit(&mut rng), vec![5]);

//     // Should still be able to derive old keys, but not updated keys.
//     let key4_rederived = tree.derive(4)?;
//     let key5_rederived = tree.derive(5)?;
//     assert_eq!(key4, key4_rederived);
//     assert_ne!(key5, key5_rederived);

//     let _ = fs::remove_dir_all("/tmp/bkeytreedir-correctness");

//     Ok(())
// }
