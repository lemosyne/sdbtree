// #[cfg(test)]
// mod tests {
//     use super::*;
//     use anyhow::Result;
//     use std::fs;

//     #[test]
//     fn simple() -> Result<()> {
//         let mut tree = BKeyTree::new("/tmp/bkeytreedir-simple")?;

//         for i in 0..1000 {
//             assert_eq!(tree.insert(i, i + 1)?, None);
//             assert_eq!(tree.len(), i + 1);
//         }

//         for i in 0..1000 {
//             assert_eq!(tree.remove_entry(&i)?, Some((i, i + 1)));
//             assert_eq!(tree.len(), 999 - i);
//         }

//         let _ = fs::remove_dir_all("/tmp/bkeytreedir-simple");

//         Ok(())
//     }

//     #[test]
//     fn reloading() -> Result<()> {
//         let mut tree = BKeyTree::new("/tmp/bkeytreedir-reload")?;

//         for i in 0..1000 {
//             assert_eq!(tree.insert(i, i + 1)?, None);
//         }
//         assert_eq!(tree.len(), 1000);

//         let mut tree = BKeyTree::load(tree.persist()?, "/tmp/bkeytreedir-reload")?;

//         for i in 0..1000 {
//             assert_eq!(tree.get_key_value(&i)?, Some((&i, &(i + 1))));
//         }

//         let _ = fs::remove_dir_all("/tmp/bkeytreedir-reload");

//         Ok(())
//     }
// }
