use crate::{error::Error, Key};
use embedded_io::blocking::{Read, Write};
use rand::{CryptoRng, RngCore};
use std::mem;
use storage::Storage;

pub fn generate_key<R, const KEY_SZ: usize>(rng: &mut R) -> Key<KEY_SZ>
where
    R: RngCore + CryptoRng,
{
    let mut key = [0; KEY_SZ];
    rng.fill_bytes(&mut key);
    key
}

pub fn serialize_ids(ids: &[u64]) -> Vec<u8> {
    let mut ser = vec![];

    ser.extend((ids.len() as u64).to_le_bytes());
    ser.extend(ids.iter().flat_map(|id| id.to_le_bytes()));

    ser
}

pub fn deserialize_ids(ids_raw: &[u8]) -> Vec<u64> {
    let mut ids = vec![];

    let len = u64::from_le_bytes(ids_raw[..mem::size_of::<u64>()].try_into().unwrap());

    for i in 1..=len {
        let start = i as usize * mem::size_of::<u64>();
        let end = start + mem::size_of::<u64>();
        let id = u64::from_le_bytes(ids_raw[start..end].try_into().unwrap());
        ids.push(id);
    }

    ids
}

pub fn serialize_keys<const KEY_SZ: usize>(keys: &[Key<KEY_SZ>]) -> Vec<u8> {
    let mut ser = vec![];

    ser.extend((keys.len() as u64).to_le_bytes());
    ser.extend(keys.iter().flat_map(|key| key.iter()));

    ser
}

pub fn deserialize_keys<const KEY_SZ: usize>(keys_raw: &[u8]) -> Vec<Key<KEY_SZ>> {
    let mut keys = vec![];

    let len = u64::from_le_bytes(keys_raw[..mem::size_of::<u64>()].try_into().unwrap());

    for i in 1..=len {
        let start = i as usize * KEY_SZ;
        let end = start + KEY_SZ;
        let key = keys_raw[start..end].try_into().unwrap();
        keys.push(key);
    }

    keys
}

pub fn read_length_prefixed_bytes<S>(
    reader: &mut S::ReadHandle<'_>,
) -> Result<Vec<u8>, Error<S::Error>>
where
    S: Storage,
{
    let mut len_raw = [0; mem::size_of::<u64>()];
    reader.read_exact(&mut len_raw).map_err(|_| Error::Read)?;

    let len = u64::from_le_bytes(len_raw);
    let mut bytes = vec![0; len as usize];
    reader.read_exact(&mut bytes).map_err(|_| Error::Read)?;

    Ok(bytes)
}

pub fn write_length_prefixed_bytes<S>(
    writer: &mut S::WriteHandle<'_>,
    bytes: &[u8],
) -> Result<(), Error<S::Error>>
where
    S: Storage,
{
    writer
        .write_all(&(bytes.len() as u64).to_le_bytes())
        .map_err(|_| Error::Write)?;
    Ok(writer.write_all(bytes).map_err(|_| Error::Write)?)
}
