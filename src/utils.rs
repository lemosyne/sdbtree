use crate::{error::Error, Key};
use crypter::Crypter;
use embedded_io::blocking::{Read, Write};
use rand::{CryptoRng, RngCore};
use std::{collections::HashMap, mem};
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

    for i in 0..len {
        let start = i as usize * KEY_SZ + mem::size_of::<u64>();
        let end = start + KEY_SZ;
        let key = keys_raw[start..end].try_into().unwrap();
        keys.push(key);
    }

    keys
}

pub fn serialize_keys_map<const KEY_SZ: usize>(keys: &HashMap<u64, Key<KEY_SZ>>) -> Vec<u8> {
    let mut ser = vec![];

    ser.extend((keys.len() as u64).to_le_bytes());
    ser.extend(keys.iter().flat_map(|(block, key)| {
        let mut entry = block.to_le_bytes().to_vec();
        entry.extend(key.iter());
        entry
    }));

    ser
}

pub fn deserialize_keys_map<const KEY_SZ: usize>(keys_raw: &[u8]) -> HashMap<u64, Key<KEY_SZ>> {
    let mut keys = HashMap::new();

    let len = u64::from_le_bytes(keys_raw[..mem::size_of::<u64>()].try_into().unwrap());
    let entry_size = mem::size_of::<u64>() + KEY_SZ;

    for i in 0..len as usize {
        let block_start = i * entry_size + mem::size_of::<u64>();
        let block_end = block_start + mem::size_of::<u64>();

        let key_start = block_end;
        let key_end = key_start + KEY_SZ;

        let block = u64::from_le_bytes(keys_raw[block_start..block_end].try_into().unwrap());
        let key = keys_raw[key_start..key_end].try_into().unwrap();

        keys.insert(block, key);
    }

    keys
}

pub fn read_u64<S>(reader: &mut S::ReadHandle<'_>) -> Result<u64, Error>
where
    S: Storage,
{
    let mut raw = [0; mem::size_of::<u64>()];
    reader.read_exact(&mut raw).map_err(|_| Error::Read)?;
    Ok(u64::from_le_bytes(raw))
}

pub fn write_u64<S>(writer: &mut S::WriteHandle<'_>, val: u64) -> Result<(), Error>
where
    S: Storage,
{
    let raw = val.to_le_bytes();
    writer.write_all(&raw).map_err(|_| Error::Write)?;
    Ok(())
}

pub fn read_length_prefixed_bytes_clear<S>(reader: &mut S::ReadHandle<'_>) -> Result<Vec<u8>, Error>
where
    S: Storage,
{
    let len = read_u64::<S>(reader)?;
    let mut bytes = vec![0; len as usize];
    reader.read_exact(&mut bytes).map_err(|_| Error::Read)?;
    Ok(bytes)
}

pub fn read_length_prefixed_bytes<C, S, const KEY_SZ: usize>(
    reader: &mut S::ReadHandle<'_>,
    key: Key<KEY_SZ>,
) -> Result<Vec<u8>, Error>
where
    C: Crypter,
    S: Storage,
{
    let len = read_u64::<S>(reader)?;
    let mut bytes = vec![0; len as usize];
    reader.read_exact(&mut bytes).map_err(|_| Error::Read)?;

    C::onetime_decrypt(&key, &mut bytes)
        .map_err(|_| ())
        .unwrap();

    Ok(bytes)
}

pub fn write_length_prefixed_bytes_clear<S>(
    writer: &mut S::WriteHandle<'_>,
    bytes: &[u8],
) -> Result<(), Error>
where
    S: Storage,
{
    write_u64::<S>(writer, bytes.len() as u64)?;
    Ok(writer.write_all(&bytes).map_err(|_| Error::Write)?)
}

pub fn write_length_prefixed_bytes<C, S, const KEY_SZ: usize>(
    writer: &mut S::WriteHandle<'_>,
    bytes: &[u8],
    key: Key<KEY_SZ>,
) -> Result<(), Error>
where
    C: Crypter,
    S: Storage,
{
    let mut bytes = bytes.to_vec();

    writer
        .write_all(&(bytes.len() as u64).to_le_bytes())
        .map_err(|_| Error::Write)?;

    C::onetime_encrypt(&key, &mut bytes)
        .map_err(|_| ())
        .unwrap();

    Ok(writer.write_all(&bytes).map_err(|_| Error::Write)?)
}
