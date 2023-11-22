use crate::{error::Error, Key};
use crypter::Crypter;
use embedded_io::blocking::{Read, Write};
use rand::{CryptoRng, RngCore};
use std::mem;

pub fn generate_key<R, const KEY_SZ: usize>(rng: &mut R) -> Key<KEY_SZ>
where
    R: RngCore + CryptoRng,
{
    let mut key = [0; KEY_SZ];
    rng.fill_bytes(&mut key);
    key
}

pub fn serialize_ids(ids: &[u64]) -> Vec<u8> {
    let mut ser = Vec::with_capacity(mem::size_of::<u64>() * ids.len());

    ser.extend((ids.len() as u64).to_le_bytes());

    for id in ids {
        ser.extend(id.to_le_bytes());
    }

    ser
}

pub fn deserialize_ids(ids_raw: &[u8]) -> Vec<u64> {
    let len = u64::from_le_bytes(ids_raw[..mem::size_of::<u64>()].try_into().unwrap());

    if len == 0 {
        return vec![];
    }

    let mut ids = Vec::with_capacity(len as usize);

    for i in 1..=len {
        let start = i as usize * mem::size_of::<u64>();
        let end = start + mem::size_of::<u64>();
        let id = u64::from_le_bytes(ids_raw[start..end].try_into().unwrap());
        ids.push(id);
    }

    ids
}

pub fn serialize_keys<const KEY_SZ: usize>(keys: &[Key<KEY_SZ>]) -> Vec<u8> {
    let mut ser = Vec::with_capacity(KEY_SZ * keys.len());

    ser.extend((keys.len() as u64).to_le_bytes());

    for key in keys {
        ser.extend(key.iter());
    }

    ser
}

pub fn deserialize_keys<const KEY_SZ: usize>(keys_raw: &[u8]) -> Vec<Key<KEY_SZ>> {
    let len = u64::from_le_bytes(keys_raw[..mem::size_of::<u64>()].try_into().unwrap());

    if len == 0 {
        return vec![];
    }

    let mut keys = Vec::with_capacity(len as usize);

    for i in 0..len {
        let start = i as usize * KEY_SZ + mem::size_of::<u64>();
        let end = start + KEY_SZ;
        let key = keys_raw[start..end].try_into().unwrap();
        keys.push(key);
    }

    keys
}

// pub fn serialize_keys_map<const KEY_SZ: usize>(keys: &HashMap<u64, Key<KEY_SZ>>) -> Vec<u8> {
//     let mut ser = Vec::with_capacity(KEY_SZ * keys.len());

//     ser.extend((keys.len() as u64).to_le_bytes());

//     for (block, key) in keys.iter() {
//         ser.extend(block.to_le_bytes());
//         ser.extend(key.iter());
//     }

//     ser
// }

// pub fn deserialize_keys_map<const KEY_SZ: usize>(keys_raw: &[u8]) -> HashMap<u64, Key<KEY_SZ>> {
//     let mut keys = HashMap::new();

//     let len = u64::from_le_bytes(keys_raw[..mem::size_of::<u64>()].try_into().unwrap());
//     let entry_size = mem::size_of::<u64>() + KEY_SZ;

//     for i in 0..len as usize {
//         let block_start = i * entry_size + mem::size_of::<u64>();
//         let block_end = block_start + mem::size_of::<u64>();

//         let key_start = block_end;
//         let key_end = key_start + KEY_SZ;

//         let block = u64::from_le_bytes(keys_raw[block_start..block_end].try_into().unwrap());
//         let key = keys_raw[key_start..key_end].try_into().unwrap();

//         keys.insert(block, key);
//     }

//     keys
// }

pub fn read_u64(reader: &mut impl Read) -> Result<u64, Error> {
    let mut raw = [0; mem::size_of::<u64>()];
    reader.read_exact(&mut raw).map_err(|_| Error::Read)?;
    Ok(u64::from_le_bytes(raw))
}

pub fn write_u64(writer: &mut impl Write, val: u64) -> Result<(), Error> {
    let raw = val.to_le_bytes();
    writer.write_all(&raw).map_err(|_| Error::Write)?;
    Ok(())
}

pub fn read_length_prefixed_bytes_clear(reader: &mut impl Read) -> Result<Vec<u8>, Error> {
    let len = read_u64(reader)?;
    let mut bytes = vec![0; len as usize];
    reader.read_exact(&mut bytes).map_err(|_| Error::Read)?;
    Ok(bytes)
}

pub fn read_length_prefixed_bytes<C, const KEY_SZ: usize>(
    reader: &mut impl Read,
    key: Key<KEY_SZ>,
) -> Result<Vec<u8>, Error>
where
    C: Crypter,
{
    let len = read_u64(reader)?;
    let mut bytes = vec![0; len as usize];
    reader.read_exact(&mut bytes).map_err(|_| Error::Read)?;

    C::onetime_decrypt(&key, &mut bytes)
        .map_err(|_| ())
        .unwrap();

    Ok(bytes)
}

pub fn write_length_prefixed_bytes_clear(
    writer: &mut impl Write,
    bytes: &[u8],
) -> Result<(), Error> {
    write_u64(writer, bytes.len() as u64)?;
    Ok(writer.write_all(&bytes).map_err(|_| Error::Write)?)
}

pub fn write_length_prefixed_bytes<C, const KEY_SZ: usize>(
    writer: &mut impl Write,
    bytes: &[u8],
    key: Key<KEY_SZ>,
) -> Result<(), Error>
where
    C: Crypter,
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
