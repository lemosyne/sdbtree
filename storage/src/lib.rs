#[cfg(feature = "dir")]
pub mod dir;

use embedded_io::blocking::{Read, Seek, Write};
use std::error::Error;

pub trait Storage {
    /// Type for an object identifier.
    type Id: PartialEq;

    /// Type for storage errors.
    type Error: Error;

    /// Type of handle to read data with.
    type ReadHandle<'a>: Read + Seek
    where
        Self: 'a;

    /// Type of handle to write data with.
    type WriteHandle<'a>: Write + Seek
    where
        Self: 'a;

    /// Type of handle to read and write data with.
    type RwHandle<'a>: Read + Write + Seek
    where
        Self: 'a;

    /// Allocates an object `id`.
    fn alloc_id(&mut self) -> Result<Self::Id, Self::Error>;

    /// Deallocates an object `id`.
    // FIXME: have this take a reference to id
    fn dealloc_id(&mut self, id: Self::Id) -> Result<(), Self::Error>;

    /// Returns a handle to read data from object `id`.
    fn read_handle(&mut self, id: &Self::Id) -> Result<Self::ReadHandle<'_>, Self::Error>;

    /// Returns a handle to write data to object `id`.
    fn write_handle(&mut self, id: &Self::Id) -> Result<Self::WriteHandle<'_>, Self::Error>;

    /// Returns a handle to read from/write to object `id`.
    fn rw_handle(&mut self, id: &Self::Id) -> Result<Self::RwHandle<'_>, Self::Error>;
}
