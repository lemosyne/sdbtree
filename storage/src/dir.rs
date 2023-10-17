use crate::Storage;
use allocator::{seq::SequentialAllocator, Allocator};
use embedded_io::adapters::FromStd;
use std::{
    fs::{self, File},
    io,
};
use thiserror::Error;

pub struct DirectoryStorage {
    root: String,
    allocator: SequentialAllocator<u64>,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error("couldn't allocate ID")]
    Alloc,

    #[error("couldn't deallocate ID: {0}")]
    Dealloc(u64),
}

impl DirectoryStorage {
    pub fn new(root: &str) -> Result<Self, Error> {
        fs::create_dir_all(root)?;

        Ok(Self {
            root: root.into(),
            allocator: SequentialAllocator::new(),
        })
    }

    fn canonicalize(&self, id: u64) -> String {
        format!("{}/{}", self.root, id)
    }
}

impl Storage for DirectoryStorage {
    type Id = u64;
    type Error = Error;
    type ReadHandle<'a> = FromStd<File>;
    type WriteHandle<'a> = FromStd<File>;
    type RwHandle<'a> = FromStd<File>;

    fn alloc_id(&mut self) -> Result<Self::Id, Self::Error> {
        self.allocator.alloc().map_err(|_| Error::Alloc)
    }

    fn dealloc_id(&mut self, id: Self::Id) -> Result<(), Self::Error> {
        self.allocator.dealloc(id).map_err(|_| Error::Dealloc(id))
    }

    fn truncate_id(&mut self, id: &Self::Id, size: u64) -> Result<(), Self::Error> {
        Ok(File::options()
            .write(true)
            .create(true)
            .open(self.canonicalize(*id))?
            .set_len(size)?)
    }

    fn read_handle(&mut self, id: &Self::Id) -> Result<Self::ReadHandle<'_>, Self::Error> {
        Ok(FromStd::new(
            File::options().read(true).open(self.canonicalize(*id))?,
        ))
    }

    fn write_handle(&mut self, id: &Self::Id) -> Result<Self::WriteHandle<'_>, Self::Error> {
        Ok(FromStd::new(
            File::options()
                .write(true)
                .create(true)
                .open(self.canonicalize(*id))?,
        ))
    }

    fn rw_handle(&mut self, id: &Self::Id) -> Result<Self::WriteHandle<'_>, Self::Error> {
        Ok(FromStd::new(
            File::options()
                .read(true)
                .write(true)
                .create(true)
                .open(self.canonicalize(*id))?,
        ))
    }
}
