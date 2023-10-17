use crate::Storage;
use allocator::{seq::SequentialAllocator, Allocator};
use embedded_io::adapters::FromStd;
use std::{
    fs::{self, File},
    io::{self, ErrorKind},
};

pub struct DirectoryStorage {
    root: String,
    allocator: SequentialAllocator<u64>,
}

impl DirectoryStorage {
    pub fn new(root: &str) -> io::Result<Self> {
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
    type Error = io::Error;
    type ReadHandle<'a> = FromStd<File>;
    type WriteHandle<'a> = FromStd<File>;
    type RwHandle<'a> = FromStd<File>;

    fn alloc_id(&mut self) -> Result<Self::Id, Self::Error> {
        self.allocator
            .alloc()
            .map_err(|_| io::Error::from(ErrorKind::OutOfMemory))
    }

    fn dealloc_id(&mut self, id: Self::Id) -> Result<(), Self::Error> {
        self.allocator
            .dealloc(id)
            .map_err(|_| io::Error::from(ErrorKind::InvalidInput))
    }

    fn read_handle(&mut self, id: &Self::Id) -> Result<Self::ReadHandle<'_>, Self::Error> {
        Ok(FromStd::new(
            File::options()
                .read(true)
                .create(true)
                .open(self.canonicalize(*id))?,
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
