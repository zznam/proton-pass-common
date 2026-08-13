use std::io;
use std::io::{Read, Seek, SeekFrom};

pub(crate) struct HeadTailReader<'a> {
    head: &'a [u8],
    tail: &'a [u8],
    total_len: u64,
    pos: u64,
}

impl<'a> HeadTailReader<'a> {
    pub(crate) fn new(head: &'a [u8], tail: &'a [u8], total_len: u64) -> Self {
        Self {
            head,
            tail,
            total_len,
            pos: 0,
        }
    }

    pub(crate) fn tail_start(&self) -> u64 {
        self.total_len.saturating_sub(self.tail.len() as u64)
    }
}

impl Read for HeadTailReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.total_len {
            return Ok(0);
        }

        if self.pos < self.head.len() as u64 {
            let start = self.pos as usize;
            let n = buf.len().min(self.head.len() - start);
            buf[..n].copy_from_slice(&self.head[start..start + n]);
            self.pos += n as u64;
            return Ok(n);
        }

        let tail_start = self.tail_start();
        if self.pos >= tail_start {
            let start = (self.pos - tail_start) as usize;
            let n = buf.len().min(self.tail.len() - start);
            buf[..n].copy_from_slice(&self.tail[start..start + n]);
            self.pos += n as u64;
            return Ok(n);
        }

        Ok(0)
    }
}

impl Seek for HeadTailReader<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(offset) => offset as i128,
            SeekFrom::End(offset) => self.total_len as i128 + offset as i128,
            SeekFrom::Current(offset) => self.pos as i128 + offset as i128,
        };

        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid seek to a negative position",
            ));
        }

        self.pos = new_pos as u64;
        Ok(self.pos)
    }
}
