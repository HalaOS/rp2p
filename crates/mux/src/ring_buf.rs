use std::cmp::min;

/// A ring buf implementation used by the recv/send buf of stream state.
#[derive(Default)]
pub(crate) struct RingBuf {
    memory: Vec<u8>,
    chunk_offset: usize,
    chunk_mut_offset: usize,
}

impl RingBuf {
    /// Create ring buf with fixed `capacity`.
    pub(crate) fn with_capacity(fixed: usize) -> Self {
        Self {
            memory: vec![0; fixed],
            ..Default::default()
        }
    }

    /// Returns the number of bytes can be read.
    pub(crate) fn remaining(&self) -> usize {
        self.chunk_mut_offset - self.chunk_offset
    }

    /// Returns the number of bytes that can be written from the current
    /// position until the end of the buffer is reached.
    pub(crate) fn remaining_mut(&self) -> usize {
        self.chunk_offset + self.memory.len() - self.chunk_mut_offset
    }

    /// Write data into ring buf.
    ///
    /// Returns the number of written bytes.
    /// the number of written bytes returned can be lower than the length of the
    /// input buffer when the ring buf doesn’t have enough capacity.
    pub(crate) fn write(&mut self, buf: &[u8]) -> usize {
        let max_written = min(self.remaining_mut(), buf.len());

        if self.chunk_mut_offset % self.memory.len() >= self.chunk_offset % self.memory.len() {
            let chunk_mut_offset = self.chunk_mut_offset % self.memory.len();
            let write_to_end = self.memory.len() - chunk_mut_offset;

            let written_size = min(write_to_end, max_written);

            self.memory[chunk_mut_offset..chunk_mut_offset + written_size]
                .copy_from_slice(&buf[..written_size]);

            if written_size < max_written {
                let next_written = max_written - write_to_end;

                if next_written > 0 {
                    self.memory[..next_written].copy_from_slice(&buf[written_size..max_written]);
                }
            }
        } else if max_written > 0 {
            let chunk_mut_offset = self.chunk_mut_offset % self.memory.len();

            self.memory[chunk_mut_offset..chunk_mut_offset + max_written]
                .copy_from_slice(&buf[..max_written]);
        }

        self.chunk_mut_offset += max_written;

        max_written
    }

    /// Read data from ring buf.
    ///
    /// Returns the number of read bytes.
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> usize {
        let max_read = min(self.remaining(), buf.len());

        if self.chunk_offset % self.memory.len() >= self.chunk_mut_offset % self.memory.len() {
            let chunk_offset = self.chunk_offset % self.memory.len();
            let read_to_end = self.memory.len() - chunk_offset;

            let read_size = min(read_to_end, max_read);

            buf[..read_size].copy_from_slice(&self.memory[chunk_offset..chunk_offset + read_size]);

            if read_size < max_read {
                let next_read_size = max_read - read_size;

                buf[read_size..max_read].copy_from_slice(&self.memory[..next_read_size]);
            }
        } else if max_read > 0 {
            let chunk_offset = self.chunk_offset % self.memory.len();
            buf[..max_read].copy_from_slice(&self.memory[chunk_offset..chunk_offset + max_read]);
        }

        self.chunk_offset += max_read;

        max_read
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_buf() {
        let capacity = 1024;
        let mut ring_buf = RingBuf::with_capacity(capacity);

        assert_eq!(ring_buf.remaining(), 0);
        assert_eq!(ring_buf.remaining_mut(), capacity);

        // write data out of range.

        assert_eq!(ring_buf.write(&vec![1; capacity * 2]), ring_buf.remaining());

        assert_eq!(ring_buf.remaining(), capacity);
        assert_eq!(ring_buf.remaining_mut(), 0);

        let mut buf = vec![0; capacity / 2];

        assert_eq!(ring_buf.read(&mut buf), capacity / 2);

        assert_eq!(buf, vec![1; capacity / 2]);

        assert_eq!(ring_buf.write(&vec![2; capacity / 4]), capacity / 4);

        let mut buf = vec![0; capacity / 2];

        assert_eq!(ring_buf.read(&mut buf), capacity / 2);

        assert_eq!(buf, vec![1; capacity / 2]);

        let mut buf = vec![0; capacity / 8];

        assert_eq!(ring_buf.read(&mut buf), capacity / 8);

        assert_eq!(buf, vec![2; capacity / 8]);

        assert_eq!(ring_buf.remaining_mut(), 7 * capacity / 8);

        assert_eq!(ring_buf.write(&vec![3; capacity * 10]), 7 * capacity / 8);

        assert_eq!(ring_buf.remaining_mut(), 0);

        assert_eq!(ring_buf.remaining(), capacity);

        let mut buf = vec![0; capacity / 8];

        assert_eq!(ring_buf.read(&mut buf), capacity / 8);

        assert_eq!(buf, vec![2; capacity / 8]);

        assert_eq!(ring_buf.remaining_mut(), capacity / 8);

        assert_eq!(ring_buf.remaining(), 7 * capacity / 8);

        let mut buf = vec![0; capacity * 10];

        assert_eq!(ring_buf.read(&mut buf), 7 * capacity / 8);

        assert_eq!(buf[..7 * capacity / 8], vec![3; 7 * capacity / 8]);
    }
}
