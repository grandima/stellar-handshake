use std::iter;
use thiserror::Error;

#[derive(Default)]
pub struct WriteStream {
    result: Vec<u8>,
}

impl WriteStream {
    pub fn new() -> WriteStream {
        WriteStream { result: Vec::with_capacity(4) }
    }
    pub fn write_binary_data(&mut self, value: &[u8]) {
        self.result.extend_from_slice(value);
        let length = value.len();
        let no_of_padding_bytes = extend_to_multiple_of_4(length) - length;
        self.result.extend(iter::repeat(0).take(no_of_padding_bytes));
    }
    pub fn write_i32(&mut self, value: i32) {
        self.result.extend(value.to_be_bytes().iter());
    }
    pub fn write_u32(&mut self, value: u32) {
        self.result.extend(value.to_be_bytes().iter());
    }
    pub fn write_u64(&mut self, value: u64) {
        self.result.extend(value.to_be_bytes().iter());
    }
    pub fn result(self) -> Vec<u8> {
        self.result
    }
}
pub struct ReadStream<T: AsRef<[u8]>> {
    read_index: usize,
    source: T,
}

impl<T: AsRef<[u8]>> ReadStream<T> {
    pub fn new(source: T) -> ReadStream<T> {
        ReadStream { read_index: 0, source }
    }

    fn sudden_end_error(&self, no_of_bytes_to_read: usize) -> DecodeError {
        DecodeError::SuddenEnd {
            actual_length: self.source.as_ref().len(),
            expected_length: no_of_bytes_to_read + self.read_index,
        }
    }
    fn ensure_size(&self, no_of_bytes_to_read: usize) -> Result<(), DecodeError> {
        if no_of_bytes_to_read + self.read_index > self.source.as_ref().len() {
            return Err(self.sudden_end_error(no_of_bytes_to_read))
        }
        Ok(())
    }

    pub fn read_bytes_array(&mut self, no_of_bytes: usize) -> Result<Vec<u8>, DecodeError> {
        self.ensure_size(extend_to_multiple_of_4(no_of_bytes))?;
        let result = self.source.as_ref()[self.read_index..self.read_index + no_of_bytes].to_vec();
        self.read_index += extend_to_multiple_of_4(no_of_bytes);
        Ok(result)
    }
    pub fn read_i32(&mut self) -> Result<i32, DecodeError> {
        let array: &[u8; 4] = self.read_limited_bytes_array(false)?;
        Ok(i32::from_be_bytes(*array))
    }
    pub fn read_next_u32(&mut self) -> Result<u32, DecodeError> {
        let array: &[u8; 4] = self.read_limited_bytes_array(false)?;
        Ok(u32::from_be_bytes(*array))
    }
    pub fn read_u64(&mut self) -> Result<u64, DecodeError> {
        let array: &[u8; 8] = self.read_limited_bytes_array(false)?;
        Ok(u64::from_be_bytes(*array))
    }
    pub fn read_length(&mut self, only_peek: bool) -> Result<usize, DecodeError> {
        let array: &[u8; 4] = self.read_limited_bytes_array(only_peek)?;
        Ok((u32::from_be_bytes(*array) & 0x7f_ff_ff_ff) as usize)
    }

    fn read_limited_bytes_array<const N: usize>(&mut self, only_peek: bool) -> Result<&[u8; N], DecodeError> {
        let array: Result<&[u8; N], _> = (self.source.as_ref()[self.read_index..self.read_index + N]).try_into();
        match array {
            Ok(array) => {
                if !only_peek {
                    self.read_index += N;
                }
                Ok(array)
            },
            Err(_) => Err(self.sudden_end_error(N)),
        }
    }
    pub fn no_of_bytes_left_to_read(&self) -> isize {
        self.source.as_ref().len() as isize - self.read_index as isize
    }
    pub fn get_position(&self) -> usize {
        self.read_index
    }
}

fn extend_to_multiple_of_4(value: usize) -> usize {
    (value + 3) & !3
}

#[derive(Debug, Error)]
#[error("Decode Error")]
pub enum DecodeError {
    SuddenEnd {
        actual_length: usize,
        expected_length: usize,
    },

    InvalidEnumDiscriminator {
        at_position: usize,
    },
    ExceedsMaximumLength {
        requested_length: usize,
        allowed_length: i32,
    },
    InvalidXdrArchiveLength {
        at_position: usize,
    },
}