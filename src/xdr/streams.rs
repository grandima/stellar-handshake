use std::iter;

pub struct WriteStream {
    result: Vec<u8>,
}

impl WriteStream {
    pub fn new() -> WriteStream {
        WriteStream { result: Vec::with_capacity(128) }
    }
    pub fn write_binary_data(&mut self, value: &[u8]) {
        self.result.extend_from_slice(value);
        let length = value.len();
        let no_of_padding_bytes = extend_to_multiple_of_4(length) - length;
        self.result.extend(iter::repeat(0).take(no_of_padding_bytes));
    }
    pub fn write_u32(&mut self, value: u32) {
        self.result.extend(value.to_be_bytes().iter());
    }
    pub fn write_u64(&mut self, value: u64) {
        self.result.extend(value.to_be_bytes().iter());
    }
    pub fn get_result(self) -> Vec<u8> {
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

    fn generate_sudden_end_error(&self, no_of_bytes_to_read: usize) -> DecodeError {
        DecodeError::SuddenEnd {
            actual_length: self.source.as_ref().len(),
            expected_length: no_of_bytes_to_read + self.read_index,
        }
    }
    fn ensure_size(&self, no_of_bytes_to_read: usize) -> Result<(), DecodeError> {
        if no_of_bytes_to_read + self.read_index > self.source.as_ref().len() {
            return Err(self.generate_sudden_end_error(no_of_bytes_to_read))
        }
        Ok(())
    }

    pub fn read_binary_data(&mut self, no_of_bytes: usize) -> Result<Vec<u8>, DecodeError> {
        self.ensure_size(extend_to_multiple_of_4(no_of_bytes))?;
        let result = self.source.as_ref()[self.read_index..self.read_index + no_of_bytes].to_vec();
        self.read_index += extend_to_multiple_of_4(no_of_bytes);
        Ok(result)
    }
    pub fn read_u32(&mut self) -> Result<u32, DecodeError> {
        let array: &[u8; 4] = self.read_byte_array()?;
        Ok(u32::from_be_bytes(*array))
    }
    pub fn read_i32(&mut self) -> Result<i32, DecodeError> {
        let array: &[u8; 4] = self.read_byte_array()?;
        Ok(i32::from_be_bytes(*array))
    }
    pub fn read_u64(&mut self) -> Result<u64, DecodeError> {
        let array: &[u8; 8] = self.read_byte_array()?;
        Ok(u64::from_be_bytes(*array))
    }

    fn read_byte_array<const N: usize>(&mut self) -> Result<&[u8; N], DecodeError> {
        let array: Result<&[u8; N], _> = (self.source.as_ref()[self.read_index..self.read_index + N]).try_into();

        match array {
            Ok(array) => {
                self.read_index += N;
                Ok(array)
            },
            Err(_) => Err(self.generate_sudden_end_error(N)),
        }
    }
    pub fn get_position(&self) -> usize {
        self.read_index
    }

    pub fn no_of_bytes_left_to_read(&self) -> isize {
        self.source.as_ref().len() as isize - self.read_index as isize
    }
    //TODO: remove this code
    pub fn get_source(&self) -> &T {
        &self.source
    }
}

fn extend_to_multiple_of_4(value: usize) -> usize {
    (value + 3) & !3
}
#[derive(Debug)]
pub enum EncodeError {
    ExceedsMaximumLength {
        requested_length: usize,
        allowed_length: i32,
    },
}
#[derive(Debug)]
pub enum DecodeError {
    /// The XDR data ends too early.
    ///
    /// The decoder expects more bytes to decode the data successfully
    /// The actual length and the expected length are given by `actual_length` and
    /// `expected_length`
    SuddenEnd {
        actual_length: usize,
        expected_length: usize,
    },

    /// There binary data is longer than expected
    ///
    /// The XDR is self delimiting and would end earlier than the length of the provided
    /// binary data. The number of remaining bytes is given by `remaining_no_of_bytes`
    TypeEndsTooEarly {
        remaining_no_of_bytes: isize,
    },

    /// The XDR contains a "Var Opaque" whose length exceeds the specified maximal length
    VarOpaqueExceedsMaxLength {
        at_position: usize,
        max_length: i32,
        actual_length: i32,
    },


    /// The XDR contains an enum with an invalid discriminator
    ///
    /// The discriminator does not have one of the allowed values
    InvalidEnumDiscriminator {
        at_position: usize,
    },

    /// The base64 encoding of the binary XDR is invalid
    InvalidBase64,

    // there is an invalid length encoding in an XDR stream
    InvalidXdrArchiveLength {
        at_position: usize,
    },
}