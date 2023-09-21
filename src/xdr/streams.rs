use std::iter;

pub struct WriteStream {
    result: Vec<u8>,
}

impl WriteStream {
    pub fn write_next_binary_data(&mut self, value: &[u8]) {
        self.result.extend_from_slice(value);
        let length = value.len();
        let no_of_padding_bytes = extend_to_multiple_of_4(length) - length;
        self.result.extend(iter::repeat(0).take(no_of_padding_bytes));
    }
}
pub struct ReadStream<T: AsRef<[u8]>> {
    read_index: usize,
    source: T,
}

impl<T: AsRef<[u8]>> ReadStream<T> {
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

    pub fn read_next_binary_data(&mut self, no_of_bytes: usize) -> Result<Vec<u8>, DecodeError> {
        self.ensure_size(extend_to_multiple_of_4(no_of_bytes))?;
        let result = self.source.as_ref()[self.read_index..self.read_index + no_of_bytes].to_vec();
        self.read_index += extend_to_multiple_of_4(no_of_bytes);
        Ok(result)
    }
}

fn extend_to_multiple_of_4(value: usize) -> usize {
    (value + 3) & !3
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

    /// The XDR contains an invalid boolean
    ///
    /// The boolean is neither encoded as 0 or 1. The value found is given by `found_integer`.
    InvalidBoolean {
        found_integer: i32,
        at_position: usize,
    },

    /// The XDR contains a "Var Opaque" whose length exceeds the specified maximal length
    VarOpaqueExceedsMaxLength {
        at_position: usize,
        max_length: i32,
        actual_length: i32,
    },

    /// The XDR contains a string whose length exceeds the specified maximal length
    StringExceedsMaxLength {
        at_position: usize,
        max_length: i32,
        actual_length: i32,
    },

    /// The XDR contains a "Var Array" whose length exceeds the specified maximal length
    VarArrayExceedsMaxLength {
        at_position: usize,
        max_length: i32,
        actual_length: i32,
    },

    /// The XDR contains an in invalid "Optional"
    ///
    /// The "optional" is neither encoded as 0 or 1. The value found is given by `has_code`.
    InvalidOptional {
        at_position: usize,
        has_code: u32,
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