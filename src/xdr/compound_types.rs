use crate::xdr::streams::EncodeError;
#[derive(Debug)]
pub struct LimitedVarOpaque<const N: i32>(pub Vec<u8>);

impl<const N: i32> LimitedVarOpaque<N> {
    pub fn new(vec: Vec<u8>) -> Result<Self, EncodeError> {
        match vec.len() > N as usize {
            true => Err(EncodeError::ExceedsMaximumLength { requested_length: vec.len(), allowed_length: N }),
            false => Ok(LimitedVarOpaque(vec)),
        }
    }
}