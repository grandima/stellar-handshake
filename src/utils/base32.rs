//TODO do I need lifetime here?
const ALPHABET: &'static [u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn encode<T: AsRef<[u8]>>(binary: T) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(binary.as_ref().len() * 2);
    let mut shift = 3;
    let mut carry = 0;

    for byte in binary.as_ref().iter() {
        let value_5bit = if shift == 8 { carry } else { carry | ((*byte) >> shift) };
        buffer.push(ALPHABET[(value_5bit & 0x1f) as usize]);

        if shift > 5 {
            shift -= 5;
            let value_5bit = (*byte) >> shift;
            buffer.push(ALPHABET[(value_5bit & 0x1f) as usize]);
        }

        shift = 5 - shift;
        carry = *byte << shift;
        shift = 8 - shift;
    }

    if shift != 3 {
        buffer.push(ALPHABET[(carry & 0x1f) as usize]);
    }

    buffer
}
