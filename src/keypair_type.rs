pub struct KeypairType(String);

impl From<String> for KeypairType {
    fn from(s: String) -> Self {
        KeypairType(s)
    }
}

impl From<KeypairType> for String {
    fn from(val: KeypairType) -> Self {
        val.0
    }
}
