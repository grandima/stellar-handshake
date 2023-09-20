pub struct KeypairType(String);

impl From<String> for KeypairType {
    fn from(s: String) -> Self {
        KeypairType(s)
    }
}

impl Into<String> for KeypairType {
    fn into(self) -> String {
        self.0
    }
}
