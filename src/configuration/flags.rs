bitflags! {
    #[derive(Default)]
    pub struct Flags: u32 {
        const CLEAR_PASSWORD = 0b00000001;
        const CLEAR_SECRET = 0b00000010;
    }
}

#[cfg(feature = "serde")]
mod serde {
    use serde::ser::{Serialize, Serializer};
    use serde::de::{Deserialize, Deserializer};

    use super::Flags;

    impl Serialize for Flags {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            unimplemented!()
        }
    }

    impl<'de> Deserialize<'de> for Flags {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Flags, D::Error> {
            unimplemented!()
        }
    }
}
