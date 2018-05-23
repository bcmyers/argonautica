bitflags! {
    #[derive(Default)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub(crate) struct Flags: u32 {
        const CLEAR_PASSWORD = 0b01;
        const CLEAR_SECRET_KEY = 0b10;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send() {
        fn assert_send<T: Send>() {}
        assert_send::<Flags>();
    }

    #[test]
    fn test_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<Flags>();
    }
}
