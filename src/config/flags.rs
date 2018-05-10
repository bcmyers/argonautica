bitflags! {
    #[derive(Default, Serialize, Deserialize)]
    pub(crate) struct Flags: u32 {
        const CLEAR_PASSWORD = 0b01;
        const CLEAR_SECRET_KEY = 0b10;
    }
}
