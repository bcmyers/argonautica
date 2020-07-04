mod ffi;

/// Returns the encoded hash length for the given input parameters
///
/// * @param t_cost  Number of iterations
/// * @param m_cost  Memory usage in kibibytes
/// * @param parallelism  Number of threads; used to compute lanes
/// * @param saltlen  Salt size in bytes
/// * @param hashlen  Hash size in bytes
/// * @param type The argon2_type that we want the encoded length for
/// * @return  The encoded hash length in bytes
pub fn argon2_encodedlen(
    t_cost: u32,
    m_cost: u32,
    parallelism: u32,
    saltlen: u32,
    hashlen: u32,
    variant: Variant,
) -> u64 {
    unsafe {
        ffi::argon2_encodedlen(
            t_cost,
            m_cost,
            parallelism,
            saltlen,
            hashlen,
            variant.into(),
        ) as u64
    }
}

/// Enum representing the various variants of the argon2 algorithm ( `Argon2d`,
/// `Argon2i`, and `Argon2id`).
///
/// "Argon2 has one primary variant: Argon2id, and two supplementary variants:
/// Argon2d and Argon2i. Argon2d uses data-dependent memory access, which makes
/// it suitable for ... applications with no threats from side-channel timing
/// attacks. Argon2i uses data-independent memory access, which is preferred for
/// password hashing and password-based key derivation. Argon2id works as
/// Argon2i for the first half of the first iteration over the memory, and as
/// Argon2d for the rest, thus providing both side-channel attack protection
/// and brute-force cost savings due to time-memory tradeoffs."
///
/// If you do not know which variant to use, use the default, which is
/// `Argon2id`
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum Variant {
    /// Variant of the Argon2 algorithm that is faster and uses data-depending memory access,
    /// which makes it suitable for applications with no threats from side-channel timing attackes.
    /// Do <b><u>not</b></u> use this unless you have a specific reason to.
    Argon2d = 0,

    /// Variant of the Argon2 algorithm that uses data-independent memory access, which is
    /// preferred for password hashing and password-based key derivation. Do <b><u>not</b></u> use
    /// this unless you have a specific reason to.
    Argon2i = 1,

    /// Default variant of the Argon2 algorithm that works as Argon2i for the first half of the
    /// first iteration over the memory, and as Argon2d for the rest, thus providing both
    /// side-channel attack protection and brute-force cost savings due to time-memory tradeoffs.
    /// Use this unless you have a specific reason not to.
    Argon2id = 2,
}

impl Default for Variant {
    fn default() -> Self {
        Self::Argon2id
    }
}

impl From<Variant> for ffi::argon2_type {
    fn from(v: Variant) -> Self {
        match v {
            Variant::Argon2d => ffi::argon2_type::Argon2_d,
            Variant::Argon2i => ffi::argon2_type::Argon2_i,
            Variant::Argon2id => ffi::argon2_type::Argon2_id,
        }
    }
}
