#![allow(non_camel_case_types)]

use argonautica::config::{Backend, Variant, Version};

/// Available backends
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(C)]
pub enum argonautica_backend_t {
    /// The C backend
    ARGONAUTICA_C = 0,

    /// The Rust backend
    ARGONAUTICA_RUST = 1,
}

impl From<argonautica_backend_t> for Backend {
    fn from(backend: argonautica_backend_t) -> Backend {
        match backend {
            argonautica_backend_t::ARGONAUTICA_C => Backend::C,
            argonautica_backend_t::ARGONAUTICA_RUST => Backend::Rust,
        }
    }
}

/// Available argon2 variants
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(C)]
pub enum argonautica_variant_t {
    /// argon2d
    ARGONAUTICA_ARGON2D = 0,

    /// argond2i
    ARGONAUTICA_ARGON2I = 1,

    /// argon2id
    ARGONAUTICA_ARGON2ID = 2,
}

impl From<argonautica_variant_t> for Variant {
    fn from(variant: argonautica_variant_t) -> Variant {
        match variant {
            argonautica_variant_t::ARGONAUTICA_ARGON2D => Variant::Argon2d,
            argonautica_variant_t::ARGONAUTICA_ARGON2I => Variant::Argon2i,
            argonautica_variant_t::ARGONAUTICA_ARGON2ID => Variant::Argon2id,
        }
    }
}

/// Available argon2 versions
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(C)]
pub enum argonautica_version_t {
    /// 0x10
    ARGONAUTICA_0x10 = 13,

    /// 0x13
    ARGONAUTICA_0x13 = 16,
}

impl From<argonautica_version_t> for Version {
    fn from(version: argonautica_version_t) -> Version {
        match version {
            argonautica_version_t::ARGONAUTICA_0x10 => Version::_0x10,
            argonautica_version_t::ARGONAUTICA_0x13 => Version::_0x13,
        }
    }
}
