//! UmbraWG configuration model: keys, INI parsing and emitting.

pub mod allowed_ip;
pub mod cipher;
pub mod endpoint;
pub mod error;
pub mod ini;
pub mod key;
pub mod model;
pub mod range;

pub use allowed_ip::{max_prefix_len, AllowedIp};
pub use cipher::Cipher;
pub use endpoint::{format_endpoint, parse_endpoint};
pub use error::Error;
pub use ini::{Document, Entry, Section, SectionKind};
pub use key::{Key, KEY_BASE64_LEN, KEY_HEX_LEN, KEY_LEN};
pub use model::{
    is_dns_address, parse_bool_value, split_list_value, Config, DeviceConfig, ObfuscationConfig,
    ParseOptions, PeerConfig, QuickConfig, QuickKey, RoutingTable, MAX_EXTRA_PORTS,
};
pub use range::{U16Range, U32Range};
