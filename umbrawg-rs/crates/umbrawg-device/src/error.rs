use umbrawg_noise::NoiseError;
use umbrawg_proto::ProtoError;

pub type Result<T> = core::result::Result<T, DeviceError>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeviceError {
    #[error("device has no private key")]
    NoPrivateKey,
    #[error("unknown peer")]
    UnknownPeer,
    #[error("peer already exists")]
    PeerExists,
    #[error("peer limit reached")]
    TooManyPeers,
    #[error("buffer too small: required {required} bytes, available {available}")]
    BufferTooSmall { required: usize, available: usize },
    #[error("packet exceeds the maximum datagram size")]
    PacketTooLarge,
    #[error("no endpoint configured for the peer")]
    NoEndpoint,
    #[error("peer has no established keypair")]
    NoKeypair,
    #[error("keypair has expired")]
    KeypairExpired,
    #[error("keypair message limit reached")]
    KeypairExhausted,
    #[error("staging queue is full")]
    StagingFull,
    #[error("device is down")]
    DeviceDown,
    #[error("invalid allowed-ip prefix")]
    InvalidPrefix,
    #[error("invalid parameter: {0}")]
    InvalidParameter(&'static str),
    #[error(transparent)]
    Noise(#[from] NoiseError),
    #[error(transparent)]
    Proto(#[from] ProtoError),
}
