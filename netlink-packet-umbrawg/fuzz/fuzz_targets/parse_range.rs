#![no_main]
use libfuzzer_sys::fuzz_target;
use netlink_packet_umbrawg::range::{u32_range_from_string, u32_range_unpack};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = u32_range_from_string(s);
    }
    if data.len() >= 8 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&data[..8]);
        let v = u64::from_le_bytes(buf);
        let (lo, hi) = u32_range_unpack(v);
        // no-op use to keep compiler happy
        let _ = (lo, hi);
    }
});
