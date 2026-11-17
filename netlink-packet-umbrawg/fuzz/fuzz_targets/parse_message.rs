// SPDX-License-Identifier: MIT

#![no_main]
use libfuzzer_sys::fuzz_target;
use netlink_packet_core::ParseableParametrized;
use netlink_packet_generic::GenlHeader;
use netlink_packet_umbrawg::UmbrawgMessage;

fuzz_target!(|data: &[u8]| {
    let header = GenlHeader { cmd: 0, version: 2 };
    let _ = UmbrawgMessage::parse_with_param(data, header);
});
