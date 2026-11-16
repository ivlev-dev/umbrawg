//! Loopback integration tests for the UDP transport.
//!
//! Offload tests are opportunistic: `UDP_SEGMENT`/`UDP_GRO` depend on the kernel
//! and the egress device, so they are skipped (with a diagnostic) when the
//! feature is unavailable instead of failing.

use std::net::SocketAddr;

use umbrawg_transport::{
    AddressFamily, Endpoint, GsoLimits, GsoSize, MAX_UDP_PAYLOAD_V4, MtuDiscover, OpenOptions,
    Outgoing, RecvQueue, SendQueue, Socket, TransportError, interface_mtu,
};

fn open(family: AddressFamily) -> Socket {
    Socket::open(OpenOptions::new(family)).expect("open UDP socket")
}

type ReceivedMeta = (usize, Option<Endpoint>, Option<GsoSize>, bool);

fn receive(
    socket: &Socket,
    queue: &mut RecvQueue,
    storage: &mut [Vec<u8>],
) -> Result<Vec<ReceivedMeta>, TransportError> {
    let count = {
        let mut buffers: Vec<&mut [u8]> =
            storage.iter_mut().map(|buffer| buffer.as_mut_slice()).collect();
        socket.recv_batch(queue, &mut buffers)?
    };
    Ok((0..count)
        .map(|index| {
            (
                queue.size(index).unwrap_or(0),
                queue.endpoint(index),
                queue.gro_size(index),
                queue.is_truncated(index),
            )
        })
        .collect())
}

fn drain(
    socket: &Socket,
    queue: &mut RecvQueue,
    storage: &mut [Vec<u8>],
) -> Vec<(Vec<u8>, Option<GsoSize>)> {
    let mut received = Vec::new();
    loop {
        match receive(socket, queue, storage) {
            Ok(metas) if metas.is_empty() => break,
            Ok(metas) => {
                for (index, (size, _, gro_size, _)) in metas.iter().enumerate() {
                    received.push((storage[index][..*size].to_vec(), *gro_size));
                }
            }
            Err(error) if error.is_would_block() => break,
            Err(error) => panic!("receive failed: {error}"),
        }
    }
    received
}

#[test]
fn plain_batch_round_trip() {
    let receiver = open(AddressFamily::Ipv4);
    let sender = open(AddressFamily::Ipv4);
    let payloads: [&[u8]; 3] = [b"alpha", b"beta", b"gamma"];
    let outgoing: Vec<Outgoing<'_>> = payloads.iter().map(|payload| Outgoing::new(payload)).collect();

    let mut send_queue = SendQueue::new(4).unwrap();
    let sent = sender
        .send_batch(&mut send_queue, Endpoint::new(receiver.local_addr()), &outgoing)
        .unwrap();
    assert_eq!(sent, 3);

    let mut recv_queue = RecvQueue::new(4).unwrap();
    let mut storage = vec![vec![0u8; 64]; 4];
    let received = drain(&receiver, &mut recv_queue, &mut storage);

    let mut actual: Vec<Vec<u8>> = received.into_iter().map(|(data, _)| data).collect();
    actual.sort();
    let mut expected: Vec<Vec<u8>> = payloads.iter().map(|payload| payload.to_vec()).collect();
    expected.sort();
    assert_eq!(actual, expected);
}

#[test]
fn receive_reports_peer_address() {
    let receiver = open(AddressFamily::Ipv4);
    let sender = open(AddressFamily::Ipv4);

    let mut send_queue = SendQueue::new(1).unwrap();
    sender
        .send_batch(
            &mut send_queue,
            Endpoint::new(receiver.local_addr()),
            &[Outgoing::new(b"ping")],
        )
        .unwrap();

    let mut recv_queue = RecvQueue::new(1).unwrap();
    let mut storage = vec![vec![0u8; 16]; 1];
    let metas = receive(&receiver, &mut recv_queue, &mut storage).unwrap();
    assert_eq!(metas.len(), 1);
    assert_eq!(metas[0].0, 4);
    let endpoint = metas[0].1.expect("peer endpoint");
    assert_eq!(endpoint.dst().port(), sender.local_addr().port());
    assert_eq!(
        endpoint.dst().ip(),
        "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(metas[0].2, None);
    assert!(!metas[0].3);

    let meta = recv_queue.meta(0).unwrap();
    assert_eq!(meta.size, 4);
    assert_eq!(meta.segments(), 1);
}

#[test]
fn empty_socket_reports_would_block() {
    let socket = open(AddressFamily::Ipv4);
    let mut queue = RecvQueue::new(4).unwrap();
    let mut storage = vec![vec![0u8; 64]; 4];

    match receive(&socket, &mut queue, &mut storage) {
        Err(error) => assert!(error.is_would_block()),
        Ok(metas) => panic!("expected WouldBlock, got {} datagrams", metas.len()),
    }
}

#[test]
fn recv_from_reports_would_block() {
    let socket = open(AddressFamily::Ipv4);
    let mut buffer = [0u8; 16];
    match socket.recv_from(&mut buffer) {
        Err(error) => assert!(error.is_would_block()),
        Ok(incoming) => panic!("unexpected datagram of {} bytes", incoming.size),
    }
}

#[test]
fn short_buffer_is_reported_as_truncated() {
    let receiver = open(AddressFamily::Ipv4);
    let sender = open(AddressFamily::Ipv4);
    sender
        .send_to(Endpoint::new(receiver.local_addr()), b"0123456789", None)
        .unwrap();

    let mut buffer = [0u8; 4];
    let incoming = receiver.recv_from(&mut buffer).unwrap();
    assert!(incoming.truncated);
    assert_eq!(incoming.size, 4);
    assert_eq!(&buffer, b"0123");
}

#[test]
fn recv_batch_rejects_oversized_batch() {
    let socket = open(AddressFamily::Ipv4);
    let mut queue = RecvQueue::new(2).unwrap();
    let mut storage = vec![vec![0u8; 16]; 3];
    let mut buffers: Vec<&mut [u8]> = storage
        .iter_mut()
        .map(|buffer| buffer.as_mut_slice())
        .collect();
    assert!(matches!(
        socket.recv_batch(&mut queue, &mut buffers),
        Err(TransportError::BatchTooLarge { .. })
    ));
}

#[test]
fn send_batch_rejects_oversized_batch() {
    let receiver = open(AddressFamily::Ipv4);
    let sender = open(AddressFamily::Ipv4);
    let mut queue = SendQueue::new(2).unwrap();
    let payloads: [&[u8]; 3] = [b"a", b"b", b"c"];
    let outgoing: Vec<Outgoing<'_>> = payloads.iter().map(|payload| Outgoing::new(payload)).collect();
    assert!(matches!(
        sender.send_batch(&mut queue, Endpoint::new(receiver.local_addr()), &outgoing),
        Err(TransportError::BatchTooLarge { .. })
    ));
}

#[test]
fn batch_receives_partial_results() {
    let receiver = open(AddressFamily::Ipv4);
    let sender = open(AddressFamily::Ipv4);

    let payloads: Vec<Vec<u8>> = (0..10u8).map(|index| vec![index; 8]).collect();
    let outgoing: Vec<Outgoing<'_>> = payloads
        .iter()
        .map(|payload| Outgoing::new(payload.as_slice()))
        .collect();
    let mut send_queue = SendQueue::new(10).unwrap();
    assert_eq!(
        sender
            .send_batch(&mut send_queue, Endpoint::new(receiver.local_addr()), &outgoing)
            .unwrap(),
        10
    );

    let mut recv_queue = RecvQueue::new(3).unwrap();
    let mut storage = vec![vec![0u8; 32]; 3];
    let mut received = Vec::new();
    loop {
        match receive(&receiver, &mut recv_queue, &mut storage) {
            Ok(metas) if metas.is_empty() => break,
            Ok(metas) => {
                assert!(metas.len() <= 3);
                for (index, (size, _, _, _)) in metas.iter().enumerate() {
                    received.push(storage[index][..*size].to_vec());
                }
            }
            Err(error) if error.is_would_block() => break,
            Err(error) => panic!("receive failed: {error}"),
        }
    }
    received.sort();
    let mut expected = payloads;
    expected.sort();
    assert_eq!(received, expected);
}

#[test]
fn gso_send_is_split_on_receive() {
    let receiver = Socket::open(OpenOptions::new(AddressFamily::Ipv4).gro(false)).unwrap();
    let limits = GsoLimits::new(1200, 8).unwrap();
    let sender = Socket::open(OpenOptions::new(AddressFamily::Ipv4).gso_limits(limits)).unwrap();
    if !sender.gso_enabled() {
        eprintln!("skipping GSO test: UDP_SEGMENT is not supported");
        return;
    }

    let payload: Vec<u8> = (0..3500).map(|value| (value % 251) as u8).collect();
    let gso_size = GsoSize::new(1200).unwrap();
    let mut send_queue = SendQueue::new(1).unwrap();
    match sender.send_batch(
        &mut send_queue,
        Endpoint::new(receiver.local_addr()),
        &[Outgoing::segmented(&payload, gso_size)],
    ) {
        Ok(1) => {}
        Ok(count) => panic!("unexpected send count {count}"),
        Err(error) => {
            eprintln!("skipping GSO test: {error}");
            return;
        }
    }

    let mut recv_queue = RecvQueue::new(8).unwrap();
    let mut storage = vec![vec![0u8; 2048]; 8];
    let received = drain(&receiver, &mut recv_queue, &mut storage);
    assert_eq!(received.len(), 3);
    assert_eq!(received[0].0.len(), 1200);
    assert_eq!(received[1].0.len(), 1200);
    assert_eq!(received[2].0.len(), 1100);
    let joined: Vec<u8> = received
        .iter()
        .flat_map(|(data, _)| data.iter().copied())
        .collect();
    assert_eq!(joined, payload);
}

#[test]
fn gso_fallback_splits_super_datagram() {
    let receiver = Socket::open(OpenOptions::new(AddressFamily::Ipv4).gro(false)).unwrap();
    let sender = open(AddressFamily::Ipv4);
    sender.disable_gso();
    assert!(!sender.gso_enabled());

    let payload: Vec<u8> = (0..2500).map(|value| (value % 251) as u8).collect();
    let gso_size = GsoSize::new(1000).unwrap();
    let mut send_queue = SendQueue::new(1).unwrap();
    assert_eq!(
        sender
            .send_batch(
                &mut send_queue,
                Endpoint::new(receiver.local_addr()),
                &[Outgoing::segmented(&payload, gso_size)],
            )
            .unwrap(),
        1
    );

    let mut recv_queue = RecvQueue::new(8).unwrap();
    let mut storage = vec![vec![0u8; 2048]; 8];
    let received = drain(&receiver, &mut recv_queue, &mut storage);
    assert_eq!(received.len(), 3);
    assert_eq!(received[0].0.len(), 1000);
    assert_eq!(received[1].0.len(), 1000);
    assert_eq!(received[2].0.len(), 500);
    let joined: Vec<u8> = received
        .iter()
        .flat_map(|(data, _)| data.iter().copied())
        .collect();
    assert_eq!(joined, payload);
}

#[test]
fn gro_receive_reports_segment_size() {
    let receiver = Socket::open(OpenOptions::new(AddressFamily::Ipv4).gro(true)).unwrap();
    if !receiver.gro_enabled() {
        eprintln!("skipping GRO test: UDP_GRO is not supported");
        return;
    }
    let sender = open(AddressFamily::Ipv4);

    let payloads: Vec<Vec<u8>> = (0..4u8).map(|index| vec![index; 100]).collect();
    let outgoing: Vec<Outgoing<'_>> = payloads
        .iter()
        .map(|payload| Outgoing::new(payload.as_slice()))
        .collect();
    let mut send_queue = SendQueue::new(4).unwrap();
    assert_eq!(
        sender
            .send_batch(&mut send_queue, Endpoint::new(receiver.local_addr()), &outgoing)
            .unwrap(),
        4
    );

    let mut recv_queue = RecvQueue::new(8).unwrap();
    let mut storage = vec![vec![0u8; 512]; 8];
    let received = drain(&receiver, &mut recv_queue, &mut storage);

    let total: usize = received.iter().map(|(data, _)| data.len()).sum();
    assert_eq!(total, 400);
    let joined: Vec<u8> = received
        .iter()
        .flat_map(|(data, _)| data.iter().copied())
        .collect();
    assert_eq!(joined, payloads.concat());

    let segments: usize = received
        .iter()
        .map(|(data, gro_size)| gro_size.map_or(1, |size| data.len().div_ceil(size.as_usize())))
        .sum();
    assert_eq!(segments, 4);
}

#[test]
fn dual_stack_socket_receives_ipv4() {
    let dual = match Socket::open(OpenOptions::new(AddressFamily::Ipv6).dual_stack(true)) {
        Ok(socket) => socket,
        Err(error) => {
            eprintln!("skipping dual-stack test: {error}");
            return;
        }
    };
    let sender = open(AddressFamily::Ipv4);
    let target = SocketAddr::from(([127, 0, 0, 1], dual.local_addr().port()));
    sender
        .send_to(Endpoint::new(target), b"dual-stack", None)
        .unwrap();

    let mut buffer = [0u8; 64];
    let incoming = dual.recv_from(&mut buffer).unwrap();
    assert_eq!(incoming.size, 10);
    assert_eq!(&buffer[..10], b"dual-stack");
    let endpoint = incoming.endpoint.expect("peer endpoint");
    assert!(endpoint.dst().is_ipv4());
    assert_eq!(
        endpoint.dst().ip(),
        "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );
}

#[test]
fn loopback_mtu_is_readable() {
    let mtu = interface_mtu("lo").expect("loopback interface exists");
    assert!(mtu >= 576);
    assert!(interface_mtu("umbrawg-no-such-interface").is_err());
}

#[test]
fn bind_to_device_uses_interface_mtu() {
    let socket = match Socket::open(OpenOptions::new(AddressFamily::Ipv4).bind_to_device("lo")) {
        Ok(socket) => socket,
        Err(error) => {
            eprintln!("skipping SO_BINDTODEVICE test: {error}");
            return;
        }
    };
    assert_eq!(socket.mtu(), interface_mtu("lo").unwrap());
    let limits = socket.gso_limits();
    assert!(limits.max_gso_size() >= 1);
    assert!(limits.max_segments() >= 1);
    assert!(socket.max_datagram_len() <= MAX_UDP_PAYLOAD_V4);
}

#[test]
fn mark_option_is_applied() {
    match Socket::open(OpenOptions::new(AddressFamily::Ipv4).mark(0x42)) {
        Ok(socket) => {
            socket.set_mark(0x43).expect("update SO_MARK");
        }
        Err(error) => eprintln!("skipping SO_MARK test: {error}"),
    }
}

#[test]
fn mtu_discover_option_is_applied() {
    let _socket =
        Socket::open(OpenOptions::new(AddressFamily::Ipv4).mtu_discover(MtuDiscover::Do)).unwrap();
}

#[test]
fn reuse_port_allows_several_queues() {
    let first = Socket::open(OpenOptions::new(AddressFamily::Ipv4).reuse_port(true)).unwrap();
    let port = first.local_addr().port();
    let second = match Socket::open(
        OpenOptions::new(AddressFamily::Ipv4)
            .reuse_port(true)
            .port(port),
    ) {
        Ok(socket) => socket,
        Err(error) => {
            eprintln!("skipping SO_REUSEPORT test: {error}");
            return;
        }
    };
    assert_eq!(second.local_addr().port(), port);
}
