use std::net::IpAddr;

use arc_swap::ArcSwap;
use parking_lot::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId(u32);

impl PeerId {
    #[must_use]
    pub const fn new(value: u32) -> Option<Self> {
        if value == 0 {
            None
        } else {
            Some(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    pub(crate) const fn new_unchecked(value: u32) -> Self {
        Self(value)
    }
}

impl From<PeerId> for u32 {
    fn from(peer: PeerId) -> Self {
        peer.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AllowedIp {
    address: IpAddr,
    cidr: u8,
}

impl AllowedIp {
    #[must_use]
    pub fn new(address: IpAddr, cidr: u8) -> Option<Self> {
        let maximum = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if cidr > maximum {
            return None;
        }
        Some(Self { address, cidr })
    }

    #[must_use]
    pub const fn address(self) -> IpAddr {
        self.address
    }

    #[must_use]
    pub const fn cidr(self) -> u8 {
        self.cidr
    }

    #[must_use]
    pub const fn max_prefix_len(self) -> u8 {
        match self.address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllowedIpEntry {
    pub prefix: AllowedIp,
    pub peer: PeerId,
}

struct Node<const N: usize> {
    prefix: [u8; N],
    cidr: u8,
    peer: Option<PeerId>,
    child: [Option<Box<Node<N>>>; 2],
}

impl<const N: usize> Node<N> {
    fn leaf(prefix: [u8; N], cidr: u8, peer: Option<PeerId>) -> Self {
        Self {
            prefix,
            cidr,
            peer,
            child: [None, None],
        }
    }

    fn branch(prefix: [u8; N], cidr: u8) -> Self {
        Self::leaf(prefix, cidr, None)
    }
}

struct Trie {
    v4: Option<Box<Node<4>>>,
    v6: Option<Box<Node<16>>>,
}

impl Trie {
    fn new() -> Self {
        Self { v4: None, v6: None }
    }

    fn insert(&mut self, prefix: AllowedIp, peer: PeerId) {
        match prefix.address {
            IpAddr::V4(address) => {
                let octets = address.octets();
                insert_node(
                    &mut self.v4,
                    masked(&octets, prefix.cidr),
                    prefix.cidr,
                    peer,
                );
            }
            IpAddr::V6(address) => {
                let octets = address.octets();
                insert_node(
                    &mut self.v6,
                    masked(&octets, prefix.cidr),
                    prefix.cidr,
                    peer,
                );
            }
        }
    }

    fn lookup(&self, address: IpAddr) -> Option<PeerId> {
        match address {
            IpAddr::V4(value) => lookup_node(self.v4.as_deref(), &value.octets()),
            IpAddr::V6(value) => lookup_node(self.v6.as_deref(), &value.octets()),
        }
    }
}

pub struct AllowedIps {
    entries: Mutex<Vec<AllowedIpEntry>>,
    table: ArcSwap<Trie>,
}

impl AllowedIps {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            table: ArcSwap::from_pointee(Trie::new()),
        }
    }

    pub fn insert(&self, prefix: AllowedIp, peer: PeerId) {
        self.insert_many(core::slice::from_ref(&prefix), peer);
    }

    pub fn insert_many(&self, prefixes: &[AllowedIp], peer: PeerId) {
        if prefixes.is_empty() {
            return;
        }
        let mut entries = self.entries.lock();
        for prefix in prefixes {
            if let Some(entry) = entries.iter_mut().find(|entry| entry.prefix == *prefix) {
                entry.peer = peer;
            } else {
                entries.push(AllowedIpEntry {
                    prefix: *prefix,
                    peer,
                });
            }
        }
        self.rebuild(&entries);
    }

    pub fn remove(&self, prefix: AllowedIp) -> bool {
        self.remove_filtered(prefix, None)
    }

    pub fn remove_from_peer(&self, prefix: AllowedIp, peer: PeerId) -> bool {
        self.remove_filtered(prefix, Some(peer))
    }

    fn remove_filtered(&self, prefix: AllowedIp, peer: Option<PeerId>) -> bool {
        let mut entries = self.entries.lock();
        let before = entries.len();
        entries.retain(|entry| {
            !(entry.prefix == prefix && peer.is_none_or(|value| value == entry.peer))
        });
        let removed = entries.len() != before;
        if removed {
            self.rebuild(&entries);
        }
        removed
    }

    pub fn remove_by_peer(&self, peer: PeerId) {
        let mut entries = self.entries.lock();
        entries.retain(|entry| entry.peer != peer);
        self.rebuild(&entries);
    }

    pub fn clear(&self) {
        self.entries.lock().clear();
        self.table.store(std::sync::Arc::new(Trie::new()));
    }

    #[must_use]
    pub fn lookup(&self, address: IpAddr) -> Option<PeerId> {
        self.table.load().lookup(address)
    }

    #[must_use]
    pub fn entries_for_peer(&self, peer: PeerId) -> Vec<AllowedIp> {
        let mut prefixes: Vec<AllowedIp> = self
            .entries
            .lock()
            .iter()
            .filter(|entry| entry.peer == peer)
            .map(|entry| entry.prefix)
            .collect();
        prefixes.sort();
        prefixes
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn rebuild(&self, entries: &[AllowedIpEntry]) {
        let mut trie = Trie::new();
        for entry in entries {
            trie.insert(entry.prefix, entry.peer);
        }
        self.table.store(std::sync::Arc::new(trie));
    }
}

impl Default for AllowedIps {
    fn default() -> Self {
        Self::new()
    }
}

fn bit(prefix: &[u8], index: u8) -> u8 {
    let byte = prefix[index as usize / 8];
    (byte >> (7 - index % 8)) & 1
}

fn common_bits<const N: usize>(left: &[u8; N], right: &[u8; N]) -> u8 {
    for (index, (left, right)) in left.iter().zip(right.iter()).enumerate() {
        let difference = left ^ right;
        if difference != 0 {
            return (index * 8 + difference.leading_zeros() as usize) as u8;
        }
    }
    (N * 8) as u8
}

fn masked<const N: usize>(address: &[u8; N], cidr: u8) -> [u8; N] {
    let mut result = *address;
    let bits = usize::from(cidr);
    for (index, byte) in result.iter_mut().enumerate() {
        let start = index * 8;
        if start >= bits {
            *byte = 0;
        } else if start + 8 > bits {
            let keep = (bits - start) as u32;
            *byte &= 0xffu8 << (8 - keep);
        }
    }
    result
}

fn insert_node<const N: usize>(
    slot: &mut Option<Box<Node<N>>>,
    prefix: [u8; N],
    cidr: u8,
    peer: PeerId,
) {
    let Some(mut node) = slot.take() else {
        *slot = Some(Box::new(Node::leaf(prefix, cidr, Some(peer))));
        return;
    };
    let common = common_bits(&node.prefix, &prefix)
        .min(node.cidr)
        .min(cidr);
    if common == node.cidr && common == cidr {
        node.peer = Some(peer);
        *slot = Some(node);
        return;
    }
    if common == node.cidr {
        let branch = bit(&prefix, node.cidr) as usize;
        let mut child = node.child[branch].take();
        insert_node(&mut child, prefix, cidr, peer);
        node.child[branch] = child;
        *slot = Some(node);
        return;
    }
    let mut parent = Node::branch(masked(&prefix, common), common);
    let existing_branch = bit(&node.prefix, common) as usize;
    parent.child[existing_branch] = Some(node);
    if common == cidr {
        parent.peer = Some(peer);
    } else {
        let new_branch = bit(&prefix, common) as usize;
        parent.child[new_branch] = Some(Box::new(Node::leaf(prefix, cidr, Some(peer))));
    }
    *slot = Some(Box::new(parent));
}

fn lookup_node<const N: usize>(
    root: Option<&Node<N>>,
    address: &[u8; N],
) -> Option<PeerId> {
    let mut current = root;
    let mut found = None;
    while let Some(node) = current {
        if common_bits(&node.prefix, address) < node.cidr {
            break;
        }
        if node.peer.is_some() {
            found = node.peer;
        }
        if usize::from(node.cidr) >= N * 8 {
            break;
        }
        current = node.child[bit(address, node.cidr) as usize].as_deref();
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn id(value: u32) -> PeerId {
        PeerId::new(value).unwrap()
    }

    fn prefix(address: &str, cidr: u8) -> AllowedIp {
        AllowedIp::new(address.parse().unwrap(), cidr).unwrap()
    }

    #[test]
    fn longest_prefix_match_wins() {
        let table = AllowedIps::new();
        let default = id(1);
        let lan = id(2);
        let host = id(3);
        table.insert(prefix("0.0.0.0", 0), default);
        table.insert(prefix("10.0.0.0", 8), lan);
        table.insert(prefix("10.1.2.3", 32), host);
        assert_eq!(table.lookup("192.0.2.1".parse().unwrap()), Some(default));
        assert_eq!(table.lookup("10.9.9.9".parse().unwrap()), Some(lan));
        assert_eq!(table.lookup("10.1.2.3".parse().unwrap()), Some(host));
        assert_eq!(table.lookup("10.1.2.4".parse().unwrap()), Some(lan));
    }

    #[test]
    fn ipv6_longest_prefix_match_wins() {
        let table = AllowedIps::new();
        let root = id(1);
        let subnet = id(2);
        let host = id(3);
        table.insert(prefix("::", 0), root);
        table.insert(prefix("2001:db8::", 32), subnet);
        table.insert(prefix("2001:db8::1", 128), host);
        assert_eq!(table.lookup("2001:db8::1".parse().unwrap()), Some(host));
        assert_eq!(table.lookup("2001:db8::2".parse().unwrap()), Some(subnet));
        assert_eq!(table.lookup("2001:db9::1".parse().unwrap()), Some(root));
    }

    #[test]
    fn replacing_a_prefix_moves_the_peer() {
        let table = AllowedIps::new();
        let first = id(1);
        let second = id(2);
        table.insert(prefix("10.0.0.0", 24), first);
        table.insert(prefix("10.0.0.0", 24), second);
        assert_eq!(table.lookup("10.0.0.1".parse().unwrap()), Some(second));
        assert!(table.entries_for_peer(first).is_empty());
        assert_eq!(table.entries_for_peer(second).len(), 1);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn removal_falls_back_to_shorter_prefix() {
        let table = AllowedIps::new();
        let lan = id(1);
        let host = id(2);
        table.insert(prefix("10.0.0.0", 8), lan);
        table.insert(prefix("10.1.2.3", 32), host);
        assert_eq!(table.lookup("10.1.2.3".parse().unwrap()), Some(host));
        assert!(table.remove(prefix("10.1.2.3", 32)));
        assert_eq!(table.lookup("10.1.2.3".parse().unwrap()), Some(lan));
        assert!(!table.remove(prefix("10.1.2.3", 32)));
    }

    #[test]
    fn remove_by_peer_drops_every_prefix() {
        let table = AllowedIps::new();
        let first = id(1);
        let second = id(2);
        table.insert_many(
            &[prefix("10.0.0.0", 8), prefix("2001:db8::", 32)],
            first,
        );
        table.insert(prefix("192.168.0.0", 16), second);
        table.remove_by_peer(first);
        assert!(table.entries_for_peer(first).is_empty());
        assert_eq!(table.lookup("10.0.0.1".parse().unwrap()), None);
        assert_eq!(
            table.lookup("192.168.0.1".parse().unwrap()),
            Some(second)
        );
    }

    #[test]
    fn removal_is_scoped_to_the_peer() {
        let table = AllowedIps::new();
        let first = id(1);
        let second = id(2);
        table.insert(prefix("10.0.0.0", 24), first);
        table.insert(prefix("10.0.1.0", 24), second);
        assert!(!table.remove_from_peer(prefix("10.0.0.0", 24), second));
        assert!(table.remove_from_peer(prefix("10.0.0.0", 24), first));
        assert_eq!(table.lookup("10.0.0.1".parse().unwrap()), None);
    }

    #[test]
    fn rejects_invalid_prefixes() {
        assert!(AllowedIp::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 33).is_none());
        assert!(AllowedIp::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 129).is_none());
        assert_eq!(
            AllowedIp::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 32)
                .unwrap()
                .max_prefix_len(),
            32
        );
    }

    #[test]
    fn peer_ids_reject_zero() {
        assert!(PeerId::new(0).is_none());
        assert_eq!(PeerId::new(7).unwrap().get(), 7);
        assert_eq!(u32::from(id(9)), 9);
    }
}
