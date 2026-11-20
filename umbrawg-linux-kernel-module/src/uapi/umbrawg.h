/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR MIT */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * Documentation
 * =============
 *
 * The below enums and macros are for interfacing with WireGuard, using generic
 * netlink, with family UWG_GENL_NAME and version UWG_GENL_VERSION. It defines two
 * methods: get and set. Note that while they share many common attributes,
 * these two functions actually accept a slightly different set of inputs and
 * outputs.
 *
 * UWG_CMD_GET_DEVICE
 * -----------------
 *
 * May only be called via NLM_F_REQUEST | NLM_F_DUMP. The command should contain
 * one but not both of:
 *
 *    UWGDEVICE_A_IFINDEX: NLA_U32
 *    UWGDEVICE_A_IFNAME: NLA_NUL_STRING, maxlen IFNAMSIZ - 1
 *
 * The kernel will then return several messages (NLM_F_MULTI) containing the
 * following tree of nested items:
 *
 *    UWGDEVICE_A_IFINDEX: NLA_U32
 *    UWGDEVICE_A_IFNAME: NLA_NUL_STRING, maxlen IFNAMSIZ - 1
 *    UWGDEVICE_A_PRIVATE_KEY: NLA_EXACT_LEN, len UWG_KEY_LEN
 *    UWGDEVICE_A_PUBLIC_KEY: NLA_EXACT_LEN, len UWG_KEY_LEN
 *    UWGDEVICE_A_LISTEN_PORT: NLA_U16
 *    UWGDEVICE_A_FWMARK: NLA_U32
 *    UWGDEVICE_A_EXTRA_PORTS: NLA_U8
 *    UWGDEVICE_A_BBR: NLA_U8
 *    UWGDEVICE_A_FEC: NLA_U32
 *    UWGDEVICE_A_FEC_STATS: NLA_NESTED
 *        UWGDEVICE_FEC_STATS_A_BLOCKS_ENCODED: NLA_U64
 *        UWGDEVICE_FEC_STATS_A_SHARDS_SENT: NLA_U64
 *        UWGDEVICE_FEC_STATS_A_BLOCKS_DECODED: NLA_U64
 *        UWGDEVICE_FEC_STATS_A_PACKETS_RECOVERED: NLA_U64
 *        UWGDEVICE_FEC_STATS_A_DECODE_FAIL: NLA_U64
 *        UWGDEVICE_FEC_STATS_A_DROPPED_BOUNDS: NLA_U64
 *        UWGDEVICE_FEC_STATS_A_DROPPED_DISABLED: NLA_U64
 *    UWGDEVICE_A_BBR_STATS: NLA_NESTED
 *        UWGDEVICE_BBR_STATS_A_MODE: NLA_U8
 *        UWGDEVICE_BBR_STATS_A_CWND: NLA_U64
 *        UWGDEVICE_BBR_STATS_A_INFLIGHT: NLA_U64
 *        UWGDEVICE_BBR_STATS_A_PACING_RATE: NLA_U64
 *        UWGDEVICE_BBR_STATS_A_BTL_BW: NLA_U64
 *        UWGDEVICE_BBR_STATS_A_MIN_RTT_NS: NLA_U64
 *        UWGDEVICE_BBR_STATS_A_ROUND_LOST: NLA_U32
 *        UWGDEVICE_BBR_STATS_A_PEERS: NLA_U32
 *    UWGDEVICE_A_PEERS: NLA_NESTED
 *        0: NLA_NESTED
 *            UWGPEER_A_PUBLIC_KEY: NLA_EXACT_LEN, len UWG_KEY_LEN
 *            UWGPEER_A_PRESHARED_KEY: NLA_EXACT_LEN, len UWG_KEY_LEN
 *            UWGPEER_A_ENDPOINT: NLA_MIN_LEN(struct sockaddr), struct sockaddr_in or struct sockaddr_in6
 *            UWGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: NLA_U16
 *            UWGPEER_A_LAST_HANDSHAKE_TIME: NLA_EXACT_LEN, struct __kernel_timespec
 *            UWGPEER_A_RX_BYTES: NLA_U64
 *            UWGPEER_A_TX_BYTES: NLA_U64
 *            UWGPEER_A_ALLOWEDIPS: NLA_NESTED
 *                0: NLA_NESTED
 *                    UWGALLOWEDIP_A_FAMILY: NLA_U16
 *                    UWGALLOWEDIP_A_IPADDR: NLA_MIN_LEN(struct in_addr), struct in_addr or struct in6_addr
 *                    UWGALLOWEDIP_A_CIDR_MASK: NLA_U8
 *                0: NLA_NESTED
 *                    ...
 *                0: NLA_NESTED
 *                    ...
 *                ...
 *            UWGPEER_A_PROTOCOL_VERSION: NLA_U32
 *            UWGPEER_A_CIPHER: NLA_U32, enum uwg_cipher
 *        0: NLA_NESTED
 *            ...
 *        ...
 *
 * It is possible that all of the allowed IPs of a single peer will not
 * fit within a single netlink message. In that case, the same peer will
 * be written in the following message, except it will only contain
 * UWGPEER_A_PUBLIC_KEY and UWGPEER_A_ALLOWEDIPS. This may occur several
 * times in a row for the same peer. It is then up to the receiver to
 * coalesce adjacent peers. Likewise, it is possible that all peers will
 * not fit within a single message. So, subsequent peers will be sent
 * in following messages, except those will only contain UWGDEVICE_A_IFNAME
 * and UWGDEVICE_A_PEERS. It is then up to the receiver to coalesce these
 * messages to form the complete list of peers.
 *
 * Since this is an NLA_F_DUMP command, the final message will always be
 * NLMSG_DONE, even if an error occurs. However, this NLMSG_DONE message
 * contains an integer error code. It is either zero or a negative error
 * code corresponding to the errno.
 *
 * UWG_CMD_SET_DEVICE
 * -----------------
 *
 * May only be called via NLM_F_REQUEST. The command should contain the
 * following tree of nested items, containing one but not both of
 * UWGDEVICE_A_IFINDEX and UWGDEVICE_A_IFNAME:
 *
 *    UWGDEVICE_A_IFINDEX: NLA_U32
 *    UWGDEVICE_A_IFNAME: NLA_NUL_STRING, maxlen IFNAMSIZ - 1
 *    UWGDEVICE_A_FLAGS: NLA_U32, 0 or UWGDEVICE_F_REPLACE_PEERS if all current
 *                      peers should be removed prior to adding the list below.
 *    UWGDEVICE_A_PRIVATE_KEY: len UWG_KEY_LEN, all zeros to remove
 *    UWGDEVICE_A_LISTEN_PORT: NLA_U16, 0 to choose randomly
 *    UWGDEVICE_A_FWMARK: NLA_U32, 0 to disable
 *    UWGDEVICE_A_EXTRA_PORTS: NLA_U8, number of additional external UDP
 *                            ports, from 0 to 8
 *    UWGDEVICE_A_BBR: NLA_U8, 0 to disable, 1 to monitor, 2 to enable
 *    UWGDEVICE_A_FEC: NLA_U32, 0 to disable, 1 to use adaptive mode,
 *                    otherwise (K << 8) | M for K data and M parity
 *                    shards, where K >= 1, M >= 1 and K + M <= 255
 *    UWGDEVICE_A_PEERS: NLA_NESTED
 *        0: NLA_NESTED
 *            UWGPEER_A_PUBLIC_KEY: len UWG_KEY_LEN
 *            UWGPEER_A_FLAGS: NLA_U32, 0 and/or UWGPEER_F_REMOVE_ME if the
 *                            specified peer should not exist at the end of the
 *                            operation, rather than added/updated and/or
 *                            UWGPEER_F_REPLACE_ALLOWEDIPS if all current allowed
 *                            IPs of this peer should be removed prior to adding
 *                            the list below and/or UWGPEER_F_UPDATE_ONLY if the
 *                            peer should only be set if it already exists.
 *            UWGPEER_A_PRESHARED_KEY: len UWG_KEY_LEN, all zeros to remove
 *            UWGPEER_A_ENDPOINT: struct sockaddr_in or struct sockaddr_in6
 *            UWGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: NLA_U16, 0 to disable
 *            UWGPEER_A_ALLOWEDIPS: NLA_NESTED
 *                0: NLA_NESTED
 *                    UWGALLOWEDIP_A_FAMILY: NLA_U16
 *                    UWGALLOWEDIP_A_IPADDR: struct in_addr or struct in6_addr
 *                    UWGALLOWEDIP_A_CIDR_MASK: NLA_U8
 *                    UWGALLOWEDIP_A_FLAGS: NLA_U32, UWGALLOWEDIP_F_REMOVE_ME if
 *                                         the specified IP should be removed;
 *                                         otherwise, this IP will be added if
 *                                         it is not already present.
 *                0: NLA_NESTED
 *                    ...
 *                0: NLA_NESTED
 *                    ...
 *                ...
 *            UWGPEER_A_PROTOCOL_VERSION: NLA_U32, should not be set or used at
 *                                       all by most users of this API, as the
 *                                       most recent protocol will be used when
 *                                       this is unset. Otherwise, must be set
 *                                       to 1.
 *            UWGPEER_A_ADVANCED_SECURITY: flag indicating that advanced security
 *                                       techniques provided by UmbraWG should
 *                                       be used.
 *            UWGPEER_A_CIPHER: NLA_U32, enum uwg_cipher, the data cipher of
 *                              the peer; UWG_CIPHER_CHACHA20POLY1305 when
 *                              unset.
 *        0: NLA_NESTED
 *            ...
 *        ...
 *
 * It is possible that the amount of configuration data exceeds that of
 * the maximum message length accepted by the kernel. In that case, several
 * messages should be sent one after another, with each successive one
 * filling in information not contained in the prior. Note that if
 * UWGDEVICE_F_REPLACE_PEERS is specified in the first message, it probably
 * should not be specified in fragments that come after, so that the list
 * of peers is only cleared the first time but appended after. Likewise for
 * peers, if UWGPEER_F_REPLACE_ALLOWEDIPS is specified in the first message
 * of a peer, it likely should not be specified in subsequent fragments.
 *
 * If an error occurs, NLMSG_ERROR will reply containing an errno.
 *
 * UWG_CMD_UNKNOWN_PEER
 * ----------------------
 *
 * This command is sent on the multicast group UWG_MULTICAST_GROUP_AUTH
 * when the initiation message received from a peer with an unknown public
 * key.
 * The kernel will send a single message containing the
 * following tree of nested items:
 *
 *    UWGDEVICE_A_IFINDEX: NLA_U32
 *    UWGDEVICE_A_IFNAME: NLA_NUL_STRING, maxlen IFNAMSIZ - 1
 *    UWGDEVICE_A_PEER: NLA_NESTED
 *        UWGPEER_A_PUBLIC_KEY: NLA_EXACT_LEN, len UWG_KEY_LEN
 *        UWGPEER_A_ENDPOINT: NLA_MIN_LEN(struct sockaddr), struct sockaddr_in or struct sockaddr_in6
 *        UWGPEER_A_ADVANCED_SECURITY: flag indicating that advanced security
 *                                    techniques provided by UmbraWG should
 *                                    be used.
 *
 */

#ifndef _UWG_UAPI_WIREGUARD_H
#define _UWG_UAPI_WIREGUARD_H

#define UWG_GENL_NAME "umbrawg"
#define UWG_GENL_VERSION 3

#define UWG_KEY_LEN 32

#define UWG_MULTICAST_GROUP_AUTH "auth"

enum uwg_cmd {
	UWG_CMD_GET_DEVICE,
	UWG_CMD_SET_DEVICE,
	UWG_CMD_UNKNOWN_PEER,
	__UWG_CMD_MAX
};
#define UWG_CMD_MAX (__UWG_CMD_MAX - 1)

enum uwgdevice_flag {
	UWGDEVICE_F_REPLACE_PEERS = 1U << 0,
	__UWGDEVICE_F_ALL = UWGDEVICE_F_REPLACE_PEERS
};
enum uwgdevice_attribute {
	UWGDEVICE_A_UNSPEC,
	UWGDEVICE_A_IFINDEX,
	UWGDEVICE_A_IFNAME,
	UWGDEVICE_A_PRIVATE_KEY,
	UWGDEVICE_A_PUBLIC_KEY,
	UWGDEVICE_A_FLAGS,
	UWGDEVICE_A_LISTEN_PORT,
	UWGDEVICE_A_FWMARK,
	UWGDEVICE_A_PEERS,
	UWGDEVICE_A_JC,
	UWGDEVICE_A_JMIN,
	UWGDEVICE_A_JMAX,
	UWGDEVICE_A_S1,
	UWGDEVICE_A_S2,
	UWGDEVICE_A_H1,
	UWGDEVICE_A_H2,
	UWGDEVICE_A_H3,
	UWGDEVICE_A_H4,
	UWGDEVICE_A_PEER,
	UWGDEVICE_A_S3,
	UWGDEVICE_A_S4,
	UWGDEVICE_A_I1,
	UWGDEVICE_A_I2,
	UWGDEVICE_A_I3,
	UWGDEVICE_A_I4,
	UWGDEVICE_A_I5,
	UWGDEVICE_A_HEADER_PROTECTION_KEY,
	UWGDEVICE_A_CONTENT_PADDING_ADDITION,
	UWGDEVICE_A_REKEY_AFTER_TIME,
	UWGDEVICE_A_REKEY_TIMEOUT,
	UWGDEVICE_A_REJECT_AFTER_TIME,
	UWGDEVICE_A_KEEPALIVE_TIMEOUT,
	UWGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS,
	UWGDEVICE_A_RANDOM_TRAILERS,
	UWGDEVICE_A_DISABLE_COOKIES,
	UWGDEVICE_A_EXTRA_PORTS,
	UWGDEVICE_A_BBR,
	UWGDEVICE_A_FEC,
	UWGDEVICE_A_FEC_STATS,	/* 38: nested uwgdevice_fec_stats_attrs */
	UWGDEVICE_A_BBR_STATS,	/* 39: nested uwgdevice_bbr_stats_attrs */
	__UWGDEVICE_A_LAST
};
#define UWGDEVICE_A_MAX (__UWGDEVICE_A_LAST - 1)

enum uwgdevice_fec_stats_attrs {
	UWGDEVICE_FEC_STATS_A_UNSPEC,
	UWGDEVICE_FEC_STATS_A_BLOCKS_ENCODED,	/* u64 */
	UWGDEVICE_FEC_STATS_A_SHARDS_SENT,	/* u64 */
	UWGDEVICE_FEC_STATS_A_BLOCKS_DECODED,	/* u64 */
	UWGDEVICE_FEC_STATS_A_PACKETS_RECOVERED,	/* u64 */
	UWGDEVICE_FEC_STATS_A_DECODE_FAIL,	/* u64 */
	UWGDEVICE_FEC_STATS_A_DROPPED_BOUNDS,	/* u64 */
	UWGDEVICE_FEC_STATS_A_DROPPED_DISABLED,	/* u64 */
	__UWGDEVICE_FEC_STATS_A_LAST,
};

enum uwgdevice_bbr_stats_attrs {
	UWGDEVICE_BBR_STATS_A_UNSPEC,
	UWGDEVICE_BBR_STATS_A_MODE,		/* u8, значения как UWGDEVICE_A_BBR */
	UWGDEVICE_BBR_STATS_A_CWND,		/* u64, байты */
	UWGDEVICE_BBR_STATS_A_INFLIGHT,		/* u64, байты */
	UWGDEVICE_BBR_STATS_A_PACING_RATE,	/* u64, байт/с */
	UWGDEVICE_BBR_STATS_A_BTL_BW,		/* u64, байт/с */
	UWGDEVICE_BBR_STATS_A_MIN_RTT_NS,	/* u64, нс */
	UWGDEVICE_BBR_STATS_A_ROUND_LOST,	/* u32, пакеты */
	UWGDEVICE_BBR_STATS_A_PEERS,		/* u32, число пиров с BBR-состоянием */
	__UWGDEVICE_BBR_STATS_A_LAST,
};

enum uwgpeer_flag {
	UWGPEER_F_REMOVE_ME = 1U << 0,
	UWGPEER_F_REPLACE_ALLOWEDIPS = 1U << 1,
	UWGPEER_F_UPDATE_ONLY = 1U << 2,
	UWGPEER_F_HAS_ADVANCED_SECURITY = 1U << 3,
	__UWGPEER_F_ALL = UWGPEER_F_REMOVE_ME | UWGPEER_F_REPLACE_ALLOWEDIPS |
			 UWGPEER_F_UPDATE_ONLY | UWGPEER_F_HAS_ADVANCED_SECURITY
};
enum uwg_cipher {
	UWG_CIPHER_CHACHA20POLY1305 = 0,
	UWG_CIPHER_AES256GCM = 1,
};
enum uwgpeer_attribute {
	UWGPEER_A_UNSPEC,
	UWGPEER_A_PUBLIC_KEY,
	UWGPEER_A_PRESHARED_KEY,
	UWGPEER_A_FLAGS,
	UWGPEER_A_ENDPOINT,
	UWGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
	UWGPEER_A_LAST_HANDSHAKE_TIME,
	UWGPEER_A_RX_BYTES,
	UWGPEER_A_TX_BYTES,
	UWGPEER_A_ALLOWEDIPS,
	UWGPEER_A_PROTOCOL_VERSION,
	UWGPEER_A_ADVANCED_SECURITY,
	UWGPEER_A_CIPHER = 12,
	__UWGPEER_A_LAST
};
#define UWGPEER_A_MAX (__UWGPEER_A_LAST - 1)

enum uwgallowedip_flag {
	UWGALLOWEDIP_F_REMOVE_ME = 1U << 0,
	__UWGALLOWEDIP_F_ALL = UWGALLOWEDIP_F_REMOVE_ME
};
enum uwgallowedip_attribute {
	UWGALLOWEDIP_A_UNSPEC,
	UWGALLOWEDIP_A_FAMILY,
	UWGALLOWEDIP_A_IPADDR,
	UWGALLOWEDIP_A_CIDR_MASK,
	UWGALLOWEDIP_A_FLAGS,
	__UWGALLOWEDIP_A_LAST
};
#define UWGALLOWEDIP_A_MAX (__UWGALLOWEDIP_A_LAST - 1)

#endif /* _UWG_UAPI_WIREGUARD_H */
