/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _UWG_EXT_H
#define _UWG_EXT_H

#include <linux/types.h>
#include <linux/bits.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>

struct sk_buff;
struct uwg_device;
struct uwg_peer;

#define UWG_EXT_TAG 0x00
#define UWG_EXT_MAGIC_0 'U'
#define UWG_EXT_MAGIC_1 'W'
#define UWG_EXT_MAGIC_2 'G'
#define UWG_EXT_VERSION 1
#define UWG_EXT_HEADER_LEN 8

#define UWG_EXT_KIND_CAPS 1
#define UWG_EXT_KIND_ACK 2
#define UWG_EXT_KIND_FEC_SHARD 3

#define UWG_EXT_CAPS_LEN 12
#define UWG_EXT_ACK_HEADER_LEN 16
#define UWG_EXT_ACK_BITMAP_MAX 8
#define UWG_EXT_FEC_HEADER_LEN 12

#define UWG_EXT_MAX_FRAME_LEN \
	(UWG_EXT_HEADER_LEN + UWG_EXT_ACK_HEADER_LEN + UWG_EXT_ACK_BITMAP_MAX)

#define UWG_EXT_ACK_BITMAP_BITS (UWG_EXT_ACK_BITMAP_MAX * 8)

/* CAPS still advertises UWG_EXT_DEFAULT_ACK_INTERVAL for wire compatibility;
 * the cadence actually used for our own ACKs is randomised per ACK so that it
 * does not look like a metronome.
 */
#define UWG_EXT_ACK_INTERVAL_MIN 8
#define UWG_EXT_ACK_INTERVAL_MAX 16
#define UWG_EXT_ACK_DELAY_MIN_US 2000
#define UWG_EXT_ACK_DELAY_MAX_US 5000

/* Upper bound of the random tail appended to CAPS/ACK frames. Control frames
 * must stay small: padding them up to the transport window would turn every
 * ACK into a ~1 KB packet.
 */
#define UWG_EXT_CONTROL_PADDING_MAX 15

#define UWG_EXT_CAPS_MAX_ATTEMPTS 3
/* Bounded number of answers to an identical peer CAPS within one negotiation
 * epoch. A repeat can mean a lost frame and must be answered, but two kernels
 * must not answer each other forever.
 */
#define UWG_EXT_CAPS_MAX_REPLIES 2
#define UWG_EXT_CAPS_RETRY_MS 2000
#define UWG_EXT_CAPS_FAST_RETRY_MS 250
/* Minimum spacing between two CAPS answers triggered by a peer profile
 * change. Our own advertisement does not depend on the peer's profile, so a
 * peer that flips its CAPS must not be able to make us emit a frame per
 * change. The bounded answer to an identical repeat (250 ms retries) still
 * converges the exchange when the earlier frame was lost.
 */
#define UWG_EXT_CAPS_CHANGED_MIN_MS 200

#define UWG_EXT_CAP_BBR BIT(0)
#define UWG_EXT_CAP_ACK BIT(1)
#define UWG_EXT_CAP_FEC BIT(2)
#define UWG_EXT_CAP_FEC_ADAPTIVE BIT(3)

#define UWG_EXT_ACK_FLAG_ECN_CE BIT(0)

#define UWG_EXT_FEC_FLAG_PARITY BIT(0)

#define UWG_EXT_DEFAULT_ACK_INTERVAL 2
#define UWG_EXT_DEFAULT_FEC_K 10
#define UWG_EXT_DEFAULT_FEC_M 1

enum uwg_ext_rx_result {
	UWG_EXT_RX_NOT_EXTENSION = 0,
	UWG_EXT_RX_CONSUMED,
	UWG_EXT_RX_INVALID,
};

struct uwg_ext_header {
	u8 kind;
	u16 payload_len;
	const u8 *payload;
};

struct uwg_ext_caps {
	u32 flags;
	u16 ack_interval;
	u8 fec_k;
	u8 fec_m;
	u32 reserved;
};

struct uwg_ext_ack {
	u64 largest;
	u32 ack_delay_us;
	u8 flags;
	u8 bitmap_len;
	u16 reserved;
	u8 bitmap[UWG_EXT_ACK_BITMAP_MAX];
};

struct uwg_ext_fec_shard {
	u32 block_id;
	u8 index;
	u8 k;
	u8 m;
	u8 flags;
	u16 shard_len;
	u16 reserved;
	const u8 *payload;
};

struct uwg_peer_caps {
	struct uwg_ext_caps local;
	struct uwg_ext_caps peer;
	/* Last profile received from the peer; a repeat must not be answered
	 * more than UWG_EXT_CAPS_MAX_REPLIES times.
	 */
	struct uwg_ext_caps last_peer;
	bool peer_valid;
	bool last_peer_valid;
	bool resend;
	/* The peer sent us an extension frame while this device has the
	 * extension switched off; its profile advertisement is stale.
	 */
	bool extension_seen;
	u8 send_attempts;
	u8 reply_attempts;
	ktime_t next_send;
	/* When our last CAPS frame actually left (successful send). Used to
	 * rate-limit answers to a peer that keeps changing its profile.
	 */
	ktime_t last_sent;
	spinlock_t lock;
};

struct uwg_peer_ack_state {
	u64 largest;
	u64 bitmap;
	u64 keypair_id;
	u32 pending;
	/* Threshold and deadline of the current ACK cycle; both are drawn
	 * anew whenever a cycle starts.
	 */
	u32 ack_target;
	unsigned long ack_deadline;
	ktime_t largest_ktime;
	bool valid;
	spinlock_t lock;
};

struct uwg_peer_ack_tracker {
	u64 largest;
	u64 bitmap;
	u64 received;
	u32 ack_delay_us;
	u16 bitmap_len;
	u8 flags;
	bool valid;
	unsigned long last_ack_jiffies;
	ktime_t last_ack_ktime;
};

bool uwg_ext_detect(const u8 *data, size_t len);
int uwg_ext_parse_header(const u8 *data, size_t len,
			 struct uwg_ext_header *header);
int uwg_ext_parse_caps(const u8 *payload, size_t len,
		       struct uwg_ext_caps *caps);
int uwg_ext_parse_ack(const u8 *payload, size_t len, struct uwg_ext_ack *ack);
u64 uwg_ext_ack_bitmap(const struct uwg_ext_ack *ack);
bool uwg_ext_ack_selftest(void);
int uwg_ext_parse_fec_shard(const u8 *payload, size_t len,
			    struct uwg_ext_fec_shard *shard);

void uwg_ext_local_caps(const struct uwg_device *uwg,
			struct uwg_ext_caps *caps);
void uwg_ext_peer_init(struct uwg_peer *peer);
enum uwg_ext_rx_result uwg_ext_receive(struct uwg_peer *peer,
				       struct sk_buff *skb);

bool uwg_ext_enabled(const struct uwg_device *uwg);
int uwg_ext_build_caps(u8 *buf, size_t len, const struct uwg_ext_caps *caps);
int uwg_ext_build_ack(u8 *buf, size_t len, const struct uwg_ext_ack *ack);
int uwg_ext_build_fec_shard_header(u8 *buf, size_t len,
				   const struct uwg_ext_fec_shard *shard);
void uwg_ext_maybe_send_caps(struct uwg_peer *peer);
void uwg_ext_caps_changed(struct uwg_device *uwg);
void uwg_ext_caps_keypair_changed(struct uwg_peer *peer);
bool uwg_ext_peer_extension(const struct sk_buff *skb);
void uwg_ext_caps_extension_seen(struct uwg_peer *peer);
void uwg_ext_data_received(struct uwg_peer *peer, u64 keypair_id, u64 nonce,
			   bool count_for_ack);
void uwg_ext_ack_timeout(struct uwg_peer *peer);

#endif /* _UWG_EXT_H */
