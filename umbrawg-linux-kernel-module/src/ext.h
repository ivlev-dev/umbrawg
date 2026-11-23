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
/* Kind 2 was the ACK frame. ACKs and BBR were removed in 0.5.0; the kind stays
 * reserved so a frame from an older peer is recognised and ignored instead of
 * being delivered as inner traffic. The number must not be reused.
 */
#define UWG_EXT_KIND_ACK 2
#define UWG_EXT_KIND_FEC_SHARD 3

#define UWG_EXT_CAPS_LEN 12
#define UWG_EXT_FEC_HEADER_LEN 12

#define UWG_EXT_MAX_FRAME_LEN (UWG_EXT_HEADER_LEN + UWG_EXT_CAPS_LEN)

/* CAPS keeps the legacy ack_interval field so the frame length stays the same.
 * The field is informational only: this module no longer emits ACKs.
 */
#define UWG_EXT_DEFAULT_ACK_INTERVAL 2

/* Upper bound of the random tail appended to CAPS frames. Control frames must
 * stay small: padding them up to the transport window would turn every
 * advertisement into a ~1 KB packet.
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

#define UWG_EXT_CAP_FEC BIT(2)
#define UWG_EXT_CAP_FEC_ADAPTIVE BIT(3)
/* The peer understands parity on a partial FEC block: a flush with n < k
 * data shards may be encoded as k' = n, m' > 0 instead of the legacy m' = 0
 * form. Both sides advertise it whenever FEC is enabled; the bit is only
 * consulted for shards from a peer that also advertises FEC.
 */
#define UWG_EXT_CAP_FEC_PARTIAL BIT(4)

#define UWG_EXT_FEC_FLAG_PARITY BIT(0)

/* Bits 0 and 1 used to mean BBR and ACK. They are no longer advertised and
 * must be ignored when an older peer still sets them: only the FEC bits take
 * part in the profile comparison.
 */
#define UWG_EXT_CAPS_KNOWN_FLAGS \
	(UWG_EXT_CAP_FEC | UWG_EXT_CAP_FEC_ADAPTIVE | UWG_EXT_CAP_FEC_PARTIAL)

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
	/* An answer to the peer's CAPS is owed and has not been sent yet. */
	bool resend;
	/* A CAPS frame was sent, but the peer still advertises another FEC
	 * profile. The advertisement is unconfirmed, so it is retried a
	 * bounded number of times: a lost first frame otherwise leaves both
	 * sides on the legacy path until the next rekey.
	 */
	bool retry;
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

bool uwg_ext_detect(const u8 *data, size_t len);
int uwg_ext_parse_header(const u8 *data, size_t len,
			 struct uwg_ext_header *header);
int uwg_ext_parse_caps(const u8 *payload, size_t len,
		       struct uwg_ext_caps *caps);
bool uwg_ext_caps_selftest(void);
int uwg_ext_parse_fec_shard(const u8 *payload, size_t len,
			    struct uwg_ext_fec_shard *shard);

void uwg_ext_local_caps(const struct uwg_device *uwg,
			struct uwg_ext_caps *caps);
void uwg_ext_peer_init(struct uwg_peer *peer);
enum uwg_ext_rx_result uwg_ext_receive(struct uwg_peer *peer,
				       struct sk_buff *skb);

bool uwg_ext_enabled(const struct uwg_device *uwg);
int uwg_ext_build_caps(u8 *buf, size_t len, const struct uwg_ext_caps *caps);
int uwg_ext_build_fec_shard_header(u8 *buf, size_t len,
				   const struct uwg_ext_fec_shard *shard);
void uwg_ext_maybe_send_caps(struct uwg_peer *peer);
void uwg_ext_caps_changed(struct uwg_device *uwg);
void uwg_ext_caps_keypair_changed(struct uwg_peer *peer);
bool uwg_ext_peer_extension(const struct sk_buff *skb);
void uwg_ext_caps_extension_seen(struct uwg_peer *peer);
void uwg_ext_caps_timeout(struct uwg_peer *peer);

#endif /* _UWG_EXT_H */
