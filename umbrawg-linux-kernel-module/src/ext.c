// SPDX-License-Identifier: GPL-2.0

#include "ext.h"
#include "peer.h"
#include "device.h"
#include "queueing.h"
#include "fec.h"
#include "fec_data.h"
#include "timers.h"

#include <linux/errno.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/unaligned.h>

/* Test knob for wire compatibility: with partial parity switched off we
 * advertise and emit exactly the legacy partial block (k' = n, m' = 0), as a
 * kernel without FEC_PARTIAL would. Default stays on.
 */
static bool uwg_ext_fec_partial = true;
module_param_named(fec_partial, uwg_ext_fec_partial, bool, 0644);
MODULE_PARM_DESC(fec_partial,
		 "Advertise FEC partial-block parity (default: on)");

static bool uwg_ext_kind_valid(u8 kind)
{
	return kind == UWG_EXT_KIND_CAPS ||
	       kind == UWG_EXT_KIND_ACK ||
	       kind == UWG_EXT_KIND_FEC_SHARD;
}

bool uwg_ext_detect(const u8 *data, size_t len)
{
	if (len < UWG_EXT_HEADER_LEN)
		return false;
	if (data[0] != UWG_EXT_TAG ||
	    data[1] != UWG_EXT_MAGIC_0 ||
	    data[2] != UWG_EXT_MAGIC_1 ||
	    data[3] != UWG_EXT_MAGIC_2 ||
	    data[4] != UWG_EXT_VERSION)
		return false;
	return uwg_ext_kind_valid(data[5]);
}

int uwg_ext_parse_header(const u8 *data, size_t len,
			 struct uwg_ext_header *header)
{
	u16 payload_len;

	if (!uwg_ext_detect(data, len))
		return -ENOENT;

	payload_len = get_unaligned_le16(data + 6);
	if ((size_t)payload_len > len - UWG_EXT_HEADER_LEN)
		return -EMSGSIZE;

	header->kind = data[5];
	header->payload_len = payload_len;
	header->payload = data + UWG_EXT_HEADER_LEN;
	return 0;
}

int uwg_ext_parse_caps(const u8 *payload, size_t len,
		       struct uwg_ext_caps *caps)
{
	if (len != UWG_EXT_CAPS_LEN)
		return -EINVAL;

	caps->flags = get_unaligned_le32(payload);
	/* Bits 0 and 1 were BBR and ACK. An older peer may still set them;
	 * they carry no meaning here and must not make its profile look
	 * different from ours.
	 */
	caps->flags &= UWG_EXT_CAPS_KNOWN_FLAGS;
	caps->ack_interval = get_unaligned_le16(payload + 4);
	caps->fec_k = payload[6];
	caps->fec_m = payload[7];
	caps->reserved = get_unaligned_le32(payload + 8);
	return 0;
}

/* What to do with a profile just received in a CAPS frame. Kept pure so the
 * 200 ms gate and the deferred answer it produces are covered by the
 * load-time self-test instead of only by the netns regression.
 */
enum uwg_ext_caps_plan {
	UWG_EXT_CAPS_PLAN_NONE = 0,
	UWG_EXT_CAPS_PLAN_SEND,
	UWG_EXT_CAPS_PLAN_DEFER,
};

static enum uwg_ext_caps_plan
uwg_ext_caps_plan(ktime_t now, ktime_t last_sent, bool changed,
		  u8 send_attempts, u8 reply_attempts, ktime_t *next_send)
{
	bool too_soon;

	/* Our own advertisement only depends on the local profile, so a peer
	 * that keeps changing its CAPS does not need an answer per change: one
	 * frame sent less than UWG_EXT_CAPS_CHANGED_MIN_MS ago carries the
	 * same information. Skipping the duplicate keeps a hostile or flapping
	 * peer from turning this into a control-frame amplifier; the bounded
	 * answer to an identical repeat (the peer retries every 250 ms) still
	 * converges the exchange if the earlier frame was lost.
	 */
	too_soon = last_sent &&
		   ktime_before(now, ktime_add_ms(last_sent,
						  UWG_EXT_CAPS_CHANGED_MIN_MS));
	if (changed || !send_attempts) {
		/* A changed profile must never be dropped: answer as soon as the
		 * minimum spacing allows. With no frame in flight (the previous
		 * transmit failed, or this is the first one) send right away.
		 */
		if (too_soon && send_attempts) {
			*next_send = ktime_add_ms(last_sent,
						  UWG_EXT_CAPS_CHANGED_MIN_MS);
			return UWG_EXT_CAPS_PLAN_DEFER;
		}
		return UWG_EXT_CAPS_PLAN_SEND;
	}
	if (!too_soon && reply_attempts < UWG_EXT_CAPS_MAX_REPLIES)
		return UWG_EXT_CAPS_PLAN_SEND;
	return UWG_EXT_CAPS_PLAN_NONE;
}

/* Regression check for the deferred changed-CAPS answer: dropping it (the
 * behaviour before the 200 ms gate was introduced) makes the first case fail,
 * and so does answering a repeat more than UWG_EXT_CAPS_MAX_REPLIES times.
 */
bool uwg_ext_caps_selftest(void)
{
	ktime_t now = ktime_set(1000, 0);
	ktime_t recent = ktime_sub_ms(now, 50);
	ktime_t old = ktime_sub_ms(now, UWG_EXT_CAPS_CHANGED_MIN_MS * 2);
	ktime_t next_send = 0;
	bool ok = true;

	if (uwg_ext_caps_plan(now, recent, true, 1, 0, &next_send) !=
	    UWG_EXT_CAPS_PLAN_DEFER)
		ok = false;
	/* The deferred answer is scheduled exactly at the gate edge. */
	if (ktime_to_ns(next_send) !=
	    ktime_to_ns(ktime_add_ms(recent, UWG_EXT_CAPS_CHANGED_MIN_MS)))
		ok = false;
	/* Outside the gate a changed profile is answered immediately. */
	if (uwg_ext_caps_plan(now, old, true, 1, 0, &next_send) !=
	    UWG_EXT_CAPS_PLAN_SEND)
		ok = false;
	/* The first answer, or the resend after a failed transmit
	 * (send_attempts == 0), is not delayed either.
	 */
	if (uwg_ext_caps_plan(now, recent, true, 0, 0, &next_send) !=
	    UWG_EXT_CAPS_PLAN_SEND)
		ok = false;
	/* An identical repeat is never answered inside the gate ... */
	if (uwg_ext_caps_plan(now, recent, false, 1, 0, &next_send) !=
	    UWG_EXT_CAPS_PLAN_NONE)
		ok = false;
	/* ... and only UWG_EXT_CAPS_MAX_REPLIES times outside it. */
	if (uwg_ext_caps_plan(now, old, false, 1,
			      UWG_EXT_CAPS_MAX_REPLIES - 1, &next_send) !=
	    UWG_EXT_CAPS_PLAN_SEND)
		ok = false;
	if (uwg_ext_caps_plan(now, old, false, 1,
			      UWG_EXT_CAPS_MAX_REPLIES, &next_send) !=
	    UWG_EXT_CAPS_PLAN_NONE)
		ok = false;
	/* The first CAPS ever (no frame sent yet) goes out now. */
	if (uwg_ext_caps_plan(now, 0, false, 0, 0, &next_send) !=
	    UWG_EXT_CAPS_PLAN_SEND)
		ok = false;

	if (!ok)
		pr_err("EXT CAPS self-test: FAIL\n");
	return ok;
}

int uwg_ext_parse_fec_shard(const u8 *payload, size_t len,
			    struct uwg_ext_fec_shard *shard)
{
	u16 total;
	bool parity;

	if (len < UWG_EXT_FEC_HEADER_LEN)
		return -EINVAL;

	shard->block_id = get_unaligned_le32(payload);
	shard->index = payload[4];
	shard->k = payload[5];
	shard->m = payload[6];
	shard->flags = payload[7];
	shard->shard_len = get_unaligned_le16(payload + 8);
	shard->reserved = get_unaligned_le16(payload + 10);

	if (!shard->k || shard->k > UWG_FEC_MAX_DATA ||
	    shard->m > UWG_FEC_MAX_PARITY)
		return -EINVAL;
	total = (u16)shard->k + shard->m;
	if (total > UWG_FEC_MAX_SHARDS)
		return -EINVAL;
	if (shard->index >= total)
		return -EINVAL;

	parity = (shard->flags & UWG_EXT_FEC_FLAG_PARITY) != 0;
	if (parity != (shard->index >= shard->k))
		return -EINVAL;
	if (shard->shard_len != len - UWG_EXT_FEC_HEADER_LEN)
		return -EINVAL;

	shard->payload = payload + UWG_EXT_FEC_HEADER_LEN;
	return 0;
}

void uwg_ext_local_caps(const struct uwg_device *uwg,
			struct uwg_ext_caps *caps)
{
	u32 flags = 0;
	u8 k = 0, m = 0;
	bool adaptive = false;

	memset(caps, 0, sizeof(*caps));
	caps->ack_interval = UWG_EXT_DEFAULT_ACK_INTERVAL;

	if (uwg->fec_mode != UWG_FEC_MODE_OFF &&
	    uwg_fec_mode_config(uwg->fec_mode, &k, &m, &adaptive)) {
		flags |= UWG_EXT_CAP_FEC;
		if (adaptive)
			flags |= UWG_EXT_CAP_FEC_ADAPTIVE;
		if (READ_ONCE(uwg_ext_fec_partial))
			flags |= UWG_EXT_CAP_FEC_PARTIAL;
		caps->fec_k = k;
		caps->fec_m = m;
	}

	caps->flags = flags;
}

void uwg_ext_peer_init(struct uwg_peer *peer)
{
	memset(&peer->caps, 0, sizeof(peer->caps));
	spin_lock_init(&peer->caps.lock);
	uwg_ext_local_caps(peer->device, &peer->caps.local);
}

bool uwg_ext_enabled(const struct uwg_device *uwg)
{
	return READ_ONCE(uwg->fec_mode) != UWG_FEC_MODE_OFF;
}

static void uwg_ext_write_header(u8 *buf, u8 kind, u16 payload_len)
{
	buf[0] = UWG_EXT_TAG;
	buf[1] = UWG_EXT_MAGIC_0;
	buf[2] = UWG_EXT_MAGIC_1;
	buf[3] = UWG_EXT_MAGIC_2;
	buf[4] = UWG_EXT_VERSION;
	buf[5] = kind;
	put_unaligned_le16(payload_len, buf + 6);
}

int uwg_ext_build_caps(u8 *buf, size_t len, const struct uwg_ext_caps *caps)
{
	size_t total = UWG_EXT_HEADER_LEN + UWG_EXT_CAPS_LEN;

	if (len < total)
		return -EMSGSIZE;

	uwg_ext_write_header(buf, UWG_EXT_KIND_CAPS, UWG_EXT_CAPS_LEN);
	put_unaligned_le32(caps->flags, buf + 8);
	put_unaligned_le16(caps->ack_interval, buf + 12);
	buf[14] = caps->fec_k;
	buf[15] = caps->fec_m;
	put_unaligned_le32(caps->reserved, buf + 16);
	return (int)total;
}

int uwg_ext_build_fec_shard_header(u8 *buf, size_t len,
				   const struct uwg_ext_fec_shard *shard)
{
	unsigned int total = (unsigned int)shard->k + shard->m;

	if (len < UWG_EXT_HEADER_LEN + UWG_EXT_FEC_HEADER_LEN)
		return -EMSGSIZE;
	if (!shard->k || total > UWG_FEC_MAX_SHARDS ||
	    shard->index >= total)
		return -EINVAL;
	if ((unsigned int)shard->shard_len +
		    UWG_EXT_FEC_HEADER_LEN > 0xffffU)
		return -EMSGSIZE;
	if (!!(shard->flags & UWG_EXT_FEC_FLAG_PARITY) !=
	    (shard->index >= shard->k))
		return -EINVAL;

	uwg_ext_write_header(buf, UWG_EXT_KIND_FEC_SHARD,
			     UWG_EXT_FEC_HEADER_LEN + shard->shard_len);
	put_unaligned_le32(shard->block_id, buf + 8);
	buf[12] = shard->index;
	buf[13] = shard->k;
	buf[14] = shard->m;
	buf[15] = shard->flags;
	put_unaligned_le16(shard->shard_len, buf + 16);
	put_unaligned_le16(shard->reserved, buf + 18);
	return UWG_EXT_HEADER_LEN + UWG_EXT_FEC_HEADER_LEN;
}

void uwg_ext_caps_changed(struct uwg_device *uwg)
{
	struct uwg_peer *peer;

	list_for_each_entry(peer, &uwg->peer_list, peer_list) {
		spin_lock_bh(&peer->caps.lock);
		peer->caps.resend = true;
		peer->caps.retry = false;
		peer->caps.send_attempts = 0;
		peer->caps.reply_attempts = 0;
		peer->caps.next_send = 0;
		peer->caps.last_sent = 0;
		spin_unlock_bh(&peer->caps.lock);
		uwg_ext_maybe_send_caps(peer);
	}
}

/* A new session key is a fresh negotiation epoch. CAPS frames sent under the
 * previous keypair may have been dropped by the peer (it installs the new
 * keypair only when it completes the handshake), so a spent attempt budget
 * must not be allowed to keep the exchange silent after a rekey. This is the
 * kernel counterpart of the userspace device re-arming CAPS on the same
 * event.
 */
void uwg_ext_caps_keypair_changed(struct uwg_peer *peer)
{
	spin_lock_bh(&peer->caps.lock);
	peer->caps.resend = true;
	peer->caps.retry = false;
	peer->caps.send_attempts = 0;
	peer->caps.reply_attempts = 0;
	peer->caps.next_send = 0;
	peer->caps.last_sent = 0;
	spin_unlock_bh(&peer->caps.lock);
}

/* True when the decrypted packet starts with a well-formed extension header
 * that proves the peer still runs the extension. CAPS is deliberately
 * excluded: two devices that both switched the extension off exchange a
 * single zero CAPS to retract their stale advertisement, and if that frame
 * itself counted as "extension traffic" they would answer each other forever.
 * FEC_SHARD means the peer's data plane is still active and a revoke is
 * worthwhile.
 */
bool uwg_ext_peer_extension(const struct sk_buff *skb)
{
	u8 buf[UWG_EXT_HEADER_LEN];
	const u8 *hdr = skb_header_pointer(skb, 0, sizeof(buf), buf);

	return hdr && uwg_ext_detect(hdr, sizeof(buf)) &&
	       hdr[5] != UWG_EXT_KIND_CAPS;
}

void uwg_ext_caps_extension_seen(struct uwg_peer *peer)
{
	spin_lock_bh(&peer->caps.lock);
	peer->caps.extension_seen = true;
	spin_unlock_bh(&peer->caps.lock);
}

/* Schedule a deferred CAPS answer on the existing control timer. A separate
 * timer per peer would need a new teardown path; timer_send_caps is already
 * initialised/shut down with the peer, and uwg_ext_caps_timeout() calls
 * uwg_ext_maybe_send_caps().
 */
static void uwg_ext_caps_arm(struct uwg_peer *peer)
{
	ktime_t next;
	unsigned long expires;
	s64 ms;
	bool pending;

	spin_lock_bh(&peer->caps.lock);
	pending = (peer->caps.resend || peer->caps.retry) &&
		  peer->caps.next_send != 0;
	next = peer->caps.next_send;
	spin_unlock_bh(&peer->caps.lock);
	if (!pending)
		return;
	ms = ktime_ms_delta(next, ktime_get());
	if (ms <= 0)
		expires = jiffies + 1;
	else
		expires = jiffies + max_t(unsigned long, 1,
					 msecs_to_jiffies((unsigned long)ms));
	uwg_timers_caps_reduce(peer, expires);
}

/* Control timer callback. It exists only to carry a deferred or retried CAPS
 * answer: the module does not emit ACKs any more, so there is no ACK state to
 * drain here.
 */
void uwg_ext_caps_timeout(struct uwg_peer *peer)
{
	uwg_ext_maybe_send_caps(peer);
	uwg_ext_caps_arm(peer);
}

/* True when the profile the peer last advertised needs no further
 * advertisement from us: the FEC setting matches (an unsupported profile was
 * sanitized earlier), so a shard we send can be decoded on the other side.
 */
static bool uwg_ext_caps_fec_synced(const struct uwg_peer_caps *caps,
				    const struct uwg_ext_caps *local)
{
	bool local_fec = local->flags & UWG_EXT_CAP_FEC;

	if (!caps->peer_valid)
		return false;
	if (!!(caps->peer.flags & UWG_EXT_CAP_FEC) != local_fec)
		return false;
	return !local_fec || (caps->peer.fec_k == local->fec_k &&
			      caps->peer.fec_m == local->fec_m);
}

void uwg_ext_maybe_send_caps(struct uwg_peer *peer)
{
	struct uwg_ext_caps local;
	u8 frame[UWG_EXT_MAX_FRAME_LEN];
	ktime_t now;
	bool revoke;
	bool retry;
	bool pending;
	int len;

	now = ktime_get();
	spin_lock_bh(&peer->caps.lock);
	uwg_ext_local_caps(peer->device, &peer->caps.local);
	/* With FEC off there is nothing to advertise, but a peer that still
	 * believes we run FEC keeps sending shards we no longer parse. A zero
	 * CAPS retracts that stale advertisement: right away when the local
	 * profile is switched off, and again while the peer actually shows
	 * extension traffic. A silent tunnel therefore stays silent.
	 */
	revoke = !peer->caps.local.flags &&
		 (peer->caps.extension_seen ||
		  ((peer->caps.resend || peer->caps.retry) &&
		   peer->caps.peer_valid &&
		   (peer->caps.peer.flags & UWG_EXT_CAP_FEC)));
	if ((!revoke && !peer->caps.local.flags) ||
	    (!revoke && peer->caps.peer_valid && !peer->caps.resend &&
	     !peer->caps.retry) ||
	    (!revoke &&
	     peer->caps.send_attempts >= UWG_EXT_CAPS_MAX_ATTEMPTS) ||
	    /* Rate limit: at most one CAPS per window, no matter what
	     * triggered the call. A fresh advertisement must not go out back
	     * to back, and a revoke must stay at UWG_EXT_CAPS_RETRY_MS.
	     */
	    (peer->caps.send_attempts &&
	     ktime_before(now, peer->caps.next_send))) {
		/* A deferred answer or a pending retry must survive a call
		 * that lands inside the rate-limit window: the control timer
		 * carries it once next_send passes.
		 */
		pending = (peer->caps.resend || peer->caps.retry) &&
			  peer->caps.next_send != 0;

		spin_unlock_bh(&peer->caps.lock);
		if (pending)
			uwg_ext_caps_arm(peer);
		return;
	}
	if (peer->caps.send_attempts < UWG_EXT_CAPS_MAX_ATTEMPTS)
		++peer->caps.send_attempts;
	peer->caps.resend = false;
	peer->caps.extension_seen = false;
	/* The very first CAPS frame races with the peer installing the new
	 * keypair and can be lost. Retry quickly at first, then back off.
	 */
	peer->caps.next_send = ktime_add_ms(
		now, revoke ||
		peer->caps.send_attempts >= UWG_EXT_CAPS_MAX_ATTEMPTS ?
			     UWG_EXT_CAPS_RETRY_MS : UWG_EXT_CAPS_FAST_RETRY_MS);
	local = peer->caps.local;
	spin_unlock_bh(&peer->caps.lock);

	len = uwg_ext_build_caps(frame, sizeof(frame), &local);
	if (likely(len > 0 &&
		   !uwg_packet_send_control(peer, frame, (size_t)len))) {
		spin_lock_bh(&peer->caps.lock);
		peer->caps.last_sent = now;
		/* As long as the peer advertises another FEC profile, our
		 * advertisement is unconfirmed: the first frame may have been
		 * sent before the peer installed the new keypair, or the peer
		 * may still answer a previous profile. Keep the bounded retry
		 * armed so a lost pair does not leave both sides on the legacy
		 * path until the next rekey.
		 */
		retry = peer->caps.send_attempts < UWG_EXT_CAPS_MAX_ATTEMPTS &&
			!uwg_ext_caps_fec_synced(&peer->caps, &local);
		peer->caps.retry = retry;
		spin_unlock_bh(&peer->caps.lock);
		if (retry)
			uwg_ext_caps_arm(peer);
		return;
	}

	spin_lock_bh(&peer->caps.lock);
	if (peer->caps.send_attempts)
		--peer->caps.send_attempts;
	peer->caps.resend = true;
	peer->caps.retry = false;
	peer->caps.next_send = 0;
	spin_unlock_bh(&peer->caps.lock);
	net_dbg_ratelimited("%s: Could not send CAPS to peer %llu\n",
			    peer->device->dev->name, peer->internal_id);
}

static bool uwg_ext_caps_same(const struct uwg_ext_caps *a,
			      const struct uwg_ext_caps *b)
{
	return a->flags == b->flags &&
	       a->ack_interval == b->ack_interval &&
	       a->fec_k == b->fec_k &&
	       a->fec_m == b->fec_m;
}

/*
 * The data plane only implements k <= 8 and m <= 2. A peer advertising a
 * bigger block is not an error - it must simply never be matched, otherwise
 * both sides would send a profile the other one drops.
 */
static void uwg_ext_sanitize_caps(struct uwg_peer *peer,
				  struct uwg_ext_caps *caps)
{
	if (!(caps->flags & UWG_EXT_CAP_FEC) ||
	    (caps->fec_k >= 1 && caps->fec_k <= UWG_FEC_DATA_MAX_K &&
	     caps->fec_m >= 1 && caps->fec_m <= UWG_FEC_DATA_MAX_M))
		return;

	net_dbg_ratelimited("%s: Peer %llu advertised unsupported FEC %u:%u\n",
			    peer->device->dev->name, peer->internal_id,
			    caps->fec_k, caps->fec_m);
	caps->flags &= ~(UWG_EXT_CAP_FEC | UWG_EXT_CAP_FEC_ADAPTIVE |
			 UWG_EXT_CAP_FEC_PARTIAL);
	caps->fec_k = 0;
	caps->fec_m = 0;
}

static void uwg_ext_handle_caps(struct uwg_peer *peer, const u8 *payload,
				size_t len)
{
	struct uwg_ext_caps caps;
	ktime_t now;
	ktime_t next_send = 0;
	enum uwg_ext_caps_plan plan;
	bool changed;
	bool defer = false;
	bool send = false;

	if (uwg_ext_parse_caps(payload, len, &caps))
		return;
	uwg_ext_sanitize_caps(peer, &caps);
	now = ktime_get();
	spin_lock_bh(&peer->caps.lock);
	uwg_ext_local_caps(peer->device, &peer->caps.local);
	changed = !peer->caps.last_peer_valid ||
		  !uwg_ext_caps_same(&peer->caps.last_peer, &caps);
	peer->caps.last_peer = caps;
	peer->caps.last_peer_valid = true;
	peer->caps.peer = caps;
	peer->caps.peer_valid = true;
	if (changed)
		peer->caps.reply_attempts = 0;
	/* Our own CAPS frame may have been sent before the peer installed the
	 * new keypair and was lost. Hearing a new profile from the peer is a
	 * good moment to (re)send ours. The 200 ms gate keeps a flapping peer
	 * from turning this into an answer per change, but a changed profile
	 * is never dropped: uwg_ext_caps_plan() asks for a deferred answer
	 * instead, carried by the control timer.
	 */
	plan = uwg_ext_caps_plan(now, peer->caps.last_sent, changed,
				 peer->caps.send_attempts,
				 peer->caps.reply_attempts, &next_send);
	if (plan == UWG_EXT_CAPS_PLAN_SEND) {
		if (!changed && peer->caps.send_attempts)
			++peer->caps.reply_attempts;
		peer->caps.resend = true;
		peer->caps.next_send = 0;
		send = true;
	} else if (plan == UWG_EXT_CAPS_PLAN_DEFER) {
		peer->caps.resend = true;
		peer->caps.next_send = next_send;
		if (peer->caps.send_attempts >= UWG_EXT_CAPS_MAX_ATTEMPTS)
			peer->caps.send_attempts =
				UWG_EXT_CAPS_MAX_ATTEMPTS - 1;
		defer = true;
	} else if (uwg_ext_caps_fec_synced(&peer->caps,
					   &peer->caps.local)) {
		/* The peer now advertises the profile we run, so our
		 * advertisement is confirmed: stop the bounded retry.
		 */
		peer->caps.retry = false;
	}
	if (send && peer->caps.send_attempts >= UWG_EXT_CAPS_MAX_ATTEMPTS)
		peer->caps.send_attempts = UWG_EXT_CAPS_MAX_ATTEMPTS - 1;
	spin_unlock_bh(&peer->caps.lock);
	if (send)
		uwg_ext_maybe_send_caps(peer);
	else if (defer)
		uwg_ext_caps_arm(peer);
}

static enum uwg_ext_rx_result uwg_ext_handle_fec_shard(struct uwg_peer *peer,
						       struct sk_buff *skb,
						       const u8 *payload,
						       size_t len)
{
	struct uwg_ext_fec_shard shard;
	u64 keypair_id;
	int ret;

	if (uwg_ext_parse_fec_shard(payload, len, &shard))
		return UWG_EXT_RX_INVALID;
	if (unlikely(!PACKET_CB(skb)->keypair))
		return UWG_EXT_RX_INVALID;
	keypair_id = PACKET_CB(skb)->keypair->internal_id;
	ret = uwg_fec_rx_shard(peer, &shard, skb,
			       UWG_EXT_HEADER_LEN + UWG_EXT_FEC_HEADER_LEN,
			       keypair_id, true);
	if (ret)
		return UWG_EXT_RX_INVALID;
	/* A shard is a real transport packet, so it keeps the data path alive
	 * just like a plain packet: without this an FEC-only flow (all inner
	 * traffic already turned into shards) would never arm the keepalive
	 * timer and the tunnel could be torn down while it is busy.
	 */
	uwg_timers_data_received(peer);
	return UWG_EXT_RX_CONSUMED;
}

enum uwg_ext_rx_result uwg_ext_receive(struct uwg_peer *peer,
				       struct sk_buff *skb)
{
	u8 hdrbuf[UWG_EXT_HEADER_LEN];
	u8 capsbuf[UWG_EXT_CAPS_LEN];
	u8 fecbuf[UWG_EXT_FEC_HEADER_LEN];
	const u8 *hdr;
	struct uwg_ext_header header;

	if (skb->len < UWG_EXT_HEADER_LEN)
		return UWG_EXT_RX_NOT_EXTENSION;

	hdr = skb_header_pointer(skb, 0, sizeof(hdrbuf), hdrbuf);
	if (!hdr || !uwg_ext_detect(hdr, sizeof(hdrbuf)))
		return UWG_EXT_RX_NOT_EXTENSION;
	if (uwg_ext_parse_header(hdr, skb->len, &header))
		return UWG_EXT_RX_INVALID;

	switch (header.kind) {
	case UWG_EXT_KIND_CAPS:
		if (header.payload_len != UWG_EXT_CAPS_LEN ||
		    skb_copy_bits(skb, UWG_EXT_HEADER_LEN, capsbuf,
				  UWG_EXT_CAPS_LEN))
			return UWG_EXT_RX_INVALID;
		uwg_ext_handle_caps(peer, capsbuf, UWG_EXT_CAPS_LEN);
		return UWG_EXT_RX_CONSUMED;
	case UWG_EXT_KIND_ACK:
		/* Reserved: older peers still send ACK frames. They are
		 * recognised as extension traffic and silently dropped, never
		 * delivered as an inner packet and never counted as an error.
		 */
		return UWG_EXT_RX_CONSUMED;
	case UWG_EXT_KIND_FEC_SHARD:
		if (header.payload_len < UWG_EXT_FEC_HEADER_LEN ||
		    skb_copy_bits(skb, UWG_EXT_HEADER_LEN, fecbuf,
				  UWG_EXT_FEC_HEADER_LEN))
			return UWG_EXT_RX_INVALID;
		return uwg_ext_handle_fec_shard(peer, skb, fecbuf,
						header.payload_len);
	default:
		return UWG_EXT_RX_INVALID;
	}
}
