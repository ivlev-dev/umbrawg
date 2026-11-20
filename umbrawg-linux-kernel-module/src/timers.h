/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _UWG_TIMERS_H
#define _UWG_TIMERS_H

#include <linux/ktime.h>

struct uwg_peer;

void uwg_timers_init(struct uwg_peer *peer);
void uwg_timers_stop(struct uwg_peer *peer);
void uwg_timers_shutdown(struct uwg_peer *peer);
void uwg_timers_ack_reduce(struct uwg_peer *peer, unsigned long expires);
void uwg_timers_data_sent(struct uwg_peer *peer);
void uwg_timers_data_received(struct uwg_peer *peer);
void uwg_timers_any_authenticated_packet_sent(struct uwg_peer *peer);
void uwg_timers_any_authenticated_packet_received(struct uwg_peer *peer);
void uwg_timers_handshake_initiated(struct uwg_peer *peer);
void uwg_timers_handshake_complete(struct uwg_peer *peer);
void uwg_timers_session_derived(struct uwg_peer *peer);
void uwg_timers_any_authenticated_packet_traversal(struct uwg_peer *peer);

static inline bool uwg_birthdate_has_expired(u64 birthday_nanoseconds,
					    u64 expiration_seconds)
{
	return (s64)(birthday_nanoseconds + expiration_seconds * NSEC_PER_SEC)
		<= (s64)ktime_get_coarse_boottime_ns();
}

#endif /* _UWG_TIMERS_H */
