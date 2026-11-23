// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2024 AmneziaVPN <admin@amnezia.org>. All Rights Reserved.
 */

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(7, 0, 0)
#error "UmbraWG requires Linux 7.0 or newer"
#endif

#include "version.h"
#include "device.h"
#include "aead.h"
#include "fec.h"
#include "noise.h"
#include "queueing.h"
#include "ratelimiter.h"
#include "netlink.h"
#include "uapi/umbrawg.h"

#include <linux/init.h>
#include <linux/module.h>
#include <net/genetlink.h>
#include <net/rtnetlink.h>

static int __init uwg_mod_init(void)
{
	int ret;

	ret = uwg_allowedips_slab_init();
	if (ret < 0)
		goto err_allowedips;

	ret = uwg_fec_init();
	if (ret < 0)
		goto err_allowedips;

	ret = uwg_fec_selftest();
	if (ret < 0) {
		pr_err("FEC self-test failed: %d\n", ret);
		goto err_allowedips;
	}

#ifdef DEBUG
	ret = -ENOTRECOVERABLE;
	if (!uwg_allowedips_selftest() || !uwg_packet_counter_selftest() ||
	    !uwg_queueing_selftest() || !uwg_ratelimiter_selftest())
		goto err_peer;
#endif
	uwg_noise_init();

	ret = uwg_peer_init();
	if (ret < 0)
		goto err_peer;

	ret = uwg_device_init();
	if (ret < 0)
		goto err_device;

	ret = uwg_aead_init();
	if (ret < 0)
		goto err_aead;

	ret = uwg_genetlink_init();
	if (ret < 0)
		goto err_netlink;

	pr_info("UmbraWG " UMBRAWG_VERSION " loaded. See github.com/ivlev-dev/umbrawg for information.\n");
	pr_info("Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.\n");
	pr_info("Copyright (C) 2024-2025 AmneziaVPN <admin@amnezia.org>. All Rights Reserved.\n");

	return 0;

err_netlink:
	uwg_aead_uninit();
err_aead:
	uwg_device_uninit();
err_device:
	uwg_peer_uninit();
err_peer:
	uwg_allowedips_slab_uninit();
err_allowedips:
	return ret;
}

static void __exit uwg_mod_exit(void)
{
	uwg_genetlink_uninit();
	uwg_device_uninit();
	uwg_aead_uninit();
	uwg_peer_uninit();
	uwg_allowedips_slab_uninit();
}

module_param(bogus_endpoints, int, 0600);
module_param(bogus_endpoints_prefix, charp, 0600);
module_param(bogus_endpoints_prefix6, charp, 0600);
module_init(uwg_mod_init);
module_exit(uwg_mod_exit);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("UmbraWG secure network tunnel");
MODULE_AUTHOR("Jason A. Donenfeld <Jason@zx2c4.com>, AmneziaVPN <admin@amnezia.org>");
MODULE_VERSION(UMBRAWG_VERSION);
MODULE_ALIAS_RTNL_LINK(KBUILD_MODNAME);
MODULE_ALIAS_GENL_FAMILY(UWG_GENL_NAME);
MODULE_INFO(intree, "Y");
