#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

shopt -s globstar

UWG="$(readlink -f "$(dirname "$(readlink -f "$0")")/../src/")"

for i in "$UWG"/**/{*.c,*.h,*.S,*.pl,*.include} "$UWG/Kbuild" "$UWG/Kconfig"; do
	[[ $i == "$UWG/tests/"* ]] && continue
	diff -u /dev/null "$i" | sed "s:${UWG}:b/net/wireguard:;s:Kbuild:Makefile:"
done

cat <<_EOF
--- a/net/Kconfig
+++ b/net/Kconfig
@@ -85,2 +85,3 @@ config INET
 if INET
+source "net/wireguard/Kconfig"
 source "net/ipv4/Kconfig"
--- a/net/Makefile
+++ b/net/Makefile
@@ -16,2 +16,3 @@
 obj-\$(CONFIG_NETFILTER)		+= netfilter/
+obj-\$(CONFIG_WIREGUARD)		+= wireguard/
 obj-\$(CONFIG_INET)		+= ipv4/
_EOF
