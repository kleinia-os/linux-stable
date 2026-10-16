#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

KSFT_PASS=0
KSFT_FAIL=1

self_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src="${IOSCHED_EXT_SRC:-$self_dir/../../../../block/iosched_ext.c}"

if [ ! -r "$src" ]; then
	echo "1..1"
	echo "not ok 1 iosched_ext.c is readable"
	exit "$KSFT_FAIL"
fi

awk '
BEGIN {
	print "1..1"
}

/^static struct blkcg_gq \*scx_io_policy_find_blkg\(/ {
	in_find = 1
}
in_find && /blkg = ref->blkg;/ {
	find_assigns_blkg = 1
	find_needs_get = 1
}
in_find && find_needs_get && /blkg_get\(blkg\);/ {
	find_gets_blkg = 1
}
in_find && /break;/ {
	if (find_assigns_blkg && find_gets_blkg)
		find_get_before_break = 1
}
in_find && /spin_unlock_irqrestore\(&policy->lock, irq_flags\);/ {
	if (find_gets_blkg)
		find_get_before_unlock = 1
}
in_find && /return blkg;/ {
	find_returns_blkg = 1
}
in_find && /^}/ {
	in_find = 0
}

/^static void scx_io_note_quiesced_dispatch\(/ {
	in_dispatch = 1
}
in_dispatch && /bool lookup_blkg = false;/ {
	dispatch_tracks_lookup_path = 1
}
in_dispatch && /if \(!blkg\)/ {
	dispatch_checks_blkg = 1
}
in_dispatch && dispatch_checks_blkg && /return;/ {
	dispatch_returns_on_null_blkg = 1
}
in_dispatch && /if \(lookup_blkg\)/ {
	dispatch_guards_next_put = 1
}
in_dispatch && /blkg_put\(blkg\);/ {
	dispatch_puts_blkg = 1
	if (dispatch_guards_next_put)
		dispatch_put_guarded_by_lookup = 1
	else
		dispatch_puts_unconditionally = 1
	dispatch_guards_next_put = 0
}
in_dispatch && /^}/ {
	in_dispatch = 0
}

END {
	if (find_assigns_blkg && find_gets_blkg && find_get_before_break &&
	    find_get_before_unlock && find_returns_blkg && dispatch_puts_blkg &&
	    dispatch_puts_unconditionally && !dispatch_put_guarded_by_lookup &&
	    dispatch_returns_on_null_blkg) {
		print "ok 1 policy find blkg returns referenced blkg and dispatch releases it"
		exit 0
	}

	print "not ok 1 policy find blkg returns referenced blkg and dispatch releases it"
	if (!find_assigns_blkg || !find_returns_blkg)
		print "# scx_io_policy_find_blkg does not return a found blkg"
	if (!find_gets_blkg || !find_get_before_break || !find_get_before_unlock)
		print "# scx_io_policy_find_blkg does not blkg_get() the found blkg before unlocking"
	if (!dispatch_puts_blkg)
		print "# scx_io_note_quiesced_dispatch does not blkg_put() a non-NULL blkg"
	if (dispatch_put_guarded_by_lookup || !dispatch_puts_unconditionally)
		print "# scx_io_note_quiesced_dispatch only blkg_put()s the fallback lookup path"
	if (!dispatch_returns_on_null_blkg)
		print "# scx_io_note_quiesced_dispatch does not preserve the NULL blkg return path"
	exit 1
}
' "$src"
