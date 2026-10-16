#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Verify that the bpf_in_flight double-decrement bug (Issue #1) remains fixed,
# and that the TOCTOU atomic ops (Issue #21) are also correctly handled.
#
# The fix for #1 made blkg_note_bpf_complete return bool to gate the global
# decrement. The fix for #21 replaced atomic_read+atomic_dec with
# atomic_dec_if_positive. This test checks both properties are preserved.

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

/^static bool scx_io_blkg_note_bpf_complete\(/ {
	in_complete = 1
	complete_returns_bool = 1
}
in_complete && /bool completed = false;/ {
	complete_tracks_decrement = 1
}
in_complete && /completed = true;/ {
	complete_sets_true = 1
}
in_complete && /atomic_dec_if_positive\(&scx_pd->bpf_in_flight\)/ {
	complete_uses_dec_if_positive = 1
}
in_complete && /ret > 0/ {
	complete_checks_ret_positive = 1
}
in_complete && /ret < 0/ {
	complete_checks_ret_negative = 1
}
in_complete && /return completed;/ {
	complete_returns_decrement = 1
}
in_complete && /^}/ {
	in_complete = 0
}

/^static void scx_io_note_bpf_dispatch\(/ {
	in_dispatch = 1
}
in_dispatch && /if \(scx_io_blkg_note_bpf_complete\(data, blkg\)\)/ {
	dispatch_gates_on_complete = 1
}
in_dispatch && /atomic_dec_if_positive\(&data->bpf_in_flight\)/ {
	dispatch_uses_dec_if_positive = 1
}
in_dispatch && /^}/ {
	in_dispatch = 0
}

END {
	pass1 = complete_returns_bool && complete_tracks_decrement &&
		complete_sets_true && complete_uses_dec_if_positive &&
		complete_checks_ret_positive && complete_checks_ret_negative &&
		complete_returns_decrement;
	pass2 = dispatch_gates_on_complete && dispatch_uses_dec_if_positive;

	if (pass1 && pass2) {
		print "ok 1 offline-evacuate BPF dispatch uses atomic_dec_if_positive and gates global on per-blkg completion"
		exit 0
	}

	print "not ok 1 offline-evacuate BPF dispatch uses atomic_dec_if_positive and gates global on per-blkg completion"
	if (!complete_returns_bool)
		print "# scx_io_blkg_note_bpf_complete does not return bool"
	if (!complete_tracks_decrement || !complete_sets_true || !complete_returns_decrement)
		print "# scx_io_blkg_note_bpf_complete does not properly track decrement completion"
	if (!complete_uses_dec_if_positive)
		print "# scx_io_blkg_note_bpf_complete does not use atomic_dec_if_positive for per-blkg inflight"
	if (!complete_checks_ret_positive || !complete_checks_ret_negative)
		print "# scx_io_blkg_note_bpf_complete does not check atomic_dec_if_positive return value"
	if (!dispatch_gates_on_complete)
		print "# scx_io_note_bpf_dispatch does not gate global inflight decrement on per-blkg completion"
	if (!dispatch_uses_dec_if_positive)
		print "# scx_io_note_bpf_dispatch does not use atomic_dec_if_positive for global inflight"
	exit 1
}
' "$src"