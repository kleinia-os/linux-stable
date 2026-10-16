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
function brace_delta(line,    text, opens, closes) {
	text = line
	opens = gsub(/\{/, "", text)
	text = line
	closes = gsub(/\}/, "", text)
	return opens - closes
}

function enter_function(name, line) {
	func = name
	depth = brace_delta(line)
}

function leave_function() {
	func = ""
	depth = 0
}

BEGIN {
	print "1..1"
}

/^static bool scx_io_blkg_note_bpf_complete\(/ {
	pending = "complete"
}
/^static void scx_io_note_bpf_dispatch\(/ {
	pending = "dispatch"
}
/^static noinline void scx_io_policy_note_dispatch\(/ {
	pending = "policy"
}

pending && /\{/ {
	enter_function(pending, $0)
	pending = ""
	next
}

func == "complete" {
	if (/atomic_dec_if_positive\(&scx_pd->bpf_in_flight\)/)
		complete_uses_dec_if_positive = 1
	if (/atomic_read\(&scx_pd->bpf_in_flight\)/)
		complete_reads_inflight = 1
	if (/atomic_dec_return\(&scx_pd->bpf_in_flight\)/)
		complete_old_dec_return = 1
	if (/atomic_dec\(&scx_pd->bpf_in_flight\)/)
		complete_old_dec = 1
}

func == "dispatch" {
	if (/scx_io_blkg_note_bpf_complete\(data, blkg\)/)
		dispatch_gates_on_complete = 1
	if (/atomic_dec_if_positive\(&data->bpf_in_flight\)/)
		dispatch_uses_dec_if_positive = 1
	if (/atomic_read\(&data->bpf_in_flight\)/)
		dispatch_reads_inflight = 1
	if (/atomic_dec_return\(&data->bpf_in_flight\)/)
		dispatch_old_dec_return = 1
	if (/atomic_dec\(&data->bpf_in_flight\)/)
		dispatch_old_dec = 1
}

func == "policy" {
	if (/atomic_dec_if_positive\(&policy->managed_inflight\)/)
		policy_uses_dec_if_positive = 1
	if (/atomic_read\(&policy->managed_inflight\)/)
		policy_reads_inflight = 1
	if (/atomic_dec_return\(&policy->managed_inflight\)/)
		policy_old_dec_return = 1
	if (/atomic_dec\(&policy->managed_inflight\)/)
		policy_old_dec = 1
}

func {
	depth += brace_delta($0)
	if (depth == 0)
		leave_function()
}

END {
	if (complete_uses_dec_if_positive && !complete_reads_inflight &&
	    !complete_old_dec_return && !complete_old_dec &&
	    dispatch_gates_on_complete && dispatch_uses_dec_if_positive &&
	    !dispatch_reads_inflight && !dispatch_old_dec_return &&
	    !dispatch_old_dec && policy_uses_dec_if_positive &&
	    !policy_reads_inflight && !policy_old_dec_return &&
	    !policy_old_dec) {
		print "ok 1 iosched_ext inflight dispatch counters use atomic_dec_if_positive"
		exit 0
	}

	print "not ok 1 iosched_ext inflight dispatch counters use atomic_dec_if_positive"
	if (!complete_uses_dec_if_positive)
		print "# scx_io_blkg_note_bpf_complete does not use atomic_dec_if_positive for scx_pd->bpf_in_flight"
	if (complete_reads_inflight || complete_old_dec_return || complete_old_dec)
		print "# scx_io_blkg_note_bpf_complete still has a read-then-decrement pattern for scx_pd->bpf_in_flight"
	if (!dispatch_gates_on_complete || !dispatch_uses_dec_if_positive)
		print "# scx_io_note_bpf_dispatch does not gate atomic_dec_if_positive on per-blkg completion"
	if (dispatch_reads_inflight || dispatch_old_dec_return || dispatch_old_dec)
		print "# scx_io_note_bpf_dispatch still has a read-then-decrement pattern for data->bpf_in_flight"
	if (!policy_uses_dec_if_positive)
		print "# scx_io_policy_note_dispatch does not use atomic_dec_if_positive for policy->managed_inflight"
	if (policy_reads_inflight || policy_old_dec_return || policy_old_dec)
		print "# scx_io_policy_note_dispatch still has a read-then-decrement pattern for policy->managed_inflight"
	exit 1
}
' "$src"
