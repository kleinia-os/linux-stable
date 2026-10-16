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

/^static void scx_io_requeue_without_fallback\(/ {
	in_requeue = 1
}
in_requeue && /rq->rq_flags[[:space:]]*&=[[:space:]]*~RQF_USE_SCHED;/ {
	clears_use_sched = 1
}
in_requeue && /blk_mq_requeue_request\(/ {
	calls_requeue = 1
}
in_requeue && /blk_mq_request_bypass_insert\(/ {
	calls_bypass_insert = 1
}
in_requeue && /blk_mq_run_hw_queue\(/ {
	calls_run_hw_queue = 1
}
in_requeue && /^}/ {
	in_requeue = 0
}

END {
	if (clears_use_sched && !calls_requeue && calls_bypass_insert && calls_run_hw_queue) {
		print "ok 1 requeue_without_fallback uses direct bypass insert"
		exit 0
	}

	print "not ok 1 requeue_without_fallback uses direct bypass insert"
	if (!clears_use_sched)
		print "# scx_io_requeue_without_fallback does not clear RQF_USE_SCHED"
	if (calls_requeue)
		print "# scx_io_requeue_without_fallback still calls blk_mq_requeue_request"
	if (!calls_bypass_insert)
		print "# scx_io_requeue_without_fallback does not call blk_mq_request_bypass_insert"
	if (!calls_run_hw_queue)
		print "# scx_io_requeue_without_fallback does not kick the hw queue"
	exit 1
}
' "$src"
