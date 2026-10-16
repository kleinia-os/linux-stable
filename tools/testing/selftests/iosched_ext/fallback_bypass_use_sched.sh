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
	requeue_clears = 1
}
in_requeue && /blk_mq_requeue_request\(/ {
	requeue_calls_requeue = 1
}
in_requeue && /blk_mq_request_bypass_insert\(/ {
	requeue_calls_bypass_insert = 1
}
in_requeue && /^}/ {
	in_requeue = 0
}

/^static noinline void scx_io_bypass_request\(/ {
	in_bypass = 1
}
in_bypass && /spin_lock\(&hdata->fallback_lock\);/ {
	seen_lock = 1
}
in_bypass && seen_lock && /rq->rq_flags[[:space:]]*&=[[:space:]]*~RQF_USE_SCHED;/ {
	cleared_under_lock = 1
}
in_bypass && seen_lock && /list_move(_tail)?\(&rq->queuelist, &hdata->fallback_list\);/ {
	if (!cleared_under_lock)
		list_move_before_clear = 1
}
in_bypass && seen_lock && /spin_unlock\(&hdata->fallback_lock\);/ {
	checked_unlock = 1
	in_bypass = 0
}

END {
	if (requeue_clears && !requeue_calls_requeue && requeue_calls_bypass_insert &&
	    cleared_under_lock && checked_unlock && !list_move_before_clear) {
		print "ok 1 fallback bypass clears RQF_USE_SCHED before queueing fallback request"
		exit 0
	}

	print "not ok 1 fallback bypass clears RQF_USE_SCHED before queueing fallback request"
	if (!requeue_clears)
		print "# scx_io_requeue_without_fallback no longer clears RQF_USE_SCHED"
	if (requeue_calls_requeue)
		print "# scx_io_requeue_without_fallback still calls blk_mq_requeue_request"
	if (!requeue_calls_bypass_insert)
		print "# scx_io_requeue_without_fallback does not call blk_mq_request_bypass_insert"
	if (!cleared_under_lock)
		print "# scx_io_bypass_request fallback list path does not clear RQF_USE_SCHED under fallback_lock"
	if (list_move_before_clear)
		print "# scx_io_bypass_request queues fallback request before clearing RQF_USE_SCHED"
	if (!checked_unlock)
		print "# scx_io_bypass_request fallback_lock section was not found"
	exit 1
}
' "$src"
