#!/bin/sh

KSFT_PASS=0
KSFT_FAIL=1

self_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src="${IOSCHED_EXT_SRC:-$self_dir/../../../../block/iosched_ext.c}"

if [ ! -r "$src" ]; then
	echo "1..3"
	echo "not ok 1 iosched_ext.c is readable"
	echo "not ok 2 iosched_ext.c is readable"
	echo "not ok 3 iosched_ext.c is readable"
	exit "$KSFT_FAIL"
fi

awk '
function count_open_braces(str, tmp)
{
	tmp = str;
	return gsub(/\{/, "{", tmp);
}

function count_close_braces(str, tmp)
{
	tmp = str;
	return gsub(/\}/, "}", tmp);
}

BEGIN {
	print "1..3";
}

/^static int scx_io_policy_capture_blkgs\(/ {
	in_capture = 1;
	capture_depth = 0;
}

in_capture {
	if (/\{/)
		seen_capture_body = 1;
	capture_depth += count_open_braces($0);
	capture_depth -= count_close_braces($0);
}

in_capture && /spin_unlock_irqrestore\(&blkcg->lock/ {
	after_blkcg_unlock = 1;
}

in_capture && after_blkcg_unlock && /if \(ret\)/ {
	ret_guard_after_unlock = 1;
}

in_capture && after_blkcg_unlock && ret_guard_after_unlock && /scx_io_policy_drop_blkg_refs\(policy\);/ {
	drops_refs_after_partial_capture = 1;
}

in_capture && seen_capture_body && capture_depth == 0 {
	in_capture = 0;
}

/^#define[[:space:]]+SCX_IO_MAX_EVAC_HCTX[[:space:]]+/ {
	max_hctx = $3;
	sub(/U$/, "", max_hctx);
	if (max_hctx + 0 >= 4096)
		hctx_cap_covers_nvme = 1;
}

/^static noinline int scx_io_policy_prepare_teardown\(/ {
	in_prepare = 1;
}

in_prepare && /if \(reason == SCX_IO_RETIRE_OFFLINE && offline_blkg\) \{/ {
	seen_offline_blkg = 1;
	in_offline_blkg = 1;
	offline_blkg_depth = 0;
}

in_prepare && in_offline_blkg {
	offline_blkg_depth += count_open_braces($0);
	offline_blkg_depth -= count_close_braces($0);
	if (offline_blkg_depth == 0) {
		in_offline_blkg = 0;
		after_offline_blkg = 1;
	}
}

in_prepare && /if \(reason == SCX_IO_RETIRE_OFFLINE\)/ && !/&& offline_blkg/ {
	null_offline_return_guard = 1;
}

in_prepare && null_offline_return_guard && /return 0;/ {
	null_offline_early_return = 1;
}

in_prepare && after_offline_blkg && !capture_seen && /return 0;/ {
	offline_blkg_early_return = 1;
}

in_prepare && /ret = scx_io_policy_capture_blkgs\(policy\);/ {
	capture_seen = 1;
	if (after_offline_blkg)
		capture_after_offline_blkg = 1;
}

in_prepare && /^}/ {
	in_prepare = 0;
}

/^static noinline void scx_io_policy_teardown_workfn\(/ {
	in_teardown = 1;
}

in_teardown && /for \(i = 0; i < SCX_IO_MAX_EVAC_HCTX; i\+\+\) \{/ {
	fallback_uses_hctx_cap = 1;
	in_hctx_fallback = 1;
}

in_teardown && in_hctx_fallback && /scx_io_policy_evacuate_hctx\(policy, NULL, i\)/ {
	fallback_evacuates_null_queue = 1;
}

in_teardown && in_hctx_fallback && /^\t\t\t}/ {
	in_hctx_fallback = 0;
}

in_teardown && /^}/ {
	in_teardown = 0;
}

END {
	pass1 = seen_offline_blkg && capture_after_offline_blkg &&
		!offline_blkg_early_return && !null_offline_early_return;
	pass2 = hctx_cap_covers_nvme && fallback_uses_hctx_cap &&
		fallback_evacuates_null_queue;
	pass3 = !drops_refs_after_partial_capture;

	if (pass1)
		print "ok 1 offline teardown captures offline blkg then all remaining blkgs";
	else {
		print "not ok 1 offline teardown captures offline blkg then all remaining blkgs";
		if (!seen_offline_blkg)
			print "# offline_blkg preservation block was not found";
		if (!capture_after_offline_blkg)
			print "# scx_io_policy_capture_blkgs does not run after offline_blkg handling";
		if (offline_blkg_early_return)
			print "# offline_blkg path still returns before global blkg capture";
		if (null_offline_early_return)
			print "# offline NULL-blkg path still returns before global blkg capture";
	}

	if (pass2)
		print "ok 2 teardown fallback scans hctx indices beyond 255";
	else {
		print "not ok 2 teardown fallback scans hctx indices beyond 255";
		if (!hctx_cap_covers_nvme)
			print "# SCX_IO_MAX_EVAC_HCTX is below 4096";
		if (!fallback_uses_hctx_cap || !fallback_evacuates_null_queue)
			print "# teardown fallback hctx scan was not found";
	}

	if (pass3)
		print "ok 3 capture_blkgs keeps partial blkg refs on allocation failure";
	else {
		print "not ok 3 capture_blkgs keeps partial blkg refs on allocation failure";
		print "# scx_io_policy_capture_blkgs drops captured refs after blkcg unlock";
	}

	exit (pass1 && pass2 && pass3) ? 0 : 1;
}
' "$src"
