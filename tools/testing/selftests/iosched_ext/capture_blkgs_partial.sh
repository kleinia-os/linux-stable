#!/bin/sh

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
	print "1..1";
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

END {
	pass1 = !drops_refs_after_partial_capture;

	if (pass1)
		print "ok 1 capture_blkgs keeps partial blkg refs on allocation failure";
	else {
		print "not ok 1 capture_blkgs keeps partial blkg refs on allocation failure";
		print "# scx_io_policy_capture_blkgs drops captured refs after blkcg unlock";
	}

	exit pass1 ? 0 : 1;
}
' "$src"
