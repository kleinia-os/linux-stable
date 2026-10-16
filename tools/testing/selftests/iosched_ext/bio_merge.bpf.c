// SPDX-License-Identifier: GPL-2.0
#define BPF_NO_KFUNC_PROTOTYPES

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define IOSCHED_INSERT_REJECT 2

char _license[] SEC("license") = "GPL";

int bio_merge_calls;

SEC("struct_ops/bio_merge_true")
bool bio_merge_true(struct iosched_bio_merge_ctx *ctx)
{
	__sync_fetch_and_add(&bio_merge_calls, 1);
	return true;
}

SEC("struct_ops/insert_request_reject")
int insert_request_reject(struct iosched_insert_ctx *ctx)
{
	return IOSCHED_INSERT_REJECT;
}

SEC("struct_ops/evacuate_empty")
u64 evacuate_empty(struct iosched_arbiter_dispatch_ctx *ctx)
{
	return 0;
}

SEC(".struct_ops.link")
struct iosched_ext_ops bio_merge_ops = {
	.bio_merge	= (void *)bio_merge_true,
	.insert_request	= (void *)insert_request_reject,
	.evacuate	= (void *)evacuate_empty,
	.name		= "bm_true",
};
