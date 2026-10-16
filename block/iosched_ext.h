/* block/iosched_ext.h - Wrapper Struct Pattern for BPF struct_ops */
#ifndef _IOSCHED_EXT_H
#define _IOSCHED_EXT_H

#include <linux/blk-mq.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>

/*
 * Kernel-side data structures for BPF
 */

/* Request node in a list */
struct iosched_request_node {
    struct request *rq;
    struct list_head node;
};

/* Request list */
struct iosched_request_list {
    struct list_head head;
    struct hlist_node h_node;  /* For registry */
    u64 list_id;
    spinlock_t lock;
};

/* Data structure registry */
#define IOSCHED_DS_REGISTRY_BITS 8
struct iosched_ds_registry {
    DECLARE_HASHTABLE(ds_hash, IOSCHED_DS_REGISTRY_BITS);
    rwlock_t lock;
    atomic64_t next_id;
};

/* Registry management functions */
void iosched_ds_registry_init(struct iosched_ds_registry *registry);
void iosched_ds_registry_cleanup(struct iosched_ds_registry *registry);

/*
 * Context structures for BPF struct_ops
 */

/*
 * BPF Context Structure for insert_request
 * 
 * CRITICAL: This is a WRAPPER STRUCT used for BPF struct_ops.
 * BPF programs access parameters via ctx->field, not separate registers.
 * This is required because struct_ops passes all params via R1 offset.
 */
struct iosched_insert_ctx {
    struct request_queue *q;
    struct request *rq;
    u64 icq_ptr;
    u64 insert_flags;
    u64 opf;
    u64 sector;
    u64 nr_sectors;
    u64 cgroup_id;
    u64 original_cgroup_id;
    u64 ioprio;
    u64 hctx_idx;
};

struct iosched_arbiter_dispatch_ctx {
    struct request_queue *q;
    u64 hctx_idx;
    u64 cgroup_id;
};

struct iosched_hctx_ctx {
	struct request_queue *q;
	struct blk_mq_hw_ctx *hctx;
	u64 hctx_idx;
};

struct iosched_icq_ctx {
	struct request_queue *q;
	struct io_cq *icq;
};

struct iosched_allow_merge_ctx {
	struct request_queue *q;
	struct request *rq;
	struct bio *bio;
	u64 rq_ioprio;
	u64 bio_ioprio;
	u64 rq_sector;
	u64 rq_nr_sectors;
	u64 bio_sector;
	u64 bio_nr_sectors;
	u64 bio_opf;
};

struct iosched_bio_merge_ctx {
	struct request_queue *q;
	struct bio *bio;
	u64 nr_segs;
	u64 bio_ioprio;
	u64 bio_sector;
	u64 bio_nr_sectors;
	u64 bio_opf;
};

struct iosched_request_merge_ctx {
	struct request_queue *q;
	struct request *rq;
	struct bio *bio;
	u64 rq_ioprio;
	u64 bio_ioprio;
	u64 rq_sector;
	u64 rq_nr_sectors;
	u64 bio_sector;
	u64 bio_nr_sectors;
	u64 bio_opf;
};

struct iosched_request_merged_ctx {
	struct request_queue *q;
	struct request *rq;
	u64 merge_type;
	u64 rq_ioprio;
	u64 rq_deadline;
	u64 rq_sector;
	u64 rq_nr_sectors;
};

struct iosched_requests_merged_ctx {
	struct request_queue *q;
	struct request *rq;
	struct request *next;
	u64 rq_ioprio;
	u64 next_ioprio;
	u64 rq_deadline;
	u64 next_deadline;
	u64 rq_sector;
	u64 rq_nr_sectors;
	u64 next_sector;
	u64 next_nr_sectors;
};

struct iosched_limit_depth_ctx {
	struct request_queue *q;
	struct blk_mq_alloc_data *data;
	u64 icq_ptr;
	u64 ioprio;
	u64 opf;
	u64 hctx_idx;
	u64 async_depth;
};

struct iosched_depth_updated_ctx {
	struct request_queue *q;
	u64 nr_requests;
	u64 async_depth;
};

struct iosched_rq_ctx {
	struct request_queue *q;
	struct request *rq;
	u64 icq_ptr;
	u64 ioprio;
	u64 opf;
	u64 sector;
	u64 nr_sectors;
	u64 hctx_idx;
};

struct iosched_completed_request_ctx {
	struct request_queue *q;
	struct request *rq;
	u64 icq_ptr;
	u64 ioprio;
	u64 opf;
	u64 sector;
	u64 nr_sectors;
	u64 hctx_idx;
	u64 cgroup_id;
	u64 now;
	u64 total_latency_ns;
	u64 io_latency_ns;
};

/*
 * BPF Context Structure for init/exit_queue
 */
struct iosched_queue_ctx {
    struct request_queue *q;
};

#define IOSCHED_BYPASS_MODE_NONE   0ULL
#define IOSCHED_BYPASS_MODE_DIRECT 1ULL

/* 
 * The operations struct for BPF struct_ops
 * All multi-param functions use wrapper struct as single param
 */
struct iosched_ext_ops {
    /* Called when scheduler is initialized */
    int (*init_queue)(struct iosched_queue_ctx *ctx);
    
    /* Called when scheduler is unloaded */
    int (*exit_queue)(struct iosched_queue_ctx *ctx);
    
	/* Core: Insert request into queue (push to BPF Map) */
	int (*insert_request)(struct iosched_insert_ctx *ctx);

	u64 (*cgroup_dispatch)(struct iosched_arbiter_dispatch_ctx *ctx);

	u64 (*evacuate)(struct iosched_arbiter_dispatch_ctx *ctx);

	int (*init_hctx)(struct iosched_hctx_ctx *ctx);

	void (*exit_hctx)(struct iosched_hctx_ctx *ctx);

	bool (*allow_merge)(struct iosched_allow_merge_ctx *ctx);

	bool (*bio_merge)(struct iosched_bio_merge_ctx *ctx);

	u64 (*request_merge)(struct iosched_request_merge_ctx *ctx);

	void (*request_merged)(struct iosched_request_merged_ctx *ctx);

	void (*requests_merged)(struct iosched_requests_merged_ctx *ctx);

	u64 (*limit_depth)(struct iosched_limit_depth_ctx *ctx);

	void (*depth_updated)(struct iosched_depth_updated_ctx *ctx);

	void (*prepare_request)(struct iosched_rq_ctx *ctx);

	void (*finish_request)(struct iosched_rq_ctx *ctx);

	void (*completed_request)(struct iosched_completed_request_ctx *ctx);

	void (*requeue_request)(struct iosched_rq_ctx *ctx);

	u64 (*former_request)(struct iosched_rq_ctx *ctx);

	u64 (*next_request)(struct iosched_rq_ctx *ctx);

	void (*init_icq)(struct iosched_icq_ctx *ctx);

	void (*exit_icq)(struct iosched_icq_ctx *ctx);

	u64 bypass_mode;

	/* Name to identify different BPF schedulers */
	char name[16];
};

struct iosched_arbiter_ops {
    u64 (*pick_cgroup)(struct iosched_arbiter_dispatch_ctx *ctx);

    bool (*hold_dispatch)(struct iosched_arbiter_dispatch_ctx *ctx);

    void (*completed_request)(struct iosched_completed_request_ctx *ctx);

    char name[16];
};


/*
 * Wrapper struct for BPF struct_ops registration
 * This MUST be defined for libbpf to find the struct_ops type in BTF.
 */
#ifdef __KERNEL__
#include <linux/bpf.h>

struct bpf_struct_ops_iosched_ext_ops {
    struct bpf_struct_ops_common_value common;
    struct iosched_ext_ops data;
};
#endif /* __KERNEL__ */

bool scx_io_bio_should_bypass(struct request_queue *q, struct bio *bio);

int iosched_ext_init(void);
#endif /* _IOSCHED_EXT_H */
