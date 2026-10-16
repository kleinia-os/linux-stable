/* block/iosched_ext.c */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/blk-mq.h>
#include <linux/slab.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/bpf_verifier.h>
#include <linux/cgroup.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/workqueue.h>
#include "blk.h"
#include "blk-cgroup.h"
#include "blk-mq-sched.h"
#include "elevator.h"
#include "iosched_ext.h"

/*
 * IOEXT_DEBUG is enabled by CONFIG_IOSCHED_EXT_DEBUG (see block/Makefile).
 * Manual build: -DIOEXT_DEBUG=1. Default off when unset.
 */
#ifndef IOEXT_DEBUG
#define IOEXT_DEBUG 0
#endif

#if IOEXT_DEBUG
#define ioext_dbg_pr_info(fmt, ...) pr_info("ioext: " fmt, ##__VA_ARGS__)
#define ioext_dbg_pr_info_once(fmt, ...) pr_info_once("ioext: " fmt, ##__VA_ARGS__)
#define ioext_dbg_pr_warn_ratelimited(fmt, ...) \
	pr_warn_ratelimited("ioext: " fmt, ##__VA_ARGS__)
#else
#define ioext_dbg_pr_info(fmt, ...) no_printk(KERN_INFO "ioext: " fmt, ##__VA_ARGS__)
#define ioext_dbg_pr_info_once(fmt, ...) no_printk(KERN_INFO "ioext: " fmt, ##__VA_ARGS__)
#define ioext_dbg_pr_warn_ratelimited(fmt, ...) \
	no_printk(KERN_WARNING "ioext: " fmt, ##__VA_ARGS__)
#endif

/*
 * Keep the older broad tracing counters active, but suppress their printk noise
 * while focusing this round on q_none DIRECT-bypass misses and fallback causes.
 */
#define IOEXT_DEBUG_VERBOSE 0

#define IOSCHED_INSERT_ACCEPT 0
#define IOSCHED_INSERT_DEFER_TO_PARENT 1
#define IOSCHED_PACK_REQUEST_MERGE(type, rq_ptr) \
	((((u64)(rq_ptr)) & ~0x7ULL) | ((type) & 0x7ULL))
#define IOSCHED_REQUEST_MERGE_TYPE(val) ((int)((val) & 0x7ULL))
#define IOSCHED_REQUEST_MERGE_RQ_PTR(val) ((val) & ~0x7ULL)
#define SCX_IO_MAX_EVAC_HCTX 4096U
#define SCX_IO_MAX_EVAC_STALL_ROUNDS 500U

/*
 * Merge hook noinline: keep scx_io_* merge path symbols probe-able by
 * bpftrace/kprobe when CONFIG_IOSCHED_EXT_DEBUG is on. In production builds
 * the compiler is free to inline these static functions.
 */
#ifdef CONFIG_IOSCHED_EXT_DEBUG
#define IOEXT_MERGE_HOOK noinline
#else
#define IOEXT_MERGE_HOOK
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OS-Dev Student");
MODULE_DESCRIPTION("eBPF I/O Scheduler Extension");

static void scx_io_depth_updated(struct request_queue *q);

__bpf_kfunc_start_defs();

__bpf_kfunc u64 bpf_scx_io_rq_total_latency_ns(struct request *rq, u64 now)
{
	if (!rq || !rq->start_time_ns)
		return 0;

	return now >= rq->start_time_ns ? now - rq->start_time_ns : 0;
}

__bpf_kfunc u64 bpf_scx_io_rq_io_latency_ns(struct request *rq, u64 now)
{
	if (!rq || !rq->io_start_time_ns)
		return 0;

	return now >= rq->io_start_time_ns ? now - rq->io_start_time_ns : 0;
}

__bpf_kfunc void bpf_scx_io_set_queue_async_depth(struct request_queue *q,
					      u32 depth)
{
	u32 new_depth;

	if (!q)
		return;

	if (!depth)
		depth = 1;
	new_depth = min(depth, q->nr_requests);
	if (!new_depth)
		new_depth = 1;
	if (q->async_depth == new_depth)
		return;

	q->async_depth = new_depth;
	scx_io_depth_updated(q);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(scx_io_kfunc_ids)
BTF_ID_FLAGS(func, bpf_scx_io_rq_total_latency_ns)
BTF_ID_FLAGS(func, bpf_scx_io_rq_io_latency_ns)
BTF_ID_FLAGS(func, bpf_scx_io_set_queue_async_depth)
BTF_KFUNCS_END(scx_io_kfunc_ids)

static const struct btf_kfunc_id_set scx_io_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &scx_io_kfunc_ids,
};

struct iosched_ext_ops __force_btf_iosched_ops;
EXPORT_SYMBOL_GPL(__force_btf_iosched_ops);

enum scx_io_policy_state {
	SCX_IO_POLICY_ACTIVE = 0,
	SCX_IO_POLICY_QUIESCING,
};

enum scx_io_policy_retire_reason {
	SCX_IO_RETIRE_DETACH = 0,
	SCX_IO_RETIRE_REPLACE,
	SCX_IO_RETIRE_OFFLINE,
};

struct scx_io_policy_blkg_ref {
	struct list_head node;
	struct blkcg_gq *blkg;
};

struct scx_io_struct_ops_link {
	struct bpf_link link;
	struct bpf_map __rcu *map;
	wait_queue_head_t wait_hup;
	struct cgroup *cgroup_ctx;
};

struct scx_io_policy {
	struct cgroup_subsys_state *css;
	struct iosched_ext_ops *ops;
	struct bpf_link *link;
	struct bpf_map *teardown_map;
	struct delayed_work teardown_work;
	spinlock_t lock;
	struct list_head blkg_refs;
	atomic_t managed_inflight;
	atomic_t teardown_queued;
	enum scx_io_policy_state state;
	enum scx_io_policy_retire_reason retire_reason;
	unsigned int stall_rounds;
	u64 cgroup_id;
	u64 bypass_mode;
};

static struct iosched_arbiter_ops __rcu *current_arbiter;
static DEFINE_MUTEX(arbiter_lock);
static struct blkcg_policy scx_io_blkcg_policy;
static struct elevator_type scx_io_elevator;
static struct workqueue_struct *scx_io_teardown_wq;

struct scx_io_blkg_data {
	struct blkg_policy_data pd;
	struct list_head active_node;
	bool on_active_list;
	bool bypass_enabled;
	u64 bypass_epoch;
	atomic_t bpf_in_flight;
};

enum scx_io_bypass_reason {
	SCX_IO_BYPASS_NO_POLICY = 0,
	SCX_IO_BYPASS_POLICY_UNAVAILABLE,
	SCX_IO_BYPASS_POLICY_REJECTED,
	SCX_IO_BYPASS_QUIESCED,
};

enum scx_io_bio_bypass_debug_reason {
	SCX_IO_BIO_BYPASS_NULL = 0,
	SCX_IO_BIO_BYPASS_NON_RW,
	SCX_IO_BIO_BYPASS_ROOT_BLKG,
	SCX_IO_BIO_BYPASS_ZONE_PLUG,
	SCX_IO_BIO_BYPASS_NOT_SCX,
	SCX_IO_BIO_BYPASS_NO_PD,
	SCX_IO_BIO_BYPASS_REFRESH_ENABLED,
	SCX_IO_BIO_BYPASS_REFRESH_DISABLED,
	SCX_IO_BIO_BYPASS_CACHE_ENABLED,
	SCX_IO_BIO_BYPASS_CACHE_DISABLED,
	SCX_IO_BIO_BYPASS_NR_REASONS,
};

struct scx_io_data {
	struct request_queue *q;
	struct list_head active_pds;
	spinlock_t lock;
	atomic_t bpf_in_flight;
	atomic_t switch_draining;
	atomic64_t bypassed_total;
	atomic64_t bypassed_no_policy;
	atomic64_t bypassed_policy_unavailable;
	atomic64_t bypassed_policy_rejected;
	atomic64_t bypassed_quiesced;
#if IOEXT_DEBUG
	atomic64_t debug_insert_accepts;
	atomic64_t debug_dispatch_returns;
	atomic64_t debug_prepare_calls;
	atomic64_t debug_finish_entries;
	atomic64_t debug_complete_entries;
	atomic64_t debug_requeue_entries;
	atomic64_t debug_has_work_false;
	atomic64_t debug_validate_failures;
	atomic64_t debug_fallback_enqueues;
	atomic64_t debug_dispatch_nulls;
	atomic64_t debug_has_work_true;
	atomic64_t debug_bio_bypass_reasons[SCX_IO_BIO_BYPASS_NR_REASONS];
	atomic64_t debug_insert_fallbacks;
#endif
};

struct scx_io_hctx_data {
	struct list_head fallback_list;
	spinlock_t fallback_lock;
	atomic_t fallback_in_flight;
};

static atomic64_t scx_io_bypass_epoch = ATOMIC64_INIT(1);

static noinline void scx_io_bypass_request(struct scx_io_data *data,
				  struct blk_mq_hw_ctx *hctx,
				  struct request *rq,
				  blk_insert_t flags,
				  enum scx_io_bypass_reason reason,
				  u64 original_cgroup_id,
				  u64 effective_cgroup_id);
static const char *scx_io_bypass_reason_name(enum scx_io_bypass_reason reason);
static void scx_io_requeue_without_fallback(struct request *rq,
					       unsigned int hctx_idx,
					       enum scx_io_bypass_reason reason,
					       u64 cgroup_id,
					       u64 opf);
static noinline void scx_io_policy_teardown_workfn(struct work_struct *work);
static noinline int scx_io_policy_prepare_teardown(struct scx_io_policy *policy,
					 struct bpf_link *link,
					 enum scx_io_policy_retire_reason reason,
					 struct blkcg_gq *offline_blkg);
static noinline void scx_io_policy_schedule_teardown(struct scx_io_policy *policy);
static void scx_io_bump_bypass_epoch(void);
static void scx_io_prepare_switch(struct request_queue *q);
static void scx_io_set_blkg_bypass(struct scx_io_blkg_data *scx_pd,
				       bool enabled,
				       u64 epoch);
static bool scx_io_refresh_blkg_bypass(struct blkcg_gq *blkg);
static struct request *scx_io_policy_evacuate_hctx(struct scx_io_policy *policy,
						   struct request_queue *q,
						   unsigned int hctx_idx);
static struct request *scx_io_policy_evacuate_any_hctx(struct scx_io_policy *policy,
						      struct request_queue *q);

static struct bpf_map *scx_io_policy_get_map(struct bpf_link *link)
{
	struct scx_io_struct_ops_link *st_link;
	struct bpf_map *map;

	if (!link)
		return NULL;

	st_link = container_of(link, struct scx_io_struct_ops_link, link);
	rcu_read_lock();
	map = rcu_dereference(st_link->map);
	if (map)
		bpf_map_inc(map);
	rcu_read_unlock();

	return map;
}

static struct scx_io_policy *scx_io_policy_alloc(struct cgroup_subsys_state *css,
					 struct iosched_ext_ops *ops,
					 struct bpf_link *link)
{
	struct scx_io_policy *policy;

	policy = kzalloc(sizeof(*policy), GFP_KERNEL);
	if (!policy)
		return NULL;

	policy->css = css;
	policy->ops = ops;
	policy->link = link;
	policy->teardown_map = NULL;
	INIT_DELAYED_WORK(&policy->teardown_work, scx_io_policy_teardown_workfn);
	spin_lock_init(&policy->lock);
	INIT_LIST_HEAD(&policy->blkg_refs);
	policy->cgroup_id = cgroup_id(css->cgroup);
	policy->bypass_mode = ops ? READ_ONCE(ops->bypass_mode) :
		IOSCHED_BYPASS_MODE_NONE;
	atomic_set(&policy->managed_inflight, 0);
	atomic_set(&policy->teardown_queued, 0);
	policy->state = SCX_IO_POLICY_ACTIVE;
	policy->retire_reason = SCX_IO_RETIRE_DETACH;
	policy->stall_rounds = 0;

	return policy;
}

static noinline void scx_io_policy_free(struct scx_io_policy *policy)
{
	struct scx_io_policy_blkg_ref *ref, *tmp;

	if (!policy)
		return;

	list_for_each_entry_safe(ref, tmp, &policy->blkg_refs, node) {
		list_del(&ref->node);
		blkg_put(ref->blkg);
		kfree(ref);
	}

	if (policy->teardown_map)
		bpf_map_put(policy->teardown_map);

	css_put(policy->css);
	kfree(policy);
}

static inline struct scx_io_policy *scx_io_policy_read_rcu(struct blkcg *blkcg)
{
	return rcu_dereference(blkcg->iosched_policy);
}

static inline struct scx_io_policy *scx_io_policy_read_locked(struct blkcg *blkcg)
{
	return rcu_dereference_protected(blkcg->iosched_policy,
					lockdep_is_held(&blkcg->iosched_sem));
}

static inline bool scx_io_policy_is_active(struct scx_io_policy *policy)
{
	return policy && READ_ONCE(policy->state) == SCX_IO_POLICY_ACTIVE;
}

static inline struct scx_io_blkg_data *pd_to_scx_io(struct blkg_policy_data *pd)
{
	return pd ? container_of(pd, struct scx_io_blkg_data, pd) : NULL;
}

static struct scx_io_blkg_data *scx_io_pd_from_blkg(struct blkcg_gq *blkg)
{
	return pd_to_scx_io(blkg_to_pd(blkg, &scx_io_blkcg_policy));
}

static const char *scx_io_policy_name(struct scx_io_policy *policy)
{
	if (!policy || !policy->ops || policy->ops->name[0] == '\0')
		return "unnamed";

	return policy->ops->name;
}

static bool scx_io_queue_is_scx(struct request_queue *q)
{
	return q && q->elevator && q->elevator->type == &scx_io_elevator;
}

#if IOEXT_DEBUG
static bool scx_io_debug_should_log(u64 seq)
{
	return seq <= 16 || is_power_of_2(seq);
}

static struct scx_io_data *scx_io_debug_data(struct request_queue *q)
{
	if (!scx_io_queue_is_scx(q) || !q->elevator->elevator_data)
		return NULL;

	return q->elevator->elevator_data;
}

static const char *scx_io_bio_bypass_debug_reason_name(
	enum scx_io_bio_bypass_debug_reason reason)
{
	switch (reason) {
	case SCX_IO_BIO_BYPASS_NULL:
		return "null-input";
	case SCX_IO_BIO_BYPASS_NON_RW:
		return "non-read-write";
	case SCX_IO_BIO_BYPASS_ROOT_BLKG:
		return "root-blkg";
	case SCX_IO_BIO_BYPASS_ZONE_PLUG:
		return "zone-plug";
	case SCX_IO_BIO_BYPASS_NOT_SCX:
		return "not-scx-queue";
	case SCX_IO_BIO_BYPASS_NO_PD:
		return "no-scx-pd";
	case SCX_IO_BIO_BYPASS_REFRESH_ENABLED:
		return "refresh-enabled";
	case SCX_IO_BIO_BYPASS_REFRESH_DISABLED:
		return "refresh-disabled";
	case SCX_IO_BIO_BYPASS_CACHE_ENABLED:
		return "cache-enabled";
	case SCX_IO_BIO_BYPASS_CACHE_DISABLED:
		return "cache-disabled";
	case SCX_IO_BIO_BYPASS_NR_REASONS:
		break;
	}

	return "unknown";
}

static bool scx_io_debug_bio_bypass_return(struct request_queue *q,
					   struct bio *bio,
					   struct scx_io_blkg_data *scx_pd,
					   enum scx_io_bio_bypass_debug_reason reason,
					   bool decision,
					   u64 global_epoch)
{
	struct scx_io_data *data = scx_io_debug_data(q);
	u64 cached_epoch = scx_pd ? smp_load_acquire(&scx_pd->bypass_epoch) : 0;
	u64 bio_cgid = bio && bio->bi_blkg ?
		cgroup_id(bio->bi_blkg->blkcg->css.cgroup) : 0;
	bool root_blkg = bio ? bio_issue_as_root_blkg(bio) : false;
	bool zone_plug = bio ? bio_needs_zone_write_plugging(bio) : false;
	unsigned int op = bio ? (__force unsigned int)bio_op(bio) : ~0U;
	u64 seq;

	if (!data)
		return decision;

	seq = atomic64_inc_return(&data->debug_bio_bypass_reasons[reason]);
	if (scx_io_debug_should_log(seq))
		ioext_dbg_pr_info(
			"dbg bio_bypass seq=%llu reason=%s decision=%d comm=%s op=%u opf=%#llx cgroup_id=%llu root_blkg=%d zone_plug=%d scx_pd=%p cached_epoch=%llu global_epoch=%llu cached_enabled=%d q=%p\n",
			seq,
			scx_io_bio_bypass_debug_reason_name(reason),
			decision,
			current->comm,
			op,
			bio ? (u64)bio->bi_opf : 0,
			bio_cgid,
			root_blkg,
			zone_plug,
			scx_pd,
			cached_epoch,
			global_epoch,
			scx_pd ? READ_ONCE(scx_pd->bypass_enabled) : 0,
			q);

	return decision;
}
#else
static bool scx_io_debug_bio_bypass_return(struct request_queue *q,
					   struct bio *bio,
					   struct scx_io_blkg_data *scx_pd,
					   enum scx_io_bio_bypass_debug_reason reason,
					   bool decision,
					   u64 global_epoch)
{
	(void)q;
	(void)bio;
	(void)scx_pd;
	(void)reason;
	(void)global_epoch;
	return decision;
}
#endif

static struct blkg_policy_data *scx_io_pd_alloc(struct gendisk *disk,
						 struct blkcg *blkcg,
						 gfp_t gfp)
{
	struct scx_io_blkg_data *scx_pd;

	(void)blkcg;

	scx_pd = kzalloc_node(sizeof(*scx_pd), gfp, disk->queue->node);
	if (!scx_pd)
		return NULL;

	return &scx_pd->pd;
}

static void scx_io_pd_init(struct blkg_policy_data *pd)
{
	struct scx_io_blkg_data *scx_pd = pd_to_scx_io(pd);

	INIT_LIST_HEAD(&scx_pd->active_node);
	scx_pd->on_active_list = false;
	scx_pd->bypass_enabled = false;
	scx_pd->bypass_epoch = 0;
	atomic_set(&scx_pd->bpf_in_flight, 0);
}

static void scx_io_offline_unlink_blkg(struct blkcg_gq *blkg)
{
	struct scx_io_blkg_data *scx_pd;
	struct request_queue *q;
	struct scx_io_data *data;
	unsigned long irq_flags;
	int inflight;

	if (!blkg)
		return;

	scx_pd = scx_io_pd_from_blkg(blkg);
	if (!scx_pd)
		return;

	q = blkg->q;
	if (!q || !q->elevator || q->elevator->type != &scx_io_elevator ||
	    !q->elevator->elevator_data)
		return;

	data = q->elevator->elevator_data;
	spin_lock_irqsave(&data->lock, irq_flags);
	inflight = atomic_xchg(&scx_pd->bpf_in_flight, 0);
	if (inflight > 0) {
		int total = atomic_read(&data->bpf_in_flight);

		if (total > inflight)
			atomic_sub(inflight, &data->bpf_in_flight);
		else
			atomic_set(&data->bpf_in_flight, 0);
	}

	if (scx_pd->on_active_list) {
		list_del_init(&scx_pd->active_node);
		scx_pd->on_active_list = false;
		blkg_put(blkg);
	}
	spin_unlock_irqrestore(&data->lock, irq_flags);
}

static void scx_io_detach_active_pds(struct scx_io_data *data)
{
	struct scx_io_blkg_data *scx_pd, *tmp;
	unsigned long irq_flags;

	if (!data)
		return;

	spin_lock_irqsave(&data->lock, irq_flags);
	list_for_each_entry_safe(scx_pd, tmp, &data->active_pds, active_node) {
		struct blkcg_gq *blkg = pd_to_blkg(&scx_pd->pd);

		atomic_set(&scx_pd->bpf_in_flight, 0);
		list_del_init(&scx_pd->active_node);
		scx_pd->on_active_list = false;
		if (blkg)
			blkg_put(blkg);
	}
	atomic_set(&data->bpf_in_flight, 0);
	spin_unlock_irqrestore(&data->lock, irq_flags);
}

static void scx_io_pd_offline(struct blkg_policy_data *pd)
{
	struct blkcg_gq *blkg = pd_to_blkg(pd);
	struct blkcg *blkcg;
	struct scx_io_policy *policy;
	bool schedule_teardown = false;
	int ret = 0;
	struct scx_io_blkg_data *scx_pd = pd_to_scx_io(pd);

	if (!blkg)
		return;

	if (scx_pd)
		scx_io_set_blkg_bypass(scx_pd, false,
				      atomic64_read(&scx_io_bypass_epoch));

	scx_io_offline_unlink_blkg(blkg);

	blkcg = blkg->blkcg;
	rcu_read_lock();
	policy = scx_io_policy_read_rcu(blkcg);
	if (policy && !atomic_read(&policy->teardown_queued)) {
		ret = scx_io_policy_prepare_teardown(policy, NULL,
					   SCX_IO_RETIRE_OFFLINE,
					   blkg);
		if (!ret)
			schedule_teardown = true;
	}
	rcu_read_unlock();

	if (schedule_teardown)
		scx_io_policy_schedule_teardown(policy);
	else if (ret)
		ioext_dbg_pr_warn_ratelimited(
			"failed to retire offline policy for cgroup_id=%llu err=%d\n",
			cgroup_id(blkcg->css.cgroup),
			ret);
}

static void scx_io_pd_free(struct blkg_policy_data *pd)
{
	struct scx_io_blkg_data *scx_pd = pd_to_scx_io(pd);

	if (WARN_ON_ONCE(scx_pd->on_active_list))
		scx_pd->on_active_list = false;
	scx_pd->bypass_enabled = false;
	scx_pd->bypass_epoch = 0;

	kfree(scx_pd);
}

static struct blkcg_policy scx_io_blkcg_policy = {
	.pd_alloc_fn = scx_io_pd_alloc,
	.pd_init_fn = scx_io_pd_init,
	.pd_offline_fn = scx_io_pd_offline,
	.pd_free_fn = scx_io_pd_free,
};

static struct blkcg *scx_io_parent_blkcg(struct blkcg *blkcg)
{
	if (!blkcg || !blkcg->css.parent)
		return NULL;

	return css_to_blkcg(blkcg->css.parent);
}

static struct blkcg_gq *scx_io_lookup_blkg_get(struct blkcg *blkcg,
						struct request_queue *q)
{
	struct blkcg_gq *blkg;

	rcu_read_lock();
	blkg = blkg_lookup(blkcg, q);
	if (!blkg || !blkg_tryget(blkg))
		blkg = NULL;
	rcu_read_unlock();
	return blkg;
}

static struct scx_io_policy *scx_io_find_policy_owner_rcu(struct blkcg *start,
					       struct blkcg **owner_out)
{
	struct blkcg *blkcg = start;

	while (blkcg) {
		struct scx_io_policy *policy = scx_io_policy_read_rcu(blkcg);

		if (scx_io_policy_is_active(policy)) {
			*owner_out = blkcg;
			return policy;
		}
		blkcg = scx_io_parent_blkcg(blkcg);
	}

	*owner_out = NULL;
	return NULL;
}

static struct blkcg *scx_io_bio_blkcg(struct bio *bio)
{
	struct cgroup_subsys_state *css;

	if (!bio)
		return NULL;

	css = bio_blkcg_css(bio);
	return css ? css_to_blkcg(css) : NULL;
}

static struct blkcg *scx_io_rq_blkcg(struct request *rq)
{
	if (!rq || !rq->bio)
		return NULL;

	return scx_io_bio_blkcg(rq->bio);
}

static struct blkcg *scx_io_current_blkcg(void)
{
	struct cgroup_subsys_state *css;
	struct cgroup *cgrp;

	cgrp = task_dfl_cgroup(current);
	css = cgrp ? cgroup_e_css(cgrp, &io_cgrp_subsys) : NULL;
	return css ? css_to_blkcg(css) : &blkcg_root;
}

static struct scx_io_policy *scx_io_find_policy_for_rq_bio_rcu(struct request *rq,
						      struct bio *bio,
						      struct blkcg **owner_out)
{
	struct blkcg *start = scx_io_bio_blkcg(bio);

	if (!start)
		start = scx_io_rq_blkcg(rq);
	if (!start)
		start = &blkcg_root;

	return scx_io_find_policy_owner_rcu(start, owner_out);
}

static struct scx_io_policy *scx_io_find_policy_for_current_rcu(struct blkcg **owner_out)
{
	return scx_io_find_policy_owner_rcu(scx_io_current_blkcg(), owner_out);
}

static struct scx_io_policy *scx_io_find_root_policy_rcu(struct blkcg **owner_out)
{
	return scx_io_find_policy_owner_rcu(&blkcg_root, owner_out);
}

static struct cgroup_subsys_state *scx_io_blkcg_css_from_cgid(u64 cgroup_id)
{
	struct cgroup *cgrp;
	struct cgroup_subsys_state *css;

	cgrp = cgroup_get_from_id(cgroup_id);
	if (IS_ERR(cgrp))
		return NULL;

	css = cgroup_get_e_css(cgrp, &io_cgrp_subsys);
	cgroup_put(cgrp);
	return css;
}

static bool scx_io_valid_rq_ptr(u64 rq_ptr)
{
	return rq_ptr && virt_addr_valid((void *)(unsigned long)rq_ptr);
}

static struct request *scx_io_validate_dispatch_rq(struct blk_mq_hw_ctx *hctx,
					   u64 rq_ptr)
{
	struct request *rq;

	if (!hctx || !hctx->queue)
		return NULL;

	if (!scx_io_valid_rq_ptr(rq_ptr)) {
#if IOEXT_DEBUG
		{
			struct scx_io_data *data = scx_io_debug_data(hctx->queue);
			u64 seq;

			if (data) {
				seq = atomic64_inc_return(&data->debug_validate_failures);
				if (scx_io_debug_should_log(seq))
					ioext_dbg_pr_info(
						"dbg validate_dispatch_fail seq=%llu reason=ptr_low rq_ptr=%#llx hctx=%u q=%p dispatch_returns=%llu bpf_in_flight=%d\n",
						seq,
						rq_ptr,
						hctx->queue_num,
						hctx->queue,
						atomic64_read(&data->debug_dispatch_returns),
						atomic_read(&data->bpf_in_flight));
			}
		}
#endif
		return NULL;
	}

	rq = (struct request *)(unsigned long)rq_ptr;
	if (rq->q != hctx->queue) {
#if IOEXT_DEBUG
		{
			struct scx_io_data *data = scx_io_debug_data(hctx->queue);
			u64 seq;

			if (data) {
				seq = atomic64_inc_return(&data->debug_validate_failures);
				if (scx_io_debug_should_log(seq))
					ioext_dbg_pr_info(
						"dbg validate_dispatch_fail seq=%llu reason=q_mismatch rq_ptr=%#llx rq=%p rq_q=%p hctx_q=%p rq_hctx=%p hctx=%p hctx_idx=%u rq_flags=%#x cmd_flags=%#x dispatch_returns=%llu bpf_in_flight=%d\n",
						seq,
						rq_ptr,
						rq,
						rq->q,
						hctx->queue,
						rq->mq_hctx,
						hctx,
						hctx->queue_num,
						rq->rq_flags,
						rq->cmd_flags,
						atomic64_read(&data->debug_dispatch_returns),
						atomic_read(&data->bpf_in_flight));
			}
		}
#endif
		return NULL;
	}
	if (!rq->mq_hctx) {
#if IOEXT_DEBUG
		{
			struct scx_io_data *data = scx_io_debug_data(hctx->queue);
			u64 seq;

			if (data) {
				seq = atomic64_inc_return(&data->debug_validate_failures);
				if (scx_io_debug_should_log(seq))
					ioext_dbg_pr_info(
						"dbg validate_dispatch_fail seq=%llu reason=null_mq_hctx rq_ptr=%#llx rq=%p rq_q=%p hctx_q=%p hctx=%p hctx_idx=%u rq_flags=%#x cmd_flags=%#x dispatch_returns=%llu bpf_in_flight=%d\n",
						seq,
						rq_ptr,
						rq,
						rq->q,
						hctx->queue,
						hctx,
						hctx->queue_num,
						rq->rq_flags,
						rq->cmd_flags,
						atomic64_read(&data->debug_dispatch_returns),
						atomic_read(&data->bpf_in_flight));
			}
		}
#endif
		return NULL;
	}
	if (rq->mq_hctx->queue != hctx->queue) {
#if IOEXT_DEBUG
		{
			struct scx_io_data *data = scx_io_debug_data(hctx->queue);
			u64 seq;

			if (data) {
				seq = atomic64_inc_return(&data->debug_validate_failures);
				if (scx_io_debug_should_log(seq))
					ioext_dbg_pr_info(
						"dbg validate_dispatch_fail seq=%llu reason=hctx_queue_mismatch rq_ptr=%#llx rq=%p rq_q=%p rq_hctx=%p rq_hctx_q=%p hctx=%p hctx_q=%p hctx_idx=%u rq_flags=%#x cmd_flags=%#x dispatch_returns=%llu bpf_in_flight=%d\n",
						seq,
						rq_ptr,
						rq,
						rq->q,
						rq->mq_hctx,
						rq->mq_hctx->queue,
						hctx,
						hctx->queue,
						hctx->queue_num,
						rq->rq_flags,
						rq->cmd_flags,
						atomic64_read(&data->debug_dispatch_returns),
						atomic_read(&data->bpf_in_flight));
			}
		}
#endif
		return NULL;
	}

	return rq;
}

static struct request *scx_io_validate_basic_rq(u64 rq_ptr)
{
	struct request *rq;

	if (!scx_io_valid_rq_ptr(rq_ptr))
		return NULL;

	rq = (struct request *)(unsigned long)rq_ptr;
	if (!rq->q || !rq->mq_hctx)
		return NULL;
	if (rq->mq_hctx->queue != rq->q)
		return NULL;

	return rq;
}

static struct request *scx_io_validate_queue_rq(struct request_queue *q, u64 rq_ptr)
{
	struct request *rq;

	if (!q || !scx_io_valid_rq_ptr(rq_ptr))
		return NULL;

	rq = (struct request *)(unsigned long)rq_ptr;
	if (rq->q != q)
		return NULL;
	if (rq->mq_hctx && rq->mq_hctx->queue != q)
		return NULL;

	return rq;
}

static struct request *scx_io_validate_evacuated_rq(struct request_queue *q,
						   u64 rq_ptr)
{
	struct request *rq;

	if (!q)
		return scx_io_validate_basic_rq(rq_ptr);

	rq = scx_io_validate_queue_rq(q, rq_ptr);

	if (!rq || !rq->mq_hctx || rq->mq_hctx->queue != q)
		return NULL;

	return rq;
}

static void scx_io_blkg_note_bpf_insert(struct scx_io_data *data,
				       struct blkcg_gq *blkg)
{
	struct scx_io_blkg_data *scx_pd;

	if (!blkg)
		return;

	scx_pd = scx_io_pd_from_blkg(blkg);
	if (!scx_pd)
		return;

	if (!scx_pd->on_active_list) {
		blkg_get(blkg);
		list_add_tail(&scx_pd->active_node, &data->active_pds);
		scx_pd->on_active_list = true;
	}

	atomic_inc(&scx_pd->bpf_in_flight);
}

static bool scx_io_blkg_note_bpf_complete(struct scx_io_data *data,
					  struct blkcg_gq *blkg)
{
	struct scx_io_blkg_data *scx_pd;
	bool completed = false;
	int ret;

	if (!blkg)
		return false;

	scx_pd = scx_io_pd_from_blkg(blkg);
	if (!scx_pd)
		return false;

	ret = atomic_dec_if_positive(&scx_pd->bpf_in_flight);
	if (ret < 0)
		goto maybe_remove;

	completed = true;
	if (ret > 0)
		return true;

maybe_remove:
	if (scx_pd->on_active_list) {
		list_del_init(&scx_pd->active_node);
		scx_pd->on_active_list = false;
		blkg_put(blkg);
	}

	return completed;
}

static void scx_io_note_bpf_dispatch(struct scx_io_data *data,
					 struct blkcg_gq *blkg)
{
	if (scx_io_blkg_note_bpf_complete(data, blkg))
		atomic_dec_if_positive(&data->bpf_in_flight);
}

static noinline void scx_io_policy_note_dispatch(struct scx_io_policy *policy)
{
	if (policy)
		atomic_dec_if_positive(&policy->managed_inflight);
}

static struct blkcg_gq *scx_io_policy_find_blkg(struct scx_io_policy *policy,
					 struct request_queue *q)
{
	struct scx_io_policy_blkg_ref *ref;
	struct blkcg_gq *blkg = NULL;
	unsigned long irq_flags;

	spin_lock_irqsave(&policy->lock, irq_flags);
	list_for_each_entry(ref, &policy->blkg_refs, node) {
		if (ref->blkg->q != q)
			continue;
		blkg = ref->blkg;
		blkg_get(blkg);
		break;
	}
	spin_unlock_irqrestore(&policy->lock, irq_flags);

	return blkg;
}

static int scx_io_policy_capture_blkgs(struct scx_io_policy *policy)
{
	struct blkcg *blkcg = css_to_blkcg(policy->css);
	struct blkcg_gq *blkg;
	unsigned long flags;
	unsigned long policy_flags;
	int ret = 0;

	spin_lock_irqsave(&blkcg->lock, flags);
	hlist_for_each_entry(blkg, &blkcg->blkg_list, blkcg_node) {
		struct scx_io_policy_blkg_ref *ref;

		ref = kzalloc(sizeof(*ref), GFP_ATOMIC);
		if (!ref) {
			ret = -ENOMEM;
			break;
		}

		blkg_get(blkg);
		ref->blkg = blkg;

		spin_lock_irqsave(&policy->lock, policy_flags);
		list_add_tail(&ref->node, &policy->blkg_refs);
		spin_unlock_irqrestore(&policy->lock, policy_flags);
	}
	spin_unlock_irqrestore(&blkcg->lock, flags);

	return ret;
}

static void scx_io_note_quiesced_dispatch(struct scx_io_policy *policy,
					  struct request *rq)
{
	struct blkcg_gq *blkg;
	struct scx_io_data *data;
	unsigned long irq_flags;

	if (!policy || !rq || !rq->q || !rq->q->elevator ||
	    !rq->q->elevator->elevator_data)
		return;

	blkg = scx_io_policy_find_blkg(policy, rq->q);
	if (!blkg)
		blkg = scx_io_lookup_blkg_get(css_to_blkcg(policy->css), rq->q);
	if (!blkg)
		return;

	data = rq->q->elevator->elevator_data;
	spin_lock_irqsave(&data->lock, irq_flags);
	scx_io_note_bpf_dispatch(data, blkg);
	spin_unlock_irqrestore(&data->lock, irq_flags);

	blkg_put(blkg);
}

static const char *scx_io_retire_reason_name(enum scx_io_policy_retire_reason reason)
{
	switch (reason) {
	case SCX_IO_RETIRE_DETACH:
		return "detach";
	case SCX_IO_RETIRE_REPLACE:
		return "replace";
	case SCX_IO_RETIRE_OFFLINE:
		return "offline";
	}

	return "unknown";
}

static noinline void scx_io_policy_teardown_workfn(struct work_struct *work)
{
	struct scx_io_policy *policy = container_of(to_delayed_work(work),
					    struct scx_io_policy,
					    teardown_work);
	struct blkcg *blkcg = css_to_blkcg(policy->css);
	struct iosched_ext_ops *ops = policy->ops;
	unsigned int drained = 0;

	if (policy->retire_reason == SCX_IO_RETIRE_OFFLINE) {
		down_write(&blkcg->iosched_sem);
		if (scx_io_policy_read_locked(blkcg) == policy)
			RCU_INIT_POINTER(blkcg->iosched_policy, NULL);
		up_write(&blkcg->iosched_sem);
	}

	synchronize_rcu();

#if IOEXT_DEBUG
	if (!policy->stall_rounds || scx_io_debug_should_log(policy->stall_rounds))
		ioext_dbg_pr_info(
			"dbg teardown_enter policy='%s' cgroup_id=%llu reason=%s managed_inflight=%d stall_rounds=%u refs_empty=%d\n",
			scx_io_policy_name(policy),
			policy->cgroup_id,
			scx_io_retire_reason_name(policy->retire_reason),
			atomic_read(&policy->managed_inflight),
			policy->stall_rounds,
			list_empty(&policy->blkg_refs));
#endif

	while (atomic_read(&policy->managed_inflight) > 0) {
		struct scx_io_policy_blkg_ref *ref;
		struct request *rq = NULL;
		bool tried = false;
		unsigned int i;

		if (!ops || !ops->evacuate)
			break;

		list_for_each_entry(ref, &policy->blkg_refs, node) {
			struct request_queue *q = ref->blkg->q;

			tried = true;
			rq = scx_io_policy_evacuate_any_hctx(policy, q);
			if (rq)
				break;
		}

		if (!tried || !rq) {
			for (i = 0; i < SCX_IO_MAX_EVAC_HCTX; i++) {
				tried = true;
				rq = scx_io_policy_evacuate_hctx(policy, NULL, i);
				if (rq)
					break;
			}
		}

		if (!rq) {
			policy->stall_rounds++;
			if (policy->stall_rounds >= SCX_IO_MAX_EVAC_STALL_ROUNDS) {
				ioext_dbg_pr_warn_ratelimited(
					"evacuate stall limit reached policy='%s' cgroup_id=%llu reason=%s managed_inflight=%d rounds=%u, forcing teardown\n",
					scx_io_policy_name(policy),
					policy->cgroup_id,
					scx_io_retire_reason_name(policy->retire_reason),
					atomic_read(&policy->managed_inflight),
					policy->stall_rounds);
				break;
			}
			ioext_dbg_pr_warn_ratelimited(
				"evacuate stalled policy='%s' cgroup_id=%llu reason=%s managed_inflight=%d round=%u\n",
				scx_io_policy_name(policy),
				policy->cgroup_id,
				scx_io_retire_reason_name(policy->retire_reason),
				atomic_read(&policy->managed_inflight),
				policy->stall_rounds);
			queue_delayed_work(scx_io_teardown_wq,
					   &policy->teardown_work,
					   msecs_to_jiffies(20));
			return;
		}

		policy->stall_rounds = 0;
		if (scx_io_queue_is_scx(rq->q) && rq->q->elevator->elevator_data) {
			scx_io_bypass_request(rq->q->elevator->elevator_data,
					     rq->mq_hctx,
					     rq,
					     0,
					     SCX_IO_BYPASS_QUIESCED,
					     policy->cgroup_id,
					     policy->cgroup_id);
			blk_mq_run_hw_queue(rq->mq_hctx, false);
		} else {
			scx_io_requeue_without_fallback(rq,
					       rq->mq_hctx->queue_num,
					       SCX_IO_BYPASS_QUIESCED,
					       policy->cgroup_id,
					       (u64)rq->cmd_flags);
		}
		drained++;
		if (!(drained % 64))
			cond_resched();
	}

	ioext_dbg_pr_info(
		"teardown complete policy='%s' cgroup_id=%llu reason=%s drained=%u\n",
		ops->name[0] != '\0' ? ops->name : "unnamed",
		policy->cgroup_id,
		scx_io_retire_reason_name(policy->retire_reason),
		drained);
	scx_io_policy_free(policy);
}

static noinline int scx_io_policy_prepare_teardown(struct scx_io_policy *policy,
					 struct bpf_link *link,
					 enum scx_io_policy_retire_reason reason,
					 struct blkcg_gq *offline_blkg)
{
	int ret;
	unsigned long irq_flags;

	if (atomic_xchg(&policy->teardown_queued, 1))
		return 0;

	policy->teardown_map = scx_io_policy_get_map(link ? link : policy->link);
	if (!policy->teardown_map) {
		atomic_set(&policy->teardown_queued, 0);
		return -ENOENT;
	}

	policy->state = SCX_IO_POLICY_QUIESCING;
	policy->retire_reason = reason;
	policy->stall_rounds = 0;
	scx_io_bump_bypass_epoch();

	if (reason == SCX_IO_RETIRE_OFFLINE && offline_blkg) {
		struct scx_io_policy_blkg_ref *ref;

		ref = kzalloc(sizeof(*ref), GFP_ATOMIC);
		if (ref) {
			blkg_get(offline_blkg);
			ref->blkg = offline_blkg;
			spin_lock_irqsave(&policy->lock, irq_flags);
			list_add_tail(&ref->node, &policy->blkg_refs);
			spin_unlock_irqrestore(&policy->lock, irq_flags);
		}
	}

	ret = scx_io_policy_capture_blkgs(policy);
	if (ret)
		ioext_dbg_pr_warn_ratelimited(
			"continuing teardown without captured blkg refs policy='%s' cgroup_id=%llu reason=%s err=%d\n",
			policy->ops->name[0] != '\0' ? policy->ops->name : "unnamed",
			policy->cgroup_id,
			scx_io_retire_reason_name(reason),
			ret);

	return 0;
}

static noinline void scx_io_policy_schedule_teardown(struct scx_io_policy *policy)
{
	queue_delayed_work(scx_io_teardown_wq, &policy->teardown_work, 0);
}

static void scx_io_bump_bypass_epoch(void)
{
	atomic64_inc(&scx_io_bypass_epoch);
}

static bool scx_io_policy_prefers_bypass(struct scx_io_policy *policy)
{
	return scx_io_policy_is_active(policy) &&
		policy->bypass_mode == IOSCHED_BYPASS_MODE_DIRECT;
}

static void scx_io_set_blkg_bypass(struct scx_io_blkg_data *scx_pd,
				       bool enabled,
				       u64 epoch)
{
	WRITE_ONCE(scx_pd->bypass_enabled, enabled);
	smp_store_release(&scx_pd->bypass_epoch, epoch);
}

static bool scx_io_refresh_blkg_bypass(struct blkcg_gq *blkg)
{
	struct scx_io_blkg_data *scx_pd;
	struct blkcg *owner = NULL;
	struct blkcg_gq *owner_blkg = NULL;
	struct scx_io_policy *policy;
	u64 epoch;
	bool enabled = false;

	if (!blkg || !blkg->q)
		return false;

	scx_pd = scx_io_pd_from_blkg(blkg);
	if (!scx_pd)
		return false;

	epoch = atomic64_read(&scx_io_bypass_epoch);
	rcu_read_lock();
	policy = scx_io_find_policy_owner_rcu(blkg->blkcg, &owner);
	if (!owner || !policy || !policy->ops ||
	    !scx_io_policy_is_active(policy)) {
		/* No usable active policy: degrade scx_io to the native none path. */
		enabled = true;
		goto out;
	}

	if (!scx_io_policy_prefers_bypass(policy))
		goto out;

	owner_blkg = scx_io_lookup_blkg_get(owner, blkg->q);
	if (!owner_blkg)
		goto out;

	enabled = scx_io_pd_from_blkg(owner_blkg)->pd.online;
	if (enabled)
		ioext_dbg_pr_info(
			"policy bypass cache enabled policy='%s' owner_cgroup_id=%llu target_cgroup_id=%llu q=%p\n",
			policy->ops->name[0] != '\0' ? policy->ops->name : "unnamed",
			policy->cgroup_id,
			cgroup_id(blkg->blkcg->css.cgroup),
			blkg->q);
out:
	rcu_read_unlock();
	if (owner_blkg)
		blkg_put(owner_blkg);

	scx_io_set_blkg_bypass(scx_pd, enabled, epoch);
	return enabled;
}

static struct scx_io_blkg_data *scx_io_pick_active_pd_locked(struct scx_io_data *data)
{
	struct scx_io_blkg_data *scx_pd;

	list_for_each_entry(scx_pd, &data->active_pds, active_node) {
		struct blkcg_gq *blkg = pd_to_blkg(&scx_pd->pd);

		if (blkg && blkg_tryget(blkg))
			return scx_pd;
	}

	return NULL;
}

static const char *scx_io_bypass_reason_name(enum scx_io_bypass_reason reason)
{
	switch (reason) {
	case SCX_IO_BYPASS_NO_POLICY:
		return "no-policy";
	case SCX_IO_BYPASS_POLICY_UNAVAILABLE:
		return "policy-unavailable";
	case SCX_IO_BYPASS_POLICY_REJECTED:
		return "policy-rejected";
	case SCX_IO_BYPASS_QUIESCED:
		return "quiesced";
	}

	return "unknown";
}

static struct blk_mq_hw_ctx *scx_io_fallback_hctx(struct scx_io_data *data,
						  struct blk_mq_hw_ctx *hctx,
						  struct request *rq)
{
	struct request_queue *q = data ? data->q : NULL;

	if (rq && rq->mq_hctx && (!q || rq->mq_hctx->queue == q))
		return rq->mq_hctx;
	if (hctx && (!q || hctx->queue == q))
		return hctx;
	return NULL;
}

static void blk_mq_request_bypass_insert(struct request *rq, blk_insert_t flags)
{
	struct blk_mq_hw_ctx *hctx = rq->mq_hctx;

	spin_lock(&hctx->lock);
	if (flags & BLK_MQ_INSERT_AT_HEAD)
		list_add(&rq->queuelist, &hctx->dispatch);
	else
		list_add_tail(&rq->queuelist, &hctx->dispatch);
	spin_unlock(&hctx->lock);
}

static void scx_io_requeue_without_fallback(struct request *rq,
					       unsigned int hctx_idx,
					       enum scx_io_bypass_reason reason,
					       u64 cgroup_id,
					       u64 opf)
{
	if (!rq)
		return;

	ioext_dbg_pr_warn_ratelimited(
		"fallback bypass requeue without hctx fallback reason=%s hctx=%u cgroup_id=%llu opf=%#llx\n",
		scx_io_bypass_reason_name(reason), hctx_idx, cgroup_id, opf);
	list_del_init(&rq->queuelist);
	rq->rq_flags &= ~RQF_USE_SCHED;
	blk_mq_request_bypass_insert(rq, BLK_MQ_INSERT_AT_HEAD);
	blk_mq_run_hw_queue(rq->mq_hctx, true);
}

__attribute__((noipa))
static noinline void scx_io_bypass_request(struct scx_io_data *data,
				  struct blk_mq_hw_ctx *hctx,
				  struct request *rq,
				  blk_insert_t flags,
				  enum scx_io_bypass_reason reason,
				  u64 original_cgroup_id,
				  u64 effective_cgroup_id)
{
	struct blk_mq_hw_ctx *fallback_hctx;
	struct scx_io_hctx_data *hdata;
	unsigned int hctx_idx = hctx ? hctx->queue_num : 0;
	u64 opf = rq ? (u64)rq->cmd_flags : 0;
	u64 total;
#if IOEXT_DEBUG
	int fallback_before = -1;
	int fallback_after = -1;
	bool queued_fallback = false;
#endif

	fallback_hctx = scx_io_fallback_hctx(data, hctx, rq);
	if (fallback_hctx)
		hctx_idx = fallback_hctx->queue_num;
	hdata = fallback_hctx ? fallback_hctx->sched_data : NULL;
	if (!hdata) {
		scx_io_requeue_without_fallback(rq, hctx_idx, reason,
					       effective_cgroup_id, opf);
		goto note_bypass;
	}

#if IOEXT_DEBUG
	fallback_before = atomic_read(&hdata->fallback_in_flight);
#endif
	spin_lock(&hdata->fallback_lock);
	rq->rq_flags &= ~RQF_USE_SCHED;
	if (flags & BLK_MQ_INSERT_AT_HEAD)
		list_move(&rq->queuelist, &hdata->fallback_list);
	else
		list_move_tail(&rq->queuelist, &hdata->fallback_list);
	atomic_inc(&hdata->fallback_in_flight);
#if IOEXT_DEBUG
	fallback_after = atomic_read(&hdata->fallback_in_flight);
	queued_fallback = true;
#endif
	spin_unlock(&hdata->fallback_lock);
	blk_mq_run_hw_queue(fallback_hctx, true);

note_bypass:
	total = atomic64_inc_return(&data->bypassed_total);

	switch (reason) {
	case SCX_IO_BYPASS_NO_POLICY:
		atomic64_inc(&data->bypassed_no_policy);
		break;
	case SCX_IO_BYPASS_POLICY_UNAVAILABLE:
		atomic64_inc(&data->bypassed_policy_unavailable);
		break;
	case SCX_IO_BYPASS_POLICY_REJECTED:
		atomic64_inc(&data->bypassed_policy_rejected);
		break;
	case SCX_IO_BYPASS_QUIESCED:
		atomic64_inc(&data->bypassed_quiesced);
		break;
	}

	if (is_power_of_2(total) || atomic_read(&data->bpf_in_flight) > 0) {
		ioext_dbg_pr_warn_ratelimited(
			"fallback bypass total=%llu reason=%s hctx=%u original_cgroup_id=%llu effective_cgroup_id=%llu opf=%#llx managed_inflight=%d\n",
			total,
			scx_io_bypass_reason_name(reason),
			hctx_idx,
			original_cgroup_id,
			effective_cgroup_id,
			opf,
			atomic_read(&data->bpf_in_flight));
	}
#if IOEXT_DEBUG
	if (queued_fallback) {
		u64 seq = atomic64_inc_return(&data->debug_fallback_enqueues);

		if (IOEXT_DEBUG_VERBOSE && scx_io_debug_should_log(seq))
			ioext_dbg_pr_info(
				"dbg fallback_enqueue seq=%llu rq=%p hctx=%u reason=%s flags=%u opf=%#llx sector=%llu fallback_before=%d fallback_after=%d run_hw_queue=1 original_cgroup_id=%llu effective_cgroup_id=%llu bpf_in_flight=%d switch_draining=%d\n",
				seq,
				rq,
				hctx_idx,
				scx_io_bypass_reason_name(reason),
				flags,
				opf,
				rq ? (unsigned long long)blk_rq_pos(rq) : 0,
				fallback_before,
				fallback_after,
				original_cgroup_id,
				effective_cgroup_id,
				atomic_read(&data->bpf_in_flight),
				atomic_read(&data->switch_draining));
	}
#endif
}

static struct request *scx_io_policy_evacuate_hctx(struct scx_io_policy *policy,
						   struct request_queue *q,
						   unsigned int hctx_idx)
{
	struct iosched_arbiter_dispatch_ctx ctx = {
		.q = q,
		.hctx_idx = hctx_idx,
		.cgroup_id = policy ? policy->cgroup_id : 0,
	};
	struct request *rq;
	u64 rq_ptr;

	if (!policy || !policy->ops || !policy->ops->evacuate)
		return NULL;

	rq_ptr = policy->ops->evacuate(&ctx);
	if (!rq_ptr)
		return NULL;

	rq = scx_io_validate_evacuated_rq(q, rq_ptr);
	if (!rq) {
		ioext_dbg_pr_warn_ratelimited(
			"evacuate returned invalid rq_ptr=%#llx policy='%s' cgroup_id=%llu hctx=%u\n",
			rq_ptr, scx_io_policy_name(policy), policy->cgroup_id,
			hctx_idx);
		/*
		 * BPF consumed the request from its internal structures;
		 * retire managed_inflight even though validation failed.
		 */
		scx_io_policy_note_dispatch(policy);
		return NULL;
	}

	scx_io_policy_note_dispatch(policy);
	if (scx_io_queue_is_scx(rq->q))
		scx_io_note_quiesced_dispatch(policy, rq);

	return rq;
}

static struct request *scx_io_policy_evacuate_any_hctx(struct scx_io_policy *policy,
						      struct request_queue *q)
{
	struct blk_mq_hw_ctx *hctx;
	unsigned long i;

	if (!policy || !q)
		return NULL;

	queue_for_each_hw_ctx(q, hctx, i) {
		struct request *rq;

		rq = scx_io_policy_evacuate_hctx(policy, q, hctx->queue_num);
		if (rq)
			return rq;
	}

	return NULL;
}

static noinline struct request *scx_io_pop_fallback_request(struct blk_mq_hw_ctx *hctx)
{
	struct scx_io_hctx_data *hdata = hctx ? hctx->sched_data : NULL;
	struct request *rq = NULL;

	if (!hdata || atomic_read(&hdata->fallback_in_flight) <= 0)
		return NULL;

	spin_lock(&hdata->fallback_lock);
	if (!list_empty(&hdata->fallback_list)) {
		rq = list_first_entry(&hdata->fallback_list, struct request,
				      queuelist);
		list_del_init(&rq->queuelist);
		atomic_dec(&hdata->fallback_in_flight);
	}
	spin_unlock(&hdata->fallback_lock);

	return rq;
}

static bool iosched_insert_ctx_scalar_access(int off, int size)
{
	if (size != sizeof(u64))
		return false;

	switch (off) {
	case offsetof(struct iosched_insert_ctx, insert_flags):
	case offsetof(struct iosched_insert_ctx, icq_ptr):
	case offsetof(struct iosched_insert_ctx, opf):
	case offsetof(struct iosched_insert_ctx, sector):
	case offsetof(struct iosched_insert_ctx, nr_sectors):
	case offsetof(struct iosched_insert_ctx, cgroup_id):
	case offsetof(struct iosched_insert_ctx, original_cgroup_id):
	case offsetof(struct iosched_insert_ctx, ioprio):
	case offsetof(struct iosched_insert_ctx, hctx_idx):
		return true;
	default:
		return false;
	}
}

static bool iosched_arbiter_dispatch_ctx_scalar_access(int off, int size)
{
	if (size != sizeof(u64))
		return false;

	switch (off) {
	case offsetof(struct iosched_arbiter_dispatch_ctx, hctx_idx):
	case offsetof(struct iosched_arbiter_dispatch_ctx, cgroup_id):
		return true;
	default:
		return false;
	}
}

static bool iosched_hctx_ctx_scalar_access(int off, int size)
{
	if (size != sizeof(u64))
		return false;

	switch (off) {
	case offsetof(struct iosched_hctx_ctx, hctx_idx):
		return true;
	default:
		return false;
	}
}

static bool iosched_icq_ctx_scalar_access(int off, int size)
{
	return false;
}

static bool iosched_bio_merge_ctx_scalar_access(int off, int size)
{
	if (size != sizeof(u64))
		return false;

	switch (off) {
	case offsetof(struct iosched_bio_merge_ctx, bio_ioprio):
	case offsetof(struct iosched_bio_merge_ctx, nr_segs):
	case offsetof(struct iosched_bio_merge_ctx, bio_sector):
	case offsetof(struct iosched_bio_merge_ctx, bio_nr_sectors):
	case offsetof(struct iosched_bio_merge_ctx, bio_opf):
		return true;
	default:
		return false;
	}
}

static bool iosched_allow_merge_ctx_scalar_access(int off, int size)
{
	if (size != sizeof(u64))
		return false;

	switch (off) {
	case offsetof(struct iosched_allow_merge_ctx, rq_ioprio):
	case offsetof(struct iosched_allow_merge_ctx, bio_ioprio):
	case offsetof(struct iosched_allow_merge_ctx, rq_sector):
	case offsetof(struct iosched_allow_merge_ctx, rq_nr_sectors):
	case offsetof(struct iosched_allow_merge_ctx, bio_sector):
	case offsetof(struct iosched_allow_merge_ctx, bio_nr_sectors):
	case offsetof(struct iosched_allow_merge_ctx, bio_opf):
		return true;
	default:
		return false;
	}
}

static bool iosched_request_merge_ctx_scalar_access(int off, int size)
{
	if (size != sizeof(u64))
		return false;

	switch (off) {
	case offsetof(struct iosched_request_merge_ctx, rq_ioprio):
	case offsetof(struct iosched_request_merge_ctx, bio_ioprio):
	case offsetof(struct iosched_request_merge_ctx, rq_sector):
	case offsetof(struct iosched_request_merge_ctx, rq_nr_sectors):
	case offsetof(struct iosched_request_merge_ctx, bio_sector):
	case offsetof(struct iosched_request_merge_ctx, bio_nr_sectors):
	case offsetof(struct iosched_request_merge_ctx, bio_opf):
		return true;
	default:
		return false;
	}
}

static bool iosched_request_merged_ctx_scalar_access(int off, int size)
{
	if (size != sizeof(u64))
		return false;

	switch (off) {
	case offsetof(struct iosched_request_merged_ctx, merge_type):
	case offsetof(struct iosched_request_merged_ctx, rq_ioprio):
	case offsetof(struct iosched_request_merged_ctx, rq_deadline):
	case offsetof(struct iosched_request_merged_ctx, rq_sector):
	case offsetof(struct iosched_request_merged_ctx, rq_nr_sectors):
		return true;
	default:
		return false;
	}
}

static bool iosched_requests_merged_ctx_scalar_access(int off, int size)
{
	if (size != sizeof(u64))
		return false;

	switch (off) {
	case offsetof(struct iosched_requests_merged_ctx, rq_ioprio):
	case offsetof(struct iosched_requests_merged_ctx, next_ioprio):
	case offsetof(struct iosched_requests_merged_ctx, rq_deadline):
	case offsetof(struct iosched_requests_merged_ctx, next_deadline):
	case offsetof(struct iosched_requests_merged_ctx, rq_sector):
	case offsetof(struct iosched_requests_merged_ctx, rq_nr_sectors):
	case offsetof(struct iosched_requests_merged_ctx, next_sector):
	case offsetof(struct iosched_requests_merged_ctx, next_nr_sectors):
		return true;
	default:
		return false;
	}
}

static bool iosched_limit_depth_ctx_scalar_access(int off, int size)
{
	if (size != sizeof(u64))
		return false;

	switch (off) {
	case offsetof(struct iosched_limit_depth_ctx, icq_ptr):
	case offsetof(struct iosched_limit_depth_ctx, ioprio):
	case offsetof(struct iosched_limit_depth_ctx, opf):
	case offsetof(struct iosched_limit_depth_ctx, hctx_idx):
	case offsetof(struct iosched_limit_depth_ctx, async_depth):
		return true;
	default:
		return false;
	}
}

static bool iosched_depth_updated_ctx_scalar_access(int off, int size)
{
	if (size != sizeof(u64))
		return false;

	switch (off) {
	case offsetof(struct iosched_depth_updated_ctx, nr_requests):
	case offsetof(struct iosched_depth_updated_ctx, async_depth):
		return true;
	default:
		return false;
	}
}

static bool iosched_completed_request_ctx_scalar_access(int off, int size)
{
	if (size != sizeof(u64))
		return false;

	switch (off) {
	case offsetof(struct iosched_completed_request_ctx, icq_ptr):
	case offsetof(struct iosched_completed_request_ctx, ioprio):
	case offsetof(struct iosched_completed_request_ctx, opf):
	case offsetof(struct iosched_completed_request_ctx, sector):
	case offsetof(struct iosched_completed_request_ctx, nr_sectors):
	case offsetof(struct iosched_completed_request_ctx, hctx_idx):
	case offsetof(struct iosched_completed_request_ctx, cgroup_id):
	case offsetof(struct iosched_completed_request_ctx, now):
	case offsetof(struct iosched_completed_request_ctx, total_latency_ns):
	case offsetof(struct iosched_completed_request_ctx, io_latency_ns):
		return true;
	default:
		return false;
	}
}

static bool iosched_rq_ctx_scalar_access(int off, int size)
{
	if (size != sizeof(u64))
		return false;

	switch (off) {
	case offsetof(struct iosched_rq_ctx, icq_ptr):
	case offsetof(struct iosched_rq_ctx, ioprio):
	case offsetof(struct iosched_rq_ctx, opf):
	case offsetof(struct iosched_rq_ctx, sector):
	case offsetof(struct iosched_rq_ctx, nr_sectors):
	case offsetof(struct iosched_rq_ctx, hctx_idx):
		return true;
	default:
		return false;
	}
}

static int iosched_reg_ctx(void *kdata, struct bpf_link *link, void *ctx)
{
	struct iosched_ext_ops *ops = kdata;
	struct cgroup *cgrp = ctx;
	struct blkcg *blkcg;
	struct cgroup_subsys_state *css;
	struct scx_io_policy *policy;
	struct scx_io_policy *old_policy;
	int ret;

	if (!cgrp){
		printk(KERN_ERR "IOSCHED: Global registration deprecated. Please attach to Root Cgroup.\n");
		return -EOPNOTSUPP;
	}
	if (!ops || !ops->insert_request || !ops->evacuate) {
		ioext_dbg_pr_warn_ratelimited(
			"policy registration requires insert_request and evacuate hooks\n");
		return -EINVAL;
	}

	css = cgroup_get_e_css(cgrp, &io_cgrp_subsys);
	if (!css)
		return -ENOENT;
	blkcg = css_to_blkcg(css);
	policy = scx_io_policy_alloc(css, ops, link);
	if (!policy) {
		css_put(css);
		return -ENOMEM;
	}

	down_write(&blkcg->iosched_sem);
	old_policy = scx_io_policy_read_locked(blkcg);
	if (old_policy) {
		ret = scx_io_policy_prepare_teardown(old_policy, NULL,
					   SCX_IO_RETIRE_REPLACE,
					   NULL);
		if (ret) {
			up_write(&blkcg->iosched_sem);
			scx_io_policy_free(policy);
			return ret;
		}
	}
	rcu_assign_pointer(blkcg->iosched_policy, policy);
	up_write(&blkcg->iosched_sem);
	scx_io_bump_bypass_epoch();
	if (old_policy)
		scx_io_policy_schedule_teardown(old_policy);
	ioext_dbg_pr_info("policy '%s' %s cgroup_id=%llu\n",
		ops->name[0] != '\0' ? ops->name : "unnamed",
		old_policy ? "replaced on" : "attached to",
		cgroup_id(cgrp));
	return 0;
}

static void iosched_unreg_ctx(void *kdata, struct bpf_link *link, void *ctx)
{
	struct cgroup *cgrp = ctx;
	struct blkcg *blkcg;
	struct cgroup_subsys_state *css;
	struct scx_io_policy *policy;

	if (!cgrp)
		return;

	css = cgroup_get_e_css(cgrp, &io_cgrp_subsys);
	if (!css)
		return;
	blkcg = css_to_blkcg(css);

	down_write(&blkcg->iosched_sem);
	policy = scx_io_policy_read_locked(blkcg);
	if (policy && policy->ops == kdata) {
		if (!scx_io_policy_prepare_teardown(policy, link,
						    SCX_IO_RETIRE_DETACH,
						    NULL)) {
			RCU_INIT_POINTER(blkcg->iosched_policy, NULL);
			up_write(&blkcg->iosched_sem);
			scx_io_policy_schedule_teardown(policy);
			ioext_dbg_pr_info("policy detached from cgroup_id=%llu\n",
				cgroup_id(cgrp));
			css_put(css);
			return;
		}
		ioext_dbg_pr_warn_ratelimited(
			"failed to queue async detach for cgroup_id=%llu, leaving policy attached\n",
			cgroup_id(cgrp));
	}
	up_write(&blkcg->iosched_sem);
	css_put(css);
}

static int iosched_reg(void *kdata, struct bpf_link *link)
{
	return iosched_reg_ctx(kdata, link, NULL);
}

static void iosched_unreg(void *kdata, struct bpf_link *link)
{
	iosched_unreg_ctx(kdata, link, NULL);
}

static int iosched_bpf_check_member(const struct btf_type *t,
				    const struct btf_member *member,
				    const struct bpf_prog *prog)
{
	return 0;
}

static int iosched_bpf_init_member(const struct btf_type *t,
	const struct btf_member *member,
	void *kdata, const void *udata)
{
	u32 moff;
	const char *mname;

	mname = btf_name_by_offset(bpf_get_btf_vmlinux(), member->name_off);
	if (!mname)
		return 0;

	moff = __btf_member_bit_offset(t, member) / 8;
	if (strcmp(mname, "name") == 0) {
		memcpy(kdata + moff, udata + moff, 16);
		((char *)kdata)[moff + 15] = '\0';
		return 1;
	}

	if (strcmp(mname, "bypass_mode") == 0) {
		memcpy(kdata + moff, udata + moff, sizeof(u64));
		return 1;
	}

	return 0;
}

static const struct btf_type *iosched_insert_ctx_type;
static const struct btf_type *iosched_arbiter_dispatch_ctx_type;
static const struct btf_type *iosched_queue_ctx_type;
static const struct btf_type *iosched_hctx_ctx_type;
static const struct btf_type *iosched_icq_ctx_type;
static const struct btf_type *iosched_allow_merge_ctx_type;
static const struct btf_type *iosched_bio_merge_ctx_type;
static const struct btf_type *iosched_request_merge_ctx_type;
static const struct btf_type *iosched_request_merged_ctx_type;
static const struct btf_type *iosched_requests_merged_ctx_type;
static const struct btf_type *iosched_limit_depth_ctx_type;
static const struct btf_type *iosched_depth_updated_ctx_type;
static const struct btf_type *iosched_rq_ctx_type;
static const struct btf_type *iosched_completed_request_ctx_type;

static int iosched_bpf_init(struct btf *btf)
{
	s32 type_id;

	type_id = btf_find_by_name_kind(btf, "iosched_insert_ctx", BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	iosched_insert_ctx_type = btf_type_by_id(btf, type_id);

	type_id = btf_find_by_name_kind(btf, "iosched_arbiter_dispatch_ctx", BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	iosched_arbiter_dispatch_ctx_type = btf_type_by_id(btf, type_id);

	type_id = btf_find_by_name_kind(btf, "iosched_queue_ctx", BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	iosched_queue_ctx_type = btf_type_by_id(btf, type_id);

	type_id = btf_find_by_name_kind(btf, "iosched_hctx_ctx", BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	iosched_hctx_ctx_type = btf_type_by_id(btf, type_id);

	type_id = btf_find_by_name_kind(btf, "iosched_icq_ctx", BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	iosched_icq_ctx_type = btf_type_by_id(btf, type_id);

	type_id = btf_find_by_name_kind(btf, "iosched_allow_merge_ctx",
					BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	iosched_allow_merge_ctx_type = btf_type_by_id(btf, type_id);

	type_id = btf_find_by_name_kind(btf, "iosched_bio_merge_ctx", BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	iosched_bio_merge_ctx_type = btf_type_by_id(btf, type_id);

	type_id = btf_find_by_name_kind(btf, "iosched_request_merge_ctx",
					BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	iosched_request_merge_ctx_type = btf_type_by_id(btf, type_id);

	type_id = btf_find_by_name_kind(btf, "iosched_request_merged_ctx",
					BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	iosched_request_merged_ctx_type = btf_type_by_id(btf, type_id);

	type_id = btf_find_by_name_kind(btf, "iosched_requests_merged_ctx",
					BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	iosched_requests_merged_ctx_type = btf_type_by_id(btf, type_id);

	type_id = btf_find_by_name_kind(btf, "iosched_limit_depth_ctx",
					BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	iosched_limit_depth_ctx_type = btf_type_by_id(btf, type_id);

	type_id = btf_find_by_name_kind(btf, "iosched_depth_updated_ctx",
					BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	iosched_depth_updated_ctx_type = btf_type_by_id(btf, type_id);

	type_id = btf_find_by_name_kind(btf, "iosched_rq_ctx", BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	iosched_rq_ctx_type = btf_type_by_id(btf, type_id);

	type_id = btf_find_by_name_kind(btf, "iosched_completed_request_ctx",
					BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	iosched_completed_request_ctx_type = btf_type_by_id(btf, type_id);

	return 0;
}

static const struct bpf_func_proto *
iosched_bpf_get_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	return bpf_base_func_proto(func_id, prog);
}

static int iosched_bpf_btf_struct_access(struct bpf_verifier_log *log,
					 const struct bpf_reg_state *reg,
					 int off, int size)
{
	const struct btf_type *t;

	t = btf_type_by_id(reg->btf, reg->btf_id);

	if (t == iosched_insert_ctx_type) {
		if (off == offsetof(struct iosched_insert_ctx, q) &&
		    size == sizeof(void *))
			return SCALAR_VALUE;
		if (off == offsetof(struct iosched_insert_ctx, rq) &&
		    size == sizeof(void *))
			return SCALAR_VALUE;
		if (iosched_insert_ctx_scalar_access(off, size))
			return SCALAR_VALUE;
		if (off + size > sizeof(struct iosched_insert_ctx)) {
            bpf_log(log, "iosched: insert_ctx access out of bounds off=%d size=%d\n", off, size);
			return -EACCES;
		}
		bpf_log(log, "iosched: insert_ctx invalid access off=%d size=%d\n", off, size);
		return -EACCES;
	}

	if (t == iosched_arbiter_dispatch_ctx_type) {
		if (off == offsetof(struct iosched_arbiter_dispatch_ctx, q) &&
		    size == sizeof(void *))
			return SCALAR_VALUE;
		if (iosched_arbiter_dispatch_ctx_scalar_access(off, size))
			return SCALAR_VALUE;
		if (off + size > sizeof(struct iosched_arbiter_dispatch_ctx)) {
            bpf_log(log, "iosched: arbiter_dispatch_ctx access out of bounds\n");
			return -EACCES;
		}
		bpf_log(log, "iosched: arbiter_dispatch_ctx invalid access off=%d size=%d\n", off, size);
		return -EACCES;
	}

	if (t == iosched_queue_ctx_type) {
		if (off + size > sizeof(struct iosched_queue_ctx)) {
            bpf_log(log, "iosched: queue_ctx access out of bounds\n");
			return -EACCES;
		}
		return SCALAR_VALUE;
	}

	if (t == iosched_hctx_ctx_type) {
		if ((off == offsetof(struct iosched_hctx_ctx, q) ||
		     off == offsetof(struct iosched_hctx_ctx, hctx)) &&
		    size == sizeof(void *))
			return SCALAR_VALUE;
		if (iosched_hctx_ctx_scalar_access(off, size))
			return SCALAR_VALUE;
		if (off + size > sizeof(struct iosched_hctx_ctx)) {
			bpf_log(log, "iosched: hctx_ctx access out of bounds\n");
			return -EACCES;
		}
		bpf_log(log, "iosched: hctx_ctx invalid access off=%d size=%d\n",
			off, size);
		return -EACCES;
	}

	if (t == iosched_icq_ctx_type) {
		if ((off == offsetof(struct iosched_icq_ctx, q) ||
		     off == offsetof(struct iosched_icq_ctx, icq)) &&
		    size == sizeof(void *))
			return SCALAR_VALUE;
		if (iosched_icq_ctx_scalar_access(off, size))
			return SCALAR_VALUE;
		if (off + size > sizeof(struct iosched_icq_ctx)) {
			bpf_log(log, "iosched: icq_ctx access out of bounds\n");
			return -EACCES;
		}
		bpf_log(log, "iosched: icq_ctx invalid access off=%d size=%d\n",
			off, size);
		return -EACCES;
	}

	if (t == iosched_allow_merge_ctx_type) {
		if ((off == offsetof(struct iosched_allow_merge_ctx, q) ||
		     off == offsetof(struct iosched_allow_merge_ctx, rq) ||
		     off == offsetof(struct iosched_allow_merge_ctx, bio)) &&
		    size == sizeof(void *))
			return SCALAR_VALUE;
		if (iosched_allow_merge_ctx_scalar_access(off, size))
			return SCALAR_VALUE;
		if (off + size > sizeof(struct iosched_allow_merge_ctx)) {
			bpf_log(log, "iosched: allow_merge_ctx access out of bounds\n");
			return -EACCES;
		}
		bpf_log(log, "iosched: allow_merge_ctx invalid access off=%d size=%d\n",
			off, size);
		return -EACCES;
	}

	if (t == iosched_bio_merge_ctx_type) {
		if ((off == offsetof(struct iosched_bio_merge_ctx, q) ||
		     off == offsetof(struct iosched_bio_merge_ctx, bio)) &&
		    size == sizeof(void *))
			return SCALAR_VALUE;
		if (iosched_bio_merge_ctx_scalar_access(off, size))
			return SCALAR_VALUE;
		if (off + size > sizeof(struct iosched_bio_merge_ctx)) {
			bpf_log(log, "iosched: bio_merge_ctx access out of bounds\n");
			return -EACCES;
		}
		bpf_log(log, "iosched: bio_merge_ctx invalid access off=%d size=%d\n",
			off, size);
		return -EACCES;
	}

	if (t == iosched_request_merge_ctx_type) {
		if ((off == offsetof(struct iosched_request_merge_ctx, q) ||
		     off == offsetof(struct iosched_request_merge_ctx, rq) ||
		     off == offsetof(struct iosched_request_merge_ctx, bio)) &&
		    size == sizeof(void *))
			return SCALAR_VALUE;
		if (iosched_request_merge_ctx_scalar_access(off, size))
			return SCALAR_VALUE;
		if (off + size > sizeof(struct iosched_request_merge_ctx)) {
			bpf_log(log, "iosched: request_merge_ctx access out of bounds\n");
			return -EACCES;
		}
		bpf_log(log, "iosched: request_merge_ctx invalid access off=%d size=%d\n",
			off, size);
		return -EACCES;
	}

	if (t == iosched_request_merged_ctx_type) {
		if ((off == offsetof(struct iosched_request_merged_ctx, q) ||
		     off == offsetof(struct iosched_request_merged_ctx, rq)) &&
		    size == sizeof(void *))
			return SCALAR_VALUE;
		if (iosched_request_merged_ctx_scalar_access(off, size))
			return SCALAR_VALUE;
		if (off + size > sizeof(struct iosched_request_merged_ctx)) {
			bpf_log(log, "iosched: request_merged_ctx access out of bounds\n");
			return -EACCES;
		}
		bpf_log(log, "iosched: request_merged_ctx invalid access off=%d size=%d\n",
			off, size);
		return -EACCES;
	}

	if (t == iosched_requests_merged_ctx_type) {
		if ((off == offsetof(struct iosched_requests_merged_ctx, q) ||
		     off == offsetof(struct iosched_requests_merged_ctx, rq) ||
		     off == offsetof(struct iosched_requests_merged_ctx, next)) &&
		    size == sizeof(void *))
			return SCALAR_VALUE;
		if (iosched_requests_merged_ctx_scalar_access(off, size))
			return SCALAR_VALUE;
		if (off + size > sizeof(struct iosched_requests_merged_ctx)) {
			bpf_log(log, "iosched: requests_merged_ctx access out of bounds\n");
			return -EACCES;
		}
		bpf_log(log, "iosched: requests_merged_ctx invalid access off=%d size=%d\n",
			off, size);
		return -EACCES;
	}

	if (t == iosched_limit_depth_ctx_type) {
		if ((off == offsetof(struct iosched_limit_depth_ctx, q) ||
		     off == offsetof(struct iosched_limit_depth_ctx, data)) &&
		    size == sizeof(void *))
			return SCALAR_VALUE;
		if (iosched_limit_depth_ctx_scalar_access(off, size))
			return SCALAR_VALUE;
		if (off + size > sizeof(struct iosched_limit_depth_ctx)) {
			bpf_log(log, "iosched: limit_depth_ctx access out of bounds\n");
			return -EACCES;
		}
		bpf_log(log, "iosched: limit_depth_ctx invalid access off=%d size=%d\n",
			off, size);
		return -EACCES;
	}

	if (t == iosched_depth_updated_ctx_type) {
		if (off == offsetof(struct iosched_depth_updated_ctx, q) &&
		    size == sizeof(void *))
			return SCALAR_VALUE;
		if (iosched_depth_updated_ctx_scalar_access(off, size))
			return SCALAR_VALUE;
		if (off + size > sizeof(struct iosched_depth_updated_ctx)) {
			bpf_log(log, "iosched: depth_updated_ctx access out of bounds\n");
			return -EACCES;
		}
		bpf_log(log, "iosched: depth_updated_ctx invalid access off=%d size=%d\n",
			off, size);
		return -EACCES;
	}

	if (t == iosched_rq_ctx_type) {
		if ((off == offsetof(struct iosched_rq_ctx, q) ||
		     off == offsetof(struct iosched_rq_ctx, rq)) &&
		    size == sizeof(void *))
			return SCALAR_VALUE;
		if (iosched_rq_ctx_scalar_access(off, size))
			return SCALAR_VALUE;
		if (off + size > sizeof(struct iosched_rq_ctx)) {
			bpf_log(log, "iosched: rq_ctx access out of bounds\n");
			return -EACCES;
		}
		bpf_log(log, "iosched: rq_ctx invalid access off=%d size=%d\n",
			off, size);
		return -EACCES;
	}

	if (t == iosched_completed_request_ctx_type) {
		if ((off == offsetof(struct iosched_completed_request_ctx, q) ||
		     off == offsetof(struct iosched_completed_request_ctx, rq)) &&
		    size == sizeof(void *))
			return SCALAR_VALUE;
		if (iosched_completed_request_ctx_scalar_access(off, size))
			return SCALAR_VALUE;
		if (off + size > sizeof(struct iosched_completed_request_ctx)) {
			bpf_log(log, "iosched: completed_request_ctx access out of bounds\n");
			return -EACCES;
		}
		bpf_log(log, "iosched: completed_request_ctx invalid access off=%d size=%d\n",
			off, size);
		return -EACCES;
	}

	return -EACCES;
}

static bool iosched_bpf_is_valid_access(int off, int size,
					enum bpf_access_type type,
					const struct bpf_prog *prog,
					struct bpf_insn_access_aux *info)
{
	u32 member_idx = prog->expected_attach_type;

	if (type != BPF_READ)
		return false;
	if (off % size != 0)
		return false;
	if (size != sizeof(u64))
		return false;

	switch (member_idx) {
	case 0:
	case 1:
		if (off == 0) {
			info->reg_type = PTR_TO_BTF_ID | PTR_TRUSTED;
			info->btf = bpf_get_btf_vmlinux();
			info->btf_id = btf_find_by_name_kind(info->btf,
						     "iosched_queue_ctx",
						     BTF_KIND_STRUCT);
			return info->btf_id > 0;
		}
		return false;
	case 2:
		if (off == 0) {
			info->reg_type = PTR_TO_BTF_ID | PTR_TRUSTED;
			info->btf = bpf_get_btf_vmlinux();
			info->btf_id = btf_find_by_name_kind(info->btf,
						     "iosched_insert_ctx",
						     BTF_KIND_STRUCT);
			return info->btf_id > 0;
		}
		return false;
	case 3:
	case 4:
		if (off == 0) {
			info->reg_type = PTR_TO_BTF_ID | PTR_TRUSTED;
			info->btf = bpf_get_btf_vmlinux();
			info->btf_id = btf_find_by_name_kind(info->btf,
						     "iosched_arbiter_dispatch_ctx",
						     BTF_KIND_STRUCT);
			return info->btf_id > 0;
		}
		return false;
	case 5:
	case 6:
		if (off == 0) {
			info->reg_type = PTR_TO_BTF_ID | PTR_TRUSTED;
			info->btf = bpf_get_btf_vmlinux();
			info->btf_id = btf_find_by_name_kind(info->btf,
						     "iosched_hctx_ctx",
						     BTF_KIND_STRUCT);
			return info->btf_id > 0;
		}
		return false;
	case 20:
	case 21:
		if (off == 0) {
			info->reg_type = PTR_TO_BTF_ID | PTR_TRUSTED;
			info->btf = bpf_get_btf_vmlinux();
			info->btf_id = btf_find_by_name_kind(info->btf,
						     "iosched_icq_ctx",
						     BTF_KIND_STRUCT);
			return info->btf_id > 0;
		}
		return false;
	case 7:
		if (off == 0) {
			info->reg_type = PTR_TO_BTF_ID | PTR_TRUSTED;
			info->btf = bpf_get_btf_vmlinux();
			info->btf_id = btf_find_by_name_kind(info->btf,
						     "iosched_allow_merge_ctx",
						     BTF_KIND_STRUCT);
			return info->btf_id > 0;
		}
		return false;
	case 8:
		if (off == 0) {
			info->reg_type = PTR_TO_BTF_ID | PTR_TRUSTED;
			info->btf = bpf_get_btf_vmlinux();
			info->btf_id = btf_find_by_name_kind(info->btf,
						     "iosched_bio_merge_ctx",
						     BTF_KIND_STRUCT);
			return info->btf_id > 0;
		}
		return false;
	case 9:
		if (off == 0) {
			info->reg_type = PTR_TO_BTF_ID | PTR_TRUSTED;
			info->btf = bpf_get_btf_vmlinux();
			info->btf_id = btf_find_by_name_kind(info->btf,
						     "iosched_request_merge_ctx",
						     BTF_KIND_STRUCT);
			return info->btf_id > 0;
		}
		return false;
	case 10:
		if (off == 0) {
			info->reg_type = PTR_TO_BTF_ID | PTR_TRUSTED;
			info->btf = bpf_get_btf_vmlinux();
			info->btf_id = btf_find_by_name_kind(info->btf,
						     "iosched_request_merged_ctx",
						     BTF_KIND_STRUCT);
			return info->btf_id > 0;
		}
		return false;
	case 11:
		if (off == 0) {
			info->reg_type = PTR_TO_BTF_ID | PTR_TRUSTED;
			info->btf = bpf_get_btf_vmlinux();
			info->btf_id = btf_find_by_name_kind(info->btf,
						     "iosched_requests_merged_ctx",
						     BTF_KIND_STRUCT);
			return info->btf_id > 0;
		}
		return false;
	case 12:
		if (off == 0) {
			info->reg_type = PTR_TO_BTF_ID | PTR_TRUSTED;
			info->btf = bpf_get_btf_vmlinux();
			info->btf_id = btf_find_by_name_kind(info->btf,
						     "iosched_limit_depth_ctx",
						     BTF_KIND_STRUCT);
			return info->btf_id > 0;
		}
		return false;
	case 13:
		if (off == 0) {
			info->reg_type = PTR_TO_BTF_ID | PTR_TRUSTED;
			info->btf = bpf_get_btf_vmlinux();
			info->btf_id = btf_find_by_name_kind(info->btf,
						     "iosched_depth_updated_ctx",
						     BTF_KIND_STRUCT);
			return info->btf_id > 0;
		}
		return false;
	case 14:
	case 15:
	case 17:
	case 18:
	case 19:
		if (off == 0) {
			info->reg_type = PTR_TO_BTF_ID | PTR_TRUSTED;
			info->btf = bpf_get_btf_vmlinux();
			info->btf_id = btf_find_by_name_kind(info->btf,
						     "iosched_rq_ctx",
						     BTF_KIND_STRUCT);
			return info->btf_id > 0;
		}
		return false;
	case 16:
		if (off == 0) {
			info->reg_type = PTR_TO_BTF_ID | PTR_TRUSTED;
			info->btf = bpf_get_btf_vmlinux();
			info->btf_id = btf_find_by_name_kind(info->btf,
						     "iosched_completed_request_ctx",
						     BTF_KIND_STRUCT);
			return info->btf_id > 0;
		}
		return false;
	default:
		return false;
	}
}

static const struct bpf_verifier_ops iosched_bpf_verifier_ops = {
	.get_func_proto = iosched_bpf_get_func_proto,
	.is_valid_access = iosched_bpf_is_valid_access,
	.btf_struct_access = iosched_bpf_btf_struct_access,
};

static int iosched_ext_init_queue_stub(struct iosched_queue_ctx *ctx)
{
	return 0;
}

static int iosched_ext_exit_queue_stub(struct iosched_queue_ctx *ctx)
{
	return 0;
}

static int iosched_ext_insert_request_stub(struct iosched_insert_ctx *ctx)
{
	return 0;
}

static u64 iosched_ext_cgroup_dispatch_stub(struct iosched_arbiter_dispatch_ctx *ctx)
{
	return 0;
}

static u64 iosched_ext_evacuate_stub(struct iosched_arbiter_dispatch_ctx *ctx)
{
	return 0;
}

static int iosched_ext_init_hctx_stub(struct iosched_hctx_ctx *ctx)
{
	return 0;
}

static void iosched_ext_exit_hctx_stub(struct iosched_hctx_ctx *ctx)
{
}

static void iosched_ext_init_icq_stub(struct iosched_icq_ctx *ctx)
{
}

static void iosched_ext_exit_icq_stub(struct iosched_icq_ctx *ctx)
{
}

static bool iosched_ext_allow_merge_stub(struct iosched_allow_merge_ctx *ctx)
{
	return true;
}

static bool iosched_ext_bio_merge_stub(struct iosched_bio_merge_ctx *ctx)
{
	return false;
}

static u64 iosched_ext_request_merge_stub(struct iosched_request_merge_ctx *ctx)
{
	return ELEVATOR_NO_MERGE;
}

static void iosched_ext_request_merged_stub(struct iosched_request_merged_ctx *ctx)
{
}

static void iosched_ext_requests_merged_stub(struct iosched_requests_merged_ctx *ctx)
{
}

static u64 iosched_ext_limit_depth_stub(struct iosched_limit_depth_ctx *ctx)
{
	return 0;
}

static void iosched_ext_depth_updated_stub(struct iosched_depth_updated_ctx *ctx)
{
}

static void iosched_ext_prepare_request_stub(struct iosched_rq_ctx *ctx)
{
}

static void iosched_ext_finish_request_stub(struct iosched_rq_ctx *ctx)
{
}

static void iosched_ext_completed_request_stub(struct iosched_completed_request_ctx *ctx)
{
}

static void iosched_ext_requeue_request_stub(struct iosched_rq_ctx *ctx)
{
}

static u64 iosched_ext_former_request_stub(struct iosched_rq_ctx *ctx)
{
	return 0;
}

static u64 iosched_ext_next_request_stub(struct iosched_rq_ctx *ctx)
{
	return 0;
}

static struct iosched_ext_ops iosched_ext_cfi_stubs = {
	.init_queue      = iosched_ext_init_queue_stub,
	.exit_queue      = iosched_ext_exit_queue_stub,
	.insert_request  = iosched_ext_insert_request_stub,
	.cgroup_dispatch = iosched_ext_cgroup_dispatch_stub,
	.evacuate        = iosched_ext_evacuate_stub,
	.init_hctx       = iosched_ext_init_hctx_stub,
	.exit_hctx       = iosched_ext_exit_hctx_stub,
	.init_icq        = iosched_ext_init_icq_stub,
	.exit_icq        = iosched_ext_exit_icq_stub,
	.allow_merge     = iosched_ext_allow_merge_stub,
	.bio_merge       = iosched_ext_bio_merge_stub,
	.request_merge   = iosched_ext_request_merge_stub,
	.request_merged  = iosched_ext_request_merged_stub,
	.requests_merged = iosched_ext_requests_merged_stub,
	.limit_depth     = iosched_ext_limit_depth_stub,
	.depth_updated   = iosched_ext_depth_updated_stub,
	.prepare_request = iosched_ext_prepare_request_stub,
	.finish_request  = iosched_ext_finish_request_stub,
	.completed_request = iosched_ext_completed_request_stub,
	.requeue_request = iosched_ext_requeue_request_stub,
	.former_request  = iosched_ext_former_request_stub,
	.next_request    = iosched_ext_next_request_stub,
};

static struct bpf_struct_ops iosched_ext_bpf_ops __used = {
	.verifier_ops = &iosched_bpf_verifier_ops,
	.init         = iosched_bpf_init,
	.check_member = iosched_bpf_check_member,
	.init_member  = iosched_bpf_init_member,
	.reg          = iosched_reg,
	.unreg        = iosched_unreg,
	.name         = "iosched_ext_ops",
	.owner        = THIS_MODULE,
	.cfi_stubs    = &iosched_ext_cfi_stubs,
	.reg_ctx      = iosched_reg_ctx,
	.unreg_ctx    = iosched_unreg_ctx,
};

static void *scx_io_alloc_sched_data(struct request_queue *q)
{
	struct scx_io_data *data;
#if IOEXT_DEBUG
	int i;
#endif

	data = kmalloc_node(sizeof(*data), GFP_KERNEL, q->node);
	if (!data)
		return NULL;

	data->q = q;
	INIT_LIST_HEAD(&data->active_pds);
	spin_lock_init(&data->lock);
	atomic_set(&data->bpf_in_flight, 0);
	atomic_set(&data->switch_draining, 0);
	atomic64_set(&data->bypassed_total, 0);
	atomic64_set(&data->bypassed_no_policy, 0);
	atomic64_set(&data->bypassed_policy_unavailable, 0);
	atomic64_set(&data->bypassed_policy_rejected, 0);
	atomic64_set(&data->bypassed_quiesced, 0);
#if IOEXT_DEBUG
	atomic64_set(&data->debug_insert_accepts, 0);
	atomic64_set(&data->debug_dispatch_returns, 0);
	atomic64_set(&data->debug_prepare_calls, 0);
	atomic64_set(&data->debug_finish_entries, 0);
	atomic64_set(&data->debug_complete_entries, 0);
	atomic64_set(&data->debug_requeue_entries, 0);
	atomic64_set(&data->debug_has_work_false, 0);
	atomic64_set(&data->debug_validate_failures, 0);
	atomic64_set(&data->debug_fallback_enqueues, 0);
	atomic64_set(&data->debug_dispatch_nulls, 0);
	atomic64_set(&data->debug_has_work_true, 0);
	for (i = 0; i < SCX_IO_BIO_BYPASS_NR_REASONS; i++)
		atomic64_set(&data->debug_bio_bypass_reasons[i], 0);
	atomic64_set(&data->debug_insert_fallbacks, 0);
#endif
	return data;
}

static void scx_io_free_sched_data(void *elv_data)
{
	struct scx_io_data *data = elv_data;
	unsigned long irq_flags;

	if (data) {
		scx_io_detach_active_pds(data);

		spin_lock_irqsave(&data->lock, irq_flags);
		WARN_ON_ONCE(!list_empty(&data->active_pds));
		spin_unlock_irqrestore(&data->lock, irq_flags);

		if (atomic64_read(&data->bypassed_total) > 0)
			ioext_dbg_pr_info(
				"fallback bypass summary total=%llu no_policy=%llu unavailable=%llu rejected=%llu quiesced=%llu\n",
				atomic64_read(&data->bypassed_total),
				atomic64_read(&data->bypassed_no_policy),
				atomic64_read(&data->bypassed_policy_unavailable),
				atomic64_read(&data->bypassed_policy_rejected),
				atomic64_read(&data->bypassed_quiesced));
	}

	kfree(data);
}

static int scx_io_init_sched(struct request_queue *q, struct elevator_queue *eq)
{
	struct scx_io_data *data = eq->elevator_data;
	int ret;

	if (!data)
		return -ENOMEM;

	blk_queue_flag_clear(QUEUE_FLAG_SQ_SCHED, q);
	blk_stat_enable_accounting(q);
	q->elevator = eq;

	ret = blkcg_activate_policy(q->disk, &scx_io_blkcg_policy);
	if (ret) {
		blk_stat_disable_accounting(q);
		return ret;
	}

	q->async_depth = q->nr_requests;
	blk_mq_set_min_shallow_depth(q, 1);
	return 0;
}

static void scx_io_exit_sched(struct elevator_queue *e)
{
	struct scx_io_data *data = e->elevator_data;

	if (!data || !data->q)
		return;

	/*
	 * blkcg_deactivate_policy() nests a queue freeze and q->blkcg_mutex.
	 * During scheduler switching the block core already holds the queue
	 * freeze lockdep maps, so deactivating here creates a q_usage_counter ->
	 * blkcg_mutex edge that conflicts with cgroup configuration paths.  Keep
	 * the scx_io blkcg policy active but dormant across runtime scheduler
	 * switches; blkcg_exit_disk()/blkg_destroy_all() tears it down when the
	 * disk goes away.
	 */
	blk_stat_disable_accounting(data->q);
	scx_io_detach_active_pds(data);
}

static void scx_io_prepare_switch(struct request_queue *q)
{
	struct scx_io_data *data;

	if (!q || !q->elevator || q->elevator->type != &scx_io_elevator)
		return;

	data = q->elevator->elevator_data;
	if (!data)
		return;

	atomic_set(&data->switch_draining, 1);
	scx_io_bump_bypass_epoch();
	ioext_dbg_pr_info(
		"prepare switch drain q=%p bpf_in_flight=%d bypassed_total=%llu\n",
		q,
		atomic_read(&data->bpf_in_flight),
		atomic64_read(&data->bypassed_total));
	blk_mq_run_hw_queues(q, true);
}

static int scx_io_init_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
	struct scx_io_hctx_data *hdata;
	struct blkcg *owner = NULL;
	struct scx_io_policy *policy;
	struct iosched_hctx_ctx ctx = {
		.q = hctx ? hctx->queue : NULL,
		.hctx = hctx,
		.hctx_idx = hctx_idx,
	};
	int ret = 0;

	if (!hctx)
		return -EINVAL;

	hdata = kzalloc_node(sizeof(*hdata), GFP_KERNEL, hctx->numa_node);
	if (!hdata)
		return -ENOMEM;

	INIT_LIST_HEAD(&hdata->fallback_list);
	spin_lock_init(&hdata->fallback_lock);
	atomic_set(&hdata->fallback_in_flight, 0);
	hctx->sched_data = hdata;

	rcu_read_lock();
	policy = scx_io_find_root_policy_rcu(&owner);
	if (policy && policy->ops && policy->ops->init_hctx &&
	    scx_io_policy_is_active(policy))
		ret = policy->ops->init_hctx(&ctx);
	rcu_read_unlock();
	if (ret) {
		hctx->sched_data = NULL;
		kfree(hdata);
	}

	return ret;
}

static void scx_io_exit_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
	struct scx_io_hctx_data *hdata = hctx ? hctx->sched_data : NULL;
	struct blkcg *owner = NULL;
	struct scx_io_policy *policy;
	struct iosched_hctx_ctx ctx = {
		.q = hctx ? hctx->queue : NULL,
		.hctx = hctx,
		.hctx_idx = hctx_idx,
	};

	rcu_read_lock();
	policy = scx_io_find_root_policy_rcu(&owner);
	if (policy && policy->ops && policy->ops->exit_hctx &&
	    scx_io_policy_is_active(policy))
		policy->ops->exit_hctx(&ctx);
	rcu_read_unlock();

	if (hdata) {
		spin_lock(&hdata->fallback_lock);
		WARN_ON_ONCE(!list_empty(&hdata->fallback_list));
		WARN_ON_ONCE(atomic_read(&hdata->fallback_in_flight) != 0);
		spin_unlock(&hdata->fallback_lock);
		kfree(hdata);
		hctx->sched_data = NULL;
	}
}

bool scx_io_bio_should_bypass(struct request_queue *q, struct bio *bio)
{
	struct scx_io_blkg_data *scx_pd;
	struct blkcg_gq *blkg;
	u64 epoch;
	bool enabled;

	if (!q || !bio || !bio->bi_blkg)
		return scx_io_debug_bio_bypass_return(q, bio, NULL,
					SCX_IO_BIO_BYPASS_NULL, false, 0);
	switch (bio_op(bio)) {
	case REQ_OP_READ:
	case REQ_OP_WRITE:
		break;
	default:
		return scx_io_debug_bio_bypass_return(q, bio, NULL,
					SCX_IO_BIO_BYPASS_NON_RW, false, 0);
	}
	if (bio_issue_as_root_blkg(bio))
		return scx_io_debug_bio_bypass_return(q, bio, NULL,
					SCX_IO_BIO_BYPASS_ROOT_BLKG, false, 0);
	if (bio_needs_zone_write_plugging(bio))
		return scx_io_debug_bio_bypass_return(q, bio, NULL,
					SCX_IO_BIO_BYPASS_ZONE_PLUG, false, 0);
	if (!q->elevator || q->elevator->type != &scx_io_elevator)
		return scx_io_debug_bio_bypass_return(q, bio, NULL,
					SCX_IO_BIO_BYPASS_NOT_SCX, false, 0);

	blkg = bio->bi_blkg;
	scx_pd = scx_io_pd_from_blkg(blkg);
	if (!scx_pd)
		return scx_io_debug_bio_bypass_return(q, bio, NULL,
					SCX_IO_BIO_BYPASS_NO_PD, false, 0);

	epoch = atomic64_read(&scx_io_bypass_epoch);
	if (smp_load_acquire(&scx_pd->bypass_epoch) != epoch) {
		enabled = scx_io_refresh_blkg_bypass(blkg);
		return scx_io_debug_bio_bypass_return(q, bio, scx_pd,
			enabled ? SCX_IO_BIO_BYPASS_REFRESH_ENABLED :
				  SCX_IO_BIO_BYPASS_REFRESH_DISABLED,
			enabled, epoch);
	}

	enabled = READ_ONCE(scx_pd->bypass_enabled);
	return scx_io_debug_bio_bypass_return(q, bio, scx_pd,
		enabled ? SCX_IO_BIO_BYPASS_CACHE_ENABLED :
			  SCX_IO_BIO_BYPASS_CACHE_DISABLED,
		enabled, epoch);
}

static bool scx_io_bio_bypass(struct request_queue *q, struct bio *bio)
{
	return scx_io_bio_should_bypass(q, bio);
}

static void scx_io_insert_requests(struct blk_mq_hw_ctx *hctx,
				       struct list_head *list,
				       blk_insert_t flags)
{
	struct request_queue *q = hctx->queue;
	struct scx_io_data *data = q->elevator->elevator_data;
	struct request *rq;
	struct request *next;
	unsigned long irq_flags;

	list_for_each_entry_safe(rq, next, list, queuelist) {
		struct blkcg *original_blkcg = NULL;
		struct blkcg *search_blkcg;
		struct scx_io_policy *policy = NULL;
		enum scx_io_bypass_reason bypass_reason = SCX_IO_BYPASS_NO_POLICY;
		u64 effective_cgroup_id = 0;
		bool inserted = false;
#if IOEXT_DEBUG
		char insert_policy_name[16] = "none";
		int insert_ret = -9999;
#endif

		list_del_init(&rq->queuelist);
		if (atomic_read(&data->switch_draining)) {
#if IOEXT_DEBUG
			strscpy(insert_policy_name, "switch-drain",
				sizeof(insert_policy_name));
#endif
			scx_io_bypass_request(data, hctx, rq, flags,
					      SCX_IO_BYPASS_QUIESCED, 0, 0);
			continue;
		}

		if (rq->bio) {
			struct cgroup_subsys_state *css = bio_blkcg_css(rq->bio);

			if (css)
				original_blkcg = css_to_blkcg(css);
		}

		if (!original_blkcg)
			original_blkcg = &blkcg_root;

		rcu_read_lock();
		search_blkcg = original_blkcg;
		while (search_blkcg) {
			struct blkcg *effective_blkcg;
			struct blkcg_gq *blkg = NULL;
			struct iosched_insert_ctx ctx = {
				.q = q,
				.rq = rq,
				.icq_ptr = rq && rq->elv.icq ? (__u64)rq->elv.icq : 0,
				.insert_flags = flags,
				.opf = rq->cmd_flags,
				.sector = blk_rq_pos(rq),
				.nr_sectors = blk_rq_sectors(rq),
				.cgroup_id = 0,
				.original_cgroup_id = cgroup_id(original_blkcg->css.cgroup),
				.ioprio = req_get_ioprio(rq),
				.hctx_idx = hctx->queue_num,
			};
			int ret;

			policy = scx_io_find_policy_owner_rcu(search_blkcg,
							     &effective_blkcg);
			if (!effective_blkcg || !policy || !policy->ops ||
			    !policy->ops->insert_request)
				break;

			effective_cgroup_id = policy->cgroup_id;
#if IOEXT_DEBUG
			strscpy(insert_policy_name, scx_io_policy_name(policy),
				sizeof(insert_policy_name));
#endif

			blkg = scx_io_lookup_blkg_get(effective_blkcg, q);

			if (!blkg) {
				bypass_reason = SCX_IO_BYPASS_POLICY_UNAVAILABLE;
				break;
			}

			if (!scx_io_pd_from_blkg(blkg)->pd.online ||
			    !scx_io_policy_is_active(policy)) {
				bypass_reason = SCX_IO_BYPASS_QUIESCED;
				blkg_put(blkg);
				break;
			}

			ctx.cgroup_id = effective_cgroup_id;
			ret = policy->ops->insert_request(&ctx);
#if IOEXT_DEBUG
			insert_ret = ret;
#endif
			if (ret == IOSCHED_INSERT_ACCEPT) {
				spin_lock_irqsave(&data->lock, irq_flags);
				scx_io_blkg_note_bpf_insert(data, blkg);
				atomic_inc(&data->bpf_in_flight);
				spin_unlock_irqrestore(&data->lock, irq_flags);

				if (!scx_io_pd_from_blkg(blkg)->pd.online ||
				    !scx_io_policy_is_active(policy)) {
					bypass_reason = SCX_IO_BYPASS_QUIESCED;
				}
				atomic_inc(&policy->managed_inflight);
				inserted = true;
#if IOEXT_DEBUG
				{
					u64 seq = atomic64_inc_return(&data->debug_insert_accepts);

					if (scx_io_debug_should_log(seq))
						ioext_dbg_pr_info(
							"dbg insert_accept seq=%llu policy='%s' rq=%p hctx=%u opf=%#llx sector=%llu bpf_in_flight=%d managed_inflight=%d flags=%u\n",
							seq,
							scx_io_policy_name(policy),
							rq,
							hctx->queue_num,
							(u64)rq->cmd_flags,
							(unsigned long long)blk_rq_pos(rq),
							atomic_read(&data->bpf_in_flight),
							atomic_read(&policy->managed_inflight),
							flags);
				}
#endif
				blk_mq_run_hw_queue(hctx, true);
				ioext_dbg_pr_info_once(
					"BPF insert path active policy='%s' hctx=%u q=%p\n",
					policy->ops->name[0] != '\0' ?
						policy->ops->name : "unnamed",
					hctx->queue_num,
					q);
			}
			blkg_put(blkg);

			if (ret == IOSCHED_INSERT_ACCEPT)
				break;
			if (ret == IOSCHED_INSERT_DEFER_TO_PARENT) {
				search_blkcg = scx_io_parent_blkcg(effective_blkcg);
				continue;
			}

			bypass_reason = SCX_IO_BYPASS_POLICY_REJECTED;

			break;
		}
		rcu_read_unlock();

		if (!inserted) {
#if IOEXT_DEBUG
			u64 seq = atomic64_inc_return(&data->debug_insert_fallbacks);
			struct bio *bio = rq ? rq->bio : NULL;
			unsigned int bio_op_num = bio ?
				(__force unsigned int)bio_op(bio) : ~0U;
			unsigned int rq_op_num = rq ?
				(__force unsigned int)req_op(rq) : ~0U;
			bool root_blkg = bio ? bio_issue_as_root_blkg(bio) : false;
			bool zone_plug = bio ? bio_needs_zone_write_plugging(bio) : false;
			u64 bio_cgid = bio && bio->bi_blkg ?
				cgroup_id(bio->bi_blkg->blkcg->css.cgroup) : 0;

			if (scx_io_debug_should_log(seq))
				ioext_dbg_pr_info(
					"dbg insert_fallback seq=%llu policy='%s' ret=%d reason=%s comm=%s rq=%p hctx=%u flags=%u opf=%#llx rq_op=%u bio_op=%u bio_opf=%#llx use_sched=%d root_blkg=%d zone_plug=%d bio_cgroup_id=%llu original_cgroup_id=%llu effective_cgroup_id=%llu sector=%llu nr_sectors=%u bpf_in_flight=%d switch_draining=%d\n",
					seq,
					insert_policy_name,
					insert_ret,
					scx_io_bypass_reason_name(bypass_reason),
					current->comm,
					rq,
					hctx->queue_num,
					flags,
					rq ? (u64)rq->cmd_flags : 0,
					rq_op_num,
					bio_op_num,
					bio ? (u64)bio->bi_opf : 0,
					rq ? !!(rq->rq_flags & RQF_USE_SCHED) : 0,
					root_blkg,
					zone_plug,
					bio_cgid,
					cgroup_id(original_blkcg->css.cgroup),
					effective_cgroup_id,
					rq ? (unsigned long long)blk_rq_pos(rq) : 0,
					rq ? blk_rq_sectors(rq) : 0,
					atomic_read(&data->bpf_in_flight),
					atomic_read(&data->switch_draining));
#endif
			scx_io_bypass_request(data, hctx, rq, flags, bypass_reason,
					      cgroup_id(original_blkcg->css.cgroup),
					      effective_cgroup_id);
		}
	}
}

static u64 scx_io_policy_dispatch_rqptr(struct scx_io_policy *policy,
				 struct blkcg_gq *blkg,
				 struct request_queue *q,
				 struct iosched_arbiter_dispatch_ctx *ctx)
{
	u64 rq_ptr = 0;

	if (!blkg)
		return 0;
	if (!policy || !policy->ops || !policy->ops->cgroup_dispatch)
		return 0;
	if (!scx_io_policy_is_active(policy))
		return 0;
	if (!scx_io_pd_from_blkg(blkg)->pd.online)
		return 0;

	ctx->q = q;
	ctx->cgroup_id = policy->cgroup_id;
	rq_ptr = policy->ops->cgroup_dispatch(ctx);
	return rq_ptr;
}

static struct request *scx_io_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
	struct request_queue *q = hctx->queue;
	struct request *rq = NULL;
	struct scx_io_data *data = q->elevator->elevator_data;
	struct iosched_arbiter_ops *arbiter;
	struct iosched_arbiter_dispatch_ctx ctx = {
		.q = q,
		.hctx_idx = hctx->queue_num,
	};
	u64 rq_ptr = 0;
	u64 selected_cgid = 0;
	unsigned long irq_flags;
	bool switch_draining = atomic_read(&data->switch_draining);
#if IOEXT_DEBUG
	bool debug_arbiter_present = false;
	bool debug_hold_dispatch = false;
#endif

	rq = scx_io_pop_fallback_request(hctx);
	if (rq) {
#if IOEXT_DEBUG
		{
			u64 seq = atomic64_inc_return(&data->debug_dispatch_returns);

			if (scx_io_debug_should_log(seq))
				ioext_dbg_pr_info(
					"dbg dispatch_return seq=%llu source=fallback rq=%p hctx=%u opf=%#llx sector=%llu bpf_in_flight=%d fallback_in_flight=%d switch_draining=%d\n",
					seq,
					rq,
					hctx->queue_num,
					(u64)rq->cmd_flags,
					(unsigned long long)blk_rq_pos(rq),
					atomic_read(&data->bpf_in_flight),
					hctx->sched_data ? atomic_read(&((struct scx_io_hctx_data *)hctx->sched_data)->fallback_in_flight) : 0,
					switch_draining);
		}
#endif
		return rq;
	}

	if (!switch_draining) {
		rcu_read_lock();
		arbiter = rcu_dereference(current_arbiter);
#if IOEXT_DEBUG
		debug_arbiter_present = !!arbiter;
#endif
		if (arbiter && arbiter->hold_dispatch && arbiter->hold_dispatch(&ctx)) {
#if IOEXT_DEBUG
			struct scx_io_hctx_data *hdata = hctx->sched_data;
			u64 seq = atomic64_inc_return(&data->debug_dispatch_nulls);

			debug_hold_dispatch = true;
			if (scx_io_debug_should_log(seq))
				ioext_dbg_pr_info(
					"dbg dispatch_null seq=%llu reason=hold_dispatch hctx=%u bpf_in_flight=%d fallback_in_flight=%d selected_cgid=%llu arbiter_present=%d hold_dispatch=%d switch_draining=%d dispatch_returns=%llu complete_entries=%llu requeue_entries=%llu\n",
					seq,
					hctx->queue_num,
					atomic_read(&data->bpf_in_flight),
					hdata ? atomic_read(&hdata->fallback_in_flight) : 0,
					selected_cgid,
					debug_arbiter_present,
					debug_hold_dispatch,
					switch_draining,
					atomic64_read(&data->debug_dispatch_returns),
					atomic64_read(&data->debug_complete_entries),
					atomic64_read(&data->debug_requeue_entries));
#endif
			rcu_read_unlock();
			return NULL;
		}
		if (arbiter && arbiter->pick_cgroup)
			selected_cgid = arbiter->pick_cgroup(&ctx);
		rcu_read_unlock();
	}

	if (selected_cgid) {
			struct cgroup_subsys_state *css;
			struct blkcg *blkcg;
			struct blkcg_gq *blkg = NULL;
			struct scx_io_policy *policy;

			css = scx_io_blkcg_css_from_cgid(selected_cgid);
			if (css) {
				blkcg = css_to_blkcg(css);
				blkg = scx_io_lookup_blkg_get(blkcg, q);
				rcu_read_lock();
				policy = scx_io_policy_read_rcu(blkcg);
				rq_ptr = scx_io_policy_dispatch_rqptr(policy, blkg, q, &ctx);
				if (rq_ptr) {
					rq = rq_ptr ? scx_io_validate_dispatch_rq(hctx, rq_ptr) : NULL;
					if (rq) {
						spin_lock_irqsave(&data->lock, irq_flags);
						scx_io_note_bpf_dispatch(data, blkg);
						spin_unlock_irqrestore(&data->lock, irq_flags);
						scx_io_policy_note_dispatch(policy);
#if IOEXT_DEBUG
						{
							u64 seq = atomic64_inc_return(&data->debug_dispatch_returns);

							if (scx_io_debug_should_log(seq))
								ioext_dbg_pr_info(
									"dbg dispatch_return seq=%llu source=arbiter policy='%s' rq=%p hctx=%u opf=%#llx sector=%llu cgid=%llu bpf_in_flight=%d managed_inflight=%d switch_draining=%d\n",
									seq,
									scx_io_policy_name(policy),
									rq,
									hctx->queue_num,
									(u64)rq->cmd_flags,
									(unsigned long long)blk_rq_pos(rq),
									selected_cgid,
									atomic_read(&data->bpf_in_flight),
									atomic_read(&policy->managed_inflight),
									switch_draining);
						}
#endif
						rcu_read_unlock();
						css_put(css);
						if (blkg)
							blkg_put(blkg);
						return rq;
					}
					if (rq_ptr) {
						ioext_dbg_pr_warn_ratelimited(
							"policy='%s' returned invalid rq_ptr=%#llx for cgroup_id=%llu\n",
							policy->ops->name[0] != '\0' ?
								policy->ops->name : "unnamed",
							rq_ptr,
							selected_cgid);
						/*
						 * BPF consumed the request from its data
						 * structures; retire the accounting even
						 * though the pointer failed validation.
						 */
						scx_io_policy_note_dispatch(policy);
						spin_lock_irqsave(&data->lock, irq_flags);
						scx_io_note_bpf_dispatch(data, blkg);
						spin_unlock_irqrestore(&data->lock, irq_flags);
					}
				}
				rcu_read_unlock();
				css_put(css);
				if (blkg)
					blkg_put(blkg);
			}
	}

	if (atomic_read(&data->bpf_in_flight) > 0) {
		struct scx_io_blkg_data *scx_pd = NULL;
		struct blkcg_gq *blkg = NULL;
		struct scx_io_policy *policy;

		spin_lock_irqsave(&data->lock, irq_flags);
		scx_pd = scx_io_pick_active_pd_locked(data);
		if (scx_pd)
			blkg = pd_to_blkg(&scx_pd->pd);
		spin_unlock_irqrestore(&data->lock, irq_flags);

		if (blkg) {
			rcu_read_lock();
			policy = scx_io_policy_read_rcu(blkg->blkcg);
			rq_ptr = scx_io_policy_dispatch_rqptr(policy, blkg, q, &ctx);
			rq = rq_ptr ? scx_io_validate_dispatch_rq(hctx, rq_ptr) : NULL;
			if (rq) {
				spin_lock_irqsave(&data->lock, irq_flags);
				scx_io_note_bpf_dispatch(data, blkg);
				if (scx_pd->on_active_list)
					list_move_tail(&scx_pd->active_node,
						       &data->active_pds);
				spin_unlock_irqrestore(&data->lock, irq_flags);
				scx_io_policy_note_dispatch(policy);
#if IOEXT_DEBUG
				{
					u64 seq = atomic64_inc_return(&data->debug_dispatch_returns);

					if (scx_io_debug_should_log(seq))
						ioext_dbg_pr_info(
							"dbg dispatch_return seq=%llu source=active policy='%s' rq=%p hctx=%u opf=%#llx sector=%llu cgid=%llu bpf_in_flight=%d managed_inflight=%d switch_draining=%d\n",
							seq,
							scx_io_policy_name(policy),
							rq,
							hctx->queue_num,
							(u64)rq->cmd_flags,
							(unsigned long long)blk_rq_pos(rq),
							ctx.cgroup_id,
							atomic_read(&data->bpf_in_flight),
							atomic_read(&policy->managed_inflight),
							switch_draining);
				}
#endif
				rcu_read_unlock();
				blkg_put(blkg);
				return rq;
			}

			spin_lock_irqsave(&data->lock, irq_flags);
			if (rq_ptr) {
				ioext_dbg_pr_warn_ratelimited(
					"policy owner cgroup_id=%llu returned invalid rq_ptr=%#llx\n",
					ctx.cgroup_id,
					rq_ptr);
				/* BPF consumed the request; retire accounting. */
				scx_io_policy_note_dispatch(policy);
				scx_io_note_bpf_dispatch(data, blkg);
			} else if (scx_pd->on_active_list) {
				list_move_tail(&scx_pd->active_node,
					       &data->active_pds);
			}
			spin_unlock_irqrestore(&data->lock, irq_flags);

			if (!rq_ptr && policy && policy->ops && policy->ops->evacuate) {
				rq = scx_io_policy_evacuate_hctx(policy, q,
							      hctx->queue_num);
				if (rq) {
#if IOEXT_DEBUG
					{
						u64 seq = atomic64_inc_return(&data->debug_dispatch_returns);

						if (scx_io_debug_should_log(seq))
							ioext_dbg_pr_info(
								"dbg dispatch_return seq=%llu source=evacuate policy='%s' rq=%p hctx=%u opf=%#llx sector=%llu cgid=%llu bpf_in_flight=%d managed_inflight=%d switch_draining=%d\n",
								seq,
								scx_io_policy_name(policy),
								rq,
								hctx->queue_num,
								(u64)rq->cmd_flags,
								(unsigned long long)blk_rq_pos(rq),
								ctx.cgroup_id,
								atomic_read(&data->bpf_in_flight),
								atomic_read(&policy->managed_inflight),
								switch_draining);
					}
#endif
					rcu_read_unlock();
					blkg_put(blkg);
					return rq;
				}
			}
			rcu_read_unlock();
			blkg_put(blkg);
		}
	}

#if IOEXT_DEBUG
	{
		struct scx_io_hctx_data *hdata = hctx->sched_data;
		int bpf_in_flight = atomic_read(&data->bpf_in_flight);
		int fallback_in_flight = hdata ? atomic_read(&hdata->fallback_in_flight) : 0;

		if (bpf_in_flight > 0 || fallback_in_flight > 0 ||
		    switch_draining || selected_cgid) {
			u64 seq = atomic64_inc_return(&data->debug_dispatch_nulls);

			if (scx_io_debug_should_log(seq))
				ioext_dbg_pr_info(
					"dbg dispatch_null seq=%llu reason=no_request hctx=%u bpf_in_flight=%d fallback_in_flight=%d selected_cgid=%llu arbiter_present=%d hold_dispatch=%d switch_draining=%d dispatch_returns=%llu complete_entries=%llu requeue_entries=%llu\n",
					seq,
					hctx->queue_num,
					bpf_in_flight,
					fallback_in_flight,
					selected_cgid,
					debug_arbiter_present,
					debug_hold_dispatch,
					switch_draining,
					atomic64_read(&data->debug_dispatch_returns),
					atomic64_read(&data->debug_complete_entries),
					atomic64_read(&data->debug_requeue_entries));
		}
	}
#endif
	return rq;
}

static bool scx_io_has_work(struct blk_mq_hw_ctx *hctx)
{
	struct scx_io_data *data = hctx->queue->elevator->elevator_data;
	struct scx_io_hctx_data *hdata = hctx->sched_data;
	bool has_work;

	has_work = atomic_read(&data->bpf_in_flight) > 0 ||
		   (hdata && atomic_read(&hdata->fallback_in_flight) > 0);
#if IOEXT_DEBUG
	if (has_work) {
		u64 seq = atomic64_inc_return(&data->debug_has_work_true);

		if (IOEXT_DEBUG_VERBOSE && scx_io_debug_should_log(seq))
			ioext_dbg_pr_info(
				"dbg has_work_true seq=%llu hctx=%u bpf_in_flight=%d fallback_in_flight=%d dispatch_returns=%llu finish_entries=%llu complete_entries=%llu requeue_entries=%llu switch_draining=%d\n",
				seq,
				hctx->queue_num,
				atomic_read(&data->bpf_in_flight),
				hdata ? atomic_read(&hdata->fallback_in_flight) : 0,
				atomic64_read(&data->debug_dispatch_returns),
				atomic64_read(&data->debug_finish_entries),
				atomic64_read(&data->debug_complete_entries),
				atomic64_read(&data->debug_requeue_entries),
				atomic_read(&data->switch_draining));
	}
	if (!has_work &&
	    atomic64_read(&data->debug_dispatch_returns) >
	    atomic64_read(&data->debug_complete_entries) +
	    atomic64_read(&data->debug_requeue_entries)) {
		u64 seq = atomic64_inc_return(&data->debug_has_work_false);

		if (IOEXT_DEBUG_VERBOSE && scx_io_debug_should_log(seq))
			ioext_dbg_pr_info(
				"dbg has_work_false seq=%llu hctx=%u bpf_in_flight=%d fallback_in_flight=%d dispatch_returns=%llu finish_entries=%llu complete_entries=%llu requeue_entries=%llu switch_draining=%d\n",
				seq,
				hctx->queue_num,
				atomic_read(&data->bpf_in_flight),
				hdata ? atomic_read(&hdata->fallback_in_flight) : 0,
				atomic64_read(&data->debug_dispatch_returns),
				atomic64_read(&data->debug_finish_entries),
				atomic64_read(&data->debug_complete_entries),
				atomic64_read(&data->debug_requeue_entries),
				atomic_read(&data->switch_draining));
	}
#endif
	return has_work;
}

static void scx_io_requeue_request(struct request *rq)
{
	struct blkcg *owner = NULL;
	struct scx_io_policy *policy;
	struct iosched_rq_ctx ctx = {
		.q = rq ? rq->q : NULL,
		.rq = rq,
		.icq_ptr = rq && rq->elv.icq ? (__u64)rq->elv.icq : 0,
		.ioprio = rq ? req_get_ioprio(rq) : 0,
		.opf = rq ? rq->cmd_flags : 0,
		.sector = rq ? blk_rq_pos(rq) : 0,
		.nr_sectors = rq ? blk_rq_sectors(rq) : 0,
		.hctx_idx = rq && rq->mq_hctx ? rq->mq_hctx->queue_num : 0,
	};

#if IOEXT_DEBUG
	{
		struct scx_io_data *data = scx_io_debug_data(rq ? rq->q : NULL);

		if (data) {
			u64 seq = atomic64_inc_return(&data->debug_requeue_entries);

			if (IOEXT_DEBUG_VERBOSE && scx_io_debug_should_log(seq))
				ioext_dbg_pr_info(
					"dbg requeue_entry seq=%llu rq=%p hctx=%llu opf=%#llx sector=%llu use_sched=%d dispatch_returns=%llu bpf_in_flight=%d switch_draining=%d\n",
					seq,
					rq,
					ctx.hctx_idx,
					ctx.opf,
					(unsigned long long)ctx.sector,
					rq ? !!(rq->rq_flags & RQF_USE_SCHED) : 0,
					atomic64_read(&data->debug_dispatch_returns),
					atomic_read(&data->bpf_in_flight),
					atomic_read(&data->switch_draining));
		}
	}
#endif
	if (!rq || !(rq->rq_flags & RQF_USE_SCHED))
		return;

	rcu_read_lock();
	policy = scx_io_find_policy_for_rq_bio_rcu(rq, NULL, &owner);
	if (policy && policy->ops && policy->ops->requeue_request &&
	    scx_io_policy_is_active(policy))
		policy->ops->requeue_request(&ctx);
	rcu_read_unlock();
}

static IOEXT_MERGE_HOOK bool scx_io_allow_merge(struct request_queue *q, struct request *rq,
				       struct bio *bio)
{
	struct blkcg *owner = NULL;
	struct scx_io_policy *policy;
	struct iosched_allow_merge_ctx ctx = {
		.q = q,
		.rq = rq,
		.bio = bio,
		.rq_ioprio = rq ? req_get_ioprio(rq) : 0,
		.bio_ioprio = bio ? bio->bi_ioprio : 0,
		.rq_sector = rq ? blk_rq_pos(rq) : 0,
		.rq_nr_sectors = rq ? blk_rq_sectors(rq) : 0,
		.bio_sector = bio ? bio->bi_iter.bi_sector : 0,
		.bio_nr_sectors = bio ? bio_sectors(bio) : 0,
		.bio_opf = bio ? bio->bi_opf : 0,
	};
	bool allow = true;

	rcu_read_lock();
	policy = scx_io_find_policy_for_rq_bio_rcu(rq, bio, &owner);
	if (policy && policy->ops && policy->ops->allow_merge &&
	    scx_io_policy_is_active(policy))
		allow = policy->ops->allow_merge(&ctx);
	rcu_read_unlock();

	return allow;
}

static void scx_io_prepare_request(struct request *rq)
{
	struct blkcg *owner = NULL;
	struct scx_io_policy *policy;
	struct iosched_rq_ctx ctx = {
		.q = rq ? rq->q : NULL,
		.rq = rq,
		.icq_ptr = rq && rq->elv.icq ? (__u64)rq->elv.icq : 0,
		.ioprio = rq ? req_get_ioprio(rq) : 0,
		.opf = rq ? rq->cmd_flags : 0,
		.sector = rq ? blk_rq_pos(rq) : 0,
		.nr_sectors = rq ? blk_rq_sectors(rq) : 0,
		.hctx_idx = rq && rq->mq_hctx ? rq->mq_hctx->queue_num : 0,
	};

#if IOEXT_DEBUG
	{
		struct scx_io_data *data = scx_io_debug_data(rq ? rq->q : NULL);

		if (data) {
			u64 seq = atomic64_inc_return(&data->debug_prepare_calls);

			if (IOEXT_DEBUG_VERBOSE && scx_io_debug_should_log(seq))
				ioext_dbg_pr_info(
					"dbg prepare_entry seq=%llu rq=%p hctx=%llu opf=%#llx sector=%llu use_sched=%d dispatch_returns=%llu bpf_in_flight=%d switch_draining=%d\n",
					seq,
					rq,
					ctx.hctx_idx,
					ctx.opf,
					(unsigned long long)ctx.sector,
					rq ? !!(rq->rq_flags & RQF_USE_SCHED) : 0,
					atomic64_read(&data->debug_dispatch_returns),
					atomic_read(&data->bpf_in_flight),
					atomic_read(&data->switch_draining));
		}
	}
#endif
	rcu_read_lock();
	policy = scx_io_find_policy_for_rq_bio_rcu(rq, NULL, &owner);
	if (policy && policy->ops && policy->ops->prepare_request &&
	    scx_io_policy_is_active(policy))
		policy->ops->prepare_request(&ctx);
	rcu_read_unlock();
}

static void scx_io_finish_request(struct request *rq)
{
	struct blkcg *owner = NULL;
	struct scx_io_policy *policy;
	struct iosched_rq_ctx ctx = {
		.q = rq ? rq->q : NULL,
		.rq = rq,
		.icq_ptr = rq && rq->elv.icq ? (__u64)rq->elv.icq : 0,
		.opf = rq ? rq->cmd_flags : 0,
		.hctx_idx = rq && rq->mq_hctx ? rq->mq_hctx->queue_num : 0,
	};

#if IOEXT_DEBUG
	{
		struct scx_io_data *data = scx_io_debug_data(rq ? rq->q : NULL);

		if (data) {
			u64 seq = atomic64_inc_return(&data->debug_finish_entries);

			if (IOEXT_DEBUG_VERBOSE && scx_io_debug_should_log(seq))
				ioext_dbg_pr_info(
					"dbg finish_entry seq=%llu rq=%p hctx=%llu opf=%#llx use_sched=%d dispatch_returns=%llu bpf_in_flight=%d switch_draining=%d\n",
					seq,
					rq,
					ctx.hctx_idx,
					ctx.opf,
					rq ? !!(rq->rq_flags & RQF_USE_SCHED) : 0,
					atomic64_read(&data->debug_dispatch_returns),
					atomic_read(&data->bpf_in_flight),
					atomic_read(&data->switch_draining));
		}
	}
#endif
	if (!rq || !(rq->rq_flags & RQF_USE_SCHED))
		return;

	rcu_read_lock();
	policy = scx_io_find_policy_for_rq_bio_rcu(rq, NULL, &owner);
	if (policy && policy->ops && policy->ops->finish_request &&
	    scx_io_policy_is_active(policy))
		policy->ops->finish_request(&ctx);
	rcu_read_unlock();
}

static void scx_io_completed_request(struct request *rq, u64 now)
{
	struct blkcg *owner = NULL;
	struct iosched_arbiter_ops *arbiter;
	struct scx_io_policy *policy;
	struct iosched_completed_request_ctx ctx = {
		.q = rq ? rq->q : NULL,
		.rq = rq,
		.icq_ptr = rq && rq->elv.icq ? (__u64)rq->elv.icq : 0,
		.ioprio = rq ? req_get_ioprio(rq) : 0,
		.opf = rq ? rq->cmd_flags : 0,
		.sector = rq ? blk_rq_pos(rq) : 0,
		.nr_sectors = rq ? blk_rq_sectors(rq) : 0,
		.hctx_idx = rq && rq->mq_hctx ? rq->mq_hctx->queue_num : 0,
		.cgroup_id = 0,
		.now = now,
		.total_latency_ns = rq && rq->start_time_ns && now >= rq->start_time_ns ?
			now - rq->start_time_ns : 0,
		.io_latency_ns = rq && rq->io_start_time_ns && now >= rq->io_start_time_ns ?
			now - rq->io_start_time_ns : 0,
	};

#if IOEXT_DEBUG
	{
		struct scx_io_data *data = scx_io_debug_data(rq ? rq->q : NULL);

		if (data) {
			u64 seq = atomic64_inc_return(&data->debug_complete_entries);

			if (IOEXT_DEBUG_VERBOSE && scx_io_debug_should_log(seq))
				ioext_dbg_pr_info(
					"dbg complete_entry seq=%llu rq=%p hctx=%llu opf=%#llx sector=%llu use_sched=%d dispatch_returns=%llu total_lat=%llu io_lat=%llu bpf_in_flight=%d switch_draining=%d\n",
					seq,
					rq,
					ctx.hctx_idx,
					ctx.opf,
					(unsigned long long)ctx.sector,
					rq ? !!(rq->rq_flags & RQF_USE_SCHED) : 0,
					atomic64_read(&data->debug_dispatch_returns),
					ctx.total_latency_ns,
					ctx.io_latency_ns,
					atomic_read(&data->bpf_in_flight),
					atomic_read(&data->switch_draining));
		}
	}
#endif
	if (!rq || !(rq->rq_flags & RQF_USE_SCHED))
		return;

	rcu_read_lock();
	policy = scx_io_find_policy_for_rq_bio_rcu(rq, NULL, &owner);
	if (policy)
		ctx.cgroup_id = policy->cgroup_id;
	if (policy && policy->ops && policy->ops->completed_request &&
	    scx_io_policy_is_active(policy))
		policy->ops->completed_request(&ctx);
	arbiter = rcu_dereference(current_arbiter);
	if (arbiter && arbiter->completed_request)
		arbiter->completed_request(&ctx);
	rcu_read_unlock();
}

static IOEXT_MERGE_HOOK bool scx_io_bio_merge(struct request_queue *q, struct bio *bio,
		     unsigned int nr_segs)
{
	struct blk_mq_ctx *mq_ctx;
	struct blk_mq_hw_ctx *hctx;
	struct blkcg *owner = NULL;
	struct scx_io_policy *policy;
	struct iosched_bio_merge_ctx ctx = {
		.q = q,
		.bio = bio,
		.nr_segs = nr_segs,
		.bio_ioprio = bio ? bio->bi_ioprio : 0,
		.bio_sector = bio ? bio->bi_iter.bi_sector : 0,
		.bio_nr_sectors = bio ? bio_sectors(bio) : 0,
		.bio_opf = bio ? bio->bi_opf : 0,
	};
	bool allow_merge = false;
	bool merged;
	enum hctx_type type;

	rcu_read_lock();
	policy = scx_io_find_policy_for_rq_bio_rcu(NULL, bio, &owner);
	if (policy && policy->ops && policy->ops->bio_merge &&
	    scx_io_policy_is_active(policy))
		allow_merge = policy->ops->bio_merge(&ctx);
	rcu_read_unlock();

	if (!allow_merge)
		return false;

	mq_ctx = blk_mq_get_ctx(q);
	hctx = blk_mq_map_queue(bio->bi_opf, mq_ctx);
	type = hctx->type;
	if (list_empty_careful(&mq_ctx->rq_lists[type]))
		return false;

	spin_lock(&mq_ctx->lock);
	merged = blk_bio_list_merge(q, &mq_ctx->rq_lists[type], bio, nr_segs);
	spin_unlock(&mq_ctx->lock);

	return merged;
}

static IOEXT_MERGE_HOOK int scx_io_request_merge(struct request_queue *q,
			struct request **req,
			struct bio *bio)
{
	struct blkcg *owner = NULL;
	struct scx_io_policy *policy;
	struct iosched_request_merge_ctx ctx = {
		.q = q,
		.rq = req ? *req : NULL,
		.bio = bio,
		.rq_ioprio = req && *req ? req_get_ioprio(*req) : 0,
		.bio_ioprio = bio ? bio->bi_ioprio : 0,
		.rq_sector = req && *req ? blk_rq_pos(*req) : 0,
		.rq_nr_sectors = req && *req ? blk_rq_sectors(*req) : 0,
		.bio_sector = bio ? bio->bi_iter.bi_sector : 0,
		.bio_nr_sectors = bio ? bio_sectors(bio) : 0,
		.bio_opf = bio ? bio->bi_opf : 0,
	};
	u64 merge_result = ELEVATOR_NO_MERGE;
	struct request *merge_rq;
	int ret = ELEVATOR_NO_MERGE;

	rcu_read_lock();
	policy = scx_io_find_policy_for_rq_bio_rcu(req ? *req : NULL, bio, &owner);
	if (policy && policy->ops && policy->ops->request_merge &&
	    scx_io_policy_is_active(policy))
		merge_result = policy->ops->request_merge(&ctx);
	rcu_read_unlock();

	ret = IOSCHED_REQUEST_MERGE_TYPE(merge_result);

	if (ret == ELEVATOR_NO_MERGE)
		return ret;

	merge_rq = scx_io_validate_queue_rq(q,
					 IOSCHED_REQUEST_MERGE_RQ_PTR(merge_result));
	if (!merge_rq) {
		ioext_dbg_pr_warn_ratelimited(
			"request_merge returned invalid rq=%#llx\n",
			IOSCHED_REQUEST_MERGE_RQ_PTR(merge_result));
		return ELEVATOR_NO_MERGE;
	}

	if (req)
		*req = merge_rq;

	return ret;
}

static IOEXT_MERGE_HOOK void scx_io_request_merged(struct request_queue *q, struct request *rq,
			 enum elv_merge type)
{
	struct blkcg *owner = NULL;
	struct scx_io_policy *policy;
	struct iosched_request_merged_ctx ctx = {
		.q = q,
		.rq = rq,
		.merge_type = type,
		.rq_ioprio = rq ? req_get_ioprio(rq) : 0,
		.rq_deadline = rq ? rq->fifo_time : 0,
		.rq_sector = rq ? blk_rq_pos(rq) : 0,
		.rq_nr_sectors = rq ? blk_rq_sectors(rq) : 0,
	};

	rcu_read_lock();
	policy = scx_io_find_policy_for_rq_bio_rcu(rq, NULL, &owner);
	if (policy && policy->ops && policy->ops->request_merged &&
	    scx_io_policy_is_active(policy))
		policy->ops->request_merged(&ctx);
	rcu_read_unlock();
}

static IOEXT_MERGE_HOOK void scx_io_requests_merged(struct request_queue *q, struct request *rq,
			  struct request *next)
{
	struct blkcg *owner = NULL;
	struct scx_io_policy *policy;
	struct iosched_requests_merged_ctx ctx = {
		.q = q,
		.rq = rq,
		.next = next,
		.rq_ioprio = rq ? req_get_ioprio(rq) : 0,
		.next_ioprio = next ? req_get_ioprio(next) : 0,
		.rq_deadline = rq ? rq->fifo_time : 0,
		.next_deadline = next ? next->fifo_time : 0,
		.rq_sector = rq ? blk_rq_pos(rq) : 0,
		.rq_nr_sectors = rq ? blk_rq_sectors(rq) : 0,
		.next_sector = next ? blk_rq_pos(next) : 0,
		.next_nr_sectors = next ? blk_rq_sectors(next) : 0,
	};

	rcu_read_lock();
	policy = scx_io_find_policy_for_rq_bio_rcu(rq, NULL, &owner);
	if (policy && policy->ops && policy->ops->requests_merged &&
	    scx_io_policy_is_active(policy))
		policy->ops->requests_merged(&ctx);
	rcu_read_unlock();
}

static void scx_io_limit_depth(unsigned int op, struct blk_mq_alloc_data *data)
{
	struct blkcg *owner = NULL;
	struct scx_io_policy *policy;
	struct io_cq *icq = NULL;
	struct iosched_limit_depth_ctx ctx = {
		.q = data ? data->q : NULL,
		.data = data,
		.ioprio = get_current_ioprio(),
		.opf = op,
		.hctx_idx = data && data->hctx ? data->hctx->queue_num : 0,
		.async_depth = data && data->q ? data->q->async_depth : 0,
	};
	u64 shallow_depth = 0;

	if (data && data->q && current->io_context)
		icq = ioc_lookup_icq(data->q);
	ctx.icq_ptr = (u64)icq;

	rcu_read_lock();
	policy = scx_io_find_policy_for_current_rcu(&owner);
	if (policy && policy->ops && policy->ops->limit_depth &&
	    scx_io_policy_is_active(policy))
		shallow_depth = policy->ops->limit_depth(&ctx);
	rcu_read_unlock();

	if (data && shallow_depth)
		data->shallow_depth = shallow_depth > USHRT_MAX ?
			USHRT_MAX : (unsigned short)shallow_depth;
}

static void scx_io_depth_updated(struct request_queue *q)
{
	struct scx_io_policy *policy;
	struct iosched_depth_updated_ctx ctx = {
		.q = q,
		.nr_requests = q ? q->nr_requests : 0,
		.async_depth = q ? q->async_depth : 0,
	};

	if (q)
		blk_mq_set_min_shallow_depth(q, 1);

	rcu_read_lock();
	policy = scx_io_policy_read_rcu(&blkcg_root);
	if (policy && policy->ops && policy->ops->depth_updated &&
	    scx_io_policy_is_active(policy))
		policy->ops->depth_updated(&ctx);
	rcu_read_unlock();
}

static void scx_io_init_icq(struct io_cq *icq)
{
	struct scx_io_policy *policy;
	struct iosched_icq_ctx ctx = {
		.q = icq ? icq->q : NULL,
		.icq = icq,
	};

	rcu_read_lock();
	policy = scx_io_policy_read_rcu(&blkcg_root);
	if (policy && policy->ops && policy->ops->init_icq &&
	    scx_io_policy_is_active(policy))
		policy->ops->init_icq(&ctx);
	rcu_read_unlock();
}

static void scx_io_exit_icq(struct io_cq *icq)
{
	struct scx_io_policy *policy;
	struct iosched_icq_ctx ctx = {
		.q = icq ? icq->q : NULL,
		.icq = icq,
	};

	rcu_read_lock();
	policy = scx_io_policy_read_rcu(&blkcg_root);
	if (policy && policy->ops && policy->ops->exit_icq &&
	    scx_io_policy_is_active(policy))
		policy->ops->exit_icq(&ctx);
	rcu_read_unlock();
}

static IOEXT_MERGE_HOOK struct request *scx_io_former_request(struct request_queue *q,
			     struct request *rq)
{
	struct blkcg *owner = NULL;
	struct scx_io_policy *policy;
	struct iosched_rq_ctx ctx = {
		.q = q,
		.rq = rq,
		.icq_ptr = rq && rq->elv.icq ? (__u64)rq->elv.icq : 0,
		.ioprio = rq ? req_get_ioprio(rq) : 0,
		.opf = rq ? rq->cmd_flags : 0,
		.sector = rq ? blk_rq_pos(rq) : 0,
		.nr_sectors = rq ? blk_rq_sectors(rq) : 0,
		.hctx_idx = rq && rq->mq_hctx ? rq->mq_hctx->queue_num : 0,
	};
	u64 rq_ptr = 0;

	rcu_read_lock();
	policy = scx_io_find_policy_for_rq_bio_rcu(rq, NULL, &owner);
	if (policy && policy->ops && policy->ops->former_request &&
	    scx_io_policy_is_active(policy))
		rq_ptr = policy->ops->former_request(&ctx);
	rcu_read_unlock();

	if (!rq_ptr)
		return NULL;

	rq = scx_io_validate_queue_rq(q, rq_ptr);
	if (!rq)
		ioext_dbg_pr_warn_ratelimited(
			"former_request returned invalid rq_ptr=%#llx\n",
			rq_ptr);

	return rq;
}

static IOEXT_MERGE_HOOK struct request *scx_io_next_request(struct request_queue *q,
			   struct request *rq)
{
	struct blkcg *owner = NULL;
	struct scx_io_policy *policy;
	struct iosched_rq_ctx ctx = {
		.q = q,
		.rq = rq,
		.icq_ptr = rq && rq->elv.icq ? (__u64)rq->elv.icq : 0,
		.ioprio = rq ? req_get_ioprio(rq) : 0,
		.opf = rq ? rq->cmd_flags : 0,
		.sector = rq ? blk_rq_pos(rq) : 0,
		.nr_sectors = rq ? blk_rq_sectors(rq) : 0,
		.hctx_idx = rq && rq->mq_hctx ? rq->mq_hctx->queue_num : 0,
	};
	u64 rq_ptr = 0;

	rcu_read_lock();
	policy = scx_io_find_policy_for_rq_bio_rcu(rq, NULL, &owner);
	if (policy && policy->ops && policy->ops->next_request &&
	    scx_io_policy_is_active(policy))
		rq_ptr = policy->ops->next_request(&ctx);
	rcu_read_unlock();

	if (!rq_ptr)
		return NULL;

	rq = scx_io_validate_queue_rq(q, rq_ptr);
	if (!rq)
		ioext_dbg_pr_warn_ratelimited(
			"next_request returned invalid rq_ptr=%#llx\n",
			rq_ptr);

	return rq;
}

static int iosched_arbiter_reg(void *kdata, struct bpf_link *link)
{
	struct iosched_arbiter_ops *ops = kdata;
	struct iosched_arbiter_ops *old;

	mutex_lock(&arbiter_lock);
	old = rcu_dereference_protected(current_arbiter,
					lockdep_is_held(&arbiter_lock));
	rcu_assign_pointer(current_arbiter, ops);
	synchronize_rcu();
	mutex_unlock(&arbiter_lock);

	ioext_dbg_pr_info("arbiter '%s' %s\n",
		ops->name[0] != '\0' ? ops->name : "unnamed",
		old ? "replaced previous arbiter" : "attached");
	return 0;
}

static void iosched_arbiter_unreg(void *kdata, struct bpf_link *link)
{
	mutex_lock(&arbiter_lock);
	if (rcu_access_pointer(current_arbiter) == kdata) {
		RCU_INIT_POINTER(current_arbiter, NULL);
		synchronize_rcu();
		ioext_dbg_pr_info("arbiter detached\n");
	}
	mutex_unlock(&arbiter_lock);
}

static u64 iosched_arbiter_pick_cgroup_stub(struct iosched_arbiter_dispatch_ctx *ctx)
{
	return 0;
}

static bool iosched_arbiter_hold_dispatch_stub(struct iosched_arbiter_dispatch_ctx *ctx)
{
	return false;
}

static void iosched_arbiter_completed_request_stub(struct iosched_completed_request_ctx *ctx)
{
}

static struct iosched_arbiter_ops arbiter_cfi_stubs = {
	.pick_cgroup = iosched_arbiter_pick_cgroup_stub,
	.hold_dispatch = iosched_arbiter_hold_dispatch_stub,
	.completed_request = iosched_arbiter_completed_request_stub,
};

static bool iosched_arbiter_is_valid_access(int off, int size,
					    enum bpf_access_type type,
					    const struct bpf_prog *prog,
					    struct bpf_insn_access_aux *info)
{
	u32 member_idx;

	if (type != BPF_READ)
		return false;
	if (off % size != 0)
		return false;
	if (size != sizeof(u64))
		return false;

	member_idx = prog->expected_attach_type;
	switch (member_idx) {
	case 0:
		if (off == 0) {
			info->reg_type = PTR_TO_BTF_ID | PTR_TRUSTED;
			info->btf = bpf_get_btf_vmlinux();
			info->btf_id = btf_find_by_name_kind(info->btf,
						     "iosched_arbiter_dispatch_ctx",
						     BTF_KIND_STRUCT);
			return info->btf_id > 0;
		}
		return false;
	case 1:
		if (off == 0) {
			info->reg_type = PTR_TO_BTF_ID | PTR_TRUSTED;
			info->btf = bpf_get_btf_vmlinux();
			info->btf_id = btf_find_by_name_kind(info->btf,
						     "iosched_arbiter_dispatch_ctx",
						     BTF_KIND_STRUCT);
			return info->btf_id > 0;
		}
		return false;
	case 2:
		if (off == 0) {
			info->reg_type = PTR_TO_BTF_ID | PTR_TRUSTED;
			info->btf = bpf_get_btf_vmlinux();
			info->btf_id = btf_find_by_name_kind(info->btf,
						     "iosched_completed_request_ctx",
						     BTF_KIND_STRUCT);
			return info->btf_id > 0;
		}
		return false;
	default:
		return false;
	}
}

static const struct bpf_verifier_ops iosched_arbiter_verifier_ops = {
	.get_func_proto = iosched_bpf_get_func_proto,
	.is_valid_access = iosched_arbiter_is_valid_access,
	.btf_struct_access = iosched_bpf_btf_struct_access,
};

static struct bpf_struct_ops iosched_arbiter_bpf_ops __used = {
	.verifier_ops = &iosched_arbiter_verifier_ops,
	.init         = iosched_bpf_init,
	.check_member = iosched_bpf_check_member,
	.init_member  = iosched_bpf_init_member,
	.reg          = iosched_arbiter_reg,
	.unreg        = iosched_arbiter_unreg,
	.name         = "iosched_arbiter_ops",
	.owner        = THIS_MODULE,
	.cfi_stubs    = &arbiter_cfi_stubs,
};

static struct elevator_type scx_io_elevator = {
	.ops = {
		.init_sched       = scx_io_init_sched,
		.exit_sched       = scx_io_exit_sched,
		.prepare_switch   = scx_io_prepare_switch,
		.init_hctx        = scx_io_init_hctx,
		.exit_hctx        = scx_io_exit_hctx,
		.alloc_sched_data = scx_io_alloc_sched_data,
		.free_sched_data  = scx_io_free_sched_data,
		.allow_merge      = scx_io_allow_merge,
		.bio_merge        = scx_io_bio_merge,
		.bio_should_bypass = scx_io_bio_bypass,
		.request_merge    = scx_io_request_merge,
		.request_merged   = scx_io_request_merged,
		.requests_merged  = scx_io_requests_merged,
		.limit_depth      = scx_io_limit_depth,
		.depth_updated    = scx_io_depth_updated,
		.prepare_request  = scx_io_prepare_request,
		.finish_request   = scx_io_finish_request,
		.insert_requests  = scx_io_insert_requests,
		.dispatch_request = scx_io_dispatch_request,
		.requeue_request  = scx_io_requeue_request,
		.has_work         = scx_io_has_work,
		.completed_request = scx_io_completed_request,
		.former_request   = scx_io_former_request,
		.next_request     = scx_io_next_request,
		.init_icq         = scx_io_init_icq,
		.exit_icq         = scx_io_exit_icq,
	},
	.icq_size = sizeof(struct io_cq),
	.icq_align = __alignof__(struct io_cq),
	.elevator_name = "scx_io",
	.elevator_owner = THIS_MODULE,
};

int __init iosched_ext_init(void)
{
	int ret;

	scx_io_teardown_wq = alloc_workqueue("scx_io_teardown",
					     WQ_UNBOUND | WQ_MEM_RECLAIM,
					     0);
	if (!scx_io_teardown_wq)
		return -ENOMEM;

	ret = blkcg_policy_register(&scx_io_blkcg_policy);
	if (ret)
		goto out_destroy_wq;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					 &scx_io_kfunc_set);
	if (ret)
		goto out_blkcg_policy_unreg;

	ret = elv_register(&scx_io_elevator);
	if (ret) {
		goto out_blkcg_policy_unreg;
	}

	ret = register_bpf_struct_ops(&iosched_ext_bpf_ops, iosched_ext_ops);
	if (ret)
		goto out_elv_unreg;

	ret = register_bpf_struct_ops(&iosched_arbiter_bpf_ops, iosched_arbiter_ops);
	if (ret)
		goto out_elv_unreg;

	ioext_dbg_pr_info("'scx_io' elevator registered successfully\n");
	ioext_dbg_pr_info("BPF struct_ops ready\n");
	return 0;

out_elv_unreg:
	elv_unregister(&scx_io_elevator);
	out_blkcg_policy_unreg:
	blkcg_policy_unregister(&scx_io_blkcg_policy);
	out_destroy_wq:
	destroy_workqueue(scx_io_teardown_wq);
	scx_io_teardown_wq = NULL;
	return ret;
}

static void __exit iosched_ext_exit(void)
{
	flush_workqueue(scx_io_teardown_wq);
	destroy_workqueue(scx_io_teardown_wq);
	scx_io_teardown_wq = NULL;
	elv_unregister(&scx_io_elevator);
	blkcg_policy_unregister(&scx_io_blkcg_policy);
}

module_init(iosched_ext_init);
module_exit(iosched_ext_exit);
