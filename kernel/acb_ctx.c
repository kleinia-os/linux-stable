// SPDX-License-Identifier: GPL-2.0
/*
 * Cnode — kernel-managed agent context (kernel/acb_ctx.c)
 *
 * Design contract (docs/cnode-design.md):
 *
 *  1. The segment log is ground truth: immutable, append-only.
 *     Compaction never rewrites history — it shadows a seq range and
 *     appends a replacement; the model-visible view is a derivation
 *     (READ skips shadowed segments by default).
 *
 *  2. Payloads live in kernel memory bounded by the cnode quota — the
 *     deliberate inversion of file-backed harness logs (dsh): a kernel
 *     append is transactional and single-writer by construction, and
 *     survives member process death.  Reboot persistence is a
 *     user-space checkpoint policy (dump via READ, re-seed via
 *     APPEND), not a kernel concern.
 *
 *  3. Crash recovery: acb_ctx_on_member_exit() synthesizes closers
 *     for unclosed tool calls plus an interrupted turn marker at the
 *     moment of member death.  Side-effect classification rides the
 *     CHECKPOINT barrier: a barrier after an unclosed tool call means
 *     the effect may have happened (OUTCOME_UNKNOWN); no barrier
 *     means NOT_STARTED (safe to retry).
 *
 *  4. Quota: appends beyond quota fail -ENOSPC once (the owner gets a
 *     single ACB_EVT_CTX_PRESSURE per over-quota crossing); the
 *     tiered response — prune, summarize, GC, fail closed — is
 *     user-space policy.  The kernel is the enforcement point and the
 *     singleton pressure authority.
 */

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/acb.h>
#include <trace/events/acb.h>

#define ACB_CTX_DEFAULT_QUOTA	(8U << 20)	/* 8 MiB */

/* closer outcomes, encoded into the synthesized LOG_CLOSER payload */
#define ACB_CTX_CLOSER_NOT_STARTED	"tool_outcome=not_started"
#define ACB_CTX_CLOSER_UNKNOWN		"tool_outcome=unknown"
#define ACB_CTX_CLOSER_TURN		"turn=interrupted"

struct acb_ctx *acb_ctx_alloc(void)
{
	struct acb_ctx *ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);

	if (!ctx)
		return NULL;
	mutex_init(&ctx->lock);
	INIT_LIST_HEAD(&ctx->segs);
	ctx->quota = ACB_CTX_DEFAULT_QUOTA;
	ctx->next_seq = 1;	/* seq 0 is the READ cursor "begin" sentinel */
	return ctx;
}

void acb_ctx_free(struct acb_ctx *ctx)
{
	struct acb_ctx_seg *seg, *n;

	if (!ctx)
		return;
	list_for_each_entry_safe(seg, n, &ctx->segs, node) {
		list_del(&seg->node);
		kvfree(seg->data);
		kfree(seg);
	}
	kfree(ctx);
}

/* caller holds ctx->lock */
static struct acb_ctx_seg *__seg_append(struct acb_ctx *ctx, u32 class,
					u32 flags, u64 origin_req,
					u64 origin_aid,
					const char *origin_skill,
					const char *data, size_t len)
{
	struct acb_ctx_seg *seg;

	if (len > ACB_CTX_MAX_SEG)
		return ERR_PTR(-EMSGSIZE);
	if (ctx->quota && ctx->bytes + len > ctx->quota)
		return ERR_PTR(-ENOSPC);

	seg = kzalloc(sizeof(*seg), GFP_KERNEL);
	if (!seg)
		return ERR_PTR(-ENOMEM);
	if (len) {
		seg->data = kvmalloc(len, GFP_KERNEL_ACCOUNT);
		if (!seg->data) {
			kfree(seg);
			return ERR_PTR(-ENOMEM);
		}
		memcpy(seg->data, data, len);
	}
	seg->seq = ctx->next_seq++;
	seg->cls = class;
	seg->flags = flags;
	seg->origin_req = origin_req;
	seg->origin_aid = origin_aid;
	if (origin_skill)
		strscpy(seg->origin_skill, origin_skill, ACB_SKILL_MAX);
	seg->len = len;

	list_add_tail(&seg->node, &ctx->segs);
	ctx->bytes += len;
	return seg;
}

/* in-kernel append (crash closers, GC bookkeeping); no quota bypass */
int acb_ctx_append(struct acb *acb, u32 class, u32 flags, u64 origin_req,
		   u64 origin_aid, const char *origin_skill,
		   const char *data, size_t len, u64 *seqp)
{
	struct acb_ctx *ctx = acb->ctx;
	struct acb_ctx_seg *seg;

	if (!ctx)
		return -ENOENT;

	mutex_lock(&ctx->lock);
	seg = __seg_append(ctx, class, flags, origin_req, origin_aid,
			   origin_skill, data, len);
	mutex_unlock(&ctx->lock);
	if (IS_ERR(seg))
		return PTR_ERR(seg);
	if (seqp)
		*seqp = seg->seq;
	return 0;
}

static bool __in_range(u64 seq, u64 start, u64 end)
{
	return seq >= start && seq <= end;
}

/* pressure event push lives in acb.c where the mailbox push is */

/* ------------------------------------------------------------------ */
/* ioctl handlers                                                      */

int acb_ctx_ioctl_setquota(struct acb *acb, unsigned long arg)
{
	struct acb_ctx *ctx = acb->ctx;
	unsigned long q;

	if (!ctx)
		return -ENOENT;
	if (copy_from_user(&q, (void __user *)arg, sizeof(q)))
		return -EFAULT;
	mutex_lock(&ctx->lock);
	ctx->quota = q;
	if (q && ctx->bytes > q)
		ctx->over_quota = true;
	else
		ctx->over_quota = false;
	mutex_unlock(&ctx->lock);
	return 0;
}

int acb_ctx_ioctl_append(struct acb *acb, unsigned long arg)
{
	struct acb_ctx *ctx = acb->ctx;
	struct acb_ctx_append a;
	struct acb_ctx_seg *seg;
	bool pressure = false;
	char *kbuf = NULL;
	u64 seq;
	int ret;

	if (!ctx)
		return -ENOENT;
	if (copy_from_user(&a, (void __user *)arg, sizeof(a)))
		return -EFAULT;
	if (a.hdr.len > ACB_CTX_MAX_SEG)
		return -EMSGSIZE;
	if (a.hdr.len) {
		kbuf = kvmalloc(a.hdr.len, GFP_KERNEL);
		if (!kbuf)
			return -ENOMEM;
		if (copy_from_user(kbuf, u64_to_user_ptr(a.data_ptr),
				   a.hdr.len)) {
			kvfree(kbuf);
			return -EFAULT;
		}
	}

	mutex_lock(&ctx->lock);
	seg = __seg_append(ctx, a.hdr.cls, a.hdr.flags, a.hdr.origin_req,
			   a.hdr.origin_aid, a.hdr.origin_skill, kbuf,
			   a.hdr.len);
	if (IS_ERR(seg))
		pressure = (PTR_ERR(seg) == -ENOSPC) && !ctx->over_quota;
	else if (ctx->over_quota && (!ctx->quota || ctx->bytes <= ctx->quota))
		ctx->over_quota = false;
	mutex_unlock(&ctx->lock);

	if (IS_ERR(seg)) {
		kvfree(kbuf);
		if (pressure)
			acb_ctx_pressure_event(acb);
		return PTR_ERR(seg);
	}

	seq = seg->seq;
	kvfree(kbuf);

	trace_acb_ctx_append(acb->aid, seq, seg->cls, seg->len);

	a.hdr.seq = seq;
	a.hdr.flags = seg->flags;
	a.hdr.len = seg->len;
	ret = copy_to_user((void __user *)arg, &a, sizeof(a)) ? -EFAULT : 0;
	return ret;
}

/* shadow [start,end] (inclusive) and append the replacement, atomically */
int acb_ctx_ioctl_compact(struct acb *acb, unsigned long arg)
{
	struct acb_ctx *ctx = acb->ctx;
	struct acb_ctx_compact c;
	struct acb_ctx_seg *seg, *rep;
	char *kbuf = NULL;
	int shadowed = 0;
	int ret;

	if (!ctx)
		return -ENOENT;
	if (copy_from_user(&c, (void __user *)arg, sizeof(c)))
		return -EFAULT;
	if (c.hdr.len > ACB_CTX_MAX_SEG)
		return -EMSGSIZE;
	if (c.end_seq < c.start_seq)
		return -EINVAL;
	if (c.hdr.len) {
		kbuf = kvmalloc(c.hdr.len, GFP_KERNEL);
		if (!kbuf)
			return -ENOMEM;
		if (copy_from_user(kbuf, u64_to_user_ptr(c.data_ptr),
				   c.hdr.len)) {
			kvfree(kbuf);
			return -EFAULT;
		}
	}

	mutex_lock(&ctx->lock);
	list_for_each_entry(seg, &ctx->segs, node) {
		if (__in_range(seg->seq, c.start_seq, c.end_seq) &&
		    !(seg->flags & ACB_CTX_F_SHADOWED)) {
			seg->flags |= ACB_CTX_F_SHADOWED;
			ctx->shadowed_bytes += seg->len;
			shadowed++;
		}
	}
	if (!shadowed) {
		mutex_unlock(&ctx->lock);
		kvfree(kbuf);
		return -ENOENT;
	}
	rep = __seg_append(ctx, c.hdr.cls, c.hdr.flags | ACB_CTX_F_REPLACEMENT,
			   c.hdr.origin_req, c.hdr.origin_aid,
			   c.hdr.origin_skill, kbuf, c.hdr.len);
	mutex_unlock(&ctx->lock);
	kvfree(kbuf);

	if (IS_ERR(rep))
		return PTR_ERR(rep);

	trace_acb_ctx_compact(acb->aid, c.start_seq, c.end_seq, shadowed);

	c.hdr.seq = rep->seq;
	c.hdr.flags = rep->flags;
	ret = copy_to_user((void __user *)arg, &c, sizeof(c)) ? -EFAULT : 0;
	return ret;
}

/* drop shadowed payload strictly below the watermark; tombstones stay */
int acb_ctx_ioctl_gc(struct acb *acb, unsigned long arg)
{
	struct acb_ctx *ctx = acb->ctx;
	u64 watermark;
	struct acb_ctx_seg *seg;
	u64 freed = 0;

	if (!ctx)
		return -ENOENT;
	if (copy_from_user(&watermark, (void __user *)arg, sizeof(watermark)))
		return -EFAULT;

	mutex_lock(&ctx->lock);
	list_for_each_entry(seg, &ctx->segs, node) {
		if (seg->seq >= watermark)
			continue;
		if ((seg->flags & ACB_CTX_F_SHADOWED) && seg->data) {
			kvfree(seg->data);
			seg->data = NULL;
			ctx->bytes -= seg->len;
			ctx->shadowed_bytes -= seg->len;
			seg->len = 0;
			seg->flags &= ~ACB_CTX_F_SHADOWED;
			seg->flags |= 1U << 31;	/* GC tombstone */
			freed += 1;
		}
	}
	if (ctx->over_quota && (!ctx->quota || ctx->bytes <= ctx->quota))
		ctx->over_quota = false;
	mutex_unlock(&ctx->lock);

	acb_ctx_append(acb, ACB_CTX_LOG_GC, 0, 0, 0, "gc", NULL, 0, NULL);
	trace_acb_ctx_gc(acb->aid, watermark, freed);
	return (int)freed;
}

int acb_ctx_ioctl_read(struct acb *acb, unsigned long arg)
{
	struct acb_ctx *ctx = acb->ctx;
	struct acb_ctx_read r;
	struct acb_ctx_seg *seg;
	bool found = false;
	int ret = 0;

	if (!ctx)
		return -ENOENT;
	if (copy_from_user(&r, (void __user *)arg, sizeof(r)))
		return -EFAULT;

	mutex_lock(&ctx->lock);
	list_for_each_entry(seg, &ctx->segs, node) {
		if (seg->seq <= r.cursor_seq)
			continue;
		if (!(r.flags & ACB_CTX_RF_INCLUDE_SHADOWED) &&
		    (seg->flags & ACB_CTX_F_SHADOWED))
			continue;
		found = true;
		break;
	}
	if (!found) {
		mutex_unlock(&ctx->lock);
		r.cursor_seq = 0;
		r.payload_len = 0;
		memset(&r.hdr, 0, sizeof(r.hdr));
		goto out;
	}

	r.hdr.seq = seg->seq;
	r.hdr.cls = seg->cls;
	r.hdr.flags = seg->flags;
	r.hdr.origin_req = seg->origin_req;
	r.hdr.origin_aid = seg->origin_aid;
	memcpy(r.hdr.origin_skill, seg->origin_skill, ACB_SKILL_MAX);
	r.hdr.len = seg->len;

	if (seg->len == 0) {
		r.payload_len = 0;
		r.cursor_seq = seg->seq;
	} else if (seg->len > r.len_cap) {
		/* cursor stays BEFORE the seg: a retry with a bigger
		 * buffer re-reads the same segment */
		r.payload_len = -E2BIG;
		r.cursor_seq = seg->seq - 1;
	} else {
		if (copy_to_user(u64_to_user_ptr(r.data_ptr), seg->data,
				 seg->len))
			ret = -EFAULT;
		r.payload_len = (s32)seg->len;
		r.cursor_seq = seg->seq;
	}
	mutex_unlock(&ctx->lock);

out:
	if (!ret)
		ret = copy_to_user((void __user *)arg, &r, sizeof(r)) ?
		      -EFAULT : 0;
	return ret;
}

int acb_ctx_ioctl_info(struct acb *acb, unsigned long arg)
{
	struct acb_ctx *ctx = acb->ctx;
	struct acb_ctx_info info;
	struct acb_ctx_seg *seg;

	if (!ctx)
		return -ENOENT;

	mutex_lock(&ctx->lock);
	memset(&info, 0, sizeof(info));
	info.quota = ctx->quota;
	info.bytes = ctx->bytes;
	info.shadowed_bytes = ctx->shadowed_bytes;
	info.head_seq = ctx->next_seq ? ctx->next_seq - 1 : 0;
	info.parent_aid = ctx->parent_aid;
	info.depth = ctx->depth;
	list_for_each_entry(seg, &ctx->segs, node) {
		info.nsegs++;
		if (seg->cls == ACB_CTX_LOG_TURN_END &&
		    !(seg->flags & ACB_CTX_F_SHADOWED))
			info.last_turn_seq = seg->seq;
	}
	mutex_unlock(&ctx->lock);

	return copy_to_user((void __user *)arg, &info, sizeof(info)) ?
	       -EFAULT : 0;
}

/*
 * Fork: copy the balanced prefix (up to the last TURN_END) into an
 * existing, empty child ACB.  Seq numbers are preserved — the child's
 * log continues the parent's numbering space, keeping lineage greppable.
 */
static DEFINE_MUTEX(acb_ctx_fork_lock);

int acb_ctx_ioctl_fork(struct acb *acb, struct file *child_file,
		       unsigned long arg)
{
	struct acb_ctx *pctx = acb->ctx;
	struct acb_ctx_fork f;
	struct acb *child = child_file->private_data;
	struct acb_ctx *cctx;
	struct acb_ctx_seg *seg;
	u64 boundary;

	if (!pctx || !child || child == acb)
		return -EINVAL;
	cctx = child->ctx;
	if (!cctx)
		return -ENOENT;
	if (copy_from_user(&f, (void __user *)arg, sizeof(f)))
		return -EFAULT;

	/* serialize forks: pctx->cctx ordering would deadlock on
	 * concurrent fork(A,B) vs fork(B,A) */
	mutex_lock(&acb_ctx_fork_lock);
	mutex_lock(&pctx->lock);
	mutex_lock(&cctx->lock);
	if (!list_empty(&cctx->segs)) {	/* next_seq==1 is the empty baseline */
		mutex_unlock(&cctx->lock);
		mutex_unlock(&pctx->lock);
		mutex_unlock(&acb_ctx_fork_lock);
		return -ENOTEMPTY;
	}

	boundary = 0;
	list_for_each_entry(seg, &pctx->segs, node)
		if (seg->cls == ACB_CTX_LOG_TURN_END &&
		    !(seg->flags & ACB_CTX_F_SHADOWED))
			boundary = seg->seq;
	if (!boundary) {
		mutex_unlock(&cctx->lock);
		mutex_unlock(&pctx->lock);
		mutex_unlock(&acb_ctx_fork_lock);
		return -ENOENT;		/* no balanced boundary to fork at */
	}

	list_for_each_entry(seg, &pctx->segs, node) {
		struct acb_ctx_seg *copy;

		if (seg->seq > boundary)
			break;
		copy = kzalloc(sizeof(*copy), GFP_KERNEL);
		if (!copy)
			break;
		*copy = *seg;
		if (seg->len) {
			copy->data = kvmalloc(seg->len, GFP_KERNEL_ACCOUNT);
			if (copy->data)
				memcpy(copy->data, seg->data, seg->len);
			else
				copy->len = 0;
		}
		INIT_LIST_HEAD(&copy->node);
		list_add_tail(&copy->node, &cctx->segs);
		cctx->bytes += copy->len;
	}
	cctx->next_seq = boundary + 1;
	cctx->parent_aid = acb->aid;
	cctx->depth = pctx->depth + 1;
	mutex_unlock(&cctx->lock);
	mutex_unlock(&pctx->lock);
	mutex_unlock(&acb_ctx_fork_lock);

	return 0;
}

int acb_ctx_ioctl_barrier(struct acb *acb)
{
	return acb_ctx_append(acb, ACB_CTX_LOG_CHECKPOINT, 0, 0, acb->aid,
			      "barrier", NULL, 0, NULL);
}

/* ------------------------------------------------------------------ */
/* crash recovery: synthesize closers at member death                  */

int acb_ctx_on_member_exit(struct acb *acb)
{
	struct acb_ctx *ctx = acb->ctx;
	struct acb_ctx_seg *seg, *open_call = NULL, *last = NULL;
	bool barrier_after_call = false;

	if (!ctx)
		return 0;

	mutex_lock(&ctx->lock);
	list_for_each_entry(seg, &ctx->segs, node) {
		if (seg->flags & (ACB_CTX_F_SHADOWED | 1U << 31))
			continue;
		if (seg->cls == ACB_CTX_LOG_TOOL_CALL) {
			open_call = seg;
			barrier_after_call = false;
		} else if (seg->cls == ACB_CTX_SURF_TOOL) {
			open_call = NULL;		/* closed */
		} else if (seg->cls == ACB_CTX_LOG_CHECKPOINT && open_call) {
			barrier_after_call = true;	/* effect may exist */
		}
		last = seg;
	}
	mutex_unlock(&ctx->lock);

	/* only synthesize for tail-of-log interruptions */
	/*
	 * Closers are forensic records of interrupted WORK, not of process
	 * death itself: synthesize only when an unclosed tool call hangs at
	 * the tail.  Without this guard every short-lived member exit (MCP
	 * server subprocesses, agentctl children inherited via fork)
	 * pollutes the log with meaningless turn=interrupted markers —
	 * found by ctxstress (2000 appends + 4 spurious closers).
	 */
	if (!open_call)
		return 0;
	{
		const char *outcome = barrier_after_call ?
			ACB_CTX_CLOSER_UNKNOWN : ACB_CTX_CLOSER_NOT_STARTED;

		acb_ctx_append(acb, ACB_CTX_LOG_CLOSER, 0, 0, 0,
			       open_call->origin_skill, outcome,
			       strlen(outcome), NULL);
		acb_ctx_append(acb, ACB_CTX_LOG_TURN_END, 0, 0, 0, "closer",
			       ACB_CTX_CLOSER_TURN,
			       sizeof(ACB_CTX_CLOSER_TURN) - 1, NULL);
		trace_acb_ctx_closer(acb->aid, open_call->seq,
				     barrier_after_call);
	}
	return 0;
}
