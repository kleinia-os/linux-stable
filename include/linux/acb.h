/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_ACB_H
#define _LINUX_ACB_H

#include <linux/refcount.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <uapi/linux/acb.h>

struct dentry;
struct file;
struct inode;
struct task_struct;

/*
 * Agent Control Block (ACB) — kernel object behind every agent.
 *
 * Identity: kernel-minted monotonic AID + registry-unique name.
 * Members:  tasks attached via acb_attach(); children inherit at fork.
 * Skills:   descriptors published by the owner, exposed via agentfs.
 * Mailbox:  skill RPC requests + subscribed hook events, drained by
 *           the owner through the agentfd (poll/ioctl).
 *
 * Lifetime: references are held by the agentfd, every member task
 * (task_struct->acb) and the registry.  When the agentfd is closed
 * and the last member exits (or an explicit kill happens), the agent
 * is destroyed: pending requests fail with -EPIPE and
 * ACB_EVT_AGENT_DESTROY is broadcast to subscribers.
 */

struct acb_member {
	struct list_head	node;
	pid_t			pid;
	char			comm[16];
};

struct acb_skill {
	struct list_head	node;
	refcount_t		refcnt;
	struct acb		*acb;			/* owning agent */
	char			name[ACB_SKILL_MAX];
	char			*schema;
	size_t			schema_len;
	struct dentry		*dentry;		/* skills/<name> */
	struct dentry		*d_schema;
	struct dentry		*d_invoke;
};

/* in-flight kernel-mediated skill invocation */
struct acb_req {
	struct list_head	node;
	refcount_t		refcnt;			/* client + queue */
	u64			id;
	u64			caller_aid;
	struct acb		*target;
	char			skill[ACB_SKILL_MAX];
	char			*buf;
	size_t			len;
	char			*reply;
	size_t			reply_len;
	bool			served;			/* popped by owner */
	bool			replied;
	bool			failed;
	struct completion	done;
};

struct acb_evt {
	struct list_head	node;
	struct acb_event	evt;
};

/* kernel-internal context segment (cnode) */
struct acb_ctx_seg {
	struct list_head	node;
	u64			seq;
	u32			cls;
	u32			flags;
	u64			origin_req;
	u64			origin_aid;
	char			origin_skill[ACB_SKILL_MAX];
	size_t			len;
	char			*data;
};

struct acb_ctx {
	struct mutex		lock;		/* guards everything below */
	struct list_head	segs;		/* seq-ordered acb_ctx_seg */
	u64			next_seq;
	u64			bytes;		/* payload bytes incl. shadowed */
	u64			shadowed_bytes;
	u64			quota;		/* 0 = unlimited */
	u64			parent_aid;
	u32			depth;
	bool			over_quota;	/* pressure event edge */
};

struct acb {
	u64			aid;
	char			name[ACB_NAME_MAX];
	u8			class;			/* ACB_CLASS_* */
	unsigned long		caps;			/* ACB_CAP_* */
	unsigned long		evt_mask;		/* ACB_EVT_* */

	refcount_t		refcnt;

	struct rb_node		name_node;		/* registry, by name */

	/* members, skills, queues */
	spinlock_t		lock;
	struct list_head	members;
	int			nmembers;
	struct list_head	skills;
	struct list_head	req_q;
	int			req_q_len;
	struct list_head	evt_q;
	int			evt_q_len;
	unsigned int		dropped_evts;
	wait_queue_head_t	wq;

	bool			registered;
	bool			dead;
	bool			owner_gone;		/* agentfd closed */
	bool			destroy_started;
	u64			created_ns;
	uid_t			owner_uid;

	struct acb_ctx		*ctx;		/* cnode (always allocated) */

	/* agentfs dir once mounted (NULL before) */
	struct dentry		*dentry;
	struct dentry		*skills_dentry;
	struct dentry		*d_status;
	struct dentry		*d_context;
	struct dentry		*d_members;
	struct dentry		*d_policy;
	struct dentry		*d_hooks;
	struct dentry		*d_ctl;

	struct rcu_head		rcu;
};

#ifdef CONFIG_AGENT

/* registry */
struct acb *acb_get_by_name(const char *name);
struct acb *acb_get_by_aid(u64 aid);
struct acb *acb_get(struct acb *acb);
void acb_put(struct acb *acb);
struct acb *acb_first(void);
struct acb *acb_next(struct acb *acb);
void acb_registry_lock(void);
void acb_registry_unlock(void);

/* members */
int acb_add_member(struct acb *acb, struct task_struct *task);
void acb_del_member(struct acb *acb, struct task_struct *task, int exit_code);
void acb_task_exit(struct task_struct *task);

/* skills (refs: acb_get_skill / acb_put_skill for readers) */
struct acb_skill *acb_get_skill(struct acb *acb, const char *name);
void acb_put_skill(struct acb_skill *skill);
int acb_add_skill(struct acb *acb, const struct acb_skill_desc *desc);
int acb_del_skill(struct acb *acb, const char *name);

/* agentfs dentry plumbing (called from fs/agentfs) */
void acb_publish_dentry(struct acb *acb, struct dentry *dir,
			struct dentry *skills);
void acb_unpublish_dentry(struct acb *acb);

/* request lifecycle (client side) */
int acb_route_request(struct acb *target, const char *skill,
		      const char *buf, size_t len, u64 caller_aid,
		      struct acb_req **reqp);
void acb_req_put(struct acb_req *req);

/* mirror task->acb's class into p->scx.agent_class (no-op without sched_ext) */
void acb_sync_scx_class(struct task_struct *t);

/* capability check for an invocation (caller may be NULL = legacy task) */
int acb_check_invoke(struct acb *caller, struct acb *target,
		       const char *skill);

/* cnode core (kernel/acb_ctx.c) */
int acb_ctx_append(struct acb *acb, u32 class, u32 flags, u64 origin_req,
		   u64 origin_aid, const char *origin_skill,
		   const char *data, size_t len, u64 *seqp);
int acb_ctx_on_member_exit(struct acb *acb);	/* crash closers */
struct acb_ctx *acb_ctx_alloc(void);
void acb_ctx_free(struct acb_ctx *ctx);
void acb_ctx_pressure_event(struct acb *acb);

/* cnode ioctls (dispatched from acb_fd_ioctl in kernel/acb.c) */
int acb_ctx_ioctl_setquota(struct acb *acb, unsigned long arg);
int acb_ctx_ioctl_append(struct acb *acb, unsigned long arg);
int acb_ctx_ioctl_compact(struct acb *acb, unsigned long arg);
int acb_ctx_ioctl_gc(struct acb *acb, unsigned long arg);
int acb_ctx_ioctl_read(struct acb *acb, unsigned long arg);
int acb_ctx_ioctl_info(struct acb *acb, unsigned long arg);
int acb_ctx_ioctl_fork(struct acb *acb, struct file *child_file,
		       unsigned long arg);
int acb_ctx_ioctl_barrier(struct acb *acb);

/* explicit destroy (agentfs ctl); idempotent */
int acb_kill(struct acb *acb);

#else /* !CONFIG_AGENT */

static inline void acb_task_exit(struct task_struct *task) { }

#endif /* CONFIG_AGENT */
#endif /* _LINUX_ACB_H */
