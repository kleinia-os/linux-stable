// SPDX-License-Identifier: GPL-2.0
/*
 * Agent Control Block (ACB) core
 *
 * Kleinia kernel: agents as first-class kernel objects.
 *
 * Lifecycle:  acb_create() mints an ACB (registry + agentfd refs) and
 *             the creating task becomes a member after acb_attach();
 *             children inherit the parent's ACB at fork.  The agent is
 *             destroyed once its agentfd is closed AND the last member
 *             exits (or on explicit acb_kill()), failing pending skill
 *             invocations with -EPIPE and broadcasting
 *             ACB_EVT_AGENT_DESTROY to subscribers.
 *
 * Mailbox:    clients enqueue skill invocations through agentfs
 *             or AF_AGENT; the owner drains requests and events
 *             via poll/ioctl on its agentfd and posts replies.
 */

#include <linux/anon_inodes.h>
#include <linux/atomic.h>
#include <linux/ctype.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/printk.h>
#include <linux/rbtree.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/acb.h>
#include <linux/agentfs.h>

#define CREATE_TRACE_POINTS
#include <trace/events/acb.h>

#ifdef CONFIG_SCHED_CLASS_EXT
#include <linux/sched/ext.h>
#endif

/* mirror the agent class into the scheduler entity: sched_ext
 * programs read it as p->scx.agent_class (only compiled in when
 * sched_ext is present; see include/linux/acb.h) */
#ifdef CONFIG_SCHED_CLASS_EXT
void acb_sync_scx_class(struct task_struct *t)
{
	t->scx.agent_class = t->acb ? t->acb->class : 0;
}
EXPORT_SYMBOL_GPL(acb_sync_scx_class);
#else
void acb_sync_scx_class(struct task_struct *t) { }
#endif

static DEFINE_MUTEX(acb_registry_mutex);
static struct rb_root acb_registry = RB_ROOT;
static atomic64_t acb_aid_counter = ATOMIC64_INIT(0x1000);
static atomic64_t acb_req_ids = ATOMIC64_INIT(1);

#define ACB_MAX_REQS		64
#define ACB_MAX_EVTS		1024

static struct kmem_cache *acb_cachep;

/* ------------------------------------------------------------------ */
/* registry                                                            */

static struct acb *__acb_find(const char *name)
{
	struct rb_node *n = acb_registry.rb_node;

	while (n) {
		struct acb *a = rb_entry(n, struct acb, name_node);
		int c = strcmp(name, a->name);

		if (c < 0)
			n = n->rb_left;
		else if (c > 0)
			n = n->rb_right;
		else
			return a;
	}
	return NULL;
}

struct acb *acb_get_by_name(const char *name)
{
	struct acb *acb;

	mutex_lock(&acb_registry_mutex);
	acb = __acb_find(name);
	if (acb && (acb->dead || !acb_get(acb)))
		acb = NULL;
	mutex_unlock(&acb_registry_mutex);
	return acb;
}

struct acb *acb_get_by_aid(u64 aid)
{
	struct acb *found = NULL;
	struct rb_node *n;

	mutex_lock(&acb_registry_mutex);
	for (n = rb_first(&acb_registry); n; n = rb_next(n)) {
		struct acb *a = rb_entry(n, struct acb, name_node);
		if (a->aid == aid && !a->dead) {
			found = acb_get(a);
			break;
		}
	}
	mutex_unlock(&acb_registry_mutex);
	return found;
}

void acb_registry_lock(void)	{ mutex_lock(&acb_registry_mutex); }
void acb_registry_unlock(void)	{ mutex_unlock(&acb_registry_mutex); }

struct acb *acb_first(void)
{
	struct rb_node *n = rb_first(&acb_registry);
	return n ? rb_entry(n, struct acb, name_node) : NULL;
}

struct acb *acb_next(struct acb *acb)
{
	struct rb_node *n = rb_next(&acb->name_node);
	return n ? rb_entry(n, struct acb, name_node) : NULL;
}

static int acb_register_agent(struct acb *acb)
{
	struct rb_node **p = &acb_registry.rb_node, *parent = NULL;

	mutex_lock(&acb_registry_mutex);
	if (__acb_find(acb->name)) {
		mutex_unlock(&acb_registry_mutex);
		return -EEXIST;
	}
	while (*p) {
		struct acb *a = rb_entry(*p, struct acb, name_node);
		int c = strcmp(acb->name, a->name);

		parent = *p;
		if (c < 0)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}
	acb->registered = true;
	rb_link_node(&acb->name_node, parent, p);
	rb_insert_color(&acb->name_node, &acb_registry);
	mutex_unlock(&acb_registry_mutex);
	return 0;
}

static void acb_unregister_agent(struct acb *acb)
{
	mutex_lock(&acb_registry_mutex);
	if (acb->registered) {
		rb_erase(&acb->name_node, &acb_registry);
		acb->registered = false;
	}
	mutex_unlock(&acb_registry_mutex);
}

/* ------------------------------------------------------------------ */
/* refs & lifecycle                                                    */

struct acb *acb_get(struct acb *acb)
{
	return refcount_inc_not_zero(&acb->refcnt) ? acb : NULL;
}

static void acb_free_rcu(struct rcu_head *rh)
{
	struct acb *acb = container_of(rh, struct acb, rcu);

	WARN_ON(!list_empty(&acb->members));
	WARN_ON(!list_empty(&acb->req_q));
	WARN_ON(!list_empty(&acb->skills));
	acb_ctx_free(acb->ctx);
	kmem_cache_free(acb_cachep, acb);
}

void acb_put(struct acb *acb)
{
	if (acb && refcount_dec_and_test(&acb->refcnt))
		call_rcu(&acb->rcu, acb_free_rcu);
}

static bool acb_name_valid(const char *name)
{
	const char *p;

	if (!*name || strlen(name) >= ACB_NAME_MAX)
		return false;
	for (p = name; *p; p++)
		if (!isalnum(*p) && *p != '.' && *p != '-' && *p != '_')
			return false;
	return true;
}

static struct acb *acb_alloc(const char *name, u8 class)
{
	struct acb *acb;

	acb = kmem_cache_zalloc(acb_cachep, GFP_KERNEL);
	if (!acb)
		return NULL;

	acb->aid = atomic64_inc_return(&acb_aid_counter);
	strscpy(acb->name, name, ACB_NAME_MAX);
	acb->class = class;
	if (class == ACB_CLASS_SYS)
		acb->caps = ACB_CAP_INVOKE_APP | ACB_CAP_INVOKE_SYS;
	else
		acb->caps = ACB_CAP_INVOKE_APP;
	acb->evt_mask = ACB_EVT_MEMBER_EXIT;
	refcount_set(&acb->refcnt, 1);	/* registry */
	spin_lock_init(&acb->lock);
	INIT_LIST_HEAD(&acb->members);
	INIT_LIST_HEAD(&acb->skills);
	INIT_LIST_HEAD(&acb->req_q);
	INIT_LIST_HEAD(&acb->evt_q);
	init_waitqueue_head(&acb->wq);
	acb->created_ns = ktime_get_boottime_ns();
	acb->owner_uid = from_kuid_munged(&init_user_ns, current_uid());
	acb->ctx = acb_ctx_alloc();
	if (!acb->ctx) {
		kmem_cache_free(acb_cachep, acb);
		return NULL;
	}
	return acb;
}

/* enqueue an event on a (possibly dead) agent queue; no-op if dead/full */
static void acb_push_event(struct acb *a, struct acb_event *evt)
{
	struct acb_evt *e;

	spin_lock(&a->lock);
	if (a->dead || a->evt_q_len >= ACB_MAX_EVTS) {
		if (!a->dead)
			a->dropped_evts++;
		spin_unlock(&a->lock);
		return;
	}
	spin_unlock(&a->lock);

	e = kmalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		return;
	e->evt = *evt;

	spin_lock(&a->lock);
	if (a->dead || a->evt_q_len >= ACB_MAX_EVTS) {
		if (!a->dead)
			a->dropped_evts++;
		spin_unlock(&a->lock);
		kfree(e);
		return;
	}
	list_add_tail(&e->node, &a->evt_q);
	a->evt_q_len++;
	spin_unlock(&a->lock);
	wake_up_interruptible(&a->wq);
}

/* cnode over-quota notification: single hook event per crossing */
void acb_ctx_pressure_event(struct acb *acb)
{
	struct acb_event evt = {
		.mask = ACB_EVT_CTX_PRESSURE,
		.aid = acb->aid,
	};

	strscpy(evt.name, acb->name, ACB_NAME_MAX);
	acb_push_event(acb, &evt);
}

/* emit ACB_EVT_AGENT_CREATE/DESTROY to every subscriber */
static void acb_broadcast(u64 mask, struct acb *subject)
{
	struct acb *a;

	acb_registry_lock();
	for (a = acb_first(); a; a = acb_next(a)) {
		if (!(a->evt_mask & mask) || a == subject)
			continue;
		if (!acb_get(a))
			continue;
		{
			struct acb_event evt = {
				.mask = mask,
				.aid = subject->aid,
				.pid = 0,
				.exit_code = 0,
			};
			strscpy(evt.name, subject->name, ACB_NAME_MAX);
			acb_push_event(a, &evt);
		}
		acb_put(a);
	}
	acb_registry_unlock();
}

static void acb_fail_pending(struct acb *acb)
{
	struct acb_req *req, *rn;
	LIST_HEAD(lost);

	spin_lock(&acb->lock);
	list_splice_init(&acb->req_q, &lost);
	acb->req_q_len = 0;
	spin_unlock(&acb->lock);

	list_for_each_entry_safe(req, rn, &lost, node) {
		list_del_init(&req->node);
		req->failed = true;
		trace_acb_rpc_exit(req->id, acb->aid, true);
		complete(&req->done);
		acb_req_put(req);	/* queue's reference */
	}
}

static void acb_destroy(struct acb *acb)
{
	struct acb_evt *e, *en;

	might_sleep();

	acb_unregister_agent(acb);
	agentfs_unpublish_agent(acb);

	spin_lock(&acb->lock);
	acb->dead = true;
	trace_acb_agent_destroy(acb->aid, acb->name);
	list_for_each_entry_safe(e, en, &acb->evt_q, node) {
		list_del(&e->node);
		kfree(e);
	}
	acb->evt_q_len = 0;
	spin_unlock(&acb->lock);
	wake_up_interruptible(&acb->wq);

	acb_fail_pending(acb);
	acb_broadcast(ACB_EVT_AGENT_DESTROY, acb);
	acb_put(acb);		/* registry reference */
}

/* idempotent destroy entry; returns -EALREADY if already destroying */
int acb_kill(struct acb *acb)
{
	bool start = false;

	spin_lock(&acb->lock);
	if (!acb->destroy_started) {
		acb->destroy_started = true;
		start = true;
	}
	spin_unlock(&acb->lock);

	if (start)
		acb_destroy(acb);
	return start ? 0 : -EALREADY;
}

/*
 * An agent dies when its agentfd is gone AND the last member left.
 * Called with our own reference held (fd release / member exit path).
 */
static void acb_maybe_destroy(struct acb *acb)
{
	bool start = false;

	spin_lock(&acb->lock);
	if (!acb->destroy_started && acb->owner_gone && acb->nmembers == 0) {
		acb->destroy_started = true;
		start = true;
	}
	spin_unlock(&acb->lock);

	if (start)
		acb_destroy(acb);
}

/* ------------------------------------------------------------------ */
/* members                                                             */

int acb_add_member(struct acb *acb, struct task_struct *task)
{
	struct acb_member *m;

	m = kmalloc(sizeof(*m), GFP_KERNEL);
	if (!m)
		return -ENOMEM;
	m->pid = task_pid_nr(task);
	get_task_comm(m->comm, task);

	spin_lock(&acb->lock);
	if (acb->dead || acb->destroy_started) {
		spin_unlock(&acb->lock);
		kfree(m);
		return -ENOENT;
	}
	list_add_tail(&m->node, &acb->members);
	acb->nmembers++;
	spin_unlock(&acb->lock);
	return 0;
}

void acb_del_member(struct acb *acb, struct task_struct *task, int exit_code)
{
	struct acb_member *m, *found = NULL;
	bool last = false;

	spin_lock(&acb->lock);
	list_for_each_entry(m, &acb->members, node) {
		if (m->pid == task_pid_nr(task)) {
			list_del(&m->node);
			found = m;
			acb->nmembers--;
			if (acb->nmembers == 0)
				last = true;
			break;
		}
	}
	spin_unlock(&acb->lock);

	if (found && (acb->evt_mask & ACB_EVT_MEMBER_EXIT)) {
		struct acb_event evt = {
			.mask = ACB_EVT_MEMBER_EXIT,
			.aid = acb->aid,
			.pid = found->pid,
			.exit_code = exit_code,
		};
		strscpy(evt.name, acb->name, ACB_NAME_MAX);
		acb_push_event(acb, &evt);
	}
	if (found)
		trace_acb_member_exit(acb->aid, acb->name, found->pid,
				      exit_code);
	kfree(found);

	if (last)
		acb_maybe_destroy(acb);
}

void acb_task_exit(struct task_struct *task)
{
	struct acb *acb = task->acb;

	if (acb) {
		task->acb = NULL;
		acb_sync_scx_class(task);
		acb_del_member(acb, task, task->exit_code);
		acb_ctx_on_member_exit(acb);	/* synthesize crash closers */
		acb_put(acb);
	}
}

/* ------------------------------------------------------------------ */
/* skills                                                              */

static struct acb_skill *__acb_find_skill(struct acb *acb, const char *name)
{
	struct acb_skill *s;

	lockdep_assert_held(&acb->lock);
	list_for_each_entry(s, &acb->skills, node)
		if (!strcmp(s->name, name))
			return s;
	return NULL;
}

int acb_add_skill(struct acb *acb, const struct acb_skill_desc *desc)
{
	struct acb_skill *s;
	size_t len;

	if (!desc->name[0])
		return -EINVAL;
	len = strnlen(desc->schema, ACB_SCHEMA_MAX);
	if (len == ACB_SCHEMA_MAX)
		return -EINVAL;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;
	strscpy(s->name, desc->name, ACB_SKILL_MAX);
	if (len) {
		s->schema = kmemdup(desc->schema, len + 1, GFP_KERNEL);
		if (!s->schema) {
			kfree(s);
			return -ENOMEM;
		}
		s->schema_len = len + 1;
	}
	s->acb = acb;
	refcount_set(&s->refcnt, 1);		/* list */

	spin_lock(&acb->lock);
	if (acb->dead || __acb_find_skill(acb, desc->name)) {
		spin_unlock(&acb->lock);
		kfree(s->schema);
		kfree(s);
		return acb->dead ? -ENOENT : -EEXIST;
	}
	list_add_tail(&s->node, &acb->skills);
	spin_unlock(&acb->lock);

	agentfs_publish_skill(acb, s);
	return 0;
}

static void acb_skill_free(struct acb_skill *s)
{
	kfree(s->schema);
	kfree(s);
}

struct acb_skill *acb_get_skill(struct acb *acb, const char *name)
{
	struct acb_skill *s;

	spin_lock(&acb->lock);
	s = __acb_find_skill(acb, name);
	if (s && !refcount_inc_not_zero(&s->refcnt))
		s = NULL;
	spin_unlock(&acb->lock);
	return s;
}

static void acb_skill_put(struct acb_skill *s)
{
	if (refcount_dec_and_test(&s->refcnt))
		acb_skill_free(s);
}

void acb_put_skill(struct acb_skill *skill)
{
	acb_skill_put(skill);
}

/* safe iteration snapshot for agentfs is done inline there (d_alloc sleeps) */

int acb_del_skill(struct acb *acb, const char *name)
{
	struct acb_skill *s;

	spin_lock(&acb->lock);
	s = __acb_find_skill(acb, name);
	if (s)
		list_del(&s->node);
	spin_unlock(&acb->lock);
	if (!s)
		return -ENOENT;

	agentfs_unpublish_skill(acb, s);
	acb_skill_put(s);		/* list's reference */
	return 0;
}

void acb_publish_dentry(struct acb *acb, struct dentry *dir, struct dentry *skills)
{
	spin_lock(&acb->lock);
	acb->dentry = dir;
	acb->skills_dentry = skills;
	spin_unlock(&acb->lock);
}

void acb_unpublish_dentry(struct acb *acb)
{
	spin_lock(&acb->lock);
	acb->dentry = NULL;
	acb->skills_dentry = NULL;
	spin_unlock(&acb->lock);
}

/* ------------------------------------------------------------------ */
/* mailbox                                                             */

static void acb_req_free(struct acb_req *req)
{
	kfree(req->buf);
	kfree(req->reply);
	kfree(req);
}

void acb_req_put(struct acb_req *req)
{
	if (refcount_dec_and_test(&req->refcnt))
		acb_req_free(req);
}

int acb_route_request(struct acb *target, const char *skill,
		      const char *buf, size_t len, u64 caller_aid,
		      struct acb_req **reqp)
{
	struct acb_req *req;

	if (len > ACB_REQ_MAX)
		return -EMSGSIZE;

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return -ENOMEM;
	if (len) {
		req->buf = kmemdup(buf, len, GFP_KERNEL);
		if (!req->buf) {
			kfree(req);
			return -ENOMEM;
		}
	}
	req->id = atomic64_inc_return(&acb_req_ids);
	req->len = len;
	req->caller_aid = caller_aid;
	req->target = acb_get(target);
	if (!req->target) {
		kfree(req->buf);
		kfree(req);
		return -ENOENT;
	}
	strscpy(req->skill, skill, ACB_SKILL_MAX);
	init_completion(&req->done);
	refcount_set(&req->refcnt, 2);		/* client + queue */

	spin_lock(&target->lock);
	if (target->dead || target->req_q_len >= ACB_MAX_REQS) {
		bool dead = target->dead;
		spin_unlock(&target->lock);
		acb_put(req->target);
		kfree(req->buf);
		kfree(req);
		return dead ? -EPIPE : -EBUSY;
	}
	list_add_tail(&req->node, &target->req_q);
	target->req_q_len++;
	spin_unlock(&target->lock);

	trace_acb_rpc_entry(req->id, caller_aid, target->aid, skill);
	wake_up_interruptible(&target->wq);
	*reqp = req;
	return 0;
}

int acb_check_invoke(struct acb *caller, struct acb *target,
		     const char *skill)
{
	unsigned long need;

	if (!caller)
		return 0;		/* legacy task, M3 tightens this */

	need = (target->class == ACB_CLASS_SYS) ?
		ACB_CAP_INVOKE_SYS : ACB_CAP_INVOKE_APP;
	if (caller->caps & need)
		return 0;

	trace_acb_invoke_denied(caller->aid, target->aid, skill);
	return -EACCES;
}

/* owner posts a reply for a request still sitting in its queue */
static int __acb_reply(struct acb *acb, u64 req_id, const char *buf, size_t len)
{
	struct acb_req *req;
	char *cp = NULL;

	if (len > ACB_REQ_MAX)
		return -EMSGSIZE;
	if (len) {
		cp = kmemdup(buf, len, GFP_KERNEL);
		if (!cp)
			return -ENOMEM;
	}

	spin_lock(&acb->lock);
	list_for_each_entry(req, &acb->req_q, node) {
		if (req->id == req_id) {
			if (req->replied) {
				spin_unlock(&acb->lock);
				kfree(cp);
				return -EALREADY;
			}
			kfree(req->reply);
			req->reply = cp;
			req->reply_len = len;
			req->replied = true;
			list_del_init(&req->node);
			acb->req_q_len--;
			spin_unlock(&acb->lock);
			trace_acb_rpc_exit(req->id, acb->aid, false);
			complete(&req->done);
			acb_req_put(req);	/* queue's reference */
			return 0;
		}
	}
	spin_unlock(&acb->lock);
	kfree(cp);
	return -ENOENT;
}

/* ------------------------------------------------------------------ */
/* agentfd                                                             */

static int acb_fd_release(struct inode *inode, struct file *file)
{
	struct acb *acb = file->private_data;

	spin_lock(&acb->lock);
	acb->owner_gone = true;
	spin_unlock(&acb->lock);
	acb_maybe_destroy(acb);
	acb_put(acb);			/* fd's reference */
	return 0;
}

static __poll_t acb_fd_poll(struct file *file, poll_table *wait)
{
	struct acb *acb = file->private_data;
	__poll_t mask = 0;

	poll_wait(file, &acb->wq, wait);
	spin_lock_irq(&acb->lock);
	if (acb->req_q_len || acb->evt_q_len)
		mask |= EPOLLIN | EPOLLRDNORM;
	if (acb->dead)
		mask |= EPOLLHUP;
	spin_unlock_irq(&acb->lock);
	return mask;
}

static int acb_ioctl_set_policy(struct acb *acb, unsigned long arg)
{
	unsigned long caps;

	if (copy_from_user(&caps, (void __user *)arg, sizeof(caps)))
		return -EFAULT;

	/* lowering is free; raising requires CAP_SYS_ADMIN */
	if ((caps & ~acb->caps) && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	spin_lock(&acb->lock);
	acb->caps = caps;
	spin_unlock(&acb->lock);
	return 0;
}

static int acb_ioctl_add_skill(struct acb *acb, unsigned long arg)
{
	struct acb_skill_desc *desc;
	int ret;

	desc = kmalloc(sizeof(*desc), GFP_KERNEL);
	if (!desc)
		return -ENOMEM;
	if (copy_from_user(desc, (void __user *)arg, sizeof(*desc))) {
		ret = -EFAULT;
		goto out;
	}
	ret = acb_add_skill(acb, desc);
out:
	kfree(desc);
	return ret;
}

static int acb_ioctl_del_skill(struct acb *acb, unsigned long arg)
{
	struct acb_skill_desc *desc;
	int ret;

	desc = kmalloc(sizeof(*desc), GFP_KERNEL);
	if (!desc)
		return -ENOMEM;
	if (copy_from_user(desc, (void __user *)arg, sizeof(*desc))) {
		ret = -EFAULT;
		goto out;
	}
	ret = acb_del_skill(acb, desc->name);
out:
	kfree(desc);
	return ret;
}

static int acb_ioctl_subscribe(struct acb *acb, unsigned long arg)
{
	unsigned long mask;

	if (copy_from_user(&mask, (void __user *)arg, sizeof(mask)))
		return -EFAULT;
	spin_lock(&acb->lock);
	acb->evt_mask = mask;
	spin_unlock(&acb->lock);
	return 0;
}

static int acb_ioctl_recv_req(struct acb *acb, unsigned long arg)
{
	struct acb_recv *r;
	struct acb_req *req;
	int ret = -EAGAIN;

	r = kmalloc(sizeof(*r), GFP_KERNEL);
	if (!r)
		return -ENOMEM;
	memset(r, 0, sizeof(*r));
	spin_lock(&acb->lock);
	list_for_each_entry(req, &acb->req_q, node) {
		if (!req->served) {
			req->served = true;
			r->req_id = req->id;
			r->caller_aid = req->caller_aid;
			strscpy(r->skill, req->skill, ACB_SKILL_MAX);
			r->len = min_t(size_t, req->len, ACB_REQ_MAX);
			if (r->len)
				memcpy(r->buf, req->buf, r->len);
			ret = 0;
			break;
		}
	}
	spin_unlock(&acb->lock);

	if (ret)
		goto out;
	if (copy_to_user((void __user *)arg, r, sizeof(*r)))
		ret = -EFAULT;
out:
	kfree(r);
	return ret;
}

static int acb_ioctl_recv_event(struct acb *acb, unsigned long arg)
{
	struct acb_evt *e;
	struct acb_event ev;
	int ret = -EAGAIN;

	spin_lock(&acb->lock);
	if (!list_empty(&acb->evt_q)) {
		e = list_first_entry(&acb->evt_q, struct acb_evt, node);
		list_del(&e->node);
		acb->evt_q_len--;
		memcpy(&ev, &e->evt, sizeof(ev));
		kfree(e);
		ret = 0;
	}
	spin_unlock(&acb->lock);

	if (ret)
		return ret;
	if (copy_to_user((void __user *)arg, &ev, sizeof(ev)))
		return -EFAULT;
	return 0;
}

static int acb_ioctl_reply(struct acb *acb, unsigned long arg)
{
	struct acb_reply *rep;
	int ret;

	rep = kmalloc(sizeof(*rep), GFP_KERNEL);
	if (!rep)
		return -ENOMEM;
	if (copy_from_user(rep, (void __user *)arg, sizeof(*rep))) {
		ret = -EFAULT;
		goto out;
	}
	if (rep->len > ACB_REQ_MAX) {
		ret = -EMSGSIZE;
		goto out;
	}
	ret = __acb_reply(acb, rep->req_id, rep->buf, rep->len);
out:
	kfree(rep);
	return ret;
}

static const struct file_operations acb_fops;

static long acb_fd_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct acb *acb = file->private_data;

	switch (cmd) {
	case ACB_IOC_SET_POLICY:
		return acb_ioctl_set_policy(acb, arg);
	case ACB_IOC_ADD_SKILL:
		return acb_ioctl_add_skill(acb, arg);
	case ACB_IOC_DEL_SKILL:
		return acb_ioctl_del_skill(acb, arg);
	case ACB_IOC_SUBSCRIBE:
		return acb_ioctl_subscribe(acb, arg);
	case ACB_IOC_RECV_REQ:
		return acb_ioctl_recv_req(acb, arg);
	case ACB_IOC_RECV_EVENT:
		return acb_ioctl_recv_event(acb, arg);
	case ACB_IOC_REPLY:
		return acb_ioctl_reply(acb, arg);
	case ACB_IOC_CTX_SETQUOTA:
		return acb_ctx_ioctl_setquota(acb, arg);
	case ACB_IOC_CTX_APPEND:
		return acb_ctx_ioctl_append(acb, arg);
	case ACB_IOC_CTX_COMPACT:
		return acb_ctx_ioctl_compact(acb, arg);
	case ACB_IOC_CTX_GC:
		return acb_ctx_ioctl_gc(acb, arg);
	case ACB_IOC_CTX_READ:
		return acb_ctx_ioctl_read(acb, arg);
	case ACB_IOC_CTX_INFO:
		return acb_ctx_ioctl_info(acb, arg);
	case ACB_IOC_CTX_FORK: {
		struct acb_ctx_fork f;
		struct fd cf;

		if (copy_from_user(&f, (void __user *)arg, sizeof(f)))
			return -EFAULT;
		cf = fdget(f.child_fd);
		if (fd_empty(cf))
			return -EBADF;
		if (fd_file(cf)->f_op != &acb_fops) {
			fdput(cf);
			return -EINVAL;
		}
		{
			int ret = acb_ctx_ioctl_fork(acb, fd_file(cf), arg);

			fdput(cf);
			return ret;
		}
	}
	case ACB_IOC_CTX_BARRIER:
		return acb_ctx_ioctl_barrier(acb);
	case ACB_IOC_WHOAMI: {
		unsigned long aid = acb->aid;

		return copy_to_user((void __user *)arg, &aid, sizeof(aid)) ?
		       -EFAULT : 0;
	}
	}
	return -ENOTTY;
}

static const struct file_operations acb_fops = {
	.owner		= THIS_MODULE,
	.release	= acb_fd_release,
	.poll		= acb_fd_poll,
	.unlocked_ioctl	= acb_fd_ioctl,
};

/* ------------------------------------------------------------------ */
/* syscalls                                                            */

SYSCALL_DEFINE3(acb_create, const char __user *, name, unsigned int, flags,
		unsigned int, class)
{
	struct acb *acb;
	char kname[ACB_NAME_MAX];
	int fd, ret;

	if (copy_from_user(kname, name, sizeof(kname)))
		return -EFAULT;
	kname[ACB_NAME_MAX - 1] = '\0';
	if (!acb_name_valid(kname))
		return -EINVAL;
	if (class != ACB_CLASS_APP && class != ACB_CLASS_SYS)
		return -EINVAL;
	if (class == ACB_CLASS_SYS && !capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (flags & ~ACB_F_EXCL)
		return -EINVAL;

	acb = acb_alloc(kname, class);
	if (!acb)
		return -ENOMEM;

	ret = acb_register_agent(acb);
	if (ret)
		goto out_put;

	if (!acb_get(acb)) {		/* fd's reference */
		acb_unregister_agent(acb);
		ret = -ENOENT;
		goto out_put;
	}
	fd = anon_inode_getfd("acb", &acb_fops, acb, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		acb_unregister_agent(acb);
		acb_put(acb);
		ret = fd;
		goto out_put;
	}

	agentfs_publish_agent(acb);
	trace_acb_agent_create(acb->aid, acb->name, acb->class);
	acb_broadcast(ACB_EVT_AGENT_CREATE, acb);
	return fd;

out_put:
	acb_put(acb);
	return ret;
}

SYSCALL_DEFINE1(acb_attach, int, fd)
{
	struct acb *acb, *old;
	struct fd f;
	int ret;

	f = fdget(fd);
	if (fd_empty(f))
		return -EBADF;
	if (fd_file(f)->f_op != &acb_fops) {
		fdput(f);
		return -EINVAL;
	}
	acb = fd_file(f)->private_data;
	if (!acb_get(acb)) {
		fdput(f);
		return -ENOENT;
	}
	fdput(f);

	old = current->acb;
	if (old == acb) {
		acb_put(acb);
		return 0;
	}

	ret = acb_add_member(acb, current);
	if (ret) {
		acb_put(acb);
		return ret;
	}
	current->acb = acb;
	acb_sync_scx_class(current);
	if (old) {
		acb_del_member(old, current, 0);
		acb_put(old);
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* init                                                                */

static int __init acb_init(void)
{
	acb_cachep = kmem_cache_create("acb_cache", sizeof(struct acb), 0,
				       SLAB_PANIC | SLAB_ACCOUNT, NULL);
	pr_info("ACB: agent control block subsystem initialized\n");
	return 0;
}
core_initcall(acb_init);
