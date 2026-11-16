// SPDX-License-Identifier: GPL-2.0
/*
 * agentfs — expose ACB agents as a filesystem tree at /agent
 *
 * Layout:
 *   /agent/<agent-name>/{status,members,policy,hooks,ctl,skills/}
 *   /agent/<agent-name>/skills/<skill>/{schema,invoke}
 *
 * Directories and files are created by the kernel on publish and
 * removed on unpublish; lookups and readdir come from libfs
 * (simple_dir_operations) over the pre-created dentries.
 *
 * skills/<skill>/invoke implements the client side of the
 * kernel-mediated skill RPC: write(2) enqueues the request into the
 * target agent's mailbox, read(2) blocks for the owner's reply.
 */

#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/pagemap.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/acb.h>
#include <linux/agentfs.h>

#define AGENTFS_REQ_TIMEOUT_MS	30000

/* single instance for now; serializes publish/unpublish */
static DEFINE_MUTEX(agentfs_pub_mutex);
static struct super_block *agentfs_sb;

struct invoke_ctx {
	struct acb		*acb;
	struct acb_skill	*skill;
	struct acb_req		*req;
};

/* ------------------------------------------------------------------ */
/* inode/dentry helpers                                                */

static struct inode *agentfs_new_inode(struct super_block *sb, umode_t mode,
				       const struct inode *dir)
{
	struct inode *inode = new_inode(sb);

	if (inode) {
		inode->i_ino = get_next_ino();
		inode->i_mode = mode;
		simple_inode_init_ts(inode);
		inode->i_private = NULL;
	}
	return inode;
}

static struct dentry *agentfs_create(struct dentry *parent, const char *name,
				     umode_t mode, void *priv,
				     const struct file_operations *fops)
{
	struct inode *dir = d_inode(parent);
	struct super_block *sb = dir->i_sb;
	struct dentry *dentry;
	struct inode *inode;

	inode_lock(dir);
	dentry = d_alloc_name(parent, name);
	if (!dentry)
		goto out_unlock;

	inode = agentfs_new_inode(sb, mode, dir);
	if (!inode) {
		dput(dentry);
		dentry = NULL;
		goto out_unlock;
	}
	inode_init_owner(&nop_mnt_idmap, inode, dir, mode);
	inode->i_private = priv;

	if (S_ISDIR(mode)) {
		inode->i_op = &simple_dir_inode_operations;
		inode->i_fop = &simple_dir_operations;
		inc_nlink(inode);
		inc_nlink(dir);
	} else {
		inode->i_fop = fops;
	}
	d_add(dentry, inode);
	dget(dentry);		/* our creation reference */
out_unlock:
	inode_unlock(dir);
	return dentry;
}

static void agentfs_drop(struct dentry **dp)
{
	if (*dp) {
		d_invalidate(*dp);
		dput(*dp);
		*dp = NULL;
	}
}

/* ------------------------------------------------------------------ */
/* status / members / policy / hooks                                   */

static int agentfs_status_show(struct seq_file *m, void *v)
{
	struct acb *acb = m->private;
	unsigned long caps;
	int nmembers, reqs, evts, dropped;
	u64 aid;
	bool dead;

	spin_lock(&acb->lock);
	caps = acb->caps;
	nmembers = acb->nmembers;
	reqs = acb->req_q_len;
	evts = acb->evt_q_len;
	dropped = acb->dropped_evts;
	dead = acb->dead;
	spin_unlock(&acb->lock);

	aid = acb->aid;
	seq_printf(m, "aid: %llu\nname: %s\nclass: %s\nstate: %s\n",
		   aid, acb->name,
		   acb->class == ACB_CLASS_SYS ? "sys" : "app",
		   dead ? "dead" : "running");
	seq_printf(m, "caps: %#lx\nmembers: %d\nqueued_requests: %d\n"
		   "queued_events: %d\ndropped_events: %d\n",
		   caps, nmembers, reqs, evts, dropped);
	seq_printf(m, "created_ns: %llu\nowner_uid: %u\n",
		   acb->created_ns, acb->owner_uid);
	return 0;
}

static int agentfs_single_open(struct inode *inode, struct file *file,
			       int (*show)(struct seq_file *, void *))
{
	return single_open(file, show, inode->i_private);
}

static int agentfs_status_open(struct inode *inode, struct file *file)
{
	return agentfs_single_open(inode, file, agentfs_status_show);
}

static int agentfs_members_show(struct seq_file *m, void *v)
{
	struct acb *acb = m->private;
	struct acb_member *mem;

	spin_lock(&acb->lock);
	list_for_each_entry(mem, &acb->members, node)
		seq_printf(m, "%d\t%s\n", mem->pid, mem->comm);
	spin_unlock(&acb->lock);
	return 0;
}

static int agentfs_members_open(struct inode *inode, struct file *file)
{
	return agentfs_single_open(inode, file, agentfs_members_show);
}

static int agentfs_policy_show(struct seq_file *m, void *v)
{
	struct acb *acb = m->private;
	unsigned long caps;

	spin_lock(&acb->lock);
	caps = acb->caps;
	spin_unlock(&acb->lock);

	seq_printf(m, "caps: %#lx\ninvoke_app: %c\ninvoke_sys: %c\nmanage: %c\n",
		   caps,
		   caps & ACB_CAP_INVOKE_APP ? 'y' : 'n',
		   caps & ACB_CAP_INVOKE_SYS ? 'y' : 'n',
		   caps & ACB_CAP_MANAGE ? 'y' : 'n');
	return 0;
}

static int agentfs_policy_open(struct inode *inode, struct file *file)
{
	return agentfs_single_open(inode, file, agentfs_policy_show);
}

static int agentfs_hooks_show(struct seq_file *m, void *v)
{
	struct acb *acb = m->private;
	unsigned long mask;
	unsigned int dropped;

	spin_lock(&acb->lock);
	mask = acb->evt_mask;
	dropped = acb->dropped_evts;
	spin_unlock(&acb->lock);

	seq_printf(m, "evt_mask: %#lx\nmember_exit: %c\nagent_create: %c\n"
		   "agent_destroy: %c\ndropped_events: %u\n",
		   mask,
		   mask & ACB_EVT_MEMBER_EXIT ? 'y' : 'n',
		   mask & ACB_EVT_AGENT_CREATE ? 'y' : 'n',
		   mask & ACB_EVT_AGENT_DESTROY ? 'y' : 'n',
		   dropped);
	return 0;
}

static int agentfs_hooks_open(struct inode *inode, struct file *file)
{
	return agentfs_single_open(inode, file, agentfs_hooks_show);
}

static int agentfs_context_show(struct seq_file *m, void *v)
{
	struct acb *acb = m->private;
	struct acb_ctx *ctx = acb->ctx;
	struct acb_ctx_seg *seg;
	u64 head = 0, last_turn = 0;

	if (!ctx)
		return 0;

	{
		u32 nsegs = 0;

		mutex_lock(&ctx->lock);
		list_for_each_entry(seg, &ctx->segs, node) {
			nsegs++;
			head = seg->seq;
			if (seg->cls == ACB_CTX_LOG_TURN_END &&
			    !(seg->flags & ACB_CTX_F_SHADOWED))
				last_turn = seg->seq;
		}
		seq_printf(m, "quota: %llu\nbytes: %llu\nshadowed_bytes: %llu\nsegments: %u\nhead_seq: %llu\nlast_turn_seq: %llu\nparent_aid: %llu\ndepth: %u\n",
			   ctx->quota, ctx->bytes, ctx->shadowed_bytes,
			   nsegs, head, last_turn, ctx->parent_aid,
			   ctx->depth);
		mutex_unlock(&ctx->lock);
	}
	return 0;
	return 0;
}

static int agentfs_context_open(struct inode *inode, struct file *file)
{
	return agentfs_single_open(inode, file, agentfs_context_show);
}

/* full log dump: every segment (shadowed/gc marked), escaped payloads */
static int agentfs_context_log_show(struct seq_file *m, void *v)
{
	struct acb *acb = m->private;
	struct acb_ctx *ctx = acb->ctx;
	struct acb_ctx_seg *seg;
	char esc[64];
	size_t i, n;

	if (!ctx)
		return 0;

	mutex_lock(&ctx->lock);
	list_for_each_entry(seg, &ctx->segs, node) {
		seq_printf(m, "[%llu] class=%u flags=%c%c origin=%s req=%llu aid=%llu len=%zu | ",
			   seg->seq, seg->cls,
			   (seg->flags & ACB_CTX_F_SHADOWED) ? 'S' : '-',
			   (seg->flags & (1U << 31)) ? 'G' : '-',
			   seg->origin_skill[0] ? seg->origin_skill : "-",
			   seg->origin_req, seg->origin_aid, seg->len);
		n = min(seg->len, (size_t)48);
		for (i = 0; i < n; i++) {
			unsigned char c = seg->data ? seg->data[i] : 0;

			if (c == '\n' || c == '\r' || c == '\t' || c == '\\')
				snprintf(esc, sizeof(esc), "\\%c", c == '\n' ? 'n' : c == '\r' ? 'r' : c == '\t' ? 't' : '\\');
			else if (c >= 0x20 && c < 0x7f)
				snprintf(esc, sizeof(esc), "%c", c);
			else
				snprintf(esc, sizeof(esc), "\\x%02x", c);
			seq_puts(m, esc);
		}
		if (seg->len > n)
			seq_puts(m, "...");
		seq_putc(m, '\n');
	}
	mutex_unlock(&ctx->lock);
	return 0;
}

static int agentfs_context_log_open(struct inode *inode, struct file *file)
{
	return agentfs_single_open(inode, file, agentfs_context_log_show);
}

static const struct file_operations agentfs_context_log_fops = {
	.owner		= THIS_MODULE,
	.open		= agentfs_context_log_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static const struct file_operations agentfs_context_fops = {
	.owner		= THIS_MODULE,
	.open		= agentfs_context_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static const struct file_operations agentfs_status_fops = {
	.owner		= THIS_MODULE,
	.open		= agentfs_status_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static const struct file_operations agentfs_members_fops = {
	.owner		= THIS_MODULE,
	.open		= agentfs_members_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static const struct file_operations agentfs_policy_fops = {
	.owner		= THIS_MODULE,
	.open		= agentfs_policy_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static const struct file_operations agentfs_hooks_fops = {
	.owner		= THIS_MODULE,
	.open		= agentfs_hooks_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/* ------------------------------------------------------------------ */
/* ctl: write "destroy"                                                */

static ssize_t agentfs_ctl_write(struct file *file, const char __user *ubuf,
				 size_t len, loff_t *ppos)
{
	struct inode *inode = file_inode(file);
	struct acb *acb = inode->i_private;
	char buf[16];
	ssize_t ret;

	if (len >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, len))
		return -EFAULT;
	buf[len] = '\0';

	if (sysfs_streq(buf, "destroy")) {
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		acb = acb_get(acb);
		if (!acb)
			return -ENOENT;
		ret = acb_kill(acb);
		acb_put(acb);
		return ret ? ret : len;
	}
	return -EINVAL;
}

static const struct file_operations agentfs_ctl_fops = {
	.owner		= THIS_MODULE,
	.write		= agentfs_ctl_write,
};

/* ------------------------------------------------------------------ */
/* skill files: schema (read) + invoke (RPC client)                    */

static int agentfs_schema_show(struct seq_file *m, void *v)
{
	struct acb_skill *s = m->private;

	if (s->schema && s->schema_len)
		seq_write(m, s->schema, s->schema_len - 1);
	seq_putc(m, '\n');
	return 0;
}

static int agentfs_schema_open(struct inode *inode, struct file *file)
{
	return agentfs_single_open(inode, file, agentfs_schema_show);
}

static const struct file_operations agentfs_schema_fops = {
	.owner		= THIS_MODULE,
	.open		= agentfs_schema_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int agentfs_invoke_open(struct inode *inode, struct file *file)
{
	struct acb_skill *skill = inode->i_private;
	struct invoke_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	if (!refcount_inc_not_zero(&skill->refcnt)) {
		kfree(ctx);
		return -ENOENT;
	}
	ctx->skill = skill;
	ctx->acb = acb_get(skill->acb);
	if (!ctx->acb) {
		acb_put_skill(skill);
		kfree(ctx);
		return -ENOENT;
	}
	file->private_data = ctx;
	return 0;
}

static ssize_t agentfs_invoke_write(struct file *file, const char __user *ubuf,
				    size_t len, loff_t *ppos)
{
	struct invoke_ctx *ctx = file->private_data;
	struct acb *caller = current->acb;
	char *kbuf = NULL;
	u64 caller_aid = caller ? caller->aid : 0;
	int ret;

	if (ctx->req)
		return -EBUSY;		/* one request per open */
	if (len > ACB_REQ_MAX)
		return -EMSGSIZE;
	if (len) {
		kbuf = memdup_user(ubuf, len);
		if (IS_ERR(kbuf))
			return PTR_ERR(kbuf);
	}

	ret = acb_check_invoke(caller, ctx->acb, ctx->skill->name);
	if (ret)
		goto out;

	ret = acb_route_request(ctx->acb, ctx->skill->name, kbuf, len,
				caller_aid, &ctx->req);
out:
	kfree(kbuf);
	return ret ? ret : len;
}

static ssize_t agentfs_invoke_read(struct file *file, char __user *ubuf,
				   size_t count, loff_t *ppos)
{
	struct invoke_ctx *ctx = file->private_data;
	struct acb_req *req = ctx->req;
	unsigned long left;
	size_t n;
	long ret;

	if (!req)
		return -EINVAL;

	ret = wait_for_completion_interruptible_timeout(&req->done,
			msecs_to_jiffies(AGENTFS_REQ_TIMEOUT_MS));
	if (ret == 0) {
		ctx->req = NULL;
		acb_req_put(req);
		return -ETIMEDOUT;
	}
	if (ret < 0) {
		ctx->req = NULL;
		acb_req_put(req);
		return ret;
	}

	if (req->failed) {
		ctx->req = NULL;
		acb_req_put(req);
		return -EPIPE;
	}

	n = min(count, req->reply_len);
	left = copy_to_user(ubuf, req->reply, n);
	ctx->req = NULL;
	acb_req_put(req);
	return left ? -EFAULT : n;
}

static int agentfs_invoke_release(struct inode *inode, struct file *file)
{
	struct invoke_ctx *ctx = file->private_data;

	if (ctx->req)
		acb_req_put(ctx->req);
	acb_put(ctx->acb);
	acb_put_skill(ctx->skill);
	kfree(ctx);
	return 0;
}

static const struct file_operations agentfs_invoke_fops = {
	.owner		= THIS_MODULE,
	.open		= agentfs_invoke_open,
	.write		= agentfs_invoke_write,
	.read		= agentfs_invoke_read,
	.release	= agentfs_invoke_release,
};

/* ------------------------------------------------------------------ */
/* publish / unpublish                                                 */

/* collect skill refs without allocating under the acb spinlock */
static struct acb_skill **agentfs_skill_snapshot(struct acb *acb, int *count)
{
	struct acb_skill *s, **snap = NULL;
	int n = 0, i = 0;

	spin_lock(&acb->lock);
	list_for_each_entry(s, &acb->skills, node)
		n++;
	spin_unlock(&acb->lock);

	*count = 0;
	if (!n)
		return NULL;

	snap = kcalloc(n, sizeof(*snap), GFP_KERNEL);
	if (!snap)
		return NULL;

	spin_lock(&acb->lock);
	list_for_each_entry(s, &acb->skills, node) {
		if (i >= n)
			break;
		if (refcount_inc_not_zero(&s->refcnt))
			snap[i++] = s;
	}
	spin_unlock(&acb->lock);

	*count = i;
	return snap;
}

int agentfs_publish_skill(struct acb *acb, struct acb_skill *skill)
{
	struct dentry *dir, *schema, *invoke;

	if (!acb->skills_dentry)
		return 0;
	if (!refcount_inc_not_zero(&skill->refcnt))
		return -ENOENT;

	dir = agentfs_create(acb->skills_dentry, skill->name, S_IFDIR | 0555,
			     skill, NULL);
	if (!dir)
		goto fail;
	schema = agentfs_create(dir, "schema", S_IFREG | 0444, skill,
				&agentfs_schema_fops);
	invoke = agentfs_create(dir, "invoke", S_IFREG | 0666, skill,
				&agentfs_invoke_fops);
	if (!schema || !invoke) {
		agentfs_drop(&schema);
		agentfs_drop(&invoke);
		agentfs_drop(&dir);
		goto fail;
	}
	skill->dentry = dir;
	skill->d_schema = schema;
	skill->d_invoke = invoke;
	return 0;
fail:
	acb_put_skill(skill);
	return -ENOMEM;
}

void agentfs_unpublish_skill(struct acb *acb, struct acb_skill *skill)
{
	if (!skill->dentry)
		return;
	agentfs_drop(&skill->d_invoke);
	agentfs_drop(&skill->d_schema);
	agentfs_drop(&skill->dentry);
	acb_put_skill(skill);		/* dentry's reference */
}

int agentfs_publish_agent(struct acb *acb)
{
	struct dentry *dir, *status, *members, *policy, *hooks, *ctl, *skills;
	struct dentry *contextf, *ctxlogf;
	struct acb_skill **snap;
	int i, n;
	int ret = 0;

	mutex_lock(&agentfs_pub_mutex);
	if (!agentfs_sb || acb->dentry)
		goto out_unlock;
	if (!acb_get(acb)) {
		ret = -ENOENT;
		goto out_unlock;
	}

	dir = agentfs_create(agentfs_sb->s_root, acb->name, S_IFDIR | 0555,
			     acb, NULL);
	if (!dir) {
		ret = -ENOMEM;
		goto out_put;
	}
	status = agentfs_create(dir, "status", S_IFREG | 0444, acb,
				&agentfs_status_fops);
	members = agentfs_create(dir, "members", S_IFREG | 0444, acb,
				 &agentfs_members_fops);
	policy = agentfs_create(dir, "policy", S_IFREG | 0444, acb,
				&agentfs_policy_fops);
	hooks = agentfs_create(dir, "hooks", S_IFREG | 0444, acb,
			       &agentfs_hooks_fops);
	contextf = agentfs_create(dir, "context", S_IFREG | 0444, acb,
				  &agentfs_context_fops);
	ctxlogf = agentfs_create(dir, "context.log", S_IFREG | 0444, acb,
				 &agentfs_context_log_fops);
	ctl = agentfs_create(dir, "ctl", S_IFREG | 0200, acb,
			     &agentfs_ctl_fops);
	skills = agentfs_create(dir, "skills", S_IFDIR | 0555, acb, NULL);
	if (!status || !members || !policy || !hooks || !ctl || !skills ||
	    !contextf || !ctxlogf) {
		agentfs_drop(&ctxlogf);
		agentfs_drop(&contextf);
		agentfs_drop(&skills);
		agentfs_drop(&ctl);
		agentfs_drop(&hooks);
		agentfs_drop(&policy);
		agentfs_drop(&members);
		agentfs_drop(&status);
		agentfs_drop(&dir);
		ret = -ENOMEM;
		goto out_put;
	}

	acb->d_status = status;
	acb->d_context = contextf;
	acb->d_members = members;
	acb->d_policy = policy;
	acb->d_hooks = hooks;
	acb->d_ctl = ctl;
	acb_publish_dentry(acb, dir, skills);

	/* publish skills registered before this agent got its directory */
	snap = agentfs_skill_snapshot(acb, &n);
	if (snap) {
		for (i = 0; i < n; i++) {
			agentfs_publish_skill(acb, snap[i]);
			acb_put_skill(snap[i]);
		}
		kfree(snap);
	}
	goto out_unlock;		/* publish ref is dropped on unpublish */

out_put:
	acb_put(acb);
out_unlock:
	mutex_unlock(&agentfs_pub_mutex);
	return ret;
}

void agentfs_unpublish_agent(struct acb *acb)
{
	struct acb_skill **snap;
	int i, n;

	mutex_lock(&agentfs_pub_mutex);
	if (!acb->dentry) {
		mutex_unlock(&agentfs_pub_mutex);
		return;
	}

	snap = agentfs_skill_snapshot(acb, &n);
	if (snap) {
		for (i = 0; i < n; i++) {
			agentfs_unpublish_skill(acb, snap[i]);
			acb_put_skill(snap[i]);
		}
		kfree(snap);
	}

	agentfs_drop(&acb->skills_dentry);
	agentfs_drop(&acb->d_ctl);
	agentfs_drop(&acb->d_hooks);
	agentfs_drop(&acb->d_policy);
	agentfs_drop(&acb->d_members);
	agentfs_drop(&acb->d_status);
	agentfs_drop(&acb->d_context);
	agentfs_drop(&acb->dentry);
	acb_unpublish_dentry(acb);
	acb_put(acb);			/* publish reference */
	mutex_unlock(&agentfs_pub_mutex);
}

/* ------------------------------------------------------------------ */
/* superblock                                                          */

static int agentfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct inode *root;
	struct acb *a;

	root = agentfs_new_inode(sb, S_IFDIR | 0555, NULL);
	if (!root)
		return -ENOMEM;
	root->i_op = &simple_dir_inode_operations;
	root->i_fop = &simple_dir_operations;
	inc_nlink(root);
	sb->s_root = d_make_root(root);
	if (!sb->s_root)
		return -ENOMEM;

	agentfs_sb = sb;

	/* publish agents registered before mount */
	acb_registry_lock();
	for (a = acb_first(); a; a = acb_next(a)) {
		if (a->dentry)
			continue;
		if (!acb_get(a))
			continue;
		acb_registry_unlock();
		agentfs_publish_agent(a);
		acb_put(a);
		acb_registry_lock();
	}
	acb_registry_unlock();
	return 0;
}

static int agentfs_get_tree(struct fs_context *fc)
{
	return get_tree_nodev(fc, agentfs_fill_super);
}

static const struct fs_context_operations agentfs_context_ops = {
	.get_tree	= agentfs_get_tree,
};

static int agentfs_init_fs_context(struct fs_context *fc)
{
	fc->ops = &agentfs_context_ops;
	return 0;
}

static void agentfs_kill_sb(struct super_block *sb)
{
	struct acb *a;

	if (agentfs_sb == sb) {
		acb_registry_lock();
		for (a = acb_first(); a; a = acb_next(a)) {
			if (!a->dentry)
				continue;
			if (!acb_get(a))
				continue;
			acb_registry_unlock();
			agentfs_unpublish_agent(a);
			acb_put(a);
			acb_registry_lock();
		}
		acb_registry_unlock();
		agentfs_sb = NULL;
	}
	kill_anon_super(sb);
}

static struct file_system_type agentfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "agentfs",
	.init_fs_context	= agentfs_init_fs_context,
	.kill_sb	= agentfs_kill_sb,
};

static int __init agentfs_init(void)
{
	return register_filesystem(&agentfs_fs_type);
}
module_init(agentfs_init);
MODULE_LICENSE("GPL");
