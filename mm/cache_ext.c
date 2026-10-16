#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/kernel.h>
#include <linux/memcontrol.h>
#include <linux/mm_types.h>
#include <linux/types.h>
#include <linux/cgroup.h>
#include <linux/init.h>

static const struct btf_type *cache_ext_eviction_ctx_type;
static const struct btf_type *cache_ext_admission_ctx_type;

static s32 cache_ext_init_stub(struct mem_cgroup *memcg) { return 0; }
static void cache_ext_evict_folios_stub(struct cache_ext_eviction_ctx *ctx,
					struct mem_cgroup *memcg) {}
static void cache_ext_folio_added_stub(struct folio *folio) {}
static void cache_ext_folio_accessed_stub(struct folio *folio) {}
static void cache_ext_folio_evicted_stub(struct folio *folio) {}
static bool cache_ext_admit_folio_stub(struct cache_ext_admission_ctx *ctx) { return false; }

static struct cache_ext_ops cache_ext_cfi_stubs = {
	.init          = cache_ext_init_stub,
	.evict_folios  = cache_ext_evict_folios_stub,
	.folio_added   = cache_ext_folio_added_stub,
	.folio_accessed = cache_ext_folio_accessed_stub,
	.folio_evicted = cache_ext_folio_evicted_stub,
	.admit_folio   = cache_ext_admit_folio_stub,
};

static int bpf_cache_ext_init(struct btf *btf)
{
	u32 eviction_type_id, admission_type_id;

	eviction_type_id = btf_find_by_name_kind(btf, "cache_ext_eviction_ctx",
					BTF_KIND_STRUCT);
	if (eviction_type_id < 0) {
		pr_err("cache_ext: failed to find struct cache_ext_eviction_ctx\n");
		return -EINVAL;
	}

	admission_type_id = btf_find_by_name_kind(btf, "cache_ext_admission_ctx",
					BTF_KIND_STRUCT);
	if (admission_type_id < 0) {
		pr_err("cache_ext: failed to find struct cache_ext_admission_ctx\n");
		return -EINVAL;
	}

	cache_ext_eviction_ctx_type = btf_type_by_id(btf, eviction_type_id);
	cache_ext_admission_ctx_type = btf_type_by_id(btf, admission_type_id);
	return 0;
}

static const struct bpf_func_proto *
bpf_cache_ext_get_func_proto(enum bpf_func_id func_id,
				  const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_get_current_pid_tgid:
		return &bpf_get_current_pid_tgid_proto;
	default:
		return bpf_base_func_proto(func_id, prog);
	}
}

static bool bpf_cache_ext_is_valid_access(int off, int size,
					       enum bpf_access_type type,
					       const struct bpf_prog *prog,
					       struct bpf_insn_access_aux *info)
{
	if (off % size != 0)
		return false;

	return btf_ctx_access(off, size, type, prog, info);
}

static int bpf_cache_ext_btf_struct_access(struct bpf_verifier_log *log,
						const struct bpf_reg_state *reg,
						int off, int size)
{
	const struct btf_type *t;

	t = btf_type_by_id(reg->btf, reg->btf_id);
	if (t == cache_ext_eviction_ctx_type) {
		if (off + size > sizeof(struct cache_ext_eviction_ctx)) {
			bpf_log(log,
				"out of bounds access at off %d with size %d\n",
				off, size);
			return -EACCES;
		}
		return SCALAR_VALUE;
	} else if (t == cache_ext_admission_ctx_type) {
		if (off + size > sizeof(struct cache_ext_admission_ctx)) {
			bpf_log(log,
				"out of bounds access at off %d with size %d\n",
				off, size);
			return -EACCES;
		}
		return SCALAR_VALUE;
	}

	return -EACCES;
}

static int bpf_cache_ext_reg_ctx(void *kdata, struct bpf_link *link,
				 void *ctx)
{
	struct cache_ext_ops *ops = kdata;
	struct cgroup *cgrp = ctx;
	struct mem_cgroup *memcg;
	int ret = 0;

	if (!cgrp) {
		pr_err("cache_ext: cgroup is NULL\n");
		return -EINVAL;
	}

	memcg = mem_cgroup_from_css(cgrp->subsys[memory_cgrp_id]);
	if (memcg == NULL) {
		pr_crit("cache_ext: failed to get memcg for registration!\n");
		return -EINVAL;
	}
	if (!memcg->cache_ext_valid) {
		pr_err("cache_ext: refusing attach to cgroup without cache_ext structures\n");
		return -EINVAL;
	}
	pr_info("cache_ext: Calling init\n");
	if (ops->init) {
		ret = ops->init(memcg);
		if (ret) {
			pr_err("cache_ext: init failed with error code: %d\n",
			       ret);
			cache_ext_ds_registry_del_all(memcg);
			return ret;
		}
	}

	down_write(&cgrp->bpf.cache_ext_sem);
	rcu_assign_pointer(cgrp->bpf.cache_ext_ops,
			   (struct cache_ext_ops *)kdata);
	up_write(&cgrp->bpf.cache_ext_sem);

	pr_info("cache_ext: Registering struct ops\n");
	return 0;
}

static void bpf_cache_ext_unreg_ctx(void *kdata, struct bpf_link *link,
				    void *ctx)
{
	struct cgroup *cgrp = ctx;
	struct mem_cgroup *memcg;

	pr_info("cache_ext: Unregistering struct ops\n");

	if (!cgrp) {
		pr_err("cache_ext: cgroup is NULL\n");
		return;
	}

	down_write(&cgrp->bpf.cache_ext_sem);
	rcu_assign_pointer(cgrp->bpf.cache_ext_ops, NULL);
	up_write(&cgrp->bpf.cache_ext_sem);

	/*
	 * Hook callers fetch the ops pointer under rcu_read_lock(); wait
	 * for them to finish before the struct_ops kdata may be freed once
	 * this returns.
	 */
	synchronize_rcu();

	memcg = mem_cgroup_from_css(cgrp->subsys[memory_cgrp_id]);
	if (memcg == NULL) {
		pr_crit("cache_ext: failed to get memcg for release!\n");
		return;
	}
	if (!memcg->cache_ext_valid) {
		pr_warn("cache_ext: skipping teardown for cgroup without cache_ext structures\n");
		return;
	}
	pr_info("cache_ext: unreg: Memcg pointer: %p\n", memcg);
	cache_ext_ds_registry_del_all(memcg);
}

static int bpf_cache_ext_init_member(const struct btf_type *t,
					  const struct btf_member *member,
					  void *kdata, const void *udata)
{
	return 0;
}

static int bpf_cache_ext_check_member(const struct btf_type *t,
					   const struct btf_member *member,
					   const struct bpf_prog *prog)
{
	return 0;
}

static int bpf_cache_ext_validate(void *kdata)
{
	return 0;
}

static const struct bpf_verifier_ops bpf_cache_ext_verifier_ops = {
	.get_func_proto = bpf_cache_ext_get_func_proto,
	.is_valid_access = bpf_cache_ext_is_valid_access,
	.btf_struct_access = bpf_cache_ext_btf_struct_access,
};

struct bpf_struct_ops bpf_cache_ext_ops = {
	.verifier_ops = &bpf_cache_ext_verifier_ops,
	.init = bpf_cache_ext_init,
	.init_member = bpf_cache_ext_init_member,
	.check_member = bpf_cache_ext_check_member,
	.validate = bpf_cache_ext_validate,
	.name = "cache_ext_ops",
	.owner = THIS_MODULE,
	.cfi_stubs = &cache_ext_cfi_stubs,
	.reg_ctx = bpf_cache_ext_reg_ctx,
	.unreg_ctx = bpf_cache_ext_unreg_ctx,
};

static int __init cache_ext_init(void)
{
	int ret;

	ret = register_bpf_struct_ops(&bpf_cache_ext_ops, cache_ext_ops);
	if (ret) {
		pr_err("cache_ext: failed to register struct_ops: %d\n", ret);
		return ret;
	}
	pr_info("cache_ext: struct_ops registered\n");
	return 0;
}
__initcall(cache_ext_init);