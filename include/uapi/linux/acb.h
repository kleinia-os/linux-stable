/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_ACB_H
#define _UAPI_LINUX_ACB_H

#include <linux/types.h>

#define ACB_NAME_MAX		64
#define ACB_SKILL_MAX		32
#define ACB_REQ_MAX		4096
#define ACB_SCHEMA_MAX		4096

/* AF_AGENT address family number (mirrored in include/linux/socket.h) */
#define AF_AGENT		46
#define PF_AGENT		AF_AGENT

/* socket address for AF_AGENT: the kernel-minted AID carries authority,
 * agent:// names are resolved in user space (libagenturi, via agentfs) */
struct sockaddr_agent {
	__u16	sag_family;		/* AF_AGENT */
	__u16	sag_pad0;
	__u64	sag_aid;		/* target agent id */
	char	sag_skill[ACB_SKILL_MAX];
	__u32	sag_pad1;
};

/* agent classes */
enum {
	ACB_CLASS_APP = 0,
	ACB_CLASS_SYS = 1,
};

/* acb_create() flags */
#define ACB_F_EXCL		0x1	/* fail if name already registered */

/* capability bits: what an agent is allowed to do */
#define ACB_CAP_INVOKE_APP	(1UL << 0)	/* call APP-class agents */
#define ACB_CAP_INVOKE_SYS	(1UL << 1)	/* call SYS-class agents */
#define ACB_CAP_MANAGE		(1UL << 2)	/* destroy agents, raise policy */

/* hook events, subscribable via ACB_IOC_SUBSCRIBE */
#define ACB_EVT_AGENT_CREATE	(1UL << 0)
#define ACB_EVT_AGENT_DESTROY	(1UL << 1)
#define ACB_EVT_MEMBER_EXIT	(1UL << 2)
#define ACB_EVT_CTX_PRESSURE	(1UL << 3)	/* cnode over quota */

/* delivered through ACB_IOC_RECV_EVENT on the agentfd */
struct acb_event {
	__u64	mask;			/* which of ACB_EVT_* fired */
	__u64	aid;			/* subject agent */
	__u32	pid;			/* member pid, MEMBER_EXIT only */
	__u32	exit_code;		/* exit code / signal, MEMBER_EXIT only */
	char	name[ACB_NAME_MAX];
};

/* skill registered by the owner through ACB_IOC_ADD_SKILL */
struct acb_skill_desc {
	char	name[ACB_SKILL_MAX];
	char	schema[ACB_SCHEMA_MAX];	/* JSON schema, NUL-terminated */
};

/* request popped by the owner through ACB_IOC_RECV_REQ */
struct acb_recv {
	__u64	req_id;
	__u64	caller_aid;		/* 0 = unattached caller */
	char	skill[ACB_SKILL_MAX];
	__u32	len;			/* payload length in buf[] */
	__u32	reserved;
	char	buf[ACB_REQ_MAX];	/* request payload */
};

/* reply posted by the owner through ACB_IOC_REPLY */
struct acb_reply {
	__u64	req_id;
	__u32	len;			/* reply length */
	__u32	reserved;
	char	buf[ACB_REQ_MAX];
};

/*
 * Cnode — kernel-managed agent context (the inode of context).
 *
 * Model: an append-only log of typed, immutable segments.  The
 * model-visible view is a *derivation*: compaction shadows a seq range
 * and appends a replacement segment; the truth is never rewritten.
 * Segments live in kernel memory bounded by the cnode quota — the
 * kernel is the runtime authority (survives member process death);
 * persistence beyond reboot is a user-space checkpoint concern
 * (dump/restore through READ/APPEND).
 */
#define ACB_CTX_MAX_SEG		65536	/* max payload per segment, bytes */

/* segment classes: kernel special-cases TOOL_CALL/TURN_END/BARRIER,
 * the rest is policy metadata for user space */
enum {
	ACB_CTX_SURF_USER	= 1,	/* model-visible surface events */
	ACB_CTX_SURF_ASSIST	= 2,
	ACB_CTX_SURF_TOOL	= 3,	/* tool result */
	ACB_CTX_SURF_SYSTEM	= 4,
	ACB_CTX_LOG_TOOL_CALL	= 10,	/* log-only: opener for closers */
	ACB_CTX_LOG_REQUEST	= 11,
	ACB_CTX_LOG_APPROVAL	= 12,
	ACB_CTX_LOG_ATTEMPT	= 13,
	ACB_CTX_LOG_TURN_END	= 14,	/* fork boundary (balanced prefix) */
	ACB_CTX_LOG_CHECKPOINT	= 15,	/* durability barrier */
	ACB_CTX_LOG_GC		= 16,
	ACB_CTX_LOG_CLOSER	= 17,	/* synthesized on member death */
	ACB_CTX_PLUGIN		= 20,	/* ignorable plugin records */
};

/* segment flags */
#define ACB_CTX_F_REPLACEMENT	(1U << 0)	/* compaction output */
#define ACB_CTX_F_SHADOWED	(1U << 1)	/* internal: covered by a
						 * replacement; kept as truth */

/* per-segment lineage header, returned by READ and echoed by APPEND */
struct acb_ctx_seginfo {
	__u64	seq;
	__u32	cls;
	__u32	flags;
	__u64	origin_req;		/* req_id that produced this seg */
	__u64	origin_aid;		/* caller AID, 0 = self */
	char	origin_skill[ACB_SKILL_MAX];
	__u32	len;
	__u32	pad;
};

struct acb_ctx_append {
	struct acb_ctx_seginfo hdr;	/* seq/flags ignored on input */
	__u64	data_ptr;		/* user pointer, may be NULL if len==0 */
};

struct acb_ctx_compact {
	__u64	start_seq;		/* shadow [start,end] inclusive */
	__u64	end_seq;
	struct acb_ctx_seginfo hdr;	/* replacement segment */
	__u64	data_ptr;
};

struct acb_ctx_read {
	__u64	cursor_seq;		/* in: read first seg with seq >
					 * cursor; out: seq read, 0 = end */
	struct acb_ctx_seginfo hdr;	/* out */
	__u64	data_ptr;		/* user buffer for payload */
	__u32	len_cap;		/* capacity of data buffer */
	__u32	flags;			/* ACB_CTX_RF_* */
#define ACB_CTX_RF_INCLUDE_SHADOWED	(1U << 0)
	__s32	payload_len;		/* out: copied, or -E2BIG (cursor
					 * stays before the seg; retry with
					 * a bigger buffer re-reads it) */
	__u32	pad;
};

struct acb_ctx_info {
	__u64	quota;			/* bytes, 0 = unlimited */
	__u64	bytes;			/* live + shadowed payload bytes */
	__u64	shadowed_bytes;		/* reclaimable by GC */
	__u32	nsegs;
	__u32	pad0;
	__u64	head_seq;
	__u64	last_turn_seq;		/* balanced fork boundary, 0 = none */
	__u64	parent_aid;		/* fork lineage */
	__u32	depth;
	__u32	pad1;
};

struct acb_ctx_fork {
	__u32	child_fd;		/* agentfd of an existing, empty ACB */
	__u32	pad;
};

#define ACB_IOC_MAGIC 'A'

#define ACB_IOC_SET_POLICY	_IOW(ACB_IOC_MAGIC, 0x01, unsigned long)
#define ACB_IOC_ADD_SKILL	_IOW(ACB_IOC_MAGIC, 0x02, struct acb_skill_desc)
#define ACB_IOC_DEL_SKILL	_IOW(ACB_IOC_MAGIC, 0x03, struct acb_skill_desc)
#define ACB_IOC_SUBSCRIBE	_IOW(ACB_IOC_MAGIC, 0x04, unsigned long)
#define ACB_IOC_RECV_REQ	_IOWR(ACB_IOC_MAGIC, 0x05, struct acb_recv)
#define ACB_IOC_RECV_EVENT	_IOWR(ACB_IOC_MAGIC, 0x06, struct acb_event)
#define ACB_IOC_REPLY		_IOW(ACB_IOC_MAGIC, 0x07, struct acb_reply)

/* cnode ioctls (agentfd) */
#define ACB_IOC_CTX_SETQUOTA	_IOW(ACB_IOC_MAGIC, 0x10, unsigned long)
#define ACB_IOC_CTX_APPEND	_IOW(ACB_IOC_MAGIC, 0x11, struct acb_ctx_append)
#define ACB_IOC_CTX_COMPACT	_IOW(ACB_IOC_MAGIC, 0x12, struct acb_ctx_compact)
#define ACB_IOC_CTX_GC		_IOW(ACB_IOC_MAGIC, 0x13, __u64) /* watermark seq */
#define ACB_IOC_CTX_READ	_IOWR(ACB_IOC_MAGIC, 0x14, struct acb_ctx_read)
#define ACB_IOC_CTX_INFO	_IOR(ACB_IOC_MAGIC, 0x15, struct acb_ctx_info)
#define ACB_IOC_CTX_FORK	_IOW(ACB_IOC_MAGIC, 0x16, struct acb_ctx_fork)
#define ACB_IOC_CTX_BARRIER	_IO(ACB_IOC_MAGIC, 0x17)
#define ACB_IOC_WHOAMI		_IOR(ACB_IOC_MAGIC, 0x18, unsigned long)

#endif /* _UAPI_LINUX_ACB_H */
