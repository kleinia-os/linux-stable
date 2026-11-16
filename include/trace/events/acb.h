/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM acb

#if !defined(_TRACE_ACB_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_ACB_H

#include <linux/tracepoint.h>

/*
 * ACB tracepoints: every agent lifecycle change, kernel-mediated skill
 * RPC and capability denial is observable with ftrace/perf/bpftrace,
 * the same way syscalls are.
 */

TRACE_EVENT(acb_agent_create,
	TP_PROTO(u64 aid, const char *name, u8 class),
	TP_ARGS(aid, name, class),
	TP_STRUCT__entry(
		__field(u64,	aid)
		__array(char,	name, 64)
		__field(u8,	class)
	),
	TP_fast_assign(
		__entry->aid	= aid;
		strscpy(__entry->name, name, 64);
		__entry->class	= class;
	),
	TP_printk("aid=%llu name=%s class=%s",
		  __entry->aid, __entry->name,
		  __entry->class == 1 ? "sys" : "app")
);

TRACE_EVENT(acb_agent_destroy,
	TP_PROTO(u64 aid, const char *name),
	TP_ARGS(aid, name),
	TP_STRUCT__entry(
		__field(u64,	aid)
		__array(char,	name, 64)
	),
	TP_fast_assign(
		__entry->aid	= aid;
		strscpy(__entry->name, name, 64);
	),
	TP_printk("aid=%llu name=%s", __entry->aid, __entry->name)
);

TRACE_EVENT(acb_member_exit,
	TP_PROTO(u64 aid, const char *name, pid_t pid, int exit_code),
	TP_ARGS(aid, name, pid, exit_code),
	TP_STRUCT__entry(
		__field(u64,	aid)
		__array(char,	name, 64)
		__field(pid_t,	pid)
		__field(int,	exit_code)
	),
	TP_fast_assign(
		__entry->aid	= aid;
		strscpy(__entry->name, name, 64);
		__entry->pid	= pid;
		__entry->exit_code = exit_code;
	),
	TP_printk("aid=%llu name=%s pid=%d exit_code=%d",
		  __entry->aid, __entry->name, __entry->pid, __entry->exit_code)
);

TRACE_EVENT(acb_rpc_entry,
	TP_PROTO(u64 req_id, u64 caller_aid, u64 target_aid, const char *skill),
	TP_ARGS(req_id, caller_aid, target_aid, skill),
	TP_STRUCT__entry(
		__field(u64,	req_id)
		__field(u64,	caller_aid)
		__field(u64,	target_aid)
		__array(char,	skill, 32)
	),
	TP_fast_assign(
		__entry->req_id		= req_id;
		__entry->caller_aid	= caller_aid;
		__entry->target_aid	= target_aid;
		strscpy(__entry->skill, skill, 32);
	),
	TP_printk("req_id=%llu caller=%llu target=%llu skill=%s",
		  __entry->req_id, __entry->caller_aid, __entry->target_aid,
		  __entry->skill)
);

TRACE_EVENT(acb_rpc_exit,
	TP_PROTO(u64 req_id, u64 target_aid, bool failed),
	TP_ARGS(req_id, target_aid, failed),
	TP_STRUCT__entry(
		__field(u64,	req_id)
		__field(u64,	target_aid)
		__field(bool,	failed)
	),
	TP_fast_assign(
		__entry->req_id		= req_id;
		__entry->target_aid	= target_aid;
		__entry->failed		= failed;
	),
	TP_printk("req_id=%llu target=%llu failed=%d",
		  __entry->req_id, __entry->target_aid, __entry->failed)
);

TRACE_EVENT(acb_invoke_denied,
	TP_PROTO(u64 caller_aid, u64 target_aid, const char *skill),
	TP_ARGS(caller_aid, target_aid, skill),
	TP_STRUCT__entry(
		__field(u64,	caller_aid)
		__field(u64,	target_aid)
		__array(char,	skill, 32)
	),
	TP_fast_assign(
		__entry->caller_aid	= caller_aid;
		__entry->target_aid	= target_aid;
		strscpy(__entry->skill, skill, 32);
	),
	TP_printk("caller=%llu target=%llu skill=%s DENIED",
		  __entry->caller_aid, __entry->target_aid, __entry->skill)
);

TRACE_EVENT(acb_ctx_append,
	TP_PROTO(u64 aid, u64 seq, u32 class, u32 len),
	TP_ARGS(aid, seq, class, len),
	TP_STRUCT__entry(
		__field(u64,	aid)
		__field(u64,	seq)
		__field(u32,	class)
		__field(u32,	len)
	),
	TP_fast_assign(
		__entry->aid	= aid;
		__entry->seq	= seq;
		__entry->class	= class;
		__entry->len	= len;
	),
	TP_printk("aid=%llu seq=%llu class=%u len=%u",
		  __entry->aid, __entry->seq, __entry->class, __entry->len)
);

TRACE_EVENT(acb_ctx_compact,
	TP_PROTO(u64 aid, u64 start, u64 end, u32 nshadowed),
	TP_ARGS(aid, start, end, nshadowed),
	TP_STRUCT__entry(
		__field(u64,	aid)
		__field(u64,	start)
		__field(u64,	end)
		__field(u32,	nshadowed)
	),
	TP_fast_assign(
		__entry->aid	= aid;
		__entry->start	= start;
		__entry->end	= end;
		__entry->nshadowed = nshadowed;
	),
	TP_printk("aid=%llu shadow [%llu,%llu] n=%u",
		  __entry->aid, __entry->start, __entry->end,
		  __entry->nshadowed)
);

TRACE_EVENT(acb_ctx_gc,
	TP_PROTO(u64 aid, u64 watermark, u64 nfreed),
	TP_ARGS(aid, watermark, nfreed),
	TP_STRUCT__entry(
		__field(u64,	aid)
		__field(u64,	watermark)
		__field(u64,	nfreed)
	),
	TP_fast_assign(
		__entry->aid	= aid;
		__entry->watermark = watermark;
		__entry->nfreed	= nfreed;
	),
	TP_printk("aid=%llu watermark=%llu freed_segs=%llu",
		  __entry->aid, __entry->watermark, __entry->nfreed)
);

TRACE_EVENT(acb_ctx_closer,
	TP_PROTO(u64 aid, u64 open_seq, bool outcome_unknown),
	TP_ARGS(aid, open_seq, outcome_unknown),
	TP_STRUCT__entry(
		__field(u64,	aid)
		__field(u64,	open_seq)
		__field(bool,	outcome_unknown)
	),
	TP_fast_assign(
		__entry->aid	= aid;
		__entry->open_seq = open_seq;
		__entry->outcome_unknown = outcome_unknown;
	),
	TP_printk("aid=%llu open_seq=%llu outcome=%s",
		  __entry->aid, __entry->open_seq,
		  __entry->outcome_unknown ? "unknown" : "not_started")
);

#endif /* _TRACE_ACB_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
