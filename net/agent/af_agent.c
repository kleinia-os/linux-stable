// SPDX-License-Identifier: GPL-2.0
/*
 * AF_AGENT — narrow transport address family over the ACB mailbox.
 *
 * Design (see docs/netstack-uri-research.md in the acb repo):
 * the socket address carries a kernel-minted AID plus a skill name;
 * agent:// name resolution happens in user space (libagenturi).
 * connect() enforces the caller's ACB capability bits in the kernel,
 * sendmsg() enqueues one request into the target agent's mailbox and
 * recvmsg() waits for the owner's reply.  The owner drains requests
 * through its agentfd (ACB_IOC_RECV_REQ/REPLY), identical to the
 * agentfs invoke path — AF_AGENT is just another entrance into the
 * same kernel-mediated RPC.
 */

#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <linux/acb.h>
#include <net/sock.h>

#define AGENT_REQ_TIMEOUT_MS	30000

struct agent_sock {
	struct sock		sk;
	struct acb		*target;	/* ref held while connected */
	char			skill[ACB_SKILL_MAX];
	struct acb_req		*req;		/* single in-flight request */
};

static inline struct agent_sock *agent_sk(const struct sock *sk)
{
	return container_of(sk, struct agent_sock, sk);
}

/* ---------------------------------------------------------------- */

static int agent_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct agent_sock *ag;

	if (!sk)
		return 0;

	ag = agent_sk(sk);
	lock_sock(sk);
	if (ag->req) {
		acb_req_put(ag->req);
		ag->req = NULL;
	}
	if (ag->target) {
		acb_put(ag->target);
		ag->target = NULL;
	}
	release_sock(sk);

	sock_orphan(sk);
	sock_put(sk);
	sock->sk = NULL;
	return 0;
}

static int agent_bind(struct socket *sock, struct sockaddr_unsized *uaddr,
		      int addr_len)
{
	return -EOPNOTSUPP;
}

static int agent_connect(struct socket *sock, struct sockaddr_unsized *uaddr,
			 int addr_len, int flags)
{
	struct sock *sk = sock->sk;
	struct agent_sock *ag = agent_sk(sk);
	struct sockaddr_agent *sa = (struct sockaddr_agent *)uaddr;
	struct acb *target;
	int rc;

	if (addr_len < sizeof(struct sockaddr_agent))
		return -EINVAL;
	if (sa->sag_family != AF_AGENT)
		return -EAFNOSUPPORT;
	if (!sa->sag_skill[0])
		return -EINVAL;

	target = acb_get_by_aid(sa->sag_aid);
	if (!target)
		return -ENOENT;

	/* the capability check point: enforced in-kernel */
	rc = acb_check_invoke(current->acb, target, sa->sag_skill);
	if (rc) {
		acb_put(target);
		return rc;
	}

	lock_sock(sk);
	if (ag->target) {
		release_sock(sk);
		acb_put(target);
		return -EISCONN;
	}
	ag->target = target;
	strscpy(ag->skill, sa->sag_skill, ACB_SKILL_MAX);
	sock->state = SS_CONNECTED;
	sk->sk_state = TCP_ESTABLISHED;
	release_sock(sk);
	return 0;
}

static int agent_getname(struct socket *sock, struct sockaddr *uaddr, int peer)
{
	struct sock *sk = sock->sk;
	struct agent_sock *ag = agent_sk(sk);
	struct sockaddr_agent *sa = (struct sockaddr_agent *)uaddr;

	if (peer) {
		if (!ag->target)
			return -ENOTCONN;
		memset(sa, 0, sizeof(*sa));
		sa->sag_family = AF_AGENT;
		sa->sag_aid = ag->target->aid;
		strscpy(sa->sag_skill, ag->skill, ACB_SKILL_MAX);
	} else {
		memset(sa, 0, sizeof(*sa));
		sa->sag_family = AF_AGENT;
		if (current->acb)
			sa->sag_aid = current->acb->aid;
	}
	return sizeof(*sa);
}

static int agent_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
	struct sock *sk = sock->sk;
	struct agent_sock *ag = agent_sk(sk);
	struct acb *caller = current->acb;
	u64 caller_aid = caller ? caller->aid : 0;
	char *kbuf;
	int rc;

	if (len > ACB_REQ_MAX)
		return -EMSGSIZE;

	kbuf = kmalloc(len ? len : 1, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;
	if (len && !copy_from_iter_full(kbuf, len, &msg->msg_iter)) {
		rc = -EFAULT;
		goto out;
	}

	lock_sock(sk);
	if (!ag->target) {
		rc = -ENOTCONN;
		goto out_unlock;
	}
	if (ag->req) {
		rc = -EBUSY;		/* one outstanding request per socket */
		goto out_unlock;
	}

	rc = acb_check_invoke(caller, ag->target, ag->skill);
	if (rc)
		goto out_unlock;

	rc = acb_route_request(ag->target, ag->skill, kbuf, len,
			       caller_aid, &ag->req);
	if (!rc)
		rc = len;

out_unlock:
	release_sock(sk);
out:
	kfree(kbuf);
	return rc;
}

static int agent_recvmsg(struct socket *sock, struct msghdr *msg, size_t len,
			 int flags)
{
	struct sock *sk = sock->sk;
	struct agent_sock *ag = agent_sk(sk);
	struct acb_req *req;
	long left;
	size_t n;
	int rc;

	lock_sock(sk);
	req = ag->req;
	if (!req) {
		rc = -ENOMSG;
		goto out;
	}

	if (!req->replied && !req->failed) {
		/* sleepable socket lock; a concurrent close waits for us */
		release_sock(sk);
		left = wait_for_completion_interruptible_timeout(&req->done,
				msecs_to_jiffies(AGENT_REQ_TIMEOUT_MS));
		lock_sock(sk);
		req = ag->req;
		if (!req) {			/* changed under us */
			rc = -ENOMSG;
			goto out;
		}
		if (left == 0) {
			ag->req = NULL;
			acb_req_put(req);
			rc = -ETIMEDOUT;
			goto out;
		}
		if (left < 0) {
			rc = left;		/* keep req, retry allowed */
			goto out;
		}
	}

	if (req->failed) {
		ag->req = NULL;
		acb_req_put(req);
		rc = -EPIPE;
		goto out;
	}

	n = min_t(size_t, len, req->reply_len);
	if (n && memcpy_to_msg(msg, req->reply, n)) {
		ag->req = NULL;
		acb_req_put(req);
		rc = -EFAULT;
		goto out;
	}
	ag->req = NULL;
	acb_req_put(req);
	rc = n;

out:
	release_sock(sk);
	return rc;
}

static __poll_t agent_poll(struct file *file, struct socket *sock,
			   poll_table *wait)
{
	struct agent_sock *ag = agent_sk(sock->sk);
	__poll_t mask = datagram_poll(file, sock, wait);

	/* reply ready to recv? */
	if (ag->req && (READ_ONCE(ag->req->replied) || READ_ONCE(ag->req->failed)))
		mask |= EPOLLIN | EPOLLRDNORM;
	/* room to send a new request? */
	if (!ag->req)
		mask |= EPOLLOUT | EPOLLWRNORM;
	return mask;
}

static int agent_setsockopt(struct socket *sock, int level, int optname,
			    sockptr_t optval, unsigned int optlen)
{
	return -ENOPROTOOPT;
}

static int agent_getsockopt(struct socket *sock, int level, int optname,
			    char __user *optval, int __user *optlen)
{
	return -ENOPROTOOPT;
}

static const struct proto_ops agent_ops = {
	.family		= PF_AGENT,
	.owner		= THIS_MODULE,
	.release	= agent_release,
	.bind		= agent_bind,
	.connect	= agent_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= sock_no_accept,
	.getname	= agent_getname,
	.poll		= agent_poll,
	.ioctl		= sock_no_ioctl,
	.gettstamp	= sock_gettstamp,
	.listen		= sock_no_listen,
	.shutdown	= sock_no_shutdown,
	.setsockopt	= agent_setsockopt,
	.getsockopt	= agent_getsockopt,
	.sendmsg	= agent_sendmsg,
	.recvmsg	= agent_recvmsg,
	.mmap		= sock_no_mmap,
};

static struct proto agent_proto = {
	.name		= "AGENT",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct agent_sock),
};

static int agent_pf_create(struct net *net, struct socket *sock,
			   int protocol, int kern)
{
	struct sock *sk;

	if (protocol)
		return -EPROTONOSUPPORT;
	if (sock->type != SOCK_DGRAM)
		return -ESOCKTNOSUPPORT;

	sock->state = SS_UNCONNECTED;
	sock->ops = &agent_ops;

	sk = sk_alloc(net, PF_AGENT, GFP_KERNEL, &agent_proto, kern);
	if (!sk)
		return -ENOMEM;

	sock_init_data(sock, sk);
	return 0;
}

static struct net_proto_family agent_family = {
	.family		= PF_AGENT,
	.create		= agent_pf_create,
	.owner		= THIS_MODULE,
};

static int __init agent_init(void)
{
	int rc;

	rc = sock_register(&agent_family);
	if (rc)
		return rc;

	rc = proto_register(&agent_proto, 0);
	if (rc) {
		sock_unregister(PF_AGENT);
		return rc;
	}

	pr_info("ACB: AF_AGENT address family registered\n");
	return 0;
}

static void __exit agent_exit(void)
{
	proto_unregister(&agent_proto);
	sock_unregister(PF_AGENT);
}

module_init(agent_init);
module_exit(agent_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ACB agent sockets (AF_AGENT)");
