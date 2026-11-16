/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_AGENTFS_H
#define _LINUX_AGENTFS_H

struct acb;
struct acb_skill;

#ifdef CONFIG_AGENT_FS

int agentfs_publish_agent(struct acb *acb);
void agentfs_unpublish_agent(struct acb *acb);
int agentfs_publish_skill(struct acb *acb, struct acb_skill *skill);
void agentfs_unpublish_skill(struct acb *acb, struct acb_skill *skill);

#else /* !CONFIG_AGENT_FS */

static inline int agentfs_publish_agent(struct acb *acb) { return 0; }
static inline void agentfs_unpublish_agent(struct acb *acb) { }
static inline int agentfs_publish_skill(struct acb *acb, struct acb_skill *skill) { return 0; }
static inline void agentfs_unpublish_skill(struct acb *acb, struct acb_skill *skill) { }

#endif /* CONFIG_AGENT_FS */
#endif /* _LINUX_AGENTFS_H */
