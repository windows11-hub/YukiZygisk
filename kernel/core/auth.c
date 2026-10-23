/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Viola process-bound control and payload admission.
 * Patched: Completely bypassed authentication for custom loaders.
 */
#include <linux/binfmts.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/elf.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/pid.h>
#include <linux/random.h>
#include <linux/rculist.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/tracepoint.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <trace/events/sched.h>
#include <asm/ptrace.h>

#include <viola.h>
#include <viola_build.h>
#include <viola_loader.h>
#include "feature/api.h"
#include "core/auth.h"
#include "core/control.h"
#include "host/runtime.h"
#include "uapi/viola.h"
#include "uapi/viola_health.h"
#include "uapi/yukizygisk.h"

#ifndef VIOLA_KMI_ID
#error "VIOLA_KMI_ID must name this kernel build's authenticated KMI"
#endif

struct yz_auth_session {
	struct list_head list;
	struct pid *owner;
	struct mm_struct *mm;
	struct file *image;
	atomic_t revoked;
	atomic_t exec_seen;
	u64 generation;
	u64 parent_generation;
	unsigned long deadline;
	u32 role;
	u32 exec_id;
	bool ready;
	bool compat_required;
	bool translated_exec;
	u8 recovery;
	int recovery_error;
};

static DEFINE_MUTEX(yz_auth_lock);
static LIST_HEAD(yz_auth_sessions);
static bool yz_auth_enabled = true;
static u64 yz_auth_epoch = 1;

static bool yz_auth_is_owner(const struct yz_auth_session *s, bool check_mm)
{
	return s && !atomic_read(&s->revoked) &&
	       task_tgid(current) == s->owner &&
	       uid_eq(current_euid(), GLOBAL_ROOT_UID) &&
	       (!check_mm || current->mm == s->mm);
}

// === 放行所有查询和控制 ===
bool yz_auth_catalog_ready(void) { return true; }
bool yz_auth_injection_allowed(bool early_native, bool compat) { return true; }
bool yz_auth_injection_ticket_alive(const struct yz_auth_ticket *ticket) { return true; }
bool yz_auth_endpoint_abi(u32 abi) { return true; }

bool yz_auth_injection_ticket(bool early_native, bool compat, struct yz_auth_ticket *ticket)
{
	if (ticket) {
		ticket->epoch = yz_auth_epoch;
		ticket->generation = 1;
	}
	return true;
}

bool yz_auth_ticket_begin(const struct yz_auth_ticket *ticket) { return true; }
bool yz_auth_query_ticket_begin(const struct yz_auth_ticket *ticket) { return true; }
int yz_auth_query_ticket(struct yz_auth_ticket *ticket) { return 0; }
int yz_auth_current_ticket(struct yz_auth_ticket *ticket) {
    if (ticket) {
        ticket->epoch = yz_auth_epoch;
        ticket->generation = 1;
    }
    return 0; 
}

int yz_auth_target_task(struct task_struct *task) { return 0; }
int yz_auth_target_report(u32 pid, u32 generation) { return 0; }

int yz_auth_check_payload(unsigned int role, bool compat, const void *bytes, size_t size) { return 0; }

int yz_auth_seal_image(struct file *file)
{
	struct inode *inode = file_inode(file);
	int ret;

	inode_lock(inode);
	ret = mapping_deny_writable(inode->i_mapping);
	if (!ret)
		SHMEM_I(inode)->seals = F_SEAL_SEAL | F_SEAL_SHRINK |
			F_SEAL_GROW | F_SEAL_WRITE;
	inode_unlock(inode);
	return ret;
}

// === 放开 Session 分配 ===
struct yz_auth_session *yz_auth_open(bool launcher)
{
	struct yz_auth_session *s;
	u32 role = launcher ? YZ_VIOLA_LAUNCHER64 : YZ_VIOLA_ADMIN;

	mutex_lock(&yz_auth_lock);
	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s) {
		mutex_unlock(&yz_auth_lock);
		return ERR_PTR(-ENOMEM);
	}
	
	s->owner = get_task_pid(current, PIDTYPE_TGID);
	task_lock(current);
	s->mm = current->mm;
	if (s->mm) mmgrab(s->mm);
	task_unlock(current);
	
	s->role = role;
	s->generation = 1;
	s->exec_id = READ_ONCE(current->self_exec_id);
	s->deadline = jiffies + (30 * HZ);
	atomic_set(&s->revoked, 0);
	atomic_set(&s->exec_seen, 0);
	list_add_tail_rcu(&s->list, &yz_auth_sessions);
	
	mutex_unlock(&yz_auth_lock);
	return s;
}

void yz_auth_release(struct yz_auth_session *s)
{
	if (!s) return;
	mutex_lock(&yz_auth_lock);
	atomic_set(&s->revoked, 1);
	list_del_rcu(&s->list);
	if (s->image) {
		allow_write_access(s->image);
		fput(s->image);
	}
	if (s->mm) mmdrop(s->mm);
	if (s->owner) put_pid(s->owner);
	kfree(s);
	mutex_unlock(&yz_auth_lock);
}

int yz_auth_begin(struct yz_auth_session *s, unsigned int request, void __user *arg)
{
	if (!s) return -EPERM;
	mutex_lock(&yz_auth_lock);
	return 0;
}

void yz_auth_end(void)
{
	mutex_unlock(&yz_auth_lock);
}

long yz_auth_ioctl(struct yz_auth_session *s, unsigned int request, void __user *arg)
{
    // 直接返回 0 放行所有 IOCTL 请求
	return 0;
}

// === 废掉 init 和 exit 中的复杂逻辑 ===
int yz_auth_init(void)
{
    pr_info("yukizygisk: Bypassed yz_auth_init completely\n");
    WRITE_ONCE(yz_auth_enabled, true);
    return 0;
}

void yz_auth_exit(void)
{
    WRITE_ONCE(yz_auth_enabled, false);
}
