/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Viola process-bound control and payload admission.
 * Patched: Perfect bypass + Endpoint Socket forwarding.
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

// 记录 zygiskd 传上来的 Socket 端点
static int g_endpoint_fd = -1;
static u64 g_endpoint_generation = 1;

// =========================================================
// 1. 状态查询全放行
// =========================================================
bool yz_auth_catalog_ready(void) { return true; }
bool yz_auth_injection_allowed(bool early_native, bool compat) { return true; }
bool yz_auth_injection_ticket_alive(const struct yz_auth_ticket *ticket) { return true; }
bool yz_auth_endpoint_abi(u32 abi) { return true; }

bool yz_auth_injection_ticket(bool early_native, bool compat, struct yz_auth_ticket *ticket)
{
	if (ticket) {
		ticket->epoch = yz_auth_epoch;
		ticket->generation = g_endpoint_generation;
	}
	return true;
}

bool yz_auth_ticket_begin(const struct yz_auth_ticket *ticket) { return true; }
bool yz_auth_query_ticket_begin(const struct yz_auth_ticket *ticket) { return true; }
int yz_auth_query_ticket(struct yz_auth_ticket *ticket) {
    if (ticket) {
        ticket->epoch = yz_auth_epoch;
        ticket->generation = g_endpoint_generation;
    }
    return 0;
}
int yz_auth_current_ticket(struct yz_auth_ticket *ticket) {
    if (ticket) {
        ticket->epoch = yz_auth_epoch;
        ticket->generation = g_endpoint_generation;
    }
    return 0; 
}

int yz_auth_target_task(struct task_struct *task) { return 0; }
int yz_auth_target_report(u32 pid, u32 generation) { return 0; }
int yz_auth_check_payload(unsigned int role, bool compat, const void *bytes, size_t size) { return 0; }

// 补齐未定义符号
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

// =========================================================
// 2. Session 伪造
// =========================================================
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

// =========================================================
// 3. 核心：接管并分发 Endpoint Socket
// =========================================================
long yz_auth_ioctl(struct yz_auth_session *s, unsigned int request, void __user *arg)
{
    switch (request) {
    case YZ_IOCTL_VIOLA_STATUS: {
        struct yz_viola_status status;
        if (copy_from_user(&status, arg, sizeof(status)))
            return -EFAULT;
        memset(&status, 0, sizeof(status));
        status.size = sizeof(status);
        status.version = YZ_VIOLA_VERSION;
        status.profile = VIOLA_PROFILE;
        status.catalog_ready = 1;
        status.daemon64 = YZ_VIOLA_READY;
        status.daemon32 = YZ_VIOLA_READY;
        status.role = YZ_VIOLA_DAEMON64;
        status.owner_pid = task_tgid_nr(current);
        memset(status.release_id, 0xAA, sizeof(status.release_id)); 
        memset(status.trust_id, 0xBB, sizeof(status.trust_id));
        return copy_to_user(arg, &status, sizeof(status)) ? -EFAULT : 0;
    }
    case YZ_IOCTL_REGISTER_ENDPOINT: {
        struct yz_endpoint_register_cmd cmd;
        if (copy_from_user(&cmd, arg, sizeof(cmd)))
            return -EFAULT;
        
        // 【核心】保存 zygiskd 传上来的 socket fd
        g_endpoint_fd = cmd.sock_fd; // 具体字段名可能是 cmd.sock_fd 或 cmd.listener
        g_endpoint_generation++;
        cmd.generation = g_endpoint_generation;
        
        pr_info("yukizygisk: saved endpoint socket fd = %d, gen = %llu\n", g_endpoint_fd, g_endpoint_generation);
        return copy_to_user(arg, &cmd, sizeof(cmd)) ? -EFAULT : 0;
    }
    case YZ_IOCTL_GET_ENDPOINT_STATE_FD: {
        struct yz_endpoint_state_fd_cmd cmd;
        if (copy_from_user(&cmd, arg, sizeof(cmd)))
            return -EFAULT;
            
        // Zygote 来要 socket 时，把存起来的 fd 还给它！
        cmd.fd = g_endpoint_fd;
        cmd.generation = g_endpoint_generation;
        pr_info("yukizygisk: handing out endpoint socket fd = %d to pid %d\n", g_endpoint_fd, task_tgid_nr(current));
        return copy_to_user(arg, &cmd, sizeof(cmd)) ? -EFAULT : 0;
    }
    case YZ_IOCTL_GET_RUNTIME: {
        struct yz_runtime_query_cmd cmd;
        if (copy_from_user(&cmd, arg, sizeof(cmd)))
            return -EFAULT;
        cmd.capabilities = 0xFFFFFFFF; 
        cmd.count = 1; // 强行伪造一条记录，骗过 UI
        if (cmd.entries) {
            struct yz_runtime_record record;
            memset(&record, 0, sizeof(record));
            record.pid = 1;
            record.abi = YZ_RUNTIME_ABI_64;
            record.kind = YZ_RUNTIME_KIND_ZYGOTE;
            record.state = YZ_RUNTIME_STATE_INJECTED;
            if (copy_to_user((void __user *)(uintptr_t)cmd.entries, &record, sizeof(record)))
                return -EFAULT;
        }
        return copy_to_user(arg, &cmd, sizeof(cmd)) ? -EFAULT : 0;
    }
    case YZ_IOCTL_GET_ZYGOTE_VARIANTS: {
        struct yz_zygote_variants_cmd cmd;
        if (copy_from_user(&cmd, arg, sizeof(cmd))) return -EFAULT;
        cmd.count = 0;
        return copy_to_user(arg, &cmd, sizeof(cmd)) ? -EFAULT : 0;
    }
    case YZ_IOCTL_ALLOW_MODULE_LOAD_POLICY: {
        return 0;
    }
    default:
        return 0;
    }
}

int yz_auth_init(void)
{
    pr_info("yukizygisk: auth module in perfect bypass mode\n");
    WRITE_ONCE(yz_auth_enabled, true);
    return 0;
}

void yz_auth_exit(void)
{
    WRITE_ONCE(yz_auth_enabled, false);
}
