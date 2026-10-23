/* SPDX-License-Identifier: Apache-2.0 */
/* Simplified launcher: Bypasses manifest and signature checks. */
#define _GNU_SOURCE
#include "kernel/uapi/viola.h"
#include "kernel/uapi/yukizygisk.h"
#include "module_loader.h"
#include "viola.h"
#include "viola_build.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#define VIOLA_BASE "/data/adb/yukizygisk"

static int failure(const char *stage, int error) {
  fprintf(stderr, "viola: %s: %s (%d)\n", stage, strerror(-error), error);
  return error ? error : -EIO;
}

// 强行获取内核控制句柄（修复了 SYS_prctl 缺失）
static int control_open(unsigned option, unsigned magic) {
  int fd = -ENODEV;
  syscall(SYS_prctl, option, magic, (unsigned long)&fd);
  return fd;
}

// 自己读取文件并调用真正的内核加载函数（修复了函数名错误）
static int load_kernel_module(const char *directory) {
    char ko_path[PATH_MAX];
    // 强行锁定你的 KMI 和模块名
    snprintf(ko_path, sizeof(ko_path), "%s/lkm/android15-6.6_yukizygisk.ko", directory);
    
    int fd = open(ko_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "viola: cannot open %s\n", ko_path);
        return -errno;
    }

    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0) {
        close(fd);
        return -EINVAL;
    }

    void *buffer = mmap(NULL, (size_t)st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buffer == MAP_FAILED) {
        close(fd);
        return -errno;
    }

    ssize_t n = read(fd, buffer, (size_t)st.st_size);
    close(fd);
    if (n != st.st_size) {
        munmap(buffer, (size_t)st.st_size);
        return -EIO;
    }

    mprotect(buffer, (size_t)st.st_size, PROT_READ);
    
    // 调用原版正确的加载函数（image指针，size，参数，syscall函数）
    int ret = viola_load_verified_kernel(buffer, (size_t)st.st_size, 
                                         "ksu_module_present=1", 
                                         (long (*)(long, unsigned long, unsigned long, unsigned long))syscall);
    
    munmap(buffer, (size_t)st.st_size);
    return ret;
}

static int start_zygiskd(const char *directory, int control_fd) {
    char bin_path[PATH_MAX];
    char control_env[64];
    snprintf(bin_path, sizeof(bin_path), "%s/bin/zygiskd64", directory);
    snprintf(control_env, sizeof(control_env), "YUKIZYGISK_CONTROL_FD=%d", control_fd);

    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        char *args[] = {bin_path, NULL};
        char *env[] = {
            "PATH=/system/bin:/system/xbin",
            control_env,
            "YUKIZYGISK_CONFIG=" VIOLA_BASE "/yzconfig.json",
            "YUKIZYGISK_LOG_DIR=" VIOLA_BASE "/log",
            NULL
        };
        execve(bin_path, args, env);
        _exit(1);
    }
    return 0;
}

int main(int argc, char **argv) {
  const char *directory = NULL;
  
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--module-dir") && i + 1 < argc) {
        directory = argv[i + 1];
    }
  }

  if (!directory) {
      fprintf(stderr, "viola: missing --module-dir\n");
      return 1;
  }

  if (!strcmp(argv[1], "verify")) {
      printf("viola: verify bypassed\n");
      return 0;
  }

  // 1. 强行加载 .ko 模块
  int ret = load_kernel_module(directory);
  if (ret) {
      fprintf(stderr, "viola: load kernel failed: %d\n", ret);
      return 1;
  }

  // 2. 获取内核控制节点
  int control = control_open(YZ_PRCTL_CONTROL_OPTION, YZ_PRCTL_CONTROL_MAGIC);
  if (control < 0) {
      fprintf(stderr, "viola: control_open failed\n");
      return 1;
  }

  // 3. 拉起 zygiskd 并传递控制句柄
  start_zygiskd(directory, control);
  
  printf("viola: launch succeeded\n");
  return 0;
}
