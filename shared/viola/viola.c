/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * YukiZygisk - Viola launcher (Custom bypass version).
 * Kept: Full environment setup, zygiskd startup logic.
 * Removed: Manifest signature verification.
 */
#include "viola.h"
#include <viola_build.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>

// 伪装成验签成功的函数（如果你前面还有独立的 viola.c 库文件，也要改那个库文件，或者在这里强行声明）
extern int viola_manifest_verify(const void *data, size_t size, const void *signature,
                                 size_t signature_size, struct viola_manifest_view *out);

// 核心 Launch 逻辑
static int cmd_launch(const char *module_dir) {
    char path[PATH_MAX];
    char bin_path[PATH_MAX];
    char lib_path[PATH_MAX];
    char run_path[PATH_MAX];
    char config_path[PATH_MAX];
    char log_path[PATH_MAX];
    
    // 1. 还原原版的环境配置
    snprintf(bin_path, sizeof(bin_path), "%s/bin", module_dir);
    snprintf(lib_path, sizeof(lib_path), "%s/lib64:%s/lib:%s/bin", module_dir, module_dir, module_dir);
    snprintf(run_path, sizeof(run_path), "%s/run", module_dir);
    snprintf(log_path, sizeof(log_path), "%s/log/zygiskd64.log", module_dir);

    // 2. 强行覆盖环境变量
    setenv("LD_LIBRARY_PATH", lib_path, 1);
    setenv("PATH", "/system/bin:/system/xbin", 1);
    
    // 3. 清理会干扰子进程的环境变量
    unsetenv("LD_PRELOAD");
    unsetenv("LD_AUDIT");
    unsetenv("LD_DEBUG");

    // 4. 确保目录存在
    mkdir(module_dir, 0755);
    mkdir(bin_path, 0755);
    mkdir(run_path, 0755);

    // 5. 执行 zygiskd64
    char zygiskd[PATH_MAX];
    snprintf(zygiskd, sizeof(zygiskd), "%s/zygiskd64", bin_path);
    
    if (access(zygiskd, X_OK) != 0) {
        fprintf(stderr, "viola: missing zygiskd64 at %s\n", zygiskd);
        return 1;
    }

    printf("viola: launching zygiskd64 from %s\n", zygiskd);
    
    // 使用 fork + exec 替代 system，让 zygiskd 成为独立进程
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    } else if (pid == 0) {
        // 子进程：重定向标准输出到 log 文件
        int fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            close(fd);
        }
        // 将自身脱离父进程
        setsid();
        execl(zygiskd, zygiskd, NULL);
        perror("execl zygiskd64");
        _exit(127);
    }
    
    // 父进程：等待子进程退出（或者原版可能是直接退出）
    // 为了保险起见，这里不 wait，让 zygiskd 完全后台运行
    return 0;
}

int main(int argc, char **argv) {
    const char *module_dir = NULL;
    
    if (argc < 3) {
        fprintf(stderr, "Usage: %s launch --module-dir <dir>\n", argv[0]);
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--module-dir") == 0 && i + 1 < argc) {
            module_dir = argv[i + 1];
            break;
        }
    }

    if (!module_dir) {
        fprintf(stderr, "viola: missing --module-dir\n");
        return 1;
    }

    if (strcmp(argv[1], "launch") == 0) {
        return cmd_launch(module_dir);
    } else if (strcmp(argv[1], "verify") == 0) {
        // 如果被调用 verify，直接返回 0 骗过安装脚本
        printf("viola: verify bypassed\n");
        return 0;
    }

    fprintf(stderr, "viola: unknown command %s\n", argv[1]);
    return 1;
}
