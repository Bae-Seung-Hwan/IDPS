#include "seccomp_filter.hpp"
#include <iostream>
#include <seccomp.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <cstring>

SeccompConfig SeccompFilter::defaultSandboxProfile() {
    SeccompConfig config;
    // 기본값 사용 (네트워크, 실행, fork 차단)
    return config;
}

SeccompConfig SeccompFilter::strictProfile() {
    SeccompConfig config;
    // 모든 것 차단
    config.allow_open  = false;
    config.allow_mmap  = false;
    config.allow_brk   = false;
    config.allow_fstat = false;
    return config;
}

void SeccompFilter::printConfig(const SeccompConfig& config) {
    std::cout << "\n\033[1;35m";
    std::cout << "╔══════════════════════════════════════╗\n";
    std::cout << "║       🔒 Seccomp 필터 설정           ║\n";
    std::cout << "╠══════════════════════════════════════╣\n";
    std::cout << "\033[0m";

    auto print_rule = [](const std::string& name, bool allowed) {
        std::string status = allowed ?
            "\033[1;32m✅ 허용\033[0m" :
            "\033[1;31m❌ 차단\033[0m";
        std::cout << "║  " << name << "\t: " << status << "\n";
    };

    print_rule("read      ", config.allow_read);
    print_rule("write     ", config.allow_write);
    print_rule("open      ", config.allow_open);
    print_rule("socket    ", config.allow_socket);
    print_rule("connect   ", config.allow_connect);
    print_rule("execve    ", config.allow_execve);
    print_rule("fork      ", config.allow_fork);
    print_rule("clone     ", config.allow_clone);
    print_rule("ptrace    ", config.allow_ptrace);
    print_rule("kill      ", config.allow_kill);
    print_rule("setuid    ", config.allow_setuid);

    std::cout << "\033[1;35m";
    std::cout << "╚══════════════════════════════════════╝\n";
    std::cout << "\033[0m\n";
}

bool SeccompFilter::apply(const SeccompConfig& config) {
    // seccomp 컨텍스트 생성 (기본: 모두 차단)
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    if (!ctx) {
        std::cerr << "[SeccompFilter] 컨텍스트 생성 실패\n";
        return false;
    }

    // 허용할 syscall 추가
    auto allow = [&](int syscall_nr) {
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscall_nr, 0);
    };

    // 기본 필수 syscall
    allow(SCMP_SYS(exit));
    allow(SCMP_SYS(exit_group));
    allow(SCMP_SYS(rt_sigreturn));
    allow(SCMP_SYS(getpid));
    allow(SCMP_SYS(getuid));
    allow(SCMP_SYS(gettid));

    // 설정에 따라 허용
    if (config.allow_read)   { allow(SCMP_SYS(read));   allow(SCMP_SYS(pread64)); }
    if (config.allow_write)  { allow(SCMP_SYS(write));  allow(SCMP_SYS(pwrite64)); }
    if (config.allow_open)   { allow(SCMP_SYS(open));   allow(SCMP_SYS(openat)); }
    if (config.allow_close)  { allow(SCMP_SYS(close)); }
    if (config.allow_mmap)   { allow(SCMP_SYS(mmap));   allow(SCMP_SYS(munmap)); allow(SCMP_SYS(mprotect)); }
    if (config.allow_brk)    { allow(SCMP_SYS(brk)); }
    if (config.allow_fstat)  { allow(SCMP_SYS(fstat));  allow(SCMP_SYS(stat)); allow(SCMP_SYS(lstat)); }
    if (config.allow_socket) { allow(SCMP_SYS(socket)); allow(SCMP_SYS(bind)); allow(SCMP_SYS(listen)); allow(SCMP_SYS(accept)); }
    if (config.allow_connect){ allow(SCMP_SYS(connect)); }
    if (config.allow_execve) { allow(SCMP_SYS(execve)); }
    if (config.allow_fork)   { allow(SCMP_SYS(fork));   allow(SCMP_SYS(vfork)); }
    if (config.allow_clone)  { allow(SCMP_SYS(clone)); }
    if (config.allow_ptrace) { allow(SCMP_SYS(ptrace)); }
    if (config.allow_kill)   { allow(SCMP_SYS(kill)); }
    if (config.allow_setuid) { allow(SCMP_SYS(setuid)); allow(SCMP_SYS(setgid)); }

    // 필터 적용
    int rc = seccomp_load(ctx);
    seccomp_release(ctx);

    if (rc != 0) {
        std::cerr << "[SeccompFilter] 필터 적용 실패: "
                  << strerror(-rc) << "\n";
        return false;
    }

    std::cout << "[SeccompFilter] ✅ 필터 적용 완료\n";
    return true;
}

bool SeccompFilter::applyToChild(pid_t pid, const SeccompConfig& config) {
    // fork한 자식 프로세스에 seccomp 적용
    // 실제로는 자식 프로세스 내부에서 apply()를 호출해야 함
    // 여기서는 격리 프로세스 생성 시 사용할 헬퍼 함수

    std::cout << "[SeccompFilter] PID=" << pid
              << " 에 seccomp 필터 예약\n";
    printConfig(config);
    return true;
}