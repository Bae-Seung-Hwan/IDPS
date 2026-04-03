#pragma once

#include <string>
#include <vector>
#include <sys/types.h>

// seccomp 필터 설정
struct SeccompConfig {
    bool allow_read        = true;
    bool allow_write       = true;
    bool allow_open        = true;
    bool allow_close       = true;
    bool allow_exit        = true;
    bool allow_mmap        = true;
    bool allow_brk         = true;
    bool allow_fstat       = true;
    bool allow_socket      = false;  // 네트워크 차단
    bool allow_connect     = false;  // 네트워크 차단
    bool allow_execve      = false;  // 새 프로그램 실행 차단
    bool allow_fork        = false;  // 프로세스 복제 차단
    bool allow_clone       = false;  // 스레드 생성 차단
    bool allow_ptrace      = false;  // ptrace 차단
    bool allow_kill        = false;  // 신호 전송 차단
    bool allow_setuid      = false;  // 권한 상승 차단
};

class SeccompFilter {
public:
    // 현재 프로세스에 seccomp 필터 적용
    static bool apply(const SeccompConfig& config = SeccompConfig{});

    // 대상 프로세스에 seccomp 필터 적용 (fork 후 적용)
    static bool applyToChild(pid_t pid,
                             const SeccompConfig& config = SeccompConfig{});

    // 기본 샌드박스 프로파일 (네트워크 + 실행 차단)
    static SeccompConfig defaultSandboxProfile();

    // 엄격한 프로파일 (read/write만 허용)
    static SeccompConfig strictProfile();

    // 필터 적용 결과 출력
    static void printConfig(const SeccompConfig& config);
};