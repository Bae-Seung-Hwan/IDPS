#include "behavior_monitor.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <csignal>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <errno.h>
#include <cstring>

// 위험 syscall 번호 목록 (x86_64 기준)
const std::set<int> BehaviorMonitor::DANGEROUS_SYSCALLS = {
    SYS_execve,       // 새 프로그램 실행
    SYS_execveat,     // 새 프로그램 실행 (확장)
    SYS_fork,         // 프로세스 복제
    SYS_clone,        // 프로세스/스레드 생성
    SYS_socket,       // 소켓 생성 (네트워크)
    SYS_connect,      // 네트워크 연결
    SYS_bind,         // 포트 바인딩
    SYS_listen,       // 포트 리슨
    SYS_ptrace,       // ptrace (디버거 탐지 우회)
    SYS_kill,         // 프로세스 종료 신호
    SYS_unlink,       // 파일 삭제
    SYS_chmod,        // 파일 권한 변경
    SYS_chown,        // 파일 소유자 변경
    SYS_setuid,       // UID 변경 (권한 상승)
    SYS_setgid,       // GID 변경
};

// syscall 번호 → 이름 매핑
std::string BehaviorMonitor::getSyscallName(long num) {
    static const std::map<long, std::string> names = {
        {SYS_read,      "read"},
        {SYS_write,     "write"},
        {SYS_open,      "open"},
        {SYS_close,     "close"},
        {SYS_execve,    "execve ⚠"},
        {SYS_execveat,  "execveat ⚠"},
        {SYS_fork,      "fork ⚠"},
        {SYS_clone,     "clone ⚠"},
        {SYS_socket,    "socket ⚠"},
        {SYS_connect,   "connect ⚠"},
        {SYS_bind,      "bind ⚠"},
        {SYS_listen,    "listen ⚠"},
        {SYS_ptrace,    "ptrace ⚠"},
        {SYS_kill,      "kill ⚠"},
        {SYS_unlink,    "unlink ⚠"},
        {SYS_chmod,     "chmod ⚠"},
        {SYS_chown,     "chown ⚠"},
        {SYS_setuid,    "setuid ⚠"},
        {SYS_setgid,    "setgid ⚠"},
        {SYS_mmap,      "mmap"},
        {SYS_munmap,    "munmap"},
        {SYS_brk,       "brk"},
        {SYS_exit,      "exit"},
        {SYS_exit_group,"exit_group"},
        {SYS_wait4,     "wait4"},
        {SYS_getpid,    "getpid"},
        {SYS_getuid,    "getuid"},
        {SYS_stat,      "stat"},
        {SYS_fstat,     "fstat"},
        {SYS_lstat,     "lstat"},
        {SYS_openat,    "openat"},
    };

    auto it = names.find(num);
    if (it != names.end()) return it->second;
    return "syscall_" + std::to_string(num);
}

BehaviorMonitor::BehaviorMonitor() : running_(true) {}

BehaviorMonitor::~BehaviorMonitor() {
    running_ = false;
}

void BehaviorMonitor::setCallback(BehaviorCallback cb) {
    callback_ = cb;
}

bool BehaviorMonitor::startMonitoring(pid_t pid) {
    std::lock_guard<std::mutex> lock(mutex_);

    // 이미 모니터링 중
    if (monitor_threads_.count(pid)) {
        std::cout << "[BehaviorMonitor] PID=" << pid
                  << " 이미 모니터링 중" << std::endl;
        return false;
    }

    // ptrace 연결
    if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) < 0) {
        std::cerr << "[BehaviorMonitor] ptrace 연결 실패: PID=" << pid
                  << " (" << strerror(errno) << ")" << std::endl;
        return false;
    }

    // 프로세스가 중지될 때까지 대기
    int status;
    waitpid(pid, &status, 0);

    // 보고서 초기화
    BehaviorReport report{};
    report.pid          = pid;
    report.total_syscalls    = 0;
    report.dangerous_syscalls = 0;
    report.started_at   = getCurrentTime();
    reports_[pid]       = report;

    std::cout << "[BehaviorMonitor] 모니터링 시작: PID=" << pid << std::endl;

    // 별도 스레드에서 모니터링
    monitor_threads_[pid] = std::thread(&BehaviorMonitor::monitorLoop, this, pid);

    return true;
}

void BehaviorMonitor::stopMonitoring(pid_t pid) {
    running_ = false;

    // ptrace 분리
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);

    // 스레드 종료 대기
    auto it = monitor_threads_.find(pid);
    if (it != monitor_threads_.end()) {
        if (it->second.joinable())
            it->second.join();
        monitor_threads_.erase(it);
    }

    // 보고서 종료 시각 기록
    auto rit = reports_.find(pid);
    if (rit != reports_.end())
        rit->second.ended_at = getCurrentTime();

    std::cout << "[BehaviorMonitor] 모니터링 중지: PID=" << pid << std::endl;
}

void BehaviorMonitor::monitorLoop(pid_t pid) {
    // syscall 추적 모드 설정
    ptrace(PTRACE_SETOPTIONS, pid, nullptr,
           PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL);

    while (running_) {
        // 다음 syscall까지 실행
        if (ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr) < 0) break;

        int status;
        pid_t result = waitpid(pid, &status, 0);
        if (result < 0 || WIFEXITED(status) || WIFSIGNALED(status)) {
            std::cout << "[BehaviorMonitor] PID=" << pid
                      << " 프로세스 종료" << std::endl;
            break;
        }

        // syscall 진입/종료 확인
        if (!WIFSTOPPED(status)) continue;
        if ((WSTOPSIG(status) & 0x80) == 0) continue;

        // 레지스터에서 syscall 번호 읽기
        struct user_regs_struct regs{};
        if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) < 0) continue;

        long syscall_num = regs.orig_rax;  // x86_64 syscall 번호
        std::string syscall_name = getSyscallName(syscall_num);
        bool is_dangerous = DANGEROUS_SYSCALLS.count(syscall_num) > 0;

        // 보고서 업데이트
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto& report = reports_[pid];
            report.total_syscalls++;
            report.syscall_counts[syscall_name]++;

            if (is_dangerous) {
                report.dangerous_syscalls++;

                BehaviorEvent event;
                event.pid          = pid;
                event.syscall_name = syscall_name;
                event.syscall_num  = syscall_num;
                event.is_dangerous = true;
                event.timestamp    = getCurrentTime();

                report.events.push_back(event);

                std::cout << "\033[1;31m"
                          << "[BehaviorMonitor] ⚠ 위험 syscall 탐지!"
                          << " PID=" << pid
                          << " syscall=" << syscall_name
                          << "\033[0m" << std::endl;

                // 콜백 호출
                if (callback_) callback_(event);
            }
        }
    }

    // 보고서 종료 시각
    std::lock_guard<std::mutex> lock(mutex_);
    if (reports_.count(pid))
        reports_[pid].ended_at = getCurrentTime();
}

void BehaviorMonitor::printReport(pid_t pid) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = reports_.find(pid);
    if (it == reports_.end()) {
        std::cout << "[BehaviorMonitor] 보고서 없음: PID=" << pid << std::endl;
        return;
    }

    const BehaviorReport& r = it->second;

    std::cout << "\n\033[1;35m";
    std::cout << "╔══════════════════════════════════════╗\n";
    std::cout << "║       📋 행동 분석 보고서            ║\n";
    std::cout << "╠══════════════════════════════════════╣\n";
    std::cout << "\033[0m";
    std::cout << "║ PID           : " << r.pid << "\n";
    std::cout << "║ 시작          : " << r.started_at << "\n";
    std::cout << "║ 종료          : " << r.ended_at << "\n";
    std::cout << "║ 총 syscall    : " << r.total_syscalls << "\n";
    std::cout << "║ 위험 syscall  : \033[1;31m"
              << r.dangerous_syscalls << "\033[0m\n";
    std::cout << "║\n";
    std::cout << "║ syscall 빈도:\n";

    for (const auto& [name, count] : r.syscall_counts)
        std::cout << "║   " << std::setw(20) << std::left << name
                  << " : " << count << "회\n";

    std::cout << "║\n";
    std::cout << "║ 위험 이벤트:\n";

    if (r.events.empty()) {
        std::cout << "║   없음\n";
    } else {
        for (const auto& e : r.events) {
            std::cout << "║   \033[1;31m[" << e.timestamp << "] "
                      << e.syscall_name << "\033[0m\n";
        }
    }

    std::cout << "\033[1;35m";
    std::cout << "╚══════════════════════════════════════╝\n";
    std::cout << "\033[0m\n";
}

const BehaviorReport* BehaviorMonitor::getReport(pid_t pid) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = reports_.find(pid);
    if (it == reports_.end()) return nullptr;
    return &it->second;
}

std::string BehaviorMonitor::getCurrentTime() const {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S");
    return oss.str();
}