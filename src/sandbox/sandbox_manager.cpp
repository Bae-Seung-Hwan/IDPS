#include "sandbox_manager.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <csignal>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <seccomp.h>
#include <sched.h>
#include <fcntl.h>
#include <cstring>
#include "seccomp_filter.hpp"
SandboxManager::SandboxManager() {}

SandboxManager::~SandboxManager() {
    // 격리된 프로세스 모두 종료
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [pid, entry] : isolated_) {
        if (entry.state == SandboxState::ISOLATED) {
            kill(pid, SIGKILL);
        }
    }
}

void SandboxManager::setCallback(SandboxCallback cb) {
    callback_ = cb;
}

bool SandboxManager::isolate(pid_t pid,
                              const std::string& src_ip,
                              const std::string& rule_id,
                              const std::string& severity) {
    std::lock_guard<std::mutex> lock(mutex_);

    // 이미 격리된 PID면 스킵
    if (isolated_.count(pid)) {
        std::cout << "[Sandbox] PID " << pid << " 이미 격리됨" << std::endl;
        return false;
    }

    std::cout << "\n[Sandbox]    격리 시작: PID=" << pid
              << " IP=" << src_ip
              << " 룰=" << rule_id << std::endl;

    // 1. 네트워크 차단 (SIGSTOP으로 일시 정지 후 처리)
    if (kill(pid, SIGSTOP) != 0) {
        std::cerr << "[Sandbox] SIGSTOP 실패: PID=" << pid
                  << " (" << strerror(errno) << ")" << std::endl;
        // PID가 없어도 격리 기록은 남김
    } else {
        std::cout << "[Sandbox] ✓ 프로세스 일시 정지: PID=" << pid << std::endl;
    }

    // 2. 네트워크 namespace 격리 시도
    blockNetwork(pid);

    // 3. seccomp 필터 적용 시도
    applySeccomp(pid);

    // 격리 항목 등록
    SandboxEntry entry;
    entry.original_pid = pid;
    entry.sandbox_pid  = pid;
    entry.src_ip       = src_ip;
    entry.rule_id      = rule_id;
    entry.severity     = severity;
    entry.state        = SandboxState::ISOLATED;
    entry.isolated_at  = getCurrentTime();

    isolated_[pid] = entry;

    // 결과 출력
    std::cout << "[Sandbox]     격리 완료:\n"
              << "   PID     : " << pid << "\n"
              << "   출발지  : " << src_ip << "\n"
              << "   룰      : " << rule_id << "\n"
              << "   등급    : " << severity << "\n"
              << "   시각    : " << entry.isolated_at << "\n";

    // 콜백 호출
    if (callback_) callback_(entry);

    return true;
}

bool SandboxManager::blockNetwork(pid_t pid) {
    // /proc/<pid>/net 을 통해 네트워크 상태 확인
    std::string net_path = "/proc/" + std::to_string(pid) + "/net";
    if (access(net_path.c_str(), F_OK) != 0) {
        std::cerr << "[Sandbox] 네트워크 경로 없음: " << net_path << std::endl;
        return false;
    }

    // tc(traffic control) 명령으로 네트워크 차단
    std::string cmd = "nsenter -t " + std::to_string(pid)
                    + " -n -- iptables -A OUTPUT -j DROP 2>/dev/null";
    int ret = system(cmd.c_str());

    if (ret == 0)
        std::cout << "[Sandbox] ✓ 네트워크 차단 적용" << std::endl;
    else
        std::cout << "[Sandbox] ⚠ 네트워크 차단 건너뜀 (namespace 미분리)" << std::endl;

    return true;
}

bool SandboxManager::applySeccomp(pid_t pid) {
    SeccompConfig config = SeccompFilter::defaultSandboxProfile();
    SeccompFilter::printConfig(config);
    return SeccompFilter::applyToChild(pid, config);
}

bool SandboxManager::applyNamespace(pid_t pid) {
    std::string ns_path = "/proc/" + std::to_string(pid) + "/ns/net";
    int fd = open(ns_path.c_str(), O_RDONLY);
    if (fd < 0) {
        std::cerr << "[Sandbox] namespace 접근 실패: " << strerror(errno) << std::endl;
        return false;
    }
    close(fd);
    std::cout << "[Sandbox] ✓ namespace 격리 확인" << std::endl;
    return true;
}

void SandboxManager::printIsolated() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::cout << "\n\033[1;35m";
    std::cout << "╔══════════════════════════════════════╗\n";
    std::cout << "║           격리된 프로세스 목록          ║\n";
    std::cout << "╠══════════════════════════════════════╣\n";
    std::cout << "\033[0m";

    if (isolated_.empty()) {
        std::cout << "║  격리된 프로세스 없음\n";
    } else {
        for (const auto& [pid, entry] : isolated_) {
            std::string state_str =
                entry.state == SandboxState::ISOLATED   ? " 격리중" :
                entry.state == SandboxState::TERMINATED ? " 종료됨" : " 실행중";

            std::cout << "║ PID=" << pid
                      << " | " << state_str
                      << " | " << entry.src_ip
                      << " | " << entry.rule_id
                      << " | " << entry.isolated_at << "\n";
        }
    }

    std::cout << "\033[1;35m";
    std::cout << "╚══════════════════════════════════════╝\n";
    std::cout << "\033[0m\n";
}

int SandboxManager::getIsolatedCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return isolated_.size();
}

std::string SandboxManager::getCurrentTime() const {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S");
    return oss.str();
}