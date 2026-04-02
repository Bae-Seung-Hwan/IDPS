#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>
#include <thread>
#include <atomic>
#include <mutex>
#include <functional>
#include <sys/types.h>

// 탐지된 행동 정보
struct BehaviorEvent {
    pid_t       pid;
    std::string syscall_name;   // 시스템콜 이름
    long        syscall_num;    // 시스템콜 번호
    bool        is_dangerous;   // 위험 여부
    std::string timestamp;
};

// 행동 보고서
struct BehaviorReport {
    pid_t       pid;
    int         total_syscalls;     // 총 syscall 횟수
    int         dangerous_syscalls; // 위험 syscall 횟수
    std::map<std::string, int> syscall_counts; // syscall별 횟수
    std::vector<BehaviorEvent> events;         // 이벤트 목록
    std::string started_at;
    std::string ended_at;
};

// 위험 행동 탐지 시 콜백
using BehaviorCallback = std::function<void(const BehaviorEvent&)>;

class BehaviorMonitor {
public:
    BehaviorMonitor();
    ~BehaviorMonitor();

    // 프로세스 모니터링 시작
    bool startMonitoring(pid_t pid);

    // 모니터링 중지
    void stopMonitoring(pid_t pid);

    // 콜백 등록
    void setCallback(BehaviorCallback cb);

    // 보고서 출력
    void printReport(pid_t pid) const;

    // 보고서 조회
    const BehaviorReport* getReport(pid_t pid) const;

private:
    std::map<pid_t, BehaviorReport> reports_;
    std::map<pid_t, std::thread>    monitor_threads_;
    std::atomic<bool>               running_;
    BehaviorCallback                callback_;
    mutable std::mutex              mutex_;

    // 위험 syscall 목록
    static const std::set<int> DANGEROUS_SYSCALLS;

    // syscall 번호 → 이름 변환
    static std::string getSyscallName(long num);

    // 모니터링 루프
    void monitorLoop(pid_t pid);

    std::string getCurrentTime() const;
};