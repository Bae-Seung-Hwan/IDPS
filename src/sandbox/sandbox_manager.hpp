#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <functional>
#include <sys/types.h>

// 격리된 프로세스 상태
enum class SandboxState {
    RUNNING,    // 실행 중
    ISOLATED,   // 격리됨
    TERMINATED  // 종료됨
};

// 격리 프로세스 정보
struct SandboxEntry {
    pid_t       original_pid;   // 원본 PID
    pid_t       sandbox_pid;    // 격리 환경 PID
    std::string src_ip;         // 위협 출발지 IP
    std::string rule_id;        // 트리거된 룰
    std::string severity;       // 위협 등급
    SandboxState state;         // 현재 상태
    std::string isolated_at;    // 격리 시각
};

// 격리 완료 콜백
using SandboxCallback = std::function<void(const SandboxEntry&)>;

class SandboxManager {
public:
    SandboxManager();
    ~SandboxManager();

    // PID를 격리
    bool isolate(pid_t pid,
                 const std::string& src_ip,
                 const std::string& rule_id,
                 const std::string& severity);

    void setCallback(SandboxCallback cb);

    // 격리 목록 출력
    void printIsolated() const;
    const std::map<pid_t, SandboxEntry>& getIsolated() const {
    return isolated_;
}
    // 격리된 프로세스 수
    int getIsolatedCount() const;

private:
    std::map<pid_t, SandboxEntry> isolated_;
    mutable std::mutex mutex_;
    SandboxCallback callback_;

    bool applyNamespace(pid_t pid);   // namespace 격리
    bool applySeccomp(pid_t pid);     // seccomp-bpf 적용
    bool blockNetwork(pid_t pid);     // 네트워크 차단
    std::string getCurrentTime() const;
};