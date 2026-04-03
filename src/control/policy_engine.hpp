#pragma once

#include <string>
#include <vector>
#include <functional>
#include <chrono>
#include "../ids/signature_engine.hpp"

// 휴리스틱 룰 (포트스캔 등)
struct HeuristicRule {
    std::string id;
    std::string name;
    int         threshold;    // 임계값
    int         window_sec;   // 시간 윈도우 (초)
    std::string severity;
    std::string action;       // sandbox / alert / log
};

// 전체 정책
struct Policy {
    std::vector<SignatureRule>  signature_rules;
    std::vector<HeuristicRule> heuristic_rules;
    std::string                version;
    std::string                loaded_at;
};

// 룰 변경 시 콜백
using PolicyCallback = std::function<void(const Policy&)>;

class PolicyEngine {
public:
    PolicyEngine(const std::string& rule_file);

    bool load();                    // 룰 파일 로드
    void setCallback(PolicyCallback cb); // 룰 변경 콜백
    void startHotReload(int interval_sec = 10); // 핫 리로드
    void stopHotReload();

    const Policy& getPolicy() const { return policy_; }
    void printPolicy() const;       // 현재 정책 출력

private:
    std::string     rule_file_;
    Policy          policy_;
    PolicyCallback  callback_;
    bool            hot_reload_running_;
    std::thread     reload_thread_;

    bool parseJson(const std::string& content);
    std::string readFile() const;
    std::string getCurrentTime() const;
    std::string getFileModTime() const;
    std::string last_mod_time_;
};