#pragma once

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <chrono>
#include <functional>
#include "signature_engine.hpp"

// 경보 레코드
struct Alert {
    int         id;               // 경보 ID (순번)
    std::string rule_id;          // 룰 ID
    std::string rule_name;        // 룰 이름
    std::string severity;         // 위협 등급
    std::string src_ip;           // 출발지 IP
    std::string dst_ip;           // 목적지 IP
    uint16_t    src_port;
    uint16_t    dst_port;
    std::string matched_pattern;  // 매칭된 패턴
    std::string timestamp;        // 발생 시각
    bool        suppressed;       // 중복 억제 여부
};

// 경보 발생 시 호출될 콜백
using AlertCallback = std::function<void(const Alert&)>;

// IP별 경보 통계
struct IpStats {
    int     alert_count;          // 총 경보 횟수
    int     critical_count;       // CRITICAL 횟수
    int     high_count;           // HIGH 횟수
    std::chrono::steady_clock::time_point last_alert_time;
};

class AlertManager {
public:
    AlertManager(int suppress_sec = 10);  // 중복 억제 시간 (초)

    void onThreat(const ThreatInfo& threat);  // 위협 수신
    void setCallback(AlertCallback cb);        // 경보 콜백 등록

    // 통계 조회
    void printStats() const;
    int  getTotalAlerts() const { return total_alerts_; }
    const std::vector<Alert>& getAlerts() const { return alerts_; }

private:
    int suppress_sec_;                    // 중복 억제 시간
    int alert_id_counter_;               // 경보 ID 카운터
    int total_alerts_;                   // 총 경보 수
    std::vector<Alert> alerts_;          // 경보 목록
    std::map<std::string, IpStats> ip_stats_;  // IP별 통계
    AlertCallback callback_;
    mutable std::mutex mutex_;

    bool isSuppressed(const std::string& src_ip, const std::string& rule_id);
    void updateIpStats(const std::string& src_ip, const std::string& severity);
    std::string getCurrentTime() const;
    void printAlert(const Alert& alert) const;
};