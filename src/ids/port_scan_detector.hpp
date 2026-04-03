#pragma once

#include <string>
#include <map>
#include <set>
#include <deque>
#include <mutex>
#include <chrono>
#include <functional>
#include "packet_parser.hpp"
#include "alert_manager.hpp"

// IP별 스캔 추적 정보
struct ScanTracker {
    std::deque<std::chrono::steady_clock::time_point> syn_times; // SYN 시각 목록
    std::set<uint16_t> scanned_ports;   // 스캔된 포트 목록
    bool alerted;                        // 이미 경보 발생했는지
};

// 포트스캔 탐지 결과
struct PortScanResult {
    std::string src_ip;
    int         port_count;    // 스캔된 포트 수
    int         syn_count;     // SYN 패킷 수
    std::string severity;
    std::string timestamp;
};

// 탐지 콜백
using PortScanCallback = std::function<void(const PortScanResult&)>;

class PortScanDetector {
public:
    PortScanDetector(int threshold = 20, int window_sec = 5);

    // 패킷 분석
    void analyze(const ParsedPacket& pkt);

    // 콜백 등록
    void setCallback(PortScanCallback cb);

    // 통계 출력
    void printStats() const;

    // 오래된 데이터 정리
    void cleanup();

private:
    int threshold_;    // 탐지 임계값 (포트 수)
    int window_sec_;   // 슬라이딩 윈도우 (초)

    std::map<std::string, ScanTracker> trackers_; // IP별 추적기
    mutable std::mutex mutex_;
    PortScanCallback callback_;

    std::string getCurrentTime() const;
    void removeExpired(ScanTracker& tracker);
};