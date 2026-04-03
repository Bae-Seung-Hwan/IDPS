#include "port_scan_detector.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>

PortScanDetector::PortScanDetector(int threshold, int window_sec)
    : threshold_(threshold), window_sec_(window_sec) {}

void PortScanDetector::setCallback(PortScanCallback cb) {
    callback_ = cb;
}

void PortScanDetector::removeExpired(ScanTracker& tracker) {
    auto now    = std::chrono::steady_clock::now();
    auto cutoff = now - std::chrono::seconds(window_sec_);

    // 윈도우 밖의 오래된 SYN 제거
    while (!tracker.syn_times.empty() &&
           tracker.syn_times.front() < cutoff) {
        tracker.syn_times.pop_front();
    }
}

void PortScanDetector::analyze(const ParsedPacket& pkt) {
    // TCP SYN 패킷만 분석 (ACK 없는 SYN = 새 연결 시도)
    if (pkt.protocol != "TCP") return;
    if (!pkt.tcp_flags.syn || pkt.tcp_flags.ack) return;

    std::lock_guard<std::mutex> lock(mutex_);

    auto& tracker = trackers_[pkt.src_ip];

    // 오래된 데이터 제거
    removeExpired(tracker);

    // 새 SYN 기록
    tracker.syn_times.push_back(std::chrono::steady_clock::now());
    tracker.scanned_ports.insert(pkt.dst_port);

    int syn_count  = tracker.syn_times.size();
    int port_count = tracker.scanned_ports.size();

    // 임계값 초과 && 아직 경보 안 보낸 경우
    if (port_count >= threshold_ && !tracker.alerted) {
        tracker.alerted = true;

        PortScanResult result;
        result.src_ip     = pkt.src_ip;
        result.port_count = port_count;
        result.syn_count  = syn_count;
        result.severity   = port_count >= threshold_ * 2 ? "CRITICAL" : "HIGH";
        result.timestamp  = getCurrentTime();

        std::cout << "\n\033[1;31m"
                  << "╔══════════════════════════════════════╗\n"
                  << "║       🔍 포트스캔 탐지!              ║\n"
                  << "╠══════════════════════════════════════╣\n"
                  << "\033[0m"
                  << "║ 출발지  : " << result.src_ip     << "\n"
                  << "║ 스캔 포트: " << result.port_count << "개\n"
                  << "║ SYN 횟수: " << result.syn_count  << "회\n"
                  << "║ 등급    : " << result.severity   << "\n"
                  << "║ 시각    : " << result.timestamp  << "\n"
                  << "\033[1;31m"
                  << "╚══════════════════════════════════════╝\n"
                  << "\033[0m\n";

        if (callback_) callback_(result);
    }

    // 윈도우가 지나면 alerted 리셋 (재탐지 허용)
    if (syn_count == 0) tracker.alerted = false;
}

void PortScanDetector::cleanup() {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now    = std::chrono::steady_clock::now();
    auto cutoff = now - std::chrono::seconds(window_sec_ * 2);

    for (auto it = trackers_.begin(); it != trackers_.end(); ) {
        removeExpired(it->second);
        if (it->second.syn_times.empty()) {
            it->second.scanned_ports.clear();
            it->second.alerted = false;
        }
        ++it;
    }
}

void PortScanDetector::printStats() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::cout << "\n\033[1;36m";
    std::cout << "╔══════════════════════════════════════╗\n";
    std::cout << "║       🔍 포트스캔 탐지 통계          ║\n";
    std::cout << "╠══════════════════════════════════════╣\n";
    std::cout << "\033[0m";
    std::cout << "║ 임계값  : " << threshold_  << "개 포트 / "
                               << window_sec_ << "초\n";
    std::cout << "║ 추적 IP : " << trackers_.size() << "개\n";
    std::cout << "║\n";

    for (const auto& [ip, tracker] : trackers_) {
        if (!tracker.scanned_ports.empty()) {
            std::cout << "║  " << ip
                      << " → " << tracker.scanned_ports.size()
                      << "개 포트 스캔\n";

            // 스캔된 포트 목록 출력 (최대 10개)
            std::cout << "║    포트: ";
            int count = 0;
            for (uint16_t port : tracker.scanned_ports) {
                if (count++ >= 10) { std::cout << "..."; break; }
                std::cout << port << " ";
            }
            std::cout << "\n";
        }
    }

    std::cout << "\033[1;36m";
    std::cout << "╚══════════════════════════════════════╝\n";
    std::cout << "\033[0m\n";
}

std::string PortScanDetector::getCurrentTime() const {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S");
    return oss.str();
}