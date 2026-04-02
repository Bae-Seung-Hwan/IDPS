#include "alert_manager.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <ctime>

AlertManager::AlertManager(int suppress_sec)
    : suppress_sec_(suppress_sec),
      alert_id_counter_(0),
      total_alerts_(0) {}

void AlertManager::setCallback(AlertCallback cb) {
    callback_ = cb;
}

void AlertManager::onThreat(const ThreatInfo& threat) {
    std::lock_guard<std::mutex> lock(mutex_);

    const std::string& src_ip  = threat.packet.src_ip;
    const std::string& rule_id = threat.rule_id;

    // 중복 경보 억제 체크
    bool suppressed = isSuppressed(src_ip, rule_id);

    // 경보 생성
    Alert alert;
    alert.id              = ++alert_id_counter_;
    alert.rule_id         = threat.rule_id;
    alert.rule_name       = threat.rule_name;
    alert.severity        = threat.severity;
    alert.src_ip          = threat.packet.src_ip;
    alert.dst_ip          = threat.packet.dst_ip;
    alert.src_port        = threat.packet.src_port;
    alert.dst_port        = threat.packet.dst_port;
    alert.matched_pattern = threat.matched_pattern;
    alert.timestamp       = getCurrentTime();
    alert.suppressed      = suppressed;

    alerts_.push_back(alert);
    total_alerts_++;

    // IP 통계 업데이트
    updateIpStats(src_ip, threat.severity);

    // 억제된 경보는 출력 스킵
    if (suppressed) return;

    // 경보 출력
    printAlert(alert);

    // 콜백 호출
    if (callback_) callback_(alert);
}

bool AlertManager::isSuppressed(const std::string& src_ip,
                                  const std::string& rule_id) {
    std::string key = src_ip + ":" + rule_id;
    auto it = ip_stats_.find(src_ip);
    if (it == ip_stats_.end()) return false;

    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - it->second.last_alert_time).count();

    return elapsed < suppress_sec_;
}

void AlertManager::updateIpStats(const std::string& src_ip,
                                   const std::string& severity) {
    auto& stats = ip_stats_[src_ip];
    stats.alert_count++;
    stats.last_alert_time = std::chrono::steady_clock::now();

    if (severity == "CRITICAL") stats.critical_count++;
    else if (severity == "HIGH") stats.high_count++;
}

std::string AlertManager::getCurrentTime() const {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

void AlertManager::printAlert(const Alert& alert) const {
    // 등급별 색상 (ANSI 코드)
    std::string color;
    if      (alert.severity == "CRITICAL") color = "\033[1;31m"; // 빨강
    else if (alert.severity == "HIGH")     color = "\033[1;33m"; // 노랑
    else if (alert.severity == "MEDIUM")   color = "\033[1;34m"; // 파랑
    else                                   color = "\033[1;32m"; // 초록
    std::string reset = "\033[0m";

    std::cout << "\n";
    std::cout << color
              << "╔══════════════════════════════════════╗\n"
              << "║         🚨 IDPS 경보 #" << std::setw(3) << alert.id << "            ║\n"
              << "╠══════════════════════════════════════╣\n"
              << reset;
    std::cout << "║ 시각   : " << alert.timestamp << "       \n";
    std::cout << "║ 등급   : " << color << alert.severity << reset << "\n";
    std::cout << "║ 룰     : [" << alert.rule_id << "] " << alert.rule_name << "\n";
    std::cout << "║ 패턴   : " << alert.matched_pattern << "\n";
    std::cout << "║ 출발지 : " << alert.src_ip << ":" << alert.src_port << "\n";
    std::cout << "║ 목적지 : " << alert.dst_ip << ":" << alert.dst_port << "\n";
    std::cout << color
              << "╚══════════════════════════════════════╝\n"
              << reset << "\n";
}

void AlertManager::printStats() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::cout << "\n\033[1;36m";
    std::cout << "╔══════════════════════════════════════╗\n";
    std::cout << "║           📊 경보 통계               ║\n";
    std::cout << "╠══════════════════════════════════════╣\n";
    std::cout << "\033[0m";
    std::cout << "║ 총 경보 수 : " << total_alerts_ << "\n";
    std::cout << "║\n";
    std::cout << "║ IP별 통계:\n";

    for (const auto& [ip, stats] : ip_stats_) {
        std::cout << "║   " << ip
                  << " → 총 " << stats.alert_count << "회"
                  << " (CRITICAL: " << stats.critical_count
                  << ", HIGH: " << stats.high_count << ")\n";
    }

    std::cout << "\033[1;36m";
    std::cout << "╚══════════════════════════════════════╝\n";
    std::cout << "\033[0m\n";
}