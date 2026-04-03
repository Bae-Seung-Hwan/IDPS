#include "policy_engine.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <thread>
#include <sys/stat.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

PolicyEngine::PolicyEngine(const std::string& rule_file)
    : rule_file_(rule_file), hot_reload_running_(false) {}

std::string PolicyEngine::readFile() const {
    std::ifstream file(rule_file_);
    if (!file.is_open()) {
        std::cerr << "[PolicyEngine] 파일 열기 실패: " << rule_file_ << std::endl;
        return "";
    }
    std::ostringstream oss;
    oss << file.rdbuf();
    return oss.str();
}

std::string PolicyEngine::getFileModTime() const {
    struct stat st;
    if (stat(rule_file_.c_str(), &st) != 0) return "";
    return std::to_string(st.st_mtime);
}

std::string PolicyEngine::getCurrentTime() const {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

bool PolicyEngine::load() {
    std::string content = readFile();
    if (content.empty()) return false;

    if (!parseJson(content)) return false;

    policy_.loaded_at  = getCurrentTime();
    last_mod_time_     = getFileModTime();

    std::cout << "[PolicyEngine] 룰 로드 완료: "
              << policy_.signature_rules.size()  << "개 시그니처 룰, "
              << policy_.heuristic_rules.size()  << "개 휴리스틱 룰"
              << std::endl;

    return true;
}

bool PolicyEngine::parseJson(const std::string& content) {
    try {
        json j = json::parse(content);

        policy_.version         = j.value("version", "1.0");
        policy_.signature_rules.clear();
        policy_.heuristic_rules.clear();

        for (const auto& rule : j["rules"]) {
            std::string type = rule.value("type", "signature");

            if (type == "signature") {
                SignatureRule sr;
                sr.id       = rule.value("id",       "");
                sr.name     = rule.value("name",     "");
                sr.severity = rule.value("severity", "LOW");

                for (const auto& p : rule["patterns"])
                    sr.patterns.push_back(p.get<std::string>());

                policy_.signature_rules.push_back(sr);

            } else if (type == "heuristic") {
                HeuristicRule hr;
                hr.id         = rule.value("id",       "");
                hr.name       = rule.value("name",     "");
                hr.severity   = rule.value("severity", "LOW");
                hr.action     = rule.value("action",   "alert");

                if (rule.contains("threshold")) {
                    hr.threshold  = rule["threshold"].value("connections", 20);
                    hr.window_sec = rule["threshold"].value("window_sec",   5);
                } else {
                    hr.threshold  = 20;
                    hr.window_sec = 5;
                }

                policy_.heuristic_rules.push_back(hr);
            }
        }
        return true;

    } catch (const json::exception& e) {
        std::cerr << "[PolicyEngine] JSON 파싱 오류: " << e.what() << std::endl;
        return false;
    }
}

void PolicyEngine::setCallback(PolicyCallback cb) {
    callback_ = cb;
}

void PolicyEngine::startHotReload(int interval_sec) {
    hot_reload_running_ = true;

    reload_thread_ = std::thread([this, interval_sec]() {
        std::cout << "[PolicyEngine] 핫 리로드 시작 ("
                  << interval_sec << "초 간격)\n";

        while (hot_reload_running_) {
            std::this_thread::sleep_for(
                std::chrono::seconds(interval_sec));

            // 파일 변경 감지
            std::string cur_mod = getFileModTime();
            if (cur_mod != last_mod_time_) {
                std::cout << "[PolicyEngine] 룰 파일 변경 감지 → 리로드\n";
                if (load() && callback_)
                    callback_(policy_);
            }
        }
    });
}

void PolicyEngine::stopHotReload() {
    hot_reload_running_ = false;
    if (reload_thread_.joinable())
        reload_thread_.join();
    std::cout << "[PolicyEngine] 핫 리로드 중지\n";
}

void PolicyEngine::printPolicy() const {
    std::cout << "\n\033[1;36m";
    std::cout << "╔══════════════════════════════════════╗\n";
    std::cout << "║          📋 현재 보안 정책            ║\n";
    std::cout << "╠══════════════════════════════════════╣\n";
    std::cout << "\033[0m";
    std::cout << "║ 버전    : " << policy_.version   << "\n";
    std::cout << "║ 로드    : " << policy_.loaded_at << "\n";
    std::cout << "║\n";
    std::cout << "║ [시그니처 룰]\n";

    for (const auto& r : policy_.signature_rules) {
        std::cout << "║  [" << r.id << "] " << r.name
                  << " (" << r.severity << ")\n";
        for (const auto& p : r.patterns)
            std::cout << "║    패턴: " << p << "\n";
    }

    std::cout << "║\n";
    std::cout << "║ [휴리스틱 룰]\n";

    for (const auto& r : policy_.heuristic_rules) {
        std::cout << "║  [" << r.id << "] " << r.name
                  << " (" << r.severity << ")\n";
        std::cout << "║    임계값: " << r.threshold
                  << "회/" << r.window_sec << "초\n";
    }

    std::cout << "\033[1;36m";
    std::cout << "╚══════════════════════════════════════╝\n";
    std::cout << "\033[0m\n";
}