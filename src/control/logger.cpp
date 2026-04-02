#include "logger.hpp"
#include "../ids/packet_parser.hpp"
#include <iostream>
#include <sstream>

Logger::Logger(const std::string& db_path)
    : db_path_(db_path), db_(nullptr) {}

Logger::~Logger() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool Logger::init() {
    // DB 파일 열기 (없으면 자동 생성)
    int rc = sqlite3_open(db_path_.c_str(), &db_);
    if (rc != SQLITE_OK) {
        std::cerr << "[Logger] DB 열기 실패: "
                  << sqlite3_errmsg(db_) << std::endl;
        return false;
    }

    std::cout << "[Logger] DB 연결 완료: " << db_path_ << std::endl;
    return createTables();
}

bool Logger::createTables() {
    // 경보 테이블
    const std::string alert_table = R"(
        CREATE TABLE IF NOT EXISTS alerts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id         TEXT NOT NULL,
            rule_name       TEXT NOT NULL,
            severity        TEXT NOT NULL,
            src_ip          TEXT NOT NULL,
            dst_ip          TEXT NOT NULL,
            src_port        INTEGER,
            dst_port        INTEGER,
            matched_pattern TEXT,
            timestamp       TEXT NOT NULL,
            suppressed      INTEGER DEFAULT 0
        );
    )";

    // 패킷 로그 테이블
    const std::string packet_table = R"(
        CREATE TABLE IF NOT EXISTS packets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip      TEXT,
            dst_ip      TEXT,
            src_port    INTEGER,
            dst_port    INTEGER,
            protocol    TEXT,
            ttl         INTEGER,
            length      INTEGER,
            flags       TEXT,
            payload_hex TEXT,
            timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    )";

    if (!execute(alert_table)) {
        std::cerr << "[Logger] alerts 테이블 생성 실패" << std::endl;
        return false;
    }
    if (!execute(packet_table)) {
        std::cerr << "[Logger] packets 테이블 생성 실패" << std::endl;
        return false;
    }

    std::cout << "[Logger] 테이블 초기화 완료" << std::endl;
    return true;
}

bool Logger::logAlert(const Alert& alert) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::ostringstream sql;
    sql << "INSERT INTO alerts "
        << "(rule_id, rule_name, severity, src_ip, dst_ip, "
        << "src_port, dst_port, matched_pattern, timestamp, suppressed) "
        << "VALUES ("
        << "'" << alert.rule_id         << "',"
        << "'" << alert.rule_name       << "',"
        << "'" << alert.severity        << "',"
        << "'" << alert.src_ip          << "',"
        << "'" << alert.dst_ip          << "',"
        <<       alert.src_port         << ","
        <<       alert.dst_port         << ","
        << "'" << alert.matched_pattern << "',"
        << "'" << alert.timestamp       << "',"
        <<      (alert.suppressed ? 1 : 0)
        << ");";

    if (!execute(sql.str())) {
        std::cerr << "[Logger] 경보 저장 실패" << std::endl;
        return false;
    }
    return true;
}

bool Logger::logPacket(const ParsedPacket& pkt) {
    std::lock_guard<std::mutex> lock(mutex_);

    // TCP 플래그 문자열 생성
    std::string flags = "";
    if (pkt.protocol == "TCP") {
        if (pkt.tcp_flags.syn) flags += "SYN ";
        if (pkt.tcp_flags.ack) flags += "ACK ";
        if (pkt.tcp_flags.fin) flags += "FIN ";
        if (pkt.tcp_flags.rst) flags += "RST ";
        if (pkt.tcp_flags.psh) flags += "PSH ";
        if (pkt.tcp_flags.urg) flags += "URG ";
    }

    std::ostringstream sql;
    sql << "INSERT INTO packets "
        << "(src_ip, dst_ip, src_port, dst_port, protocol, "
        << "ttl, length, flags, payload_hex) "
        << "VALUES ("
        << "'" << pkt.src_ip          << "',"
        << "'" << pkt.dst_ip          << "',"
        <<       pkt.src_port         << ","
        <<       pkt.dst_port         << ","
        << "'" << pkt.protocol        << "',"
        <<  (int)pkt.ttl              << ","
        <<       pkt.total_length     << ","
        << "'" << flags               << "',"
        << "'" << pkt.payload_str.substr(0, 200) << "'"
        << ");";

    if (!execute(sql.str())) {
        std::cerr << "[Logger] 패킷 로그 저장 실패" << std::endl;
        return false;
    }
    return true;
}

void Logger::printRecentAlerts(int limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_) return;

    std::string sql = "SELECT id, severity, rule_name, src_ip, "
                      "dst_ip, matched_pattern, timestamp "
                      "FROM alerts ORDER BY id DESC LIMIT "
                      + std::to_string(limit) + ";";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return;

    std::cout << "\n\033[1;36m📋 최근 경보 목록 (최대 " << limit << "개)\033[0m\n";
    std::cout << "─────────────────────────────────────────\n";

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int         id        = sqlite3_column_int (stmt, 0);
        std::string severity  = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        std::string rule_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        std::string src_ip    = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        std::string dst_ip    = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        std::string pattern   = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        std::string timestamp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));

        std::string color = (severity == "CRITICAL") ? "\033[1;31m" :
                            (severity == "HIGH")     ? "\033[1;33m" : "\033[0m";

        std::cout << "[" << id << "] "
                  << color << severity << "\033[0m"
                  << " | " << timestamp
                  << " | " << rule_name
                  << " | " << src_ip << " → " << dst_ip
                  << " | 패턴: " << pattern << "\n";
    }

    std::cout << "─────────────────────────────────────────\n";
    sqlite3_finalize(stmt);
}

bool Logger::execute(const std::string& sql) {
    char* err_msg = nullptr;
    int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::cerr << "[Logger] SQL 오류: " << err_msg << std::endl;
        sqlite3_free(err_msg);
        return false;
    }
    return true;
}