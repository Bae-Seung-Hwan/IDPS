#pragma once

#include <string>
#include <vector>
#include <mutex>
#include <sqlite3.h>
#include "../ids/alert_manager.hpp"
#include "../ids/packet_parser.hpp"

class Logger {
public:
    Logger(const std::string& db_path = "./idps.db");
    ~Logger();

    bool init();
    bool logAlert(const Alert& alert);
    bool logPacket(const ParsedPacket& pkt);

    std::vector<Alert> getAlerts(int limit = 100) const;
    void printRecentAlerts(int limit = 10) const;

private:
    std::string db_path_;
    sqlite3* db_;
    mutable std::mutex mutex_;

    bool execute(const std::string& sql);
    bool createTables();
};
