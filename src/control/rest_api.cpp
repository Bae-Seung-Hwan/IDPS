#include "rest_api.hpp"
#include <iostream>
#include <sstream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

RestApi::RestApi(int port)
    : port_(port), server_fd_(-1), running_(false) {}

RestApi::~RestApi() { stop(); }

bool RestApi::start() {
    // TCP 소켓 생성
    server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd_ < 0) {
        std::cerr << "[RestApi] 소켓 생성 실패\n";
        return false;
    }

    // SO_REUSEADDR 설정
    int opt = 1;
    setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // 바인드
    struct sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port_);

    if (bind(server_fd_, reinterpret_cast<struct sockaddr*>(&addr),
             sizeof(addr)) < 0) {
        std::cerr << "[RestApi] 바인드 실패\n";
        return false;
    }

    if (listen(server_fd_, 10) < 0) {
        std::cerr << "[RestApi] 리슨 실패\n";
        return false;
    }

    running_ = true;
    server_thread_ = std::thread(&RestApi::serverLoop, this);

    std::cout << "[RestApi] 서버 시작: http://0.0.0.0:" << port_ << "\n";
    std::cout << "[RestApi] 엔드포인트:\n"
              << "  GET  /api/status\n"
              << "  GET  /api/alerts\n"
              << "  GET  /api/alerts/stats\n"
              << "  GET  /api/packets\n"
              << "  GET  /api/sandbox\n"
              << "  POST /api/rules/reload\n";
    return true;
}

void RestApi::stop() {
    running_ = false;
    if (server_fd_ >= 0) {
        close(server_fd_);
        server_fd_ = -1;
    }
    if (server_thread_.joinable())
        server_thread_.join();
    std::cout << "[RestApi] 서버 중지\n";
}

void RestApi::serverLoop() {
    while (running_) {
        struct sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(server_fd_,
                               reinterpret_cast<struct sockaddr*>(&client_addr),
                               &client_len);
        if (client_fd < 0) {
            if (running_)
                std::cerr << "[RestApi] accept 실패\n";
            break;
        }

        std::thread(&RestApi::handleClient, this, client_fd).detach();
    }
}

void RestApi::handleClient(int client_fd) {
    char buf[4096] = {};
    recv(client_fd, buf, sizeof(buf) - 1, 0);

    HttpRequest  req  = parseRequest(std::string(buf));
    HttpResponse resp = handleRequest(req);
    std::string  raw  = buildResponse(resp);

    send(client_fd, raw.c_str(), raw.size(), 0);
    close(client_fd);
}

HttpRequest RestApi::parseRequest(const std::string& raw) {
    HttpRequest req;
    std::istringstream ss(raw);
    std::string line;

    // 첫 줄: METHOD PATH HTTP/1.1
    std::getline(ss, line);
    std::istringstream first_line(line);
    first_line >> req.method >> req.path;

    // 쿼리 파라미터 파싱
    auto q = req.path.find('?');
    if (q != std::string::npos) {
        std::string query = req.path.substr(q + 1);
        req.path = req.path.substr(0, q);
        std::istringstream qs(query);
        std::string param;
        while (std::getline(qs, param, '&')) {
            auto eq = param.find('=');
            if (eq != std::string::npos)
                req.params[param.substr(0, eq)] = param.substr(eq + 1);
        }
    }

    // body 파싱 (빈 줄 이후)
    bool in_body = false;
    while (std::getline(ss, line)) {
        if (line == "\r" || line.empty()) { in_body = true; continue; }
        if (in_body) req.body += line;
    }

    return req;
}

std::string RestApi::buildResponse(const HttpResponse& resp) {
    std::ostringstream oss;
    oss << "HTTP/1.1 " << resp.status_code;

    switch (resp.status_code) {
        case 200: oss << " OK"; break;
        case 404: oss << " Not Found"; break;
        case 405: oss << " Method Not Allowed"; break;
        default:  oss << " Unknown"; break;
    }

    oss << "\r\n"
        << "Content-Type: " << resp.content_type << "; charset=utf-8\r\n"
        << "Access-Control-Allow-Origin: *\r\n"
        << "Content-Length: " << resp.body.size() << "\r\n"
        << "\r\n"
        << resp.body;

    return oss.str();
}

HttpResponse RestApi::handleRequest(const HttpRequest& req) {
    std::cout << "[RestApi] " << req.method << " " << req.path << "\n";

    if      (req.path == "/api/status")        return handleGetStatus(req);
    else if (req.path == "/api/alerts"
          && req.method == "GET")              return handleGetAlerts(req);
    else if (req.path == "/api/alerts/stats")  return handleGetStats(req);
    else if (req.path == "/api/packets")       return handleGetPackets(req);
    else if (req.path == "/api/sandbox")       return handleGetSandbox(req);
    else if (req.path == "/api/rules/reload"
          && req.method == "POST")             return handlePostReload(req);

    HttpResponse resp;
    resp.status_code = 404;
    resp.body = R"({"error":"Not Found"})";
    return resp;
}

HttpResponse RestApi::handleGetStatus(const HttpRequest& /*req*/) {
    HttpResponse resp;
    std::ostringstream json;

    int alert_count   = alert_manager_  ? alert_manager_->getTotalAlerts()  : 0;
    int sandbox_count = sandbox_manager_ ? sandbox_manager_->getIsolatedCount() : 0;

    json << "{"
         << "\"status\":\"running\","
         << "\"total_alerts\":" << alert_count << ","
         << "\"isolated_processes\":" << sandbox_count << ","
         << "\"version\":\"1.0\""
         << "}";

    resp.body = json.str();
    return resp;
}

HttpResponse RestApi::handleGetAlerts(const HttpRequest& req) {
    HttpResponse resp;
    if (!alert_manager_) {
        resp.body = R"({"alerts":[]})";
        return resp;
    }

    // limit 파라미터
    int limit = 20;
    auto it = req.params.find("limit");
    if (it != req.params.end())
        limit = std::stoi(it->second);

    const auto& alerts = alert_manager_->getAlerts();
    std::ostringstream json;
    json << "{\"alerts\":[";

    int count = 0;
    int start = std::max(0, (int)alerts.size() - limit);
    for (int i = alerts.size() - 1; i >= start; i--) {
        if (count++ > 0) json << ",";
        json << alertToJson(alerts[i]);
    }

    json << "],\"total\":" << alerts.size() << "}";
    resp.body = json.str();
    return resp;
}

HttpResponse RestApi::handleGetStats(const HttpRequest& /*req*/) {
    HttpResponse resp;
    if (!alert_manager_) {
        resp.body = R"({"total":0})";
        return resp;
    }

    const auto& alerts = alert_manager_->getAlerts();
    int critical = 0, high = 0, medium = 0, low = 0;

    for (const auto& a : alerts) {
        if      (a.severity == "CRITICAL") critical++;
        else if (a.severity == "HIGH")     high++;
        else if (a.severity == "MEDIUM")   medium++;
        else                               low++;
    }

    std::ostringstream json;
    json << "{"
         << "\"total\":"    << alerts.size() << ","
         << "\"critical\":" << critical << ","
         << "\"high\":"     << high     << ","
         << "\"medium\":"   << medium   << ","
         << "\"low\":"      << low
         << "}";

    resp.body = json.str();
    return resp;
}

HttpResponse RestApi::handleGetSandbox(const HttpRequest& /*req*/) {
    HttpResponse resp;
    if (!sandbox_manager_) {
        resp.body = R"({"isolated":[]})";
        return resp;
    }

    std::ostringstream json;
    json << "{\"isolated\":[";

    int count = 0;
    for (const auto& [pid, entry] : sandbox_manager_->getIsolated()) {
        if (count++ > 0) json << ",";
        json << "{"
             << "\"pid\":"        << pid << ","
             << "\"src_ip\":\""   << entry.src_ip      << "\","
             << "\"rule_id\":\""  << entry.rule_id     << "\","
             << "\"severity\":\"" << entry.severity    << "\","
             << "\"state\":\""
             << (entry.state == SandboxState::ISOLATED ? "isolated" : "terminated")
             << "\","
             << "\"isolated_at\":\"" << entry.isolated_at << "\""
             << "}";
    }

    json << "],\"count\":" << sandbox_manager_->getIsolatedCount() << "}";
    resp.body = json.str();
    return resp;
}

HttpResponse RestApi::handleGetPackets(const HttpRequest& /*req*/) {
    HttpResponse resp;
    resp.body = R"({"message":"패킷 로그는 DB에서 조회하세요","db":"idps.db"})";
    return resp;
}

HttpResponse RestApi::handlePostReload(const HttpRequest& /*req*/) {
    HttpResponse resp;
    if (!policy_engine_) {
        resp.body = R"({"success":false,"message":"PolicyEngine 없음"})";
        return resp;
    }

    bool ok = policy_engine_->load();
    std::ostringstream json;
    json << "{"
         << "\"success\":" << (ok ? "true" : "false") << ","
         << "\"message\":\"" << (ok ? "룰 재로드 완료" : "룰 재로드 실패") << "\""
         << "}";

    resp.body = json.str();
    return resp;
}

std::string RestApi::alertToJson(const Alert& a) {
    std::ostringstream json;
    json << "{"
         << "\"id\":"             << a.id             << ","
         << "\"rule_id\":\""      << a.rule_id        << "\","
         << "\"rule_name\":\""    << a.rule_name      << "\","
         << "\"severity\":\""     << a.severity       << "\","
         << "\"src_ip\":\""       << a.src_ip         << "\","
         << "\"dst_ip\":\""       << a.dst_ip         << "\","
         << "\"src_port\":"       << a.src_port       << ","
         << "\"dst_port\":"       << a.dst_port       << ","
         << "\"pattern\":\""      << a.matched_pattern << "\","
         << "\"timestamp\":\""    << a.timestamp      << "\","
         << "\"suppressed\":"     << (a.suppressed ? "true" : "false")
         << "}";
    return json.str();
}