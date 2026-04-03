#pragma once

#include <string>
#include <thread>
#include <atomic>
#include <functional>
#include <map>
#include "../ids/alert_manager.hpp"
#include "../sandbox/sandbox_manager.hpp"
#include "../control/logger.hpp"
#include "../control/policy_engine.hpp"

// HTTP 요청
struct HttpRequest {
    std::string method;   // GET, POST 등
    std::string path;     // /api/alerts 등
    std::string body;     // POST body
    std::map<std::string, std::string> params; // 쿼리 파라미터
};

// HTTP 응답
struct HttpResponse {
    int         status_code = 200;
    std::string body;
    std::string content_type = "application/json";
};

// 라우트 핸들러
using RouteHandler = std::function<HttpResponse(const HttpRequest&)>;

class RestApi {
public:
    RestApi(int port = 8080);
    ~RestApi();

    // 의존성 주입
    void setAlertManager(AlertManager* am)   { alert_manager_  = am; }
    void setSandboxManager(SandboxManager* sm){ sandbox_manager_ = sm; }
    void setLogger(Logger* l)                { logger_          = l;  }
    void setPolicyEngine(PolicyEngine* pe)   { policy_engine_   = pe; }

    bool start();   // 서버 시작
    void stop();    // 서버 중지

private:
    int  port_;
    int  server_fd_;
    std::atomic<bool> running_;
    std::thread       server_thread_;

    AlertManager*   alert_manager_  = nullptr;
    SandboxManager* sandbox_manager_ = nullptr;
    Logger*         logger_          = nullptr;
    PolicyEngine*   policy_engine_   = nullptr;

    // 라우트 처리
    HttpResponse handleRequest(const HttpRequest& req);
    HttpResponse handleGetAlerts(const HttpRequest& req);
    HttpResponse handleGetStats(const HttpRequest& req);
    HttpResponse handleGetSandbox(const HttpRequest& req);
    HttpResponse handleGetStatus(const HttpRequest& req);
    HttpResponse handlePostReload(const HttpRequest& req);
    HttpResponse handleGetPackets(const HttpRequest& req);

    // 서버 루프
    void serverLoop();
    void handleClient(int client_fd);

    // HTTP 파싱/응답
    HttpRequest  parseRequest(const std::string& raw);
    std::string  buildResponse(const HttpResponse& resp);

    // JSON 헬퍼
    std::string alertToJson(const Alert& alert);
    std::string notFound();
    std::string methodNotAllowed();
};