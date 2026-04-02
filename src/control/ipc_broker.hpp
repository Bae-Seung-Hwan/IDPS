#pragma once

#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <queue>

// IPC 메시지 타입
enum class IpcMessageType {
    ISOLATE_REQUEST,   // 격리 요청 (IDS → Sandbox)
    ISOLATE_ACK,       // 격리 확인 (Sandbox → IDS)
    STATUS_REQUEST,    // 상태 조회
    STATUS_RESPONSE,   // 상태 응답
    HEARTBEAT,         // 연결 확인
    SHUTDOWN           // 종료
};

// IPC 메시지 구조체
struct IpcMessage {
    IpcMessageType type;
    pid_t          pid;           // 대상 PID
    char           src_ip[64];   // 출발지 IP
    char           rule_id[32];  // 룰 ID
    char           severity[16]; // 위협 등급
    char           payload[256]; // 추가 데이터
};

// 메시지 수신 콜백
using IpcCallback = std::function<void(const IpcMessage&)>;

// ── 서버 (Sandbox 측) ──────────────────────────
class IpcServer {
public:
    IpcServer(const std::string& socket_path = "/tmp/idps.sock");
    ~IpcServer();

    bool start();           // 서버 시작
    void stop();            // 서버 중지
    void setCallback(IpcCallback cb);
    bool send(const IpcMessage& msg, int client_fd); // 클라이언트에 응답

private:
    std::string socket_path_;
    int server_fd_;
    std::atomic<bool> running_;
    std::thread accept_thread_;
    IpcCallback callback_;
    mutable std::mutex mutex_;

    void acceptLoop();      // 연결 수락 루프
    void handleClient(int client_fd); // 클라이언트 처리
};

// ── 클라이언트 (IDS 측) ────────────────────────
class IpcClient {
public:
    IpcClient(const std::string& socket_path = "/tmp/idps.sock");
    ~IpcClient();

    bool connect();         // 서버 연결
    void disconnect();      // 연결 해제
    bool send(const IpcMessage& msg);  // 메시지 전송
    bool isConnected() const { return connected_; }

private:
    std::string socket_path_;
    int client_fd_;
    std::atomic<bool> connected_;
    mutable std::mutex mutex_;
};