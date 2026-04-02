#include "ipc_broker.hpp"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

// ══════════════════════════════════════
// IpcServer 구현
// ══════════════════════════════════════

IpcServer::IpcServer(const std::string& socket_path)
    : socket_path_(socket_path), server_fd_(-1), running_(false) {}

IpcServer::~IpcServer() {
    stop();
}

void IpcServer::setCallback(IpcCallback cb) {
    callback_ = cb;
}

bool IpcServer::start() {
    // Unix domain socket 생성
    server_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd_ < 0) {
        std::cerr << "[IpcServer] socket 생성 실패" << std::endl;
        return false;
    }

    // 기존 소켓 파일 제거
    unlink(socket_path_.c_str());

    // 소켓 주소 설정
    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

    // 바인드
    if (bind(server_fd_, reinterpret_cast<struct sockaddr*>(&addr),
             sizeof(addr)) < 0) {
        std::cerr << "[IpcServer] bind 실패" << std::endl;
        return false;
    }

    // 리슨
    if (listen(server_fd_, 5) < 0) {
        std::cerr << "[IpcServer] listen 실패" << std::endl;
        return false;
    }

    running_ = true;
    accept_thread_ = std::thread(&IpcServer::acceptLoop, this);

    std::cout << "[IpcServer] 시작: " << socket_path_ << std::endl;
    return true;
}

void IpcServer::stop() {
    running_ = false;
    if (server_fd_ >= 0) {
        close(server_fd_);
        server_fd_ = -1;
    }
    if (accept_thread_.joinable())
        accept_thread_.join();
    unlink(socket_path_.c_str());
    std::cout << "[IpcServer] 중지" << std::endl;
}

void IpcServer::acceptLoop() {
    while (running_) {
        struct sockaddr_un client_addr{};
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(server_fd_,
                               reinterpret_cast<struct sockaddr*>(&client_addr),
                               &client_len);
        if (client_fd < 0) {
            if (running_)
                std::cerr << "[IpcServer] accept 실패" << std::endl;
            break;
        }

        std::cout << "[IpcServer] 클라이언트 연결됨" << std::endl;

        // 별도 스레드로 클라이언트 처리
        std::thread(&IpcServer::handleClient, this, client_fd).detach();
    }
}

void IpcServer::handleClient(int client_fd) {
    IpcMessage msg{};

    while (running_) {
        ssize_t n = recv(client_fd, &msg, sizeof(msg), 0);
        if (n <= 0) break;

        std::cout << "[IpcServer] 메시지 수신: 타입="
                  << static_cast<int>(msg.type)
                  << " PID=" << msg.pid
                  << " IP=" << msg.src_ip
                  << std::endl;

        // 콜백 호출
        if (callback_) callback_(msg);

        // ACK 응답
        IpcMessage ack{};
        ack.type = IpcMessageType::ISOLATE_ACK;
        ack.pid  = msg.pid;
        strncpy(ack.payload, "OK", sizeof(ack.payload) - 1);
        send(ack, client_fd);
    }

    close(client_fd);
    std::cout << "[IpcServer] 클라이언트 연결 해제" << std::endl;
}

bool IpcServer::send(const IpcMessage& msg, int client_fd) {
    ssize_t n = ::send(client_fd, &msg, sizeof(msg), 0);
    return n == sizeof(msg);
}

// ══════════════════════════════════════
// IpcClient 구현
// ══════════════════════════════════════

IpcClient::IpcClient(const std::string& socket_path)
    : socket_path_(socket_path), client_fd_(-1), connected_(false) {}

IpcClient::~IpcClient() {
    disconnect();
}

bool IpcClient::connect() {
    client_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client_fd_ < 0) {
        std::cerr << "[IpcClient] socket 생성 실패" << std::endl;
        return false;
    }

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

    if (::connect(client_fd_,
                  reinterpret_cast<struct sockaddr*>(&addr),
                  sizeof(addr)) < 0) {
        std::cerr << "[IpcClient] 연결 실패: " << socket_path_ << std::endl;
        close(client_fd_);
        client_fd_ = -1;
        return false;
    }

    connected_ = true;
    std::cout << "[IpcClient] 서버 연결 완료: " << socket_path_ << std::endl;
    return true;
}

void IpcClient::disconnect() {
    connected_ = false;
    if (client_fd_ >= 0) {
        close(client_fd_);
        client_fd_ = -1;
    }
}

bool IpcClient::send(const IpcMessage& msg) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!connected_ || client_fd_ < 0) {
        std::cerr << "[IpcClient] 연결 안됨" << std::endl;
        return false;
    }

    ssize_t n = ::send(client_fd_, &msg, sizeof(msg), 0);
    if (n != sizeof(msg)) {
        std::cerr << "[IpcClient] 전송 실패" << std::endl;
        connected_ = false;
        return false;
    }

    std::cout << "[IpcClient] 메시지 전송: 타입="
              << static_cast<int>(msg.type)
              << " PID=" << msg.pid
              << " IP=" << msg.src_ip
              << std::endl;
    return true;
}