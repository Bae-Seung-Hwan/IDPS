#pragma once

#include <pcap.h>
#include <string>
#include <vector>
#include <functional>
#include <thread>
#include <atomic>

struct PacketInfo {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    std::string protocol;
    std::vector<uint8_t> payload;
    std::vector<uint8_t> raw_data;  // PacketParser용 raw 데이터
    struct timeval timestamp;
};

using PacketCallback = std::function<void(const PacketInfo&)>;

class PacketCapture {
public:
    PacketCapture(const std::string& interface, PacketCallback callback);
    ~PacketCapture();

    bool start();
    void stop();
    bool isRunning() const { return running_; }

private:
    std::string interface_;
    PacketCallback callback_;
    pcap_t* handle_;
    std::thread capture_thread_;
    std::atomic<bool> running_;

    void captureLoop();
    static void packetHandler(u_char* user,
                               const struct pcap_pkthdr* header,
                               const u_char* packet);
};
