#include "packet_capture.hpp"
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

PacketCapture::PacketCapture(const std::string& interface, PacketCallback callback)
    : interface_(interface), callback_(callback), handle_(nullptr), running_(false) {}

PacketCapture::~PacketCapture() {
    stop();
}

bool PacketCapture::start() {
    char errbuf[PCAP_ERRBUF_SIZE];

    handle_ = pcap_open_live(
        interface_.c_str(),
        65535,
        1,
        1000,
        errbuf
    );

    if (!handle_) {
        std::cerr << "[PacketCapture] 인터페이스 열기 실패: " << errbuf << std::endl;
        return false;
    }

    struct bpf_program fp;
    if (pcap_compile(handle_, &fp, "ip", 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle_, &fp) == -1) {
        std::cerr << "[PacketCapture] 필터 설정 실패" << std::endl;
        return false;
    }

    running_ = true;
    capture_thread_ = std::thread(&PacketCapture::captureLoop, this);

    std::cout << "[PacketCapture] 캡처 시작: " << interface_ << std::endl;
    return true;
}

void PacketCapture::stop() {
    running_ = false;
    if (handle_) {
        pcap_breakloop(handle_);
        if (capture_thread_.joinable())
            capture_thread_.join();
        pcap_close(handle_);
        handle_ = nullptr;
    }
    std::cout << "[PacketCapture] 캡처 중지" << std::endl;
}

void PacketCapture::captureLoop() {
    pcap_loop(handle_, -1, packetHandler, reinterpret_cast<u_char*>(this));
}

void PacketCapture::packetHandler(u_char* user,
                                   const struct pcap_pkthdr* header,
                                   const u_char* packet) {
    auto* self = reinterpret_cast<PacketCapture*>(user);
    if (!self->running_) return;

    PacketInfo info;
    info.timestamp = header->ts;

    // raw 패킷 전체 저장 (PacketParser용)
    info.raw_data.assign(packet, packet + header->caplen);

    // 이더넷 헤더 스킵 (14바이트)
    const struct ip* ip_header = reinterpret_cast<const struct ip*>(packet + 14);
    info.src_ip = inet_ntoa(ip_header->ip_src);
    info.dst_ip = inet_ntoa(ip_header->ip_dst);

    int ip_header_len = ip_header->ip_hl * 4;

    if (ip_header->ip_p == IPPROTO_TCP) {
        info.protocol = "TCP";
        const struct tcphdr* tcp =
            reinterpret_cast<const struct tcphdr*>(packet + 14 + ip_header_len);
        info.src_port = ntohs(tcp->source);
        info.dst_port = ntohs(tcp->dest);

        int tcp_header_len = tcp->doff * 4;
        const u_char* payload_start = packet + 14 + ip_header_len + tcp_header_len;
        int payload_len = header->caplen - 14 - ip_header_len - tcp_header_len;
        if (payload_len > 0)
            info.payload.assign(payload_start, payload_start + payload_len);

    } else if (ip_header->ip_p == IPPROTO_UDP) {
        info.protocol = "UDP";
        const struct udphdr* udp =
            reinterpret_cast<const struct udphdr*>(packet + 14 + ip_header_len);
        info.src_port = ntohs(udp->source);
        info.dst_port = ntohs(udp->dest);

    } else {
        info.protocol = "OTHER";
        info.src_port = 0;
        info.dst_port = 0;
    }

    self->callback_(info);
}
