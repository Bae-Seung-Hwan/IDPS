#include "packet_parser.hpp"
#include <arpa/inet.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cctype>

ParsedPacket PacketParser::parse(const u_char* raw_packet, int length) {
    ParsedPacket pkt{};

    // 이더넷 헤더 스킵 (14바이트)
    if (length < 14) return pkt;
    const u_char* ip_data = raw_packet + 14;
    int remaining = length - 14;

    parseIP(ip_data, pkt);

    const struct ip* ip_header = reinterpret_cast<const struct ip*>(ip_data);
    int ip_header_len = ip_header->ip_hl * 4;

    if (pkt.protocol == "TCP")
        parseTCP(ip_data, ip_header_len, pkt);
    else if (pkt.protocol == "UDP")
        parseUDP(ip_data, ip_header_len, pkt);
    else if (pkt.protocol == "ICMP")
        parseICMP(ip_data, ip_header_len, pkt);

    return pkt;
}

void PacketParser::parseIP(const u_char* data, ParsedPacket& pkt) {
    const struct ip* ip_header = reinterpret_cast<const struct ip*>(data);

    pkt.src_ip       = inet_ntoa(ip_header->ip_src);
    pkt.dst_ip       = inet_ntoa(ip_header->ip_dst);
    pkt.ttl          = ip_header->ip_ttl;
    pkt.total_length = ntohs(ip_header->ip_len);

    switch (ip_header->ip_p) {
        case IPPROTO_TCP:  pkt.protocol = "TCP";  break;
        case IPPROTO_UDP:  pkt.protocol = "UDP";  break;
        case IPPROTO_ICMP: pkt.protocol = "ICMP"; break;
        default:           pkt.protocol = "OTHER"; break;
    }
}

void PacketParser::parseTCP(const u_char* data, int ip_header_len, ParsedPacket& pkt) {
    const struct tcphdr* tcp =
        reinterpret_cast<const struct tcphdr*>(data + ip_header_len);

    pkt.src_port    = ntohs(tcp->source);
    pkt.dst_port    = ntohs(tcp->dest);
    pkt.seq_number  = ntohl(tcp->seq);
    pkt.ack_number  = ntohl(tcp->ack_seq);
    pkt.window_size = ntohs(tcp->window);

    // TCP 플래그 파싱
    pkt.tcp_flags.syn = tcp->syn;
    pkt.tcp_flags.ack = tcp->ack;
    pkt.tcp_flags.fin = tcp->fin;
    pkt.tcp_flags.rst = tcp->rst;
    pkt.tcp_flags.psh = tcp->psh;
    pkt.tcp_flags.urg = tcp->urg;

    // 위험 징후 탐지
    pkt.is_syn_scan  = tcp->syn && !tcp->ack;  // SYN 스캔
    pkt.is_null_scan = !tcp->syn && !tcp->ack  // NULL 스캔
                    && !tcp->fin && !tcp->rst
                    && !tcp->psh && !tcp->urg;
    pkt.is_xmas_scan = tcp->fin && tcp->psh && tcp->urg;  // XMAS 스캔

    // 페이로드 추출
    int tcp_header_len = tcp->doff * 4;
    const u_char* payload_start = data + ip_header_len + tcp_header_len;
    int payload_len = pkt.total_length - ip_header_len - tcp_header_len;

    if (payload_len > 0)
        parsePayload(payload_start, payload_len, pkt);
}

void PacketParser::parseUDP(const u_char* data, int ip_header_len, ParsedPacket& pkt) {
    const struct udphdr* udp =
        reinterpret_cast<const struct udphdr*>(data + ip_header_len);

    pkt.src_port   = ntohs(udp->source);
    pkt.dst_port   = ntohs(udp->dest);
    pkt.udp_length = ntohs(udp->len);

    // 페이로드 추출
    const u_char* payload_start = data + ip_header_len + 8;
    int payload_len = pkt.udp_length - 8;

    if (payload_len > 0)
        parsePayload(payload_start, payload_len, pkt);
}

void PacketParser::parseICMP(const u_char* data, int ip_header_len, ParsedPacket& pkt) {
    const struct icmphdr* icmp =
        reinterpret_cast<const struct icmphdr*>(data + ip_header_len);

    pkt.icmp_type = icmp->type;
    pkt.icmp_code = icmp->code;
    pkt.src_port  = 0;
    pkt.dst_port  = 0;
}

void PacketParser::parsePayload(const u_char* data, int length, ParsedPacket& pkt) {
    pkt.payload.assign(data, data + length);
    pkt.is_printable = checkPrintable(pkt.payload);

    if (pkt.is_printable) {
        pkt.payload_str = std::string(pkt.payload.begin(), pkt.payload.end());
    } else {
        // 바이너리는 hex로 표시
        std::ostringstream oss;
        for (int i = 0; i < std::min(length, 32); i++)
            oss << std::hex << std::setw(2) << std::setfill('0')
                << (int)pkt.payload[i] << " ";
        pkt.payload_str = oss.str();
    }
}

bool PacketParser::checkPrintable(const std::vector<uint8_t>& payload) {
    for (uint8_t c : payload)
        if (!std::isprint(c) && !std::isspace(c)) return false;
    return !payload.empty();
}

void PacketParser::print(const ParsedPacket& pkt) {
    std::cout << "┌─────────────────────────────────\n";
    std::cout << "│ " << pkt.src_ip << ":" << pkt.src_port
              << " → " << pkt.dst_ip << ":" << pkt.dst_port
              << " [" << pkt.protocol << "]\n";
    std::cout << "│ TTL=" << (int)pkt.ttl
              << " Length=" << pkt.total_length;

    if (pkt.protocol == "TCP") {
        std::cout << " Window=" << pkt.window_size << "\n";
        std::cout << "│ Flags: ";
        if (pkt.tcp_flags.syn) std::cout << "SYN ";
        if (pkt.tcp_flags.ack) std::cout << "ACK ";
        if (pkt.tcp_flags.fin) std::cout << "FIN ";
        if (pkt.tcp_flags.rst) std::cout << "RST ";
        if (pkt.tcp_flags.psh) std::cout << "PSH ";
        if (pkt.tcp_flags.urg) std::cout << "URG ";
        std::cout << "\n";

        // 위험 징후 출력
        if (pkt.is_syn_scan)  std::cout << "│ ⚠️  SYN 스캔 의심!\n";
        if (pkt.is_null_scan) std::cout << "│ ⚠️  NULL 스캔 의심!\n";
        if (pkt.is_xmas_scan) std::cout << "│ ⚠️  XMAS 스캔 의심!\n";
    }

    if (!pkt.payload.empty()) {
        std::cout << "│ Payload(" << pkt.payload.size() << "bytes): ";
        std::cout << pkt.payload_str.substr(0, 80) << "\n";
    }

    std::cout << "└─────────────────────────────────\n";
}