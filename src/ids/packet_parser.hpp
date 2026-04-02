#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

// TCP 플래그 정보
struct TcpFlags {
    bool syn;
    bool ack;
    bool fin;
    bool rst;
    bool psh;
    bool urg;
};

// 상세 파싱된 패킷 정보
struct ParsedPacket {
    // IP 레이어
    std::string src_ip;
    std::string dst_ip;
    uint8_t     ttl;
    uint16_t    total_length;
    std::string protocol;   // TCP / UDP / ICMP / OTHER

    // TCP 레이어
    uint16_t  src_port;
    uint16_t  dst_port;
    uint32_t  seq_number;   // 시퀀스 번호
    uint32_t  ack_number;   // ACK 번호
    TcpFlags  tcp_flags;    // SYN, ACK, FIN 등
    uint16_t  window_size;  // TCP 윈도우 크기

    // UDP 레이어
    uint16_t  udp_length;

    // ICMP 레이어
    uint8_t   icmp_type;
    uint8_t   icmp_code;

    // 페이로드
    std::vector<uint8_t> payload;
    std::string          payload_str;  // 출력용 문자열
    bool                 is_printable; // 페이로드가 텍스트인지

    // 위험 징후 플래그
    bool is_syn_scan;     // SYN만 있고 ACK 없음 → 포트스캔 의심
    bool is_null_scan;    // 모든 플래그 꺼짐 → 스텔스 스캔
    bool is_xmas_scan;    // FIN+PSH+URG → 스텔스 스캔
};

class PacketParser {
public:
    // raw 패킷 데이터를 ParsedPacket으로 변환
    static ParsedPacket parse(const u_char* raw_packet, int length);

    // 파싱 결과 출력 (디버그용)
    static void print(const ParsedPacket& pkt);

private:
    static void parseIP(const u_char* data, ParsedPacket& pkt);
    static void parseTCP(const u_char* data, int ip_header_len, ParsedPacket& pkt);
    static void parseUDP(const u_char* data, int ip_header_len, ParsedPacket& pkt);
    static void parseICMP(const u_char* data, int ip_header_len, ParsedPacket& pkt);
    static void parsePayload(const u_char* data, int length, ParsedPacket& pkt);
    static bool checkPrintable(const std::vector<uint8_t>& payload);
};