#include <gtest/gtest.h>
#include "ids/alert_manager.hpp"

TEST(AlertManagerTest, CallbackCalled) {
    AlertManager manager(0);

    int callback_count = 0;
    manager.setCallback([&](const Alert& /*alert*/) {
        callback_count++;
    });

    ThreatInfo threat;
    threat.rule_id         = "RULE-001";
    threat.rule_name       = "쉘 탐지";
    threat.matched_pattern = "/bin/sh";
    threat.severity        = "CRITICAL";
    threat.packet.src_ip   = "192.168.1.1";
    threat.packet.dst_ip   = "192.168.1.2";
    threat.packet.src_port = 1234;
    threat.packet.dst_port = 80;

    manager.onThreat(threat);

    EXPECT_EQ(callback_count,           1);
    EXPECT_EQ(manager.getTotalAlerts(), 1);
}

TEST(AlertManagerTest, SuppressDuplicateAlerts) {
    AlertManager manager(10);

    int callback_count = 0;
    manager.setCallback([&](const Alert& /*alert*/) {
        callback_count++;
    });

    ThreatInfo threat;
    threat.rule_id         = "RULE-001";
    threat.rule_name       = "쉘 탐지";
    threat.matched_pattern = "/bin/sh";
    threat.severity        = "CRITICAL";
    threat.packet.src_ip   = "192.168.1.1";
    threat.packet.dst_ip   = "192.168.1.2";
    threat.packet.src_port = 1234;
    threat.packet.dst_port = 80;

    manager.onThreat(threat);
    manager.onThreat(threat);
    manager.onThreat(threat);

    EXPECT_EQ(manager.getTotalAlerts(), 3);
    EXPECT_EQ(callback_count,           1);
}

TEST(AlertManagerTest, DifferentIpNotSuppressed) {
    AlertManager manager(10);

    int callback_count = 0;
    manager.setCallback([&](const Alert& /*alert*/) {
        callback_count++;
    });

    ThreatInfo threat1;
    threat1.rule_id         = "RULE-001";
    threat1.rule_name       = "쉘 탐지";
    threat1.matched_pattern = "/bin/sh";
    threat1.severity        = "CRITICAL";
    threat1.packet.src_ip   = "192.168.1.1";
    threat1.packet.dst_ip   = "192.168.1.2";
    threat1.packet.src_port = 1234;
    threat1.packet.dst_port = 80;

    ThreatInfo threat2    = threat1;
    threat2.packet.src_ip = "10.0.0.1";

    manager.onThreat(threat1);
    manager.onThreat(threat2);

    EXPECT_EQ(callback_count, 2);
}
