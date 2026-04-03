#include <gtest/gtest.h>
#include <fstream>
#include "control/policy_engine.hpp"

// 임시 룰 파일 생성 후 테스트
class PolicyEngineTest : public ::testing::Test {
protected:
    void SetUp() override {
        // 테스트용 임시 JSON 파일 생성
        std::ofstream f("/tmp/test_rules.json");
        f << R"({
            "version": "1.0",
            "rules": [
                {
                    "id": "RULE-001",
                    "name": "쉘 탐지",
                    "type": "signature",
                    "patterns": ["/bin/sh", "/bin/bash"],
                    "severity": "CRITICAL",
                    "action": "sandbox"
                },
                {
                    "id": "RULE-002",
                    "name": "포트스캔 탐지",
                    "type": "heuristic",
                    "threshold": { "connections": 20, "window_sec": 5 },
                    "severity": "HIGH",
                    "action": "sandbox"
                }
            ]
        })";
    }

    void TearDown() override {
        remove("/tmp/test_rules.json");
    }
};

TEST_F(PolicyEngineTest, LoadRules) {
    PolicyEngine engine("/tmp/test_rules.json");
    EXPECT_TRUE(engine.load());
}

TEST_F(PolicyEngineTest, SignatureRuleCount) {
    PolicyEngine engine("/tmp/test_rules.json");
    engine.load();

    EXPECT_EQ(engine.getPolicy().signature_rules.size(), 1);
    EXPECT_EQ(engine.getPolicy().heuristic_rules.size(), 1);
}

TEST_F(PolicyEngineTest, SignatureRuleContent) {
    PolicyEngine engine("/tmp/test_rules.json");
    engine.load();

    const auto& rule = engine.getPolicy().signature_rules[0];
    EXPECT_EQ(rule.id,       "RULE-001");
    EXPECT_EQ(rule.name,     "쉘 탐지");
    EXPECT_EQ(rule.severity, "CRITICAL");
    EXPECT_EQ(rule.patterns.size(), 2);
    EXPECT_EQ(rule.patterns[0], "/bin/sh");
    EXPECT_EQ(rule.patterns[1], "/bin/bash");
}

TEST_F(PolicyEngineTest, HeuristicRuleContent) {
    PolicyEngine engine("/tmp/test_rules.json");
    engine.load();

    const auto& rule = engine.getPolicy().heuristic_rules[0];
    EXPECT_EQ(rule.id,         "RULE-002");
    EXPECT_EQ(rule.severity,   "HIGH");
    EXPECT_EQ(rule.threshold,  20);
    EXPECT_EQ(rule.window_sec, 5);
}

TEST_F(PolicyEngineTest, InvalidFile) {
    PolicyEngine engine("/tmp/nonexistent.json");
    EXPECT_FALSE(engine.load());
}

TEST_F(PolicyEngineTest, VersionParsed) {
    PolicyEngine engine("/tmp/test_rules.json");
    engine.load();
    EXPECT_EQ(engine.getPolicy().version, "1.0");
}