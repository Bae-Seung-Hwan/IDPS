#pragma once

#include <string>
#include <vector>
#include <map>
#include <queue>
#include <functional>
#include "packet_capture.hpp"

// 탐지된 위협 정보
struct ThreatInfo {
    std::string rule_id;       // 룰 ID (예: RULE-002)
    std::string rule_name;     // 룰 이름
    std::string matched_pattern; // 매칭된 패턴
    std::string severity;      // 위협 등급 (LOW/MEDIUM/HIGH/CRITICAL)
    PacketInfo  packet;        // 원본 패킷 정보
};

// 시그니처 룰
struct SignatureRule {
    std::string id;
    std::string name;
    std::vector<std::string> patterns;
    std::string severity;
};

// 위협 탐지 시 호출될 콜백
using ThreatCallback = std::function<void(const ThreatInfo&)>;

class SignatureEngine {
public:
    SignatureEngine();

    void addRule(const SignatureRule& rule);   // 룰 추가
    void build();                              // Aho-Corasick 트라이 빌드
    void analyze(const PacketInfo& packet,
                 ThreatCallback callback);     // 패킷 분석

private:
    // Aho-Corasick 트라이 노드
    struct AhoNode {
        std::map<char, int> children;  // 자식 노드
        int fail;                      // 실패 링크
        std::vector<int> output;       // 매칭된 패턴 인덱스
        AhoNode() : fail(0) {}
    };

    std::vector<AhoNode> trie_;               // 트라이 노드 배열
    std::vector<SignatureRule> rules_;         // 등록된 룰 목록
    std::vector<std::pair<int,int>> patterns_; // {룰 인덱스, 패턴 인덱스}
    bool built_;

    void buildTrie();    // 트라이 구성
    void buildFail();    // 실패 링크 구성 (BFS)
};