#include "signature_engine.hpp"
#include <iostream>
#include <queue>

SignatureEngine::SignatureEngine() : built_(false) {
    trie_.emplace_back(); // 루트 노드 (index 0)
}

void SignatureEngine::addRule(const SignatureRule& rule) {
    rules_.push_back(rule);
}

void SignatureEngine::build() {
    buildTrie();
    buildFail();
    built_ = true;
    std::cout << "[SignatureEngine] 빌드 완료 - "
              << rules_.size() << "개 룰, "
              << patterns_.size() << "개 패턴" << std::endl;
}

void SignatureEngine::buildTrie() {
    for (int ri = 0; ri < (int)rules_.size(); ri++) {
        for (int pi = 0; pi < (int)rules_[ri].patterns.size(); pi++) {
            const std::string& pattern = rules_[ri].patterns[pi];
            int cur = 0;

            // 패턴의 각 문자를 트라이에 삽입
            for (char c : pattern) {
                if (trie_[cur].children.find(c) == trie_[cur].children.end()) {
                    trie_[cur].children[c] = trie_.size();
                    trie_.emplace_back();
                }
                cur = trie_[cur].children[c];
            }

            // 패턴 끝 노드에 출력 정보 저장
            trie_[cur].output.push_back(patterns_.size());
            patterns_.push_back({ri, pi});
        }
    }
}

void SignatureEngine::buildFail() {
    // BFS로 실패 링크 구성
    std::queue<int> q;

    // 루트의 직접 자식들은 실패 링크 = 루트
    for (auto& [c, child] : trie_[0].children) {
        trie_[child].fail = 0;
        q.push(child);
    }

    while (!q.empty()) {
        int cur = q.front(); q.pop();

        for (auto& [c, child] : trie_[cur].children) {
            // 실패 링크 따라가며 같은 문자 찾기
            int fail = trie_[cur].fail;
            while (fail != 0 && trie_[fail].children.find(c) == trie_[fail].children.end())
                fail = trie_[fail].fail;

            if (trie_[fail].children.count(c) && trie_[fail].children[c] != child)
                trie_[child].fail = trie_[fail].children[c];
            else
                trie_[child].fail = 0;

            // 출력 링크 합치기
            for (int out : trie_[trie_[child].fail].output)
                trie_[child].output.push_back(out);

            q.push(child);
        }
    }
}

void SignatureEngine::analyze(const PacketInfo& packet, ThreatCallback callback) {
    if (!built_) {
        std::cerr << "[SignatureEngine] build() 먼저 호출하세요!" << std::endl;
        return;
    }

    // 페이로드를 문자열로 변환
    std::string payload(packet.payload.begin(), packet.payload.end());
    if (payload.empty()) return;

    int cur = 0;
    for (char c : payload) {
        // 실패 링크 따라가며 매칭 시도
        while (cur != 0 && trie_[cur].children.find(c) == trie_[cur].children.end())
            cur = trie_[cur].fail;

        if (trie_[cur].children.count(c))
            cur = trie_[cur].children[c];

        // 매칭된 패턴 처리
        for (int idx : trie_[cur].output) {
            auto [ri, pi] = patterns_[idx];
            const SignatureRule& rule = rules_[ri];

            ThreatInfo threat;
            threat.rule_id        = rule.id;
            threat.rule_name      = rule.name;
            threat.matched_pattern = rule.patterns[pi];
            threat.severity       = rule.severity;
            threat.packet         = packet;

            callback(threat);
        }
    }
}