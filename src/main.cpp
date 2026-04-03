#include <iostream>
#include <thread>
#include <chrono>
#include <csignal>
#include <cstring>
#include "ids/packet_capture.hpp"
#include "ids/packet_parser.hpp"
#include "ids/signature_engine.hpp"
#include "ids/alert_manager.hpp"
#include "ids/port_scan_detector.hpp"
#include "control/logger.hpp"
#include "control/ipc_broker.hpp"
#include "control/policy_engine.hpp"
#include "sandbox/sandbox_manager.hpp"
#include "sandbox/behavior_monitor.hpp"

AlertManager*    g_alert_manager    = nullptr;
Logger*          g_logger           = nullptr;
SandboxManager*  g_sandbox_manager  = nullptr;
BehaviorMonitor* g_behavior_monitor = nullptr;

void signalHandler(int) {
    if (g_alert_manager)   g_alert_manager->printStats();
    if (g_sandbox_manager) g_sandbox_manager->printIsolated();
    if (g_logger)          g_logger->printRecentAlerts(10);
    exit(0);
}

int main() {
    std::cout << "IDPS starting..." << std::endl;
    std::signal(SIGINT, signalHandler);

    // ── Logger ────────────────────────────────
    Logger logger("./idps.db");
    if (!logger.init()) return 1;
    g_logger = &logger;

    // ── 정책 엔진 ─────────────────────────────
    PolicyEngine policy_engine("../rules/default.json");
    if (!policy_engine.load()) {
        std::cerr << "[main] 룰 파일 로드 실패" << std::endl;
        return 1;
    }
    policy_engine.printPolicy();

    // ── 시그니처 엔진 ─────────────────────────
    SignatureEngine engine;
    for (const auto& rule : policy_engine.getPolicy().signature_rules)
        engine.addRule(rule);
    engine.build();

    policy_engine.setCallback([&engine](const Policy& policy) {
        std::cout << "[PolicyEngine] 룰 변경 → 시그니처 엔진 재빌드\n";
        for (const auto& rule : policy.signature_rules)
            engine.addRule(rule);
        engine.build();
    });
    policy_engine.startHotReload(10);

    // ── 행동 모니터 ───────────────────────────
    BehaviorMonitor behavior_monitor;
    g_behavior_monitor = &behavior_monitor;

    behavior_monitor.setCallback([](const BehaviorEvent& event) {
        std::cout << "[BehaviorMonitor] 위험 행동 감지: "
                  << "PID=" << event.pid
                  << " syscall=" << event.syscall_name
                  << std::endl;
    });

    // ── 샌드박스 매니저 ───────────────────────
    SandboxManager sandbox;
    g_sandbox_manager = &sandbox;

    sandbox.setCallback([&](const SandboxEntry& entry) {
        std::cout << "[Sandbox] 격리 완료 → 행동 모니터링 시작\n";
        behavior_monitor.startMonitoring(entry.original_pid);
    });

    // ── IPC 서버 ──────────────────────────────
    IpcServer ipc_server("/tmp/idps.sock");

    ipc_server.setCallback([&sandbox](const IpcMessage& msg) {
        if (msg.type == IpcMessageType::ISOLATE_REQUEST) {
            std::cout << "[IPC] 격리 요청 수신: PID=" << msg.pid
                      << " IP=" << msg.src_ip << std::endl;
            sandbox.isolate(msg.pid, msg.src_ip,
                            msg.rule_id, msg.severity);
        }
    });
    ipc_server.start();

    // ── IPC 클라이언트 ────────────────────────
    IpcClient ipc_client("/tmp/idps.sock");
    ipc_client.connect();

    // ── 경보 매니저 ───────────────────────────
    AlertManager alert_manager(10);
    g_alert_manager = &alert_manager;

    alert_manager.setCallback([&](const Alert& alert) {
        logger.logAlert(alert);

        if (alert.severity == "CRITICAL" || alert.severity == "HIGH") {
            std::string cmd = "ss -tnp sport = :80 | grep -oP 'pid=\\K[0-9]+'";
            FILE* pipe = popen(cmd.c_str(), "r");
            pid_t target_pid = 0;
            if (pipe) {
                int ret = fscanf(pipe, "%d", &target_pid);
                (void)ret;
                pclose(pipe);
            }

            if (target_pid > 0 && target_pid != getpid()) {
                IpcMessage msg{};
                msg.type = IpcMessageType::ISOLATE_REQUEST;
                msg.pid  = target_pid;
                strncpy(msg.src_ip,   alert.src_ip.c_str(),   sizeof(msg.src_ip) - 1);
                strncpy(msg.rule_id,  alert.rule_id.c_str(),  sizeof(msg.rule_id) - 1);
                strncpy(msg.severity, alert.severity.c_str(), sizeof(msg.severity) - 1);

                if (ipc_client.send(msg))
                    std::cout << "[IPC] 격리 요청 전송 완료\n";
            } else {
                std::cout << "[Sandbox] ⚠ 대상 PID 없음 - 격리 스킵\n";
            }
        }
    });

    // ── 포트스캔 탐지기 ───────────────────────
    PortScanDetector port_scan_detector(3,5);

    port_scan_detector.setCallback([&](const PortScanResult& result) {
        std::cout << "[PortScan] 격리 대상: " << result.src_ip << "\n";

        ThreatInfo threat;
        threat.rule_id         = "RULE-004";
        threat.rule_name       = "포트 스캔 탐지";
        threat.matched_pattern = std::to_string(result.port_count) + "개 포트";
        threat.severity        = result.severity;
        threat.packet.src_ip   = result.src_ip;
        threat.packet.dst_ip   = "0.0.0.0";
        threat.packet.src_port = 0;
        threat.packet.dst_port = 0;
        alert_manager.onThreat(threat);
    });

    // ── 패킷 캡처 ─────────────────────────────
    PacketCapture capture("any", [&](const PacketInfo& raw_pkt) {
        ParsedPacket pkt = PacketParser::parse(
            raw_pkt.raw_data.data(),
            raw_pkt.raw_data.size()
        );

        PacketParser::print(pkt);
        logger.logPacket(pkt);

        // 시그니처 분석
        engine.analyze(raw_pkt, [&](const ThreatInfo& threat) {
            alert_manager.onThreat(threat);
        });

        // 포트스캔 분석
        port_scan_detector.analyze(pkt);
    });

    capture.start();

    std::this_thread::sleep_for(std::chrono::seconds(30));
    capture.stop();

    // ── 종료 시 통계 출력 ─────────────────────
    alert_manager.printStats();
    sandbox.printIsolated();
    port_scan_detector.printStats();

    for (const auto& [pid, entry] : sandbox.getIsolated())
        behavior_monitor.printReport(pid);

    logger.printRecentAlerts(10);
    policy_engine.stopHotReload();
    ipc_server.stop();

    return 0;
}