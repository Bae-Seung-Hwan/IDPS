# IDPS
C++로 구현한 네트워크 침입 탐지 + 프로세스 샌드박스 통합 보안 플랫폼

프로젝트 개요
IDPS는 실시간 네트워크 트래픽을 감시하다가 이상 패킷을 탐지하면 해당 프로세스를 자동으로 격리하는 보안 플랫폼입니다.
상용 EDR(Endpoint Detection & Response) 솔루션과 동일한 원리로 동작하며, 다음 두 시스템을 C++로 직접 구현하고 통합했습니다.

IDS (Intrusion Detection System): libpcap 기반 패킷 캡처 + Aho-Corasick 시그니처 매칭
Sandbox: Linux namespace + seccomp-bpf 기반 프로세스 격리 + ptrace 행동 모니터링

네트워크 트래픽 → 패킷 캡처 → 시그니처 매칭 → 위협 감지
                                                    ↓
                              행동 보고서 ← 프로세스 격리 (sandbox)

핵심 기능
기능설명구현 방법실시간 패킷 캡처멀티스레드 비동기 캡처libpcap + POSIX thread시그니처 탐지페이로드 내 악성 패턴 탐지Aho-Corasick 알고리즘이상 행동 탐지연결 빈도·포트 스캔 탐지슬라이딩 윈도우 통계자동 프로세스 격리위협 감지 시 해당 PID 즉시 격리IPC → sandbox 파이프라인시스템 콜 차단화이트리스트 기반 syscall 필터seccomp-bpf네트워크 격리격리된 프로세스의 외부 통신 차단Linux network namespace행동 모니터링격리 환경 내 프로세스 행동 추적ptrace로그 저장모든 이벤트 영속 저장SQLite3REST API외부 대시보드 연동C++ HTTP 서버 (선택)

시스템 아키텍처
┌─────────────────────────────────────────────────────┐
│                   IDS 레이어                         │
│  [패킷 캡처] → [패킷 파서] → [시그니처 엔진]           │
└────────────────────────┬────────────────────────────┘
                         │ 위협 감지 (Unix socket IPC)
┌────────────────────────▼────────────────────────────┐
│                  제어 레이어                         │
│  [경보 매니저] → [정책 엔진] → [IPC 브로커]           │
│                     ↓              ↓                │
│               [SQLite 로그]   [REST API]            │
└────────────────────────┬────────────────────────────┘
                         │ 격리 명령
┌────────────────────────▼────────────────────────────┐
│                 샌드박스 레이어                      │
│  [seccomp 필터] + [namespace 격리] + [행동 모니터]   │
└─────────────────────────────────────────────────────┘
디렉토리 구조
idps/
├── CMakeLists.txt
├── README.md
├── rules/
│   └── default.json          # 시그니처 룰 파일
├── src/
│   ├── main.cpp
│   ├── ids/
│   │   ├── packet_capture.hpp/.cpp    # libpcap 래퍼
│   │   ├── packet_parser.hpp/.cpp     # IP/TCP/UDP 헤더 파싱
│   │   ├── signature_engine.hpp/.cpp  # Aho-Corasick 매칭
│   │   └── alert_manager.hpp/.cpp     # 위협 등급 분류
│   ├── sandbox/
│   │   ├── sandbox_manager.hpp/.cpp   # 격리 실행 제어
│   │   ├── seccomp_filter.hpp/.cpp    # BPF 정책 설계
│   │   └── behavior_monitor.hpp/.cpp  # ptrace 행동 수집
│   └── control/
│       ├── ipc_broker.hpp/.cpp        # Unix socket 통신
│       ├── policy_engine.hpp/.cpp     # JSON 룰 로더
│       └── logger.hpp/.cpp            # SQLite 연동
├── tests/
│   ├── test_signature_engine.cpp
│   ├── test_sandbox.cpp
│   └── pcap_samples/                 # 테스트용 PCAP 파일
└── docs/
    └── design.md

빌드 및 실행
요구 사항

Linux (Ubuntu 20.04+ 권장)
C++17 이상
CMake 3.16+
libpcap-dev
libsqlite3-dev
libseccomp-dev

bashsudo apt install build-essential cmake libpcap-dev libsqlite3-dev libseccomp-dev
빌드
bashgit clone https://github.com/yourusername/idps.git
cd idps
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
실행
bash# root 권한 필요 (raw socket, namespace 생성)
sudo ./idps --interface eth0 --rules ../rules/default.json

# 옵션
--interface, -i   감시할 네트워크 인터페이스 (기본: eth0)
--rules, -r       시그니처 룰 파일 경로
--log, -l         로그 DB 경로 (기본: ./idps.db)
--verbose, -v     상세 출력 모드
테스트
bashcd build
ctest --output-on-failure

# 특정 PCAP으로 오프라인 테스트
sudo ./idps --interface eth0 --pcap ../tests/pcap_samples/portscan.pcap

시그니처 룰 예시
rules/default.json에서 탐지 규칙을 정의합니다.
json{
  "rules": [
    {
      "id": "RULE-001",
      "name": "포트 스캔 탐지",
      "type": "heuristic",
      "threshold": { "connections": 20, "window_sec": 5 },
      "severity": "HIGH",
      "action": "sandbox"
    },
    {
      "id": "RULE-002",
      "name": "악성 페이로드 패턴",
      "type": "signature",
      "patterns": ["/bin/sh", "cmd.exe", "wget http"],
      "severity": "CRITICAL",
      "action": "sandbox"
    }
  ]
}

기술 스택
구분기술언어C++17패킷 캡처libpcap패턴 매칭Aho-Corasick (직접 구현)프로세스 격리Linux namespaces (PID, net, mount, user)시스템 콜 필터seccomp-bpf행동 추적ptraceIPCUnix domain socket데이터 저장SQLite3빌드CMake테스트Google Test

개발 배경
네트워크 보안과 시스템 보안을 별개로 공부하다 보면 "실제로 어떻게 연결되는가"라는 질문이 생깁니다. 상용 EDR 솔루션(안랩 V3, CrowdStrike Falcon 등)이 이 두 영역을 통합하여 동작한다는 점에 착안해, 핵심 원리를 직접 C++로 구현해보는 것을 목표로 했습니다.
