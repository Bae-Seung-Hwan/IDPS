# IDPS — Integrated Detection & Protection System

> C++로 구현한 네트워크 침입 탐지 + 프로세스 샌드박스 통합 보안 플랫폼

---

## 프로젝트 개요

IDPS는 실시간 네트워크 트래픽을 감시하다가 **이상 패킷을 탐지하면 해당 프로세스를 자동으로 격리**하는 보안 플랫폼입니다.

상용 EDR(Endpoint Detection & Response) 솔루션과 동일한 원리로 동작하며, 다음 두 시스템을 C++로 직접 구현하고 통합했습니다.

- **IDS (Intrusion Detection System)**: libpcap 기반 패킷 캡처 + Aho-Corasick 시그니처 매칭
- **Sandbox**: Linux namespace + seccomp-bpf 기반 프로세스 격리 + ptrace 행동 모니터링

```
네트워크 트래픽 → 패킷 캡처 → 시그니처 매칭 → 위협 감지
                                                    ↓
                              행동 보고서 ← 프로세스 격리 (sandbox)
```

---

## 핵심 기능

| 기능 | 설명 | 구현 방법 |
|------|------|-----------|
| 실시간 패킷 캡처 | 멀티스레드 비동기 캡처 | libpcap + POSIX thread |
| 시그니처 탐지 | 페이로드 내 악성 패턴 탐지 | Aho-Corasick 알고리즘 |
| 이상 행동 탐지 | 연결 빈도·포트 스캔 탐지 | 슬라이딩 윈도우 통계 |
| 자동 프로세스 격리 | 위협 감지 시 해당 PID 즉시 격리 | IPC → sandbox 파이프라인 |
| 시스템 콜 차단 | 화이트리스트 기반 syscall 필터 | seccomp-bpf |
| 네트워크 격리 | 격리된 프로세스의 외부 통신 차단 | Linux network namespace |
| 행동 모니터링 | 격리 환경 내 프로세스 행동 추적 | ptrace |
| 로그 저장 | 모든 이벤트 영속 저장 | SQLite3 |
| REST API | 외부 대시보드 연동 | C++ HTTP 서버 (선택) |

---

## 시스템 아키텍처

```
┌─────────────────────────────────────────────────────┐
│                   IDS 레이어                         │
│  [패킷 캡처] → [패킷 파서] → [시그니처 엔진]         │
└────────────────────────┬────────────────────────────┘
                         │ 위협 감지 (Unix socket IPC)
┌────────────────────────▼────────────────────────────┐
│                  제어 레이어                          │
│  [경보 매니저] → [정책 엔진] → [IPC 브로커]          │
│                     ↓              ↓                 │
│               [SQLite 로그]   [REST API]             │
└────────────────────────┬────────────────────────────┘
                         │ 격리 명령
┌────────────────────────▼────────────────────────────┐
│                 샌드박스 레이어                        │
│  [seccomp 필터] + [namespace 격리] + [행동 모니터]   │
└─────────────────────────────────────────────────────┘
```

### 디렉토리 구조

```
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
```

---

## 빌드 및 실행

### 요구 사항

- Linux (Ubuntu 20.04+ 권장)
- C++17 이상
- CMake 3.16+
- libpcap-dev
- libsqlite3-dev
- libseccomp-dev

```bash
sudo apt install build-essential cmake libpcap-dev libsqlite3-dev libseccomp-dev
```

### 빌드

```bash
git clone https://github.com/Bae-Seung-Hawn/IDPS.git
cd idps
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

### 실행

```bash
# root 권한 필요 (raw socket, namespace 생성)
sudo ./idps --interface eth0 --rules ../rules/default.json

# 옵션
--interface, -i   감시할 네트워크 인터페이스 (기본: eth0)
--rules, -r       시그니처 룰 파일 경로
--log, -l         로그 DB 경로 (기본: ./idps.db)
--verbose, -v     상세 출력 모드
```

### 테스트

```bash
cd build
ctest --output-on-failure

# 특정 PCAP으로 오프라인 테스트
sudo ./idps --interface eth0 --pcap ../tests/pcap_samples/portscan.pcap
```

---

## 시그니처 룰 예시

`rules/default.json`에서 탐지 규칙을 정의합니다.

```json
{
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
```

---

## 기술 스택

| 구분 | 기술 |
|------|------|
| 언어 | C++17 |
| 패킷 캡처 | libpcap |
| 패턴 매칭 | Aho-Corasick (직접 구현) |
| 프로세스 격리 | Linux namespaces (PID, net, mount, user) |
| 시스템 콜 필터 | seccomp-bpf |
| 행동 추적 | ptrace |
| IPC | Unix domain socket |
| 데이터 저장 | SQLite3 |
| 빌드 | CMake |
| 테스트 | Google Test |

---

## 개발 배경

네트워크 보안과 시스템 보안을 별개로 공부하다 보면 "실제로 어떻게 연결되는가"라는 질문이 생깁니다. 상용 EDR 솔루션(안랩 V3, CrowdStrike Falcon 등)이 이 두 영역을 통합하여 동작한다는 점에 착안해, 핵심 원리를 직접 C++로 구현해보는 것을 목표로 했습니다.

---

## 라이선스

MIT License. 자세한 내용은 [LICENSE](./LICENSE)를 참고하세요.
## 구현 현황

### 완성된 모듈

| 모듈 | 파일 | 설명 |
|------|------|------|
| 패킷 캡처 | `src/ids/packet_capture.cpp` | libpcap 기반 멀티스레드 비동기 캡처 |
| 패킷 파서 | `src/ids/packet_parser.cpp` | IP/TCP/UDP/ICMP 헤더 상세 파싱, SYN/NULL/XMAS 스캔 감지 |
| 시그니처 엔진 | `src/ids/signature_engine.cpp` | Aho-Corasick 알고리즘 직접 구현, 멀티 패턴 동시 탐지 |
| 경보 매니저 | `src/ids/alert_manager.cpp` | 위협 등급 분류, 중복 경보 억제 (슬라이딩 윈도우) |
| 포트스캔 탐지 | `src/ids/port_scan_detector.cpp` | SYN 패킷 기반 포트스캔 탐지, IP별 스캔 포트 추적 |
| 로거 | `src/control/logger.cpp` | SQLite3 기반 경보/패킷 로그 영속 저장 |
| IPC 브로커 | `src/control/ipc_broker.cpp` | Unix domain socket 기반 IDS ↔ Sandbox 통신 |
| 정책 엔진 | `src/control/policy_engine.cpp` | JSON 룰 파일 로더, 핫 리로드 (파일 변경 자동 감지) |
| REST API | `src/control/rest_api.cpp` | C++ HTTP 서버, 6개 엔드포인트 |
| 샌드박스 매니저 | `src/sandbox/sandbox_manager.cpp` | Linux namespace + SIGSTOP 기반 프로세스 격리 |
| seccomp 필터 | `src/sandbox/seccomp_filter.cpp` | syscall 화이트리스트 기반 차단 (socket, execve, fork 등) |
| 행동 모니터 | `src/sandbox/behavior_monitor.cpp` | ptrace 기반 syscall 추적 및 위험 행동 탐지 |

---

## REST API

IDPS 실행 중 아래 엔드포인트로 데이터를 조회할 수 있습니다.
```bash
# IDPS 상태 조회
curl http://localhost:8080/api/status

# 경보 목록 조회 (최근 20개)
curl http://localhost:8080/api/alerts?limit=20

# 경보 통계 조회
curl http://localhost:8080/api/alerts/stats

# 격리된 프로세스 목록
curl http://localhost:8080/api/sandbox

# 룰 재로드
curl -X POST http://localhost:8080/api/rules/reload
```

### 응답 예시
```json
// GET /api/status
{
  "status": "running",
  "total_alerts": 9,
  "isolated_processes": 1,
  "version": "1.0"
}

// GET /api/alerts/stats
{
  "total": 9,
  "critical": 3,
  "high": 3,
  "medium": 2,
  "low": 0
}
```

---

## 웹 대시보드

`dashboard/index.html` 을 브라우저에서 열면 실시간 모니터링 대시보드를 사용할 수 있습니다.
\wsl$\Ubuntu\home\user\IDPS\dashboard\index.html

### 기능

- 경보 통계 실시간 시각화 (TOTAL / CRITICAL / HIGH / MEDIUM)
- 등급별 분포 바 차트
- 격리된 프로세스 목록
- 최근 경보 테이블
- 룰 재로드 버튼
- 5초마다 자동 갱신

---

## 탐지 기능 상세

### 시그니처 탐지 (Aho-Corasick)

패킷 페이로드에서 악성 패턴을 실시간으로 탐지합니다.
```json
{
  "id": "RULE-001",
  "name": "악성 쉘 탐지",
  "type": "signature",
  "patterns": ["/bin/sh", "/bin/bash", "cmd.exe"],
  "severity": "CRITICAL",
  "action": "sandbox"
}
```

### 포트스캔 탐지 (휴리스틱)

슬라이딩 윈도우 기반으로 SYN 패킷을 분석해 포트스캔을 탐지합니다.
```json
{
  "id": "RULE-004",
  "name": "포트 스캔 탐지",
  "type": "heuristic",
  "threshold": { "connections": 20, "window_sec": 5 },
  "severity": "HIGH",
  "action": "sandbox"
}
```

### seccomp-bpf syscall 필터

격리된 프로세스에 syscall 화이트리스트를 적용합니다.

| syscall | 기본 프로파일 | 엄격한 프로파일 |
|---------|-------------|--------------|
| read / write | ✅ 허용 | ✅ 허용 |
| open / close | ✅ 허용 | ❌ 차단 |
| socket | ❌ 차단 | ❌ 차단 |
| connect | ❌ 차단 | ❌ 차단 |
| execve | ❌ 차단 | ❌ 차단 |
| fork / clone | ❌ 차단 | ❌ 차단 |
| setuid | ❌ 차단 | ❌ 차단 |

---

## 테스트
```bash
cd build
./idps_test
```

### 테스트 현황

| 테스트 스위트 | 테스트 수 | 상태 |
|-------------|---------|------|
| SignatureEngineTest | 5개 | ✅ PASSED |
| AlertManagerTest | 3개 | ✅ PASSED |
| PolicyEngineTest | 6개 | ✅ PASSED |
| SeccompFilterTest | 4개 | ✅ PASSED |
| **합계** | **18개** | **✅ ALL PASSED** |

---

## 개발 과정

각 모듈을 단계적으로 구현하고 통합했습니다.
1단계: IDS 레이어
패킷 캡처 → 패킷 파서 → 시그니처 엔진 → 경보 매니저
2단계: 제어 레이어
로거 → IPC 브로커 → 정책 엔진 → REST API
3단계: 샌드박스 레이어
샌드박스 매니저 → seccomp 필터 → 행동 모니터
4단계: 고도화
포트스캔 탐지 → 웹 대시보드 → 단위 테스트
##실행 결과
<img width="307" height="421" alt="image" src="https://github.com/user-attachments/assets/affa3f43-022d-457d-9d76-1c5e4f8d9164" />
<img width="777" height="488" alt="image" src="https://github.com/user-attachments/assets/971c5a57-c3b4-4cc8-904f-91856c53ff11" />
