# IDPS — Integrated Detection & Protection System

> C++17로 구현한 네트워크 침입 탐지 + 프로세스 샌드박스 통합 보안 플랫폼

[![Build](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Tests](https://img.shields.io/badge/tests-18%20passed-brightgreen)]()
[![Language](https://img.shields.io/badge/language-C++17-blue)]()
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()

---

## 한 줄 요약

**네트워크에서 이상 패킷을 감지하면 해당 프로세스를 자동으로 격리하는 EDR 핵심 원리 구현체.**

안랩 V3, CrowdStrike Falcon 같은 상용 EDR 솔루션과 동일한 구조(IDS → 위협 판단 → 프로세스 격리)를 C++17과 Linux 커널 API로 직접 구현했습니다.

---

## 데모

> 스크린샷 / GIF 삽입 위치
> `dashboard/index.html` 실행 화면, 터미널 탐지 로그 등

---

## 전체 구조

```
네트워크 트래픽
      │
      ▼
┌─────────────────────────────────────┐
│           IDS 레이어                 │
│  패킷 캡처 → 패킷 파서 → 시그니처 엔진 │
│               └─→ 포트스캔 탐지기     │
│                        │            │
│                   경보 매니저        │
└─────────────────────┬───────────────┘
                      │ Unix socket IPC
┌─────────────────────▼───────────────┐
│           제어 레이어                 │
│  IPC 브로커 → 정책 엔진 → 로거        │
│                   └─→ REST API       │
└─────────────────────┬───────────────┘
                      │ 격리 명령
┌─────────────────────▼───────────────┐
│          샌드박스 레이어              │
│  샌드박스 매니저                      │
│  ├─ namespace 격리 (PID/net/mount)  │
│  ├─ seccomp-bpf syscall 필터        │
│  └─ 행동 모니터 (ptrace)             │
└─────────────────────────────────────┘
```

---

## 구현 모듈

| 레이어 | 모듈 | 파일 | 설명 |
|--------|------|------|------|
| IDS | 패킷 캡처 | `src/ids/packet_capture.cpp` | libpcap 기반 멀티스레드 비동기 캡처 |
| IDS | 패킷 파서 | `src/ids/packet_parser.cpp` | IP/TCP/UDP/ICMP 파싱, SYN·NULL·XMAS 스캔 감지 |
| IDS | 시그니처 엔진 | `src/ids/signature_engine.cpp` | Aho-Corasick 직접 구현, 멀티 패턴 단일 패스 탐지 |
| IDS | 경보 매니저 | `src/ids/alert_manager.cpp` | 위협 등급 분류, 슬라이딩 윈도우 중복 억제 |
| IDS | 포트스캔 탐지 | `src/ids/port_scan_detector.cpp` | SYN 패킷 기반 포트스캔, IP별 스캔 포트 추적 |
| 제어 | 로거 | `src/control/logger.cpp` | SQLite3 기반 경보·패킷 로그 영속 저장 |
| 제어 | IPC 브로커 | `src/control/ipc_broker.cpp` | Unix domain socket IDS ↔ Sandbox 통신 |
| 제어 | 정책 엔진 | `src/control/policy_engine.cpp` | JSON 룰 로더, 파일 변경 시 핫 리로드 |
| 제어 | REST API | `src/control/rest_api.cpp` | C++ HTTP 서버, 6개 엔드포인트 |
| 샌드박스 | 샌드박스 매니저 | `src/sandbox/sandbox_manager.cpp` | Linux namespace + SIGSTOP 프로세스 격리 |
| 샌드박스 | seccomp 필터 | `src/sandbox/seccomp_filter.cpp` | syscall 화이트리스트 차단 |
| 샌드박스 | 행동 모니터 | `src/sandbox/behavior_monitor.cpp` | ptrace 기반 syscall 추적·위험 행동 탐지 |

---

## 탐지 기능

### 시그니처 탐지 (Aho-Corasick)

패킷 페이로드에서 악성 패턴을 실시간 탐지합니다. 패턴 수에 관계없이 O(N) 단일 패스로 처리합니다.

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

슬라이딩 윈도우 기반으로 SYN 패킷을 분석해 포트스캔을 탐지합니다. SYN, NULL, XMAS 스캔을 패킷 파서 레벨에서 식별합니다.

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

### 위협 등급

| 등급 | 조건 | 자동 액션 |
|------|------|-----------|
| LOW | 포트스캔 1~5회 | 로그 기록 |
| MEDIUM | 포트스캔 6~19회 / 알려진 패턴 1건 | 로그 + 알림 |
| HIGH | 포트스캔 20회+ / 악성 패턴 1건 | 자동 격리 |
| CRITICAL | 셸 명령 패턴 / C2 통신 패턴 | 즉시 격리 + 보고서 |

---

## 샌드박스 격리

### Linux namespace 격리

```cpp
int flags = CLONE_NEWPID   // 자체 PID 네임스페이스
          | CLONE_NEWNET   // 네트워크 완전 차단
          | CLONE_NEWNS    // 마운트 격리
          | CLONE_NEWUSER  // UID/GID 격리
          | SIGCHLD;
pid_t child = clone(child_func, stack_top, flags, &args);
```

### seccomp-bpf syscall 필터

| syscall | 기본 프로파일 | 엄격한 프로파일 |
|---------|--------------|----------------|
| read / write |  허용 |  허용 |
| open / close |  허용 |  차단 |
| socket |  차단 |  차단 |
| connect |  차단 |  차단 |
| execve |  차단 |  차단 |
| fork / clone |  차단 |  차단 |
| setuid |  차단 |  차단 |

---

## REST API

IDPS 실행 중 아래 엔드포인트로 데이터를 조회할 수 있습니다.

| 메서드 | 엔드포인트 | 설명 |
|--------|-----------|------|
| GET | `/api/status` | 시스템 상태 조회 |
| GET | `/api/alerts` | 경보 목록 (`?limit=N`) |
| GET | `/api/alerts/stats` | 경보 통계 |
| GET | `/api/sandbox` | 격리된 프로세스 목록 |
| POST | `/api/rules/reload` | 룰 파일 재로드 |

```bash
# 상태 조회
curl http://localhost:8080/api/status
# → {"status":"running","total_alerts":9,"isolated_processes":1,"version":"1.0"}

# 경보 통계
curl http://localhost:8080/api/alerts/stats
# → {"total":9,"critical":3,"high":3,"medium":2,"low":0}
```

---

## 웹 대시보드

`dashboard/index.html`을 브라우저에서 열면 실시간 모니터링 대시보드를 사용할 수 있습니다.

**기능**
- 경보 통계 실시간 시각화 (TOTAL / CRITICAL / HIGH / MEDIUM)
- 등급별 분포 바 차트
- 격리된 프로세스 목록
- 최근 경보 테이블
- 룰 재로드 버튼
- 5초마다 자동 갱신

---

## 빌드 및 실행

### 요구 사항

```bash
sudo apt install build-essential cmake \
  libpcap-dev libsqlite3-dev libseccomp-dev libgtest-dev
```

### 빌드

```bash
git clone https://github.com/Bae-Seung-Hwan/IDPS.git
cd IDPS
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

### 오프라인 PCAP 테스트

```bash
sudo ./idps --pcap ../tests/pcap_samples/portscan.pcap --rules ../rules/default.json
```

---

## 테스트

```bash
cd build && ./idps_test
```

| 테스트 스위트 | 테스트 수 | 결과 |
|--------------|-----------|------|
| SignatureEngineTest | 5개 |  PASSED |
| AlertManagerTest | 3개 |  PASSED |
| PolicyEngineTest | 6개 |  PASSED |
| SeccompFilterTest | 4개 |  PASSED |
| **합계** | **18개** | ** ALL PASSED** |

---

## 기술적 의사결정

| 결정 | 선택 이유 |
|------|-----------|
| Aho-Corasick 직접 구현 | 수백 개 패턴을 O(N) 단일 패스로 처리. `strstr()` 반복 대비 패턴 수에 무관한 성능 보장 |
| Unix domain socket IPC | 동일 호스트 내 TCP 대비 오버헤드 낮고, 파일 시스템 퍼미션으로 접근 제어 가능 |
| Linux namespace 격리 | VM 없이 커널 레벨에서 네트워크·PID·파일 시스템을 완전 분리 |
| seccomp-bpf | 화이트리스트 방식으로 허용 syscall만 지정, 나머지 전체 SIGKILL 처리 |
| SQLite3 | 외부 DB 서버 없이 단일 파일로 이벤트 영속 저장, 배포 환경 의존성 최소화 |
| ptrace 행동 모니터 | 커널 레벨 syscall 인터셉트로 격리 프로세스의 모든 시스템 콜 기록 |

---

## 디렉토리 구조

```
idps/
├── CMakeLists.txt
├── README.md
├── rules/
│   └── default.json
├── dashboard/
│   └── index.html
├── src/
│   ├── main.cpp
│   ├── ids/
│   │   ├── packet_capture.hpp/.cpp
│   │   ├── packet_parser.hpp/.cpp
│   │   ├── signature_engine.hpp/.cpp
│   │   ├── alert_manager.hpp/.cpp
│   │   └── port_scan_detector.hpp/.cpp
│   ├── sandbox/
│   │   ├── sandbox_manager.hpp/.cpp
│   │   ├── seccomp_filter.hpp/.cpp
│   │   └── behavior_monitor.hpp/.cpp
│   └── control/
│       ├── ipc_broker.hpp/.cpp
│       ├── policy_engine.hpp/.cpp
│       ├── logger.hpp/.cpp
│       └── rest_api.hpp/.cpp
└── tests/
    ├── test_signature_engine.cpp
    ├── test_alert_manager.cpp
    ├── test_policy_engine.cpp
    ├── test_seccomp_filter.cpp
    └── pcap_samples/
```

---

## 기술 스택

| 구분 | 기술 |
|------|------|
| 언어 | C++17 |
| 패킷 캡처 | libpcap |
| syscall 필터 | libseccomp (seccomp-bpf) |
| 프로세스 격리 | Linux namespaces, ptrace |
| IPC | Unix domain socket |
| 데이터 저장 | SQLite3 |
| 빌드 | CMake |
| 테스트 | Google Test |

---

## 라이선스

MIT License
