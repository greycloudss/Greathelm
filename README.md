# Greathelm

**Greathelm** is a modular Windows security service focused on **process inspection**, **PowerShell telemetry**, and **automated response enforcement**.
It’s built entirely in C++ and designed for minimal dependencies, direct API usage, and reliable operation in low-level environments such as service contexts.


> Work in progress: APIs and internals are evolving. Expect breaking changes across minor versions until v1.0.  
>Part of the **Armour series**  
>**No Longer Developed**  
---

## Overview

Greathelm acts as a **system service** that observes process activity and network behavior, analyzes PowerShell command streams, and applies controlled mitigations (blocking, isolation, or escalation).
The architecture emphasizes transparency — all actions are logged and correlated to the originating trigger.

Core modules include:

| Module                | Purpose                                                                                         |
| :-------------------- | :---------------------------------------------------------------------------------------------- |
| **match/powershell**  | Parses and analyzes PowerShell command streams for dangerous constructs or encoded payloads     |
| **escalate/defender** | Handles escalation logic, integrates with Windows Defender and system protection components     |
| **escalate/firewall** | Performs IP isolation and network restrictions using `netsh` and Windows Firewall APIs          |
| **utils/**            | Shared utility code for string handling, registry, address abstraction, and process interaction |

---

## Design Goals

* **No external dependencies** – only uses Win32 APIs and system libraries
* **Service-oriented** – runs as a Windows service under `LocalSystem`
* **Modular escalation** – “Defender”, “Firewall”, and “PowerShell” act independently but communicate via shared logging
* **Fail-safe behavior** – when a module encounters a fault, it logs and isolates the condition rather than halting the host process
* **User-mode only** – no kernel drivers, no injected hooks; all monitoring is done through native Windows facilities

---

## Technical Summary

| Area                  | Implementation                                                            |
| --------------------- | ------------------------------------------------------------------------- |
| **Language**          | C++20 (Win32 API only)                                                    |
| **Runtime**           | Windows 10 / 11, x64                                                      |
| **Build system**      | Manual `g++` / MinGW / Visual Studio compatible                           |
| **Privileges**        | Runs as SYSTEM service                                                    |
| **Core dependencies** | `advapi32`, `fwpuclnt`, `rpcrt4`, `ws2_32`, `wtsapi32`                    |
| **Interaction**       | ETW, PowerShell execution tracing, network restriction via firewall rules |

---

## Architecture

```
[ Windows Service Host ]
          │
          ├── [ PowerShell Monitor ]
          │       ↳ Analyzes command input and detects encoded or obfuscated scripts
          │
          ├── [ Defender Module ]
          │       ↳ Decides escalation, passes candidate IPs or processes to Firewall
          │
          ├── [ Firewall Module ]
          │       ↳ Executes isolation (netsh deny rule) and maintains block list
          │
          └── [ Utility Layer ]
                  ↳ Logging, string conversion, pair abstraction, IP address parsing
```

The service initializes each module in its own thread during startup.
Communication between modules occurs through lightweight shared objects and log correlation.

---

## Building

### Requirements

* Windows 10 or 11 SDK
* MinGW-w64 or Visual Studio (C++20)
* Administrator privileges to install services

### Example (MinGW)

```bash
g++ -std=c++20 -O2 -s -DNDEBUG -DUNICODE -D_UNICODE -D_WIN32_WINNT=0x0A00 ^
main.cpp escalate\defender.cpp escalate\firewall.cpp match\powershell\powershell.cpp ^
-o Greathelm_service.exe ^
-static -static-libstdc++ -static-libgcc ^
-Wl,-Bstatic -lwinpthread -Wl,-Bdynamic ^
-lole32 -loleaut32 -luuid -ladvapi32 -luser32 -lws2_32 -lwscapi -lwtsapi32 -ltdh -lrpcrt4
```

### Installing the service

```bash
sc create GreathelmService binPath= "C:\Path\To\Greathelm_service.exe"
sc start GreathelmService
```

---

## Logging

Greathelm logs all major actions and detections to a flat text log under:

```
C:\ProgramData\Greathelm\logs\
```

Each entry is timestamped and module-scoped, e.g.:

```
2025-10-17T22:25:33 [PowerShell] invoke-expression ...
2025-10-17T22:25:33 [Firewall] candidate: 1.1.1.1
2025-10-17T22:25:33 escalation executed
2025-10-17T22:25:33 FIREWALL addBlock called: 1.1.1.1
```

---

## Current Capabilities

* Detects PowerShell remote sessions, encoded commands, and unsafe expressions
* Isolates offending IP addresses through Windows Firewall automation
* Integrates with Windows Defender telemetry for post-detection escalation
* Designed to expand toward registry and process event correlation

---

## Planned Work

* Event Tracing (ETW) integration for process and image loads
* Registry monitoring via WMI (`RegistryValueChangeEvent`)
* the rest - on the fly

---

## Developer Notes

* The service’s threading model uses detached threads per subsystem; PowerShell inspection runs asynchronously.
* All modules are implemented in user-mode — no drivers, no undocumented kernel access.
* Exceptions are caught locally; no global structured exception filters are required.

---

## License

This project is provided for **research and educational purposes**.
No warranty is provided. Redistribution or deployment on production systems is at your own risk.

© 2025 greycloudss — All Rights Reserved.

---
