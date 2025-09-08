# GreatHelm

A modular, Windows-first Endpoint Detection & Response (EDR) service focused on real‑time telemetry, practical detections, and safe response actions.

> Work in progress: APIs and internals are evolving. Expect breaking changes across minor versions until v1.0.  
>Part of the **Armour series**  

---

## WIP Features

* **Real-time telemetry** via ETW (process/thread/image/file/registry/network) and Windows Event Log (PowerShell Operational 4103/4104).
* **Detection-first engine**: rule-based patterns (e.g., suspicious PowerShell flags), behavioral sequences (write→allocate→remote thread), and simple heuristics.
* **PowerShell visibility**: ScriptBlock logging ingestion and command-line pattern matching.
* **Pluggable responses**: terminate process, isolate host (egress block), alert/forward.
* **Efficient agent**: user-mode service, low overhead.

---

**Responses**

* `terminate` — kill offending PID/tree
* `isolate` — apply local egress deny (with allowlist)
* `alert` — push event to collector or file sink

---

## Getting Started

### Prerequisites

* Windows 10/11 or Server 2019+
* Visual Studio 2022 (v143 toolset) or compatible C++20 compiler
* Windows SDK (ETW, Event Log, Service APIs)

### Build

```bash
git clone https://github.com/greycloudss/greathelm.git
cd Greathelm
# Open solution in Visual Studio or build via MSBuild/CMake as configured
```

---

## License

MIT — see [LICENSE](LICENSE).
