# SentinelX — Real-Time Browser Security Shield & Threat Blocker

**SentinelX** is a local-first, zero-cost cybersecurity browser shield engineered for **Ubuntu Linux** and **Google Chrome (Manifest V3)**. It provides pre-navigation network blocking via `declarativeNetRequest`, real-time navigation evaluation, full-page interstitial warnings for dangerous destinations, transparent risk scoring heuristics, and an automatically managed local FastAPI backend with user-level systemd service autostart.

---

## 🛡️ Architecture & Core Components

```
┌────────────────────────────────────────────────────────────────────────┐
│                        GOOGLE CHROME BROWSER                           │
│                                                                        │
│  ┌───────────────────────┐             ┌────────────────────────────┐  │
│  │   Chrome Manifest V3  │             │   declarativeNetRequest    │  │
│  │    Service Worker     │             │    Pre-Navigation Rules    │  │
│  │   (background.js)     │◄───────────►│    (Intercepts Sockets)    │  │
│  └──────────┬────────────┘             └─────────────┬──────────────┘  │
│             │                                        │                 │
│             ▼                                        ▼                 │
│  ┌───────────────────────┐             ┌────────────────────────────┐  │
│  │  In-Extension Engine  │             │   Full-Page Interstitial   │  │
│  │  (local-analyzer.ts)  │             │       (blocked.html)       │  │
│  │  Sub-ms Heuristics &  │             │   Dual Mode: BLOCK / WARN  │  │
│  │ Degraded Mode Offline │             │   Controlled Override      │  │
│  └──────────┬────────────┘             └────────────────────────────┘  │
│             │                                                          │
│             ▼                                                          │
│  ┌───────────────────────┐                                             │
│  │  Popup Cyber Dashboard│                                             │
│  │   Scanner • History   │                                             │
│  │     Settings Tab      │                                             │
│  └──────────┬────────────┘                                             │
└─────────────┼──────────────────────────────────────────────────────────┘
              │ HTTP (Local Loopback 127.0.0.1:8000 only)
              ▼
┌────────────────────────────────────────────────────────────────────────┐
│                         UBUNTU HOST SYSTEM                             │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                 Ubuntu Systemd User Service                      │  │
│  │                    (sentinelx.service)                           │  │
│  │   • Automatic start at user login                                │  │
│  │   • Auto-restart within 3s on crashes (Restart=on-failure)       │  │
│  │   • Logs routed to journalctl --user                             │  │
│  └──────────────────────────────────┬───────────────────────────────┘  │
│                                     │                                  │
│                                     ▼                                  │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                 FastAPI Local Core Backend                       │  │
│  │            Bound exclusively to 127.0.0.1:8000                   │  │
│  │    Strict Localhost restriction & Chrome Extension Origin Guard  │  │
│  │    Deep URL structure, IDN, brand spoofing & protocol analysis   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Key Highlights & Critical Upgrades

### 1. Zero Manual Backend Startup (Ubuntu Systemd User Service)
- **Eliminates manual terminal runs**: No need to run `.venv/bin/python backend/run.py` manually.
- **Systemd User Unit**: Installed in `~/.config/systemd/user/sentinelx.service`.
- **Automatic autostart**: Launches upon login (`default.target`).
- **Crash Recovery**: `Restart=on-failure` automatically restarts the process in 3 seconds if terminated.
- **Diagnostic Tool**: Includes `./scripts/diagnostics.sh` to verify Python venv, service state, loopback binding, API health, and extension artifacts.

### 2. Browser-Wide Navigation Protection (Manifest V3)
- **Real-Time Evaluation**: Monitors top-level navigations (`chrome.webNavigation.onBeforeNavigate`).
- **Pre-Navigation Socket Cutoff**: Automatically compiles high-confidence threats into `chrome.declarativeNetRequest` dynamic rules to abort connections before packets leave the machine.
- **In-Extension Heuristic Engine (`local-analyzer.ts`)**: Evaluates navigations in under 0.2ms using transparent rules without latency.
- **Loopback & Sandbox Safeguards**: Restricted system schemes (`chrome://`, `about:`, `file:`, `chrome-extension://`) and developer loopback interfaces (`127.0.0.1`, `localhost`) are preserved.

### 3. Full-Page Warning & Block Interstitial (`blocked.html`)
- Displays requested URL, target hostname, risk score, verdict, and specific detection reasons.
- **Dual Enforcement Modes**:
  - **BLOCK (Score 90–100 or Confirmed Threat)**: Aborts connection immediately; proceed action disabled; includes accordion override with explicit risk acknowledgement for false positives.
  - **WARN_INTERSTITIAL (Score 80–89)**: Displays prominent amber warning with "Back to Safety" and a controlled "Proceed to Website" action.
- **Strict Single-Use Transition Tokens & Repeat Protection**: Proceeding from a warning issues a strict single-use navigation token (`ALLOW_SESSION_BYPASS`) scoped only to that immediate tab transition. Warnings are never permanently suppressed: repeat visits, page reloads, new tabs, and different paths are guaranteed to re-trigger the security warning.

### 4. Central Risk Policy & Degraded Mode Resilience
| Score Range | Verdict | Action | Policy Behavior |
| :--- | :--- | :--- | :--- |
| **90 – 100** | `dangerous` | `BLOCK` | Automatic pre-navigation block via DNR and interstitial. |
| **80 – 89** | `suspicious` | `WARN_INTERSTITIAL` | Intercepts navigation with prominent warning interstitial. |
| **30 – 79** | `suspicious` | `PROCEED_WITH_CAUTION` | Displays caution advisory in popup scanner. |
| **< 30 (Trusted)** | `safe` | `ALLOW` | Verified reputable domain (e.g. `google.com`, `github.com`). |
| **< 30 (Unverified)** | `unknown` | `PROCEED_WITH_CAUTION` | **Never falsely assumed safe.** Flagged as unverified domain. |
| **Override** | `dangerous` | `BLOCK` | Brand impersonation / userinfo spoofing immediately triggers BLOCK. |

- **Offline Degraded Mode**: If the local backend is offline, the extension automatically falls back to `evaluateUrlLocally`, displays `DEGRADED (Backend Offline - In-Browser Local Heuristics)`, keeps declarativeNetRequest active, and **never marks unverified sites safe**.

### 5. Cyber Dashboard UI
- **Dark Theme**: Deep navy background (`#070b14`), electric blue accents (`#00d4ff`), emerald safe (`#10b981`), amber warning (`#f59e0b`), and crimson block (`#ef4444`).
- **Multi-Tab Architecture**:
  - **Scanner**: One-click active tab scanning, manual URL input, animated risk gauge, structured flags, and protocol explainers.
  - **History**: Local session history with quick re-scan capabilities.
  - **Settings**: Toggle between *Standard*, *Strict Allowlist*, and *Disabled* modes, adjust threshold numbers, manage custom blocklists/allowlists, and run live backend test pings.

---

## 🚀 Quick Start & Installation

### Step 1: Install & Verify Ubuntu Systemd Service
The backend service installs into your user session without root/sudo permissions:

```bash
# Make scripts executable and install the systemd user service
./scripts/install_service.sh

# Run full system diagnostics
./scripts/diagnostics.sh
```

To manage the service directly:
```bash
# Check status
systemctl --user status sentinelx.service

# View live logs
journalctl --user -u sentinelx.service -f

# Stop / Start / Restart
systemctl --user stop sentinelx.service
systemctl --user start sentinelx.service
systemctl --user restart sentinelx.service
```

### Step 2: Build the Chrome Extension
```bash
cd extension
npm install
npm run build
```

### Step 3: Load the Extension into Google Chrome
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Toggle **Developer mode** on (top-right switch).
3. Click **Load unpacked** (top-left button).
4. Select the directory: `~/Projects/sentinelx/extension`.
5. Pin **SentinelX** to your toolbar.

---

## 🧪 Verification & Automated Testing

### 1. Backend Pytest Suite (26 Tests)
Validates model validation, analyzer penalties, risk thresholds, loopback binding restriction, and extension origin authorization:
```bash
.venv/bin/pytest -v
```

### 2. Extension TypeScript Unit Tests (28 Tests)
Validates domain normalization, boundary matching, DNR compilation, in-extension heuristic analysis, and open-redirect sanitization:
```bash
cd extension && npm test
```

### 3. Chrome Headless Integration Test (Verifiable Proof)
Launches headless Google Chrome with remote debugging pipe to test real declarativeNetRequest blocking:
```bash
node scripts/verify_chrome_blocking.mjs
```

---

## 🔒 Security & Privacy Guarantees
- **100% Zero Cost**: No external subscriptions, paid threat APIs, or cloud infrastructure.
- **Zero Telemetry**: All analysis runs locally on `127.0.0.1` and inside browser memory. Browsing history is never transmitted over the internet.
- **Safe Execution**: SentinelX never executes or visits flagged URLs; analysis operates strictly on URL strings and pre-navigation metadata.
