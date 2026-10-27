# SentinelX — Advanced Browser Security Platform

**SentinelX** is a local-first, zero-cost cybersecurity browser shield engineered for **Ubuntu Linux** and **Google Chrome (Manifest V3)**. It provides pre-navigation network blocking via `declarativeNetRequest`, real-time navigation evaluation, full-page glassmorphic interstitial warnings for dangerous destinations, transparent risk scoring heuristics, structured evidence tracking, and an automatically managed local FastAPI backend with user-level systemd service autostart.

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
│  │  In-Extension Engine  │             │  Glassmorphic Interstitial │  │
│  │  (local-analyzer.ts)  │             │       (blocked.html)       │  │
│  │  Sub-ms Heuristics &  │             │   Mode A: Unknown Pub (3s) │  │
│  │ Degraded Mode Offline │             │   Mode B: Warning (80-89)  │  │
│  │ Bounded Cache (100)   │             │   Mode C: Block (90+)      │  │
│  └──────────┬────────────┘             └────────────────────────────┘  │
│             │                                                          │
│             ▼                                                          │
│  ┌───────────────────────┐                                             │
│  │ Glassmorphism Dashboard│                                            │
│  │ 3-State Protection    │                                             │
│  │ Light/Dark Theming    │                                             │
│  │ Scanner • History     │                                             │
│  │ Settings & Thresholds │                                             │
│  └──────────┬────────────┘                                             │
│             │                                                          │
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
│  │    Structured evidence (Confirmed, Heuristic, Inconclusive)      │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Key Highlights & Platform Capabilities

### 1. Professional Glassmorphism Design System
- **Midnight Navy Aesthetics**: Deep dark background (`#060913` to `#0d1527`), subtle cyan (`#00d4ff`) and violet (`#a855f7`) accents, restrained blur (`backdrop-filter: blur(14px)`), and thin borders (`rgba(255, 255, 255, 0.09)`).
- **Light/Dark Theme Switching**: Full support for Dark (Midnight Navy), Light (Clean Slate), and System default with instant toggle and persistent storage.
- **3-State Global Protection Status**:
  - `Protected`: Green glow. Pre-navigation DNR active with either local engine or backend online.
  - `Limited Protection`: Amber glow. Backend offline or unverified publisher warnings disabled; local heuristic engine and DNR remain active.
  - `Protection Unavailable`: Red glow. User explicitly disabled protection in settings.
- **Responsive Layout**: Designed for seamless use both inside the compact 440px popup dropdown and in full browser tab dashboard mode (`chrome-extension://<id>/popup.html`).

### 2. Full-Page Warning & Block Interstitials (`blocked.html`)
- **Mode A: Unknown Publisher**:
  - Compact amber warning explaining that website publisher identity is unverified (not automatically malicious).
  - Displays target domain and requested URL.
  - Visible **3-second safety countdown** before enabling the explicit "Continue to Website" button.
  - Destination remains strictly blocked during the countdown; timer expiration does **NOT** automatically open the site.
  - "Return to Safety" / "Close Tab" safe action.
  - Continuing issues a tab-scoped single-use bypass; no permanent trust is granted.
- **Mode B: Suspicious Website Warning (Risk 80–89)**:
  - Prominent amber banner detailing observed suspicious signals and why they matter.
  - Distinguishes confirmed evidence from heuristic signals.
  - Return to safety primary button with controlled, delayed continue option.
- **Mode C: High-Risk Block (Risk 90+)**:
  - Crimson restrained warning with exact block reason, normalized hostname, timestamp, and rule breakdown.
  - No unrestricted bypass by default.
  - Guaranteed prevention of infinite redirect loops.

### 3. Structured Detection Results
Every triggered finding in both the Python core and the in-extension analyzer includes:
- **`evidence_type`**:
  - `confirmed`: Directly observed structural indicators (e.g. raw IP host, userinfo `@` credential spoofing, confirmed malicious signature).
  - `heuristic`: Statistically correlated patterns (e.g. brand impersonation, high-abuse TLDs, excessive subdomains, open redirect query params).
  - `inconclusive`: Contextual flags requiring user review (e.g. elevated URL length).
- **`source`**: `local_heuristic`, `reputation_list`, or `verified_signature`.
- **`confidence`**: `HIGH`, `MEDIUM`, or `LOW`.

### 4. Central Risk Policy Thresholds
| Score Range | Verdict | Action | Policy Behavior |
| :--- | :--- | :--- | :--- |
| **90 – 100** | `dangerous` | `BLOCK` | Automatic pre-navigation block via DNR and block interstitial. |
| **80 – 89** | `suspicious` | `WARN_INTERSTITIAL` | Intercepts navigation with warning interstitial and 3s countdown. |
| **30 – 79** | `suspicious` | `PROCEED_WITH_CAUTION` | Displays caution advisory in popup scanner. |
| **< 30 (Trusted)** | `safe` | `ALLOW` | Verified reputable domain (e.g. `google.com`, `github.com`). |
| **< 30 (Unverified)** | `unknown` | `PROCEED_WITH_CAUTION` | **Never assumed safe.** Flagged as unverified domain. |
| **Override** | `dangerous` | `BLOCK` | Brand impersonation / userinfo spoofing immediately triggers BLOCK. |

### 5. Advanced, Lightweight Navigation Defense
- **Single-Use Warning Transitions & Repeat Protection**: Single-use tokens in `oneTimeNavigationBypasses` map (`tabId:url` / `tabId:domain`) with 15s TTL are strictly consumed upon first use. Repeat visits, reloads, new tabs, and different paths are guaranteed to re-trigger warnings.
- **Bounded In-Memory Cache**: 100 entries max with 60s TTL; automatically purged upon settings modification or list updates.
- **Redirect Chain Tracking**: Monitored via `webNavigation.onCommitted` qualifier flags (`server_redirect`, `client_redirect`) without requiring invasive permissions.
- **Zero Cloud Calls / Privacy Guarantee**: 100% local processing; zero third-party telemetry, tracking, or cloud dependencies.

---

## 🚀 Installation & Setup

### Step 1: Install & Verify Ubuntu Systemd Service
The backend service installs into your user session without root/sudo permissions:

```bash
# Make scripts executable and install the systemd user service
./scripts/install_service.sh

# Run full system diagnostics
./scripts/diagnostics.sh
```

Service management commands:
```bash
# Check status
systemctl --user status sentinelx.service

# View live logs
journalctl --user -u sentinelx.service -f

# Restart / Stop / Start
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
4. Select the directory: `/home/child/Projects/sentinelx/extension`.
5. Pin **SentinelX** to your toolbar.

---

## 🧪 Verification & Automated Testing

### 1. Extension Test Suite (49 Tests)
Validates unknown publisher interception, 3-second countdown state machine, single-use bypass tokens, repeat visit protection, structured evidence types, bounded cache eviction, redirect tracking, and DNR compilation:
```bash
cd extension
npm test
```
*Current status: 49 passing, 0 failing.*

### 2. Backend Pytest Suite (29 Tests)
Validates FastAPI endpoints, transparent heuristic engine, central risk policy boundaries (79, 80, 89, 90, 100), origin validation, localhost restriction, and structured evidence fields (`evidence_type`, `source`, `confidence`):
```bash
.venv/bin/pytest backend/tests -v
```
*Current status: 29 passing, 0 failing.*

### 3. Real Chrome Headless Integration Test
Launches headless Google Chrome with remote debugging pipe to test real declarativeNetRequest blocking:
```bash
node scripts/verify_chrome_blocking.mjs
```
*Current status: Verified pre-navigation socket cutoff with 0 bytes transmitted to destination server.*

---

## 📋 Permissions Justification

| Permission | Justification |
| :--- | :--- |
| `declarativeNetRequest` | Pre-navigation socket-level blocking of confirmed threats before network packets leave the host. |
| `webNavigation` | Interception of top-level tab navigations to evaluate URLs and redirect unverified/unsafe destinations to `blocked.html`. |
| `storage` | Local storage of user settings, custom blocklists/allowlists, and scan history in Chrome's local storage sandbox. |
| `tabs` | Required to query the active tab's domain for on-demand scanner analysis and safe back navigation. |
| `127.0.0.1:8000/*` | Local loopback communication with the SentinelX FastAPI backend service. |

---

## 🔒 Security & Privacy Guarantees
- **100% Zero Cost**: No external subscriptions, paid threat APIs, or cloud infrastructure.
- **Zero Telemetry**: All analysis runs locally on `127.0.0.1` and inside browser memory. Browsing history is never transmitted over the internet.
- **Safe Execution**: SentinelX never executes or visits flagged URLs; analysis operates strictly on URL strings and pre-navigation metadata.
- **Honest Security Language**: Transport encryption (HTTPS) is explicitly explained as encryption in transit rather than proof of authenticity or safety. Unverified domains are never falsely assumed safe.
