# SentinelX — Pre-Navigation Web Security Architecture

**SentinelX** is a zero-cost, local-only web security and privacy protection platform for Ubuntu Linux and Google Chrome (Manifest V3).

Unlike conventional extensions that merely warn you *after* a page has already begun loading or rely on slow cloud API lookups, SentinelX features **pre-navigation blocking** powered by Chrome's native `declarativeNetRequest` (DNR) engine. Confirmed high-confidence threats are intercepted and redirected to a safe, extension-owned blocked page **before your browser establishes a TCP socket connection or sends any HTTP request** to the destination server.

---

## 1. Core Architecture & Protection Layers

```
                                  [ Browser Navigation Event ]
                                                │
                                                ▼
                         ┌─────────────────────────────────────────────┐
                         │  Chrome declarativeNetRequest (DNR) Engine   │
                         │      (Synchronous Pre-Navigation Stack)     │
                         └──────────────────────┬──────────────────────┘
                                                │
                       ┌────────────────────────┴────────────────────────┐
                       │                                                 │
               [ Matches Block Rule ]                            [ No Match / Allowed ]
                       │                                                 │
                       ▼                                                 ▼
        ┌──────────────────────────────┐                  ┌──────────────────────────────┐
        │  Safe Block Interstitial     │                  │  Destination Server Network  │
        │  (chrome-extension://.../    │                  │  (Connection & Page Load)    │
        │   blocked.html)              │                  └──────────────┬───────────────┘
        │                              │                                 │
        │ • Explains matched indicator │                                 ▼
        │ • Zero remote scripts / CSP  │                  ┌──────────────────────────────┐
        │ • Anti-open-redirect guard   │                  │  SentinelX Popup & Backend   │
        │ • Controlled allowlist add   │                  │  (Asynchronous Heuristics)   │
        └──────────────────────────────┘                  │ • Transparent explainable ML │
                                                          │ • Bound to 127.0.0.1:8000    │
                                                          │ • Zero telemetry / logs      │
                                                          └──────────────────────────────┘
```

### Synchronous Pre-Navigation Blocking vs. Asynchronous Analysis
1. **Pre-Navigation Enforcement (DeclarativeNetRequest)**:
   - Synchronous and instantaneous.
   - Evaluated by Chrome's core networking stack prior to DNS resolution, TLS handshake, or HTTP request transmission.
   - Uses preinstalled static rules (`rules/rules.json`) and locally compiled dynamic rules (`chrome.declarativeNetRequest.updateDynamicRules`).
   - Destination server receives **0 packets / 0 requests** when a block occurs.
2. **Asynchronous Local Heuristic Analysis (FastAPI Backend)**:
   - Deep structural, lexical, and behavioral evaluation of target URLs.
   - Runs exclusively on `127.0.0.1:8000` with transparent scoring (0–100) and clear explanations.
   - Does **not** claim to block a navigation that has already started; instead, when new high-confidence evidence is verified, the user or engine can promote the indicator into browser dynamic rules for all subsequent navigations.

---

## 2. Protection Modes

SentinelX provides three distinct operating modes configured in the extension settings:

| Mode | Behavior | Use Case |
| :--- | :--- | :--- |
| **Standard** *(Default)* | Blocks confirmed high-confidence indicators; warns about suspicious URLs in the popup. | Everyday secure browsing with zero workflow disruption. |
| **Strict Allowlist** | Blocks all web navigations *except* explicitly approved domains on the allowlist. | High-security environments, kiosk setups, or locked-down workstations. *(May disrupt normal browsing).* |
| **Protection Disabled** | Bypasses all DNR rules and navigation blocking; displays prominent disabled badge. | Temporary troubleshooting or uninhibited access. |

> **Safety Guarantee**: SentinelX defaults to **Standard** mode and will never silently activate Strict Allowlist mode without explicit user selection.

---

## 3. Local Threat Rule Manager & Boundary Safety

### Strict Boundary Matching
Naive substring matching causes disastrous false positives (e.g., blocking `bad.com` must never block `notbad.com` or `mybad.company.org`). SentinelX enforces strict domain boundary syntax:
```
||malicious-domain.test^
```
- The leading `||` anchors the rule to the start of the hostname or any subdomain.
- The trailing `^` delimiter matches domain boundaries (port separators `:`, path separators `/`, query separators `?`, or the end of the string).

### Normalization Pipeline
All input indicators pass through `normalizeDomain()`:
- Strips protocol schemes (`http://`, `https://`).
- Strips ports (`:8080`, `:9797`), paths (`/login`), and query strings.
- Strips userinfo credentials (`user:pass@`).
- Converts internationalized domain names (IDN) to ASCII Punycode (`xn--...`).
- Validates syntax to reject wildcards, spaces, empty strings, and malformed characters.

### Safeguard Whitelist
To prevent self-bricking, the engine protects system destinations from accidental blocks:
- `localhost`, `127.0.0.1`, `::1`
- `chrome`, `chrome-extension`, `about`, `edge`

---

## 4. Blocked-Page Interstitial (`blocked.html`)

When a navigation is blocked, Chrome immediately redirects the tab to SentinelX's local, extension-owned interstitial:
- **No Remote Network Access**: The blocked destination server is never contacted.
- **Strict Content Security Policy (CSP)**: `blocked.html` contains no inline scripts or remote resources; only bundled, local CSS and TypeScript execute.
- **Transparent Indicator Breakdown**: Details the blocked hostname, matched indicator, and the active protection mode.
- **Anti-Open-Redirect Security**: URL parameters (`url`, `threat`, `mode`) are strictly sanitized. `javascript:`, `data:`, or malformed redirect targets are completely rejected.
- **False-Positive Override**: Users can review false positives and add the domain to the local allowlist with explicit user consent. Websites cannot tamper with or bypass their own rules.

---

## 5. Repository Structure

```
sentinelx/
├── .gitignore                      # Excludes venvs, node_modules, build caches
├── pytest.ini                      # Pytest runner configuration
├── README.md                       # Comprehensive documentation
├── backend/                        # Local Python FastAPI Security Engine
│   ├── run.py                      # Local runner bound strictly to 127.0.0.1:8000
│   ├── requirements.txt            # Python dependencies
│   ├── app/
│   │   ├── main.py                 # FastAPI application & localhost enforcement
│   │   ├── models.py               # Pydantic schemas
│   │   ├── analyzer.py             # Heuristic scoring engine (0-100 risk score)
│   │   └── rules.py                # Brand dictionaries & known malicious patterns
│   └── tests/
│       └── test_analyzer.py        # 16 automated backend tests
├── extension/                      # Chrome Manifest V3 Extension
│   ├── manifest.json               # MV3 manifest with declarativeNetRequest
│   ├── package.json                # TypeScript & testing dependencies
│   ├── tsconfig.json               # Strict TypeScript config
│   ├── popup.html / popup.css      # Dual-tab UI (URL Scanner & Rules Manager)
│   ├── blocked.html / blocked.css  # Safe interstitial block page
│   ├── icons/                      # Extension icons (16x16, 48x48, 128x128)
│   ├── rules/
│   │   └── rules.json              # Seeded static DNR ruleset
│   ├── src/
│   │   ├── types.ts                # TypeScript data models
│   │   ├── threat-manager.ts       # Domain normalization, validation, DNR compiler
│   │   ├── background.ts           # Service worker & dynamic rule synchronizer
│   │   ├── popup.ts                # Scanner UI & rules configuration controller
│   │   ├── blocked.ts              # Interstitial controller & allowlist handler
│   │   └── utils.ts                # HTML sanitization & URL validation
│   ├── dist/                       # Compiled JavaScript bundle
│   └── tests/
│       ├── threat-manager.test.mjs # Domain normalization & DNR compiler unit tests
│       └── integration-lifecycle.test.mjs # Rule persistence, restart, allowlist tests
└── scripts/
    ├── generate_icons.py           # PNG icon generator
    └── verify_chrome_blocking.mjs  # Live Chrome 154 CDP pre-navigation verification
```

---

## 6. Installation & Setup

### Prerequisites (Ubuntu Linux)
- Python 3.10+
- Node.js 18+ and npm
- Google Chrome

### Step 1: Start the Local Security Backend
```bash
# 1. Activate the local virtual environment
source .venv/bin/activate

# 2. Run the FastAPI server
python backend/run.py
```
*The backend binds exclusively to `127.0.0.1:8000`. No external connections are accepted.*

### Step 2: Build the Chrome Extension
```bash
cd extension
npm run build
```

### Step 3: Load into Google Chrome
Due to Chrome security restrictions introduced in Chrome 137+ (`--load-extension is not allowed in Google Chrome`), unpacked extensions are loaded via the browser interface:
1. Open Google Chrome and enter `chrome://extensions/` in the address bar.
2. Toggle on **Developer mode** in the top-right corner.
3. Click the **Load unpacked** button.
4. Select the `extension` directory:
   ```
   /home/child/Projects/sentinelx/extension
   ```
5. SentinelX is now installed and actively enforcing pre-navigation blocking.

---

## 7. Automated Testing & Verification

### 1. Live Browser Pre-Navigation Verification
SentinelX includes an automated integration test that boots Google Chrome using Chrome DevTools Protocol (`--remote-debugging-pipe`), loads the unpacked extension, starts an isolated mock HTTP server, and attempts navigation to a blocked indicator:

```bash
node scripts/verify_chrome_blocking.mjs
```

**Recorded Verification Output:**
```
[TEST SETUP] Mock destination server active on 127.0.0.1:9797
[TEST] Loading SentinelX unpacked extension into Chrome 154...
[TEST] Extension loaded into Chrome. Extension ID: ciiifckfnjkgjjpjgooeiekgjlmbnbkl

[TEST 1] Probing safe domain: http://safe-benign.test:9797/probe
[MOCK SERVER] Incoming request: GET /probe (Host: safe-benign.test:9797)
[MOCK SERVER] Incoming request: GET /favicon.ico (Host: safe-benign.test:9797)
[TEST 1 RESULT] Destination server received 2 request(s) for safe domain.

[TEST 2] Probing blocked threat domain: http://paypal-security-verification.test:9797/malicious-login

======================================================================
  RECORDED EVIDENCE OF BROWSER PRE-NAVIGATION BLOCKING
======================================================================
  Extension ID:                     ciiifckfnjkgjjpjgooeiekgjlmbnbkl
  Test Threat URL:                  http://paypal-security-verification.test:9797/malicious-login
  Requests Received by Mock Server: 0 (Expected: 0)
  Final Browser Page URL:           chrome-extension://ciiifckfnjkgjjpjgooeiekgjlmbnbkl/blocked.html
  Redirected to blocked.html:       true
======================================================================

>>> VERIFICATION SUCCESS: Chrome DeclarativeNetRequest blocked navigation before socket connect! <<<
```

### 2. Extension Unit & Integration Lifecycle Tests
Verify dynamic rule persistence, browser restart simulation, boundary matching, allowlist precedence, and open-redirect protections:
```bash
cd extension
npm test
```
*Passes all 18 test specifications.*

### 3. Backend Heuristic & API Tests
Verify URL scoring, brand spoof detection, IDN homoglyphs, and localhost loopback isolation:
```bash
.venv/bin/pytest -v
```
*Passes all 16 test specifications.*

---

## 8. Honest Security Disclaimers & Technical Limitations

1. **Lack of Evidence is Not Proof of Safety**: A low risk score indicates that no known threat patterns were identified; it is not a certificate of safety.
2. **No 100% Malware Immunity**: Attackers continually craft novel techniques. SentinelX provides explainable heuristic signals and synchronous rule-based blocks, not an impenetrable barrier.
3. **Strict Allowlist Disruptions**: In Strict Allowlist mode, external dependencies (CDNs, OAuth providers, fonts) on unapproved domains will be blocked. Use this mode deliberately.
4. **HTTPS Encryption vs. Authenticity**: Transport Layer Security (HTTPS) proves only that the connection is encrypted, not that the recipient is trustworthy.
5. **Completely Local & Zero Cost**: SentinelX does not communicate with external intelligence feeds or cloud servers. All dynamic rules are managed and persisted on your local machine.
