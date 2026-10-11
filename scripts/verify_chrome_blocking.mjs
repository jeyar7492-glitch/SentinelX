/**
 * SentinelX Pre-Navigation Blocking Chrome Integration Test
 * Demonstrates and records verifiable proof that declarativeNetRequest rules
 * block malicious navigations before any network connection reaches the destination server.
 */

import { spawn } from "node:child_process";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const extPath = path.resolve(__dirname, "../extension");
const chromePath = "/opt/google/chrome/chrome";
const TEST_PORT = 9797;

let receivedRequests = [];

// 1. Mock Destination Server
const mockServer = http.createServer((req, res) => {
  const host = req.headers.host || "";
  console.log(`[MOCK SERVER] Incoming request: ${req.method} ${req.url} (Host: ${host})`);
  receivedRequests.push({ url: req.url, host });
  res.writeHead(200, { "Content-Type": "text/plain" });
  res.end("DESTINATION SERVER REACHED");
});

await new Promise((resolve) => mockServer.listen(TEST_PORT, "127.0.0.1", resolve));
console.log(`[TEST SETUP] Mock destination server active on 127.0.0.1:${TEST_PORT}`);

// 2. Spawn Chrome with CDP Pipe and Host Resolver mapping
const chromeProcess = spawn(
  chromePath,
  [
    "--headless=new",
    "--remote-debugging-pipe",
    "--enable-unsafe-extension-debugging",
    `--host-resolver-rules=MAP *.test 127.0.0.1:${TEST_PORT}`,
    "--user-data-dir=/tmp/sentinel_chrome_verify",
    "about:blank",
  ],
  {
    stdio: ["ignore", "pipe", "pipe", "pipe", "pipe"],
  }
);

let msgId = 1;
const pendingCallbacks = new Map();
let cdpBuffer = "";

function sendCdp(method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = msgId++;
    pendingCallbacks.set(id, { resolve, reject });
    const payload = JSON.stringify({ id, method, params }) + "\0";
    chromeProcess.stdio[3].write(payload);
  });
}

chromeProcess.stdio[4].on("data", (chunk) => {
  cdpBuffer += chunk.toString();
  while (true) {
    const nullIdx = cdpBuffer.indexOf("\0");
    if (nullIdx === -1) break;
    const raw = cdpBuffer.substring(0, nullIdx);
    cdpBuffer = cdpBuffer.substring(nullIdx + 1);
    try {
      const msg = JSON.parse(raw);
      if (msg.id && pendingCallbacks.has(msg.id)) {
        const { resolve } = pendingCallbacks.get(msg.id);
        pendingCallbacks.delete(msg.id);
        resolve(msg);
      }
    } catch (err) {
      console.error("CDP JSON parse error", err);
    }
  }
});

async function runVerification() {
  console.log("[TEST] Loading SentinelX unpacked extension into Chrome 154...");
  const extResult = await sendCdp("Extensions.loadUnpacked", { path: extPath });
  const extensionId = extResult.result?.id;
  console.log(`[TEST] Extension loaded into Chrome. Extension ID: ${extensionId}`);

  // Get available target page
  const targets = await sendCdp("Target.getTargets");
  const pageTarget = targets.result.targetInfos.find((t) => t.type === "page");
  const attachResult = await sendCdp("Target.attachToTarget", {
    targetId: pageTarget.targetId,
    flatten: true,
  });
  const sessionId = attachResult.result.sessionId;

  // Helper to send command to the specific page session
  function sendSession(method, params = {}) {
    return sendCdp("Target.sendMessageToTarget", {
      sessionId,
      message: JSON.stringify({ id: msgId++, method, params }),
    });
  }

  // TEST 1: Probe unblocked domain
  console.log("\n[TEST 1] Probing safe domain: http://safe-benign.test:" + TEST_PORT + "/probe");
  receivedRequests = [];
  const safeTarget = await sendCdp("Target.createTarget", { url: `http://safe-benign.test:${TEST_PORT}/probe` });
  await new Promise((r) => setTimeout(r, 1200));

  const safeCount = receivedRequests.length;
  console.log(`[TEST 1 RESULT] Destination server received ${safeCount} request(s) for safe domain.`);

  // TEST 2: Probe blocked threat domain (paypal-security-verification.test)
  console.log("\n[TEST 2] Probing blocked threat domain: http://paypal-security-verification.test:" + TEST_PORT + "/malicious-login");
  receivedRequests = [];
  const blockedTarget = await sendCdp("Target.createTarget", {
    url: `http://paypal-security-verification.test:${TEST_PORT}/malicious-login`,
  });
  await new Promise((r) => setTimeout(r, 1500));

  const blockedCount = receivedRequests.length;

  // Check final URL of the blocked target page
  const updatedTargets = await sendCdp("Target.getTargets");
  const targetInfo = updatedTargets.result.targetInfos.find((t) => t.targetId === blockedTarget.result.targetId);
  const currentUrl = targetInfo?.url || "";

  console.log("\n" + "=".repeat(70));
  console.log("  RECORDED EVIDENCE OF BROWSER PRE-NAVIGATION BLOCKING");
  console.log("=".repeat(70));
  console.log(`  Extension ID:                     ${extensionId}`);
  console.log(`  Test Threat URL:                  http://paypal-security-verification.test:${TEST_PORT}/malicious-login`);
  console.log(`  Requests Received by Mock Server: ${blockedCount} (Expected: 0)`);
  console.log(`  Final Browser Page URL:           ${currentUrl}`);
  console.log(`  Redirected to blocked.html:       ${currentUrl.includes("blocked.html")}`);
  console.log("=".repeat(70));

  // Cleanup
  chromeProcess.kill();
  mockServer.close();

  if (blockedCount === 0 && currentUrl.includes("blocked.html")) {
    console.log("\n>>> VERIFICATION SUCCESS: Chrome DeclarativeNetRequest blocked navigation before socket connect! <<<");
    process.exit(0);
  } else {
    console.error("\n>>> VERIFICATION FAILED: Request was not blocked before destination server. <<<");
    process.exit(1);
  }
}

// Timeout watchdog
setTimeout(() => {
  console.error("Test timeout after 20s");
  chromeProcess.kill();
  mockServer.close();
  process.exit(1);
}, 20000);

await runVerification();
