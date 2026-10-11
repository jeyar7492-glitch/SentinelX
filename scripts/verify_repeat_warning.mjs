/**
 * SentinelX Real Browser Repeat-Warning Verification Script
 * Validates in actual Google Chrome (via CDP) that:
 * 1. Visit 1 to an unsafe URL displays the warning interstitial.
 * 2. Visit 2 to the exact same URL displays the warning interstitial again.
 * 3. A new tab visiting the unsafe URL displays the warning interstitial.
 */

import { spawn } from "node:child_process";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const extPath = path.resolve(__dirname, "../extension");
const chromePath = "/opt/google/chrome/chrome";
const TEST_PORT = 9798;

let receivedRequests = [];

// Mock destination HTTP server
const mockServer = http.createServer((req, res) => {
  const host = req.headers.host || "";
  console.log(`[MOCK SERVER :${TEST_PORT}] Request received: ${req.method} ${req.url} (Host: ${host})`);
  receivedRequests.push({ url: req.url, host });
  res.writeHead(200, { "Content-Type": "text/html" });
  res.end("<html><body>Unsafe Target Reached</body></html>");
});

await new Promise((resolve) => mockServer.listen(TEST_PORT, "127.0.0.1", resolve));
console.log(`[TEST SETUP] Mock destination server listening on 127.0.0.1:${TEST_PORT}`);

const chromeProcess = spawn(
  chromePath,
  [
    "--headless=new",
    "--remote-debugging-pipe",
    "--enable-unsafe-extension-debugging",
    `--host-resolver-rules=MAP *.test 127.0.0.1:${TEST_PORT}`,
    "--user-data-dir=/tmp/sentinel_chrome_repeat_verify",
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

async function run() {
  try {
    console.log("[TEST] Loading SentinelX unpacked extension into Google Chrome...");
    const extResult = await sendCdp("Extensions.loadUnpacked", { path: extPath });
    const extensionId = extResult.result?.id;
    console.log(`[TEST] Extension loaded. Extension ID: ${extensionId}`);

    // Unsafe test URL with elevated risk score exactly 85 (insecure HTTP + non-standard port + sensitive path + length)
    const testUnsafeUrl = `http://auth-portal.test:${TEST_PORT}/verify-login?session=${"x".repeat(90)}`;

    // TEST 1: First visit to simulated unsafe URL
    console.log(`\n[STEP 1] First visit to unsafe URL: ${testUnsafeUrl}`);
    const target1 = await sendCdp("Target.createTarget", { url: testUnsafeUrl });
    await new Promise((r) => setTimeout(r, 1500));

    let targets = await sendCdp("Target.getTargets");
    let info1 = targets.result.targetInfos.find((t) => t.targetId === target1.result.targetId);
    let url1 = info1?.url || "";
    console.log(`[STEP 1 RESULT] Final URL: ${url1}`);
    const isWarning1 = url1.includes("blocked.html") && url1.includes("type=warning");
    console.log(`[STEP 1 VERIFIED] Intercepted with Warning on first visit: ${isWarning1}`);

    // TEST 2: Second visit to exact same unsafe URL in a new tab
    console.log(`\n[STEP 2] Second visit to exact same unsafe URL (repeat visit in new tab)...`);
    const target2 = await sendCdp("Target.createTarget", { url: testUnsafeUrl });
    await new Promise((r) => setTimeout(r, 1500));

    targets = await sendCdp("Target.getTargets");
    let info2 = targets.result.targetInfos.find((t) => t.targetId === target2.result.targetId);
    let url2 = info2?.url || "";
    console.log(`[STEP 2 RESULT] Final URL: ${url2}`);
    const isWarning2 = url2.includes("blocked.html") && url2.includes("type=warning");
    console.log(`[STEP 2 VERIFIED] Intercepted with Warning on repeat visit: ${isWarning2}`);

    // TEST 3: Visiting another unsafe path on the same domain
    const otherPathUrl = `http://auth-portal.test:${TEST_PORT}/reset-password?token=${"y".repeat(90)}`;
    console.log(`\n[STEP 3] Visiting another unsafe path on the same domain: ${otherPathUrl}`);
    const target3 = await sendCdp("Target.createTarget", { url: otherPathUrl });
    await new Promise((r) => setTimeout(r, 1500));

    targets = await sendCdp("Target.getTargets");
    let info3 = targets.result.targetInfos.find((t) => t.targetId === target3.result.targetId);
    let url3 = info3?.url || "";
    console.log(`[STEP 3 RESULT] Final URL: ${url3}`);
    const isWarning3 = url3.includes("blocked.html") && url3.includes("type=warning");
    console.log(`[STEP 3 VERIFIED] Intercepted with Warning on separate path: ${isWarning3}`);

    console.log("\n" + "=".repeat(70));
    console.log("  REAL GOOGLE CHROME VERIFICATION: REPEAT WARNING INTERCEPTION");
    console.log("=".repeat(70));
    console.log(`  Extension ID:                     ${extensionId}`);
    console.log(`  Step 1 (First Visit Intercepted): ${isWarning1}`);
    console.log(`  Step 2 (Repeat Visit Intercepted):${isWarning2}`);
    console.log(`  Step 3 (Other Path Intercepted):  ${isWarning3}`);
    console.log("======================================================================");

    if (isWarning1 && isWarning2 && isWarning3) {
      console.log("\n>>> SUCCESS: Real Google Chrome verified repeat warnings appear reliably! <<<");
    } else {
      console.error("\n>>> FAILURE: Repeat warning failed in Google Chrome! <<<");
      process.exitCode = 1;
    }
  } finally {
    mockServer.close();
    chromeProcess.kill();
  }
}

run();
