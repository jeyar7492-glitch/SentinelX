import { spawn } from "node:child_process";
import fs from "node:fs";

// Test if Chrome starts with --remote-debugging-pipe and accepts CDP
const chromePath = "/opt/google/chrome/chrome";
const extPath = "/home/child/Projects/sentinelx/extension";

// Open pipes: stdin(0), stdout(1), stderr(2), pipeRead(3), pipeWrite(4)
const proc = spawn(chromePath, [
  "--headless=new",
  "--remote-debugging-pipe",
  "--enable-unsafe-extension-debugging",
  "--user-data-dir=/tmp/sentinel_cdp_test",
  "about:blank"
], {
  stdio: ["ignore", "pipe", "pipe", "pipe", "pipe"]
});

let msgId = 1;
function sendCommand(method, params = {}) {
  const msg = JSON.stringify({ id: msgId++, method, params }) + "\0";
  proc.stdio[3].write(msg);
}

let buffer = "";
proc.stdio[4].on("data", (chunk) => {
  buffer += chunk.toString();
  const nullIdx = buffer.indexOf("\0");
  if (nullIdx !== -1) {
    const raw = buffer.substring(0, nullIdx);
    buffer = buffer.substring(nullIdx + 1);
    try {
      const parsed = JSON.parse(raw);
      console.log("[CDP RECEIVED]", parsed);
      if (parsed.id === 1) {
        console.log("[CDP] Extension loaded successfully! ID:", parsed.result?.id);
        proc.kill();
        process.exit(0);
      }
    } catch (e) {
      console.error("Parse error", e);
    }
  }
});

proc.stderr.on("data", (d) => {
  // console.log("[CHROME STDERR]", d.toString());
});

setTimeout(() => {
  console.log("[CDP SENDING] Extensions.loadUnpacked");
  sendCommand("Extensions.loadUnpacked", { path: extPath });
}, 500);

setTimeout(() => {
  console.log("Timeout");
  proc.kill();
  process.exit(1);
}, 5000);
