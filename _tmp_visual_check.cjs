const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");

const root = process.cwd();
const edgePath = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const debugPort = 9223;
const userDataDir = path.join(os.tmpdir(), `productiv-edge-check-${Date.now()}`);
const baseUrl = "http://127.0.0.1:4173/";

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForJson(url, tries = 60) {
  let lastError = null;
  for (let i = 0; i < tries; i += 1) {
    try {
      const response = await fetch(url);
      if (response.ok) return await response.json();
    } catch (error) {
      lastError = error;
    }
    await wait(200);
  }
  throw lastError || new Error(`No response from ${url}`);
}

function connect(wsUrl) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl);
    let nextId = 0;
    const pending = new Map();

    ws.addEventListener("open", () => {
      resolve({
        send(method, params = {}) {
          const id = ++nextId;
          ws.send(JSON.stringify({ id, method, params }));
          return new Promise((res, rej) => {
            pending.set(id, { res, rej });
          });
        },
        event(method) {
          return new Promise((res) => {
            const listener = (message) => {
              const data = JSON.parse(message.data);
              if (data.method !== method) return;
              ws.removeEventListener("message", listener);
              res(data.params || {});
            };
            ws.addEventListener("message", listener);
          });
        },
        close() {
          ws.close();
        },
      });
    });

    ws.addEventListener("message", (message) => {
      const data = JSON.parse(message.data);
      if (!data.id || !pending.has(data.id)) return;
      const entry = pending.get(data.id);
      pending.delete(data.id);
      if (data.error) entry.rej(new Error(data.error.message));
      else entry.res(data.result || {});
    });
    ws.addEventListener("error", reject);
  });
}

function prepareUiExpression(showPanel = "") {
  return `(() => {
    document.body.classList.add("is-authenticated", "is-app-ready");
    document.body.classList.toggle("is-mobile-layout", innerWidth <= 760);
    for (const id of ["appBrand", "modes", "timeframes", "viewTypes", "candleTimeframes", "commentControls", "tasksTab", "soundsTab", "dataControls", "authPanel", "levelsPanel", "mobileToolbar"]) {
      document.getElementById(id)?.classList.remove("hidden");
    }
    document.getElementById("mobileToolbar")?.querySelectorAll("button").forEach((button) => { button.hidden = false; });
    if (${JSON.stringify(showPanel)}) {
      document.querySelector(\`[data-mobile-open="${showPanel}"]\`)?.click();
    }
    const rect = (selector) => {
      const element = document.querySelector(selector);
      if (!element) return null;
      const r = element.getBoundingClientRect();
      return { left: r.left, top: r.top, right: r.right, bottom: r.bottom, width: r.width, height: r.height };
    };
    const overlaps = (a, b) => !!a && !!b && !(a.right <= b.left || b.right <= a.left || a.bottom <= b.top || b.bottom <= a.top);
    const toolbar = rect(".mobile-toolbar");
    const hint = rect(".hint");
    const stats = rect(".stats");
    const clock = rect(".clock");
    const openPanel = rect(".mobile-open");
    const brand = rect(".app-brand");
    return {
      viewport: { width: innerWidth, height: innerHeight },
      toolbar,
      hint,
      stats,
      clock,
      openPanel,
      brand,
      overlaps: {
        toolbarHint: overlaps(toolbar, hint),
        toolbarPanel: overlaps(toolbar, openPanel),
        statsClock: overlaps(stats, clock),
        brandStats: overlaps(brand, stats)
      }
    };
  })()`;
}

async function screenshot(client, name, width, height, mobile, showPanel = "") {
  await client.send("Emulation.setDeviceMetricsOverride", {
    width,
    height,
    deviceScaleFactor: 1,
    mobile,
    screenWidth: width,
    screenHeight: height,
  });
  const loaded = client.event("Page.loadEventFired");
  await client.send("Page.navigate", { url: baseUrl });
  await loaded;
  await wait(500);
  const evaluation = await client.send("Runtime.evaluate", {
    expression: prepareUiExpression(showPanel),
    returnByValue: true,
    awaitPromise: true,
  });
  const shot = await client.send("Page.captureScreenshot", { format: "png", captureBeyondViewport: false });
  fs.writeFileSync(path.join(root, name), Buffer.from(shot.data, "base64"));
  return evaluation.result.value;
}

(async () => {
  const browser = spawn(edgePath, [
    "--headless=new",
    "--disable-gpu",
    "--no-first-run",
    "--no-default-browser-check",
    `--remote-debugging-port=${debugPort}`,
    `--user-data-dir=${userDataDir}`,
    "about:blank",
  ], { stdio: "ignore" });

  try {
    await waitForJson(`http://127.0.0.1:${debugPort}/json/version`);
    const targets = await waitForJson(`http://127.0.0.1:${debugPort}/json`);
    const pageTarget = targets.find((target) => target.type === "page") || targets[0];
    const client = await connect(pageTarget.webSocketDebuggerUrl);
    await client.send("Page.enable");
    await client.send("Runtime.enable");

    const results = {
      desktop: await screenshot(client, "_check_desktop.png", 1366, 768, false),
      mobile: await screenshot(client, "_check_mobile.png", 390, 844, true),
      mobilePanel: await screenshot(client, "_check_mobile_panel.png", 390, 844, true, "modes"),
    };
    fs.writeFileSync(path.join(root, "_check_results.json"), JSON.stringify(results, null, 2));
    client.close();
  } finally {
    browser.kill();
    await wait(500);
    try {
      fs.rmSync(userDataDir, { recursive: true, force: true });
    } catch {
      // Edge can keep cache files locked for a moment; screenshots and metrics are already written.
    }
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
