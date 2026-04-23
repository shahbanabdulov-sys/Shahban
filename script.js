const canvas = document.getElementById("scene");
const ctx = canvas.getContext("2d");
const valueYNode = document.getElementById("valueY");
const deltaYNode = document.getElementById("deltaY");
const clockNode = document.getElementById("clock");
const timeframeNode = document.getElementById("timeframes");
const viewTypesNode = document.getElementById("viewTypes");
const candleTimeframesNode = document.getElementById("candleTimeframes");
const commentControlsNode = document.getElementById("commentControls");
const addCommentBtn = document.getElementById("addCommentBtn");
const toggleCommentsBtn = document.getElementById("toggleCommentsBtn");
const modesNode = document.getElementById("modes");
const hintNode = document.querySelector(".hint");
const exportBtn = document.getElementById("exportBtn");
const importBtn = document.getElementById("importBtn");
const importInput = document.getElementById("importInput");
const dataControlsNode = document.getElementById("dataControls") || document.querySelector(".data-controls");
const shareLinkNode = document.getElementById("shareLink");
const authPanelNode = document.getElementById("authPanel");
const levelsPanelNode = document.getElementById("levelsPanel");
const pointsValueNode = document.getElementById("pointsValue");
const levelNameNode = document.getElementById("levelName");
const levelProgressBarNode = document.getElementById("levelProgressBar");
const nextLevelHintNode = document.getElementById("nextLevelHint");
const levelNameInput = document.getElementById("levelNameInput");
const levelPointsInput = document.getElementById("levelPointsInput");
const addLevelBtn = document.getElementById("addLevelBtn");
const levelsListNode = document.getElementById("levelsList");
const candleCommentModalNode = document.getElementById("candleCommentModal");
const candleCommentMetaNode = document.getElementById("candleCommentMeta");
const candleCommentTextNode = document.getElementById("candleCommentText");
const candleCommentSaveBtn = document.getElementById("candleCommentSaveBtn");
const candleCommentDeleteBtn = document.getElementById("candleCommentDeleteBtn");
const candleCommentCancelBtn = document.getElementById("candleCommentCancelBtn");
const authUsernameInput = document.getElementById("authUsername");
const authPasswordInput = document.getElementById("authPassword");
const registerBtn = document.getElementById("registerBtn");
const loginBtn = document.getElementById("loginBtn");
const logoutBtn = document.getElementById("logoutBtn");
const authStatus = document.getElementById("authStatus");
const mobileToolbarNode = document.getElementById("mobileToolbar");
const mobileOverlayNode = document.getElementById("mobileOverlay");

let width = 0;
let height = 0;
let lastTime = performance.now();
let isMouseDown = false;
let pendingVerticalDelta = 0;
let lastMouseY = 0;
let pointerDownX = 0;
let pointerDownY = 0;
let pointerDidDrag = false;
let currentValue = 0;
let previousValue = 0;
let currentX = 0;

const speedX = 60;
const livePoints = [];
const liveTailLength = 2000;
const gridStepPx = 60;
const valueStepPerGrid = 10;

const pointIntervalMs = 60;
const maxHistoryMs = 32 * 24 * 60 * 60 * 1000;
const history = [];
let lastPointAt = 0;

const rangeMap = {
  "1h": 60 * 60 * 1000,
  "1d": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
  "15d": 15 * 24 * 60 * 60 * 1000,
  "30d": 30 * 24 * 60 * 60 * 1000,
};

const candleRangeMap = {
  "5m": 5 * 60 * 1000,
  "1h": 60 * 60 * 1000,
  "1d": 24 * 60 * 60 * 1000,
  "1w": 7 * 24 * 60 * 60 * 1000,
  "14d": 14 * 24 * 60 * 60 * 1000,
  "30d": 30 * 24 * 60 * 60 * 1000,
};

let selectedRange = "1h";
let selectedViewType = "line";
let selectedCandleRange = "5m";
let selectedMode = "live";
let currentUser = null;
let lastAutosaveAt = 0;
let totalPoints = 0;
let levels = [
  { name: "Новичок", points: 0 },
  { name: "Уверенный", points: 200 },
  { name: "Профи", points: 600 },
];
let candleOffset = 0;
let candleZoom = 1;
let hoveredCandle = null;
let selectedCandle = null;
let commentsVisible = true;
const candleComments = [];
let latestCandleHover = null;
let touchCandlePanX = 0;
let touchPinchStartDistance = 0;
let touchPinchStartZoom = 1;
let lastCandleHitboxes = [];
let commentEditingCandleTime = null;

const AUTOSAVE_MS = 1500;

function toSafeNumber(value, fallback = 0) {
  return Number.isFinite(value) ? value : fallback;
}

function normalizeUsername(value) {
  return String(value || "").trim().toLowerCase();
}

async function apiJson(method, url, body) {
  const res = await fetch(url, {
    method,
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = null; }
  if (!res.ok) {
    const err = new Error(data?.error || `HTTP_${res.status}`);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

function getSnapshot() {
  return {
    version: 1,
    savedAt: Date.now(),
    currentValue,
    currentX,
    selectedRange,
    selectedViewType,
    selectedCandleRange,
    candleOffset,
    candleZoom,
    commentsVisible,
    candleComments,
    totalPoints,
    levels,
    history: history.slice(-50000),
  };
}

function applySnapshot(parsed) {
  const rawHistory = Array.isArray(parsed.history) ? parsed.history : [];
  const nextHistory = rawHistory
    .map((item) => ({
      t: toSafeNumber(item?.t, NaN),
      y: toSafeNumber(item?.y, NaN),
    }))
    .filter((item) => Number.isFinite(item.t) && Number.isFinite(item.y))
    .sort((a, b) => a.t - b.t);

  if (nextHistory.length === 0) {
    return false;
  }

  history.length = 0;
  for (const item of nextHistory) history.push(item);

  currentValue = toSafeNumber(parsed.currentValue, history[history.length - 1].y);
  previousValue = currentValue;
  currentX = toSafeNumber(parsed.currentX, currentX);
  lastPointAt = history[history.length - 1].t;
  totalPoints = Math.max(0, toSafeNumber(parsed.totalPoints, 0));
  if (Array.isArray(parsed.levels)) {
    const cleaned = parsed.levels
      .map((item) => ({
        name: String(item?.name || "").trim().slice(0, 30),
        points: Math.max(0, Math.floor(toSafeNumber(item?.points, NaN))),
      }))
      .filter((x) => x.name && Number.isFinite(x.points))
      .sort((a, b) => a.points - b.points);
    if (cleaned.length > 0) levels = cleaned;
  }

  if (parsed.selectedRange && rangeMap[parsed.selectedRange]) {
    selectedRange = parsed.selectedRange;
    timeframeNode.querySelectorAll("button").forEach((item) => {
      item.classList.toggle("active", item.dataset.range === selectedRange);
    });
  }

  if (parsed.selectedViewType === "line" || parsed.selectedViewType === "candles") {
    selectedViewType = parsed.selectedViewType;
  }
  if (parsed.selectedCandleRange && candleRangeMap[parsed.selectedCandleRange]) {
    selectedCandleRange = parsed.selectedCandleRange;
  }
  candleOffset = toSafeNumber(parsed.candleOffset, 0);
  candleZoom = Math.max(0.5, Math.min(4, toSafeNumber(parsed.candleZoom, 1)));
  commentsVisible = parsed.commentsVisible !== false;
  toggleCommentsBtn.textContent = commentsVisible ? "Скрыть комментарии" : "Показать комментарии";
  candleComments.length = 0;
  if (Array.isArray(parsed.candleComments)) {
    for (const item of parsed.candleComments) {
      const t = toSafeNumber(item?.t, NaN);
      const text = String(item?.text || "").trim();
      if (Number.isFinite(t) && text) {
        candleComments.push({ t, text });
      }
    }
  }

  viewTypesNode.querySelectorAll("button").forEach((item) => {
    item.classList.toggle("active", item.dataset.viewType === selectedViewType);
  });
  candleTimeframesNode.querySelectorAll("button").forEach((item) => {
    item.classList.toggle("active", item.dataset.candleRange === selectedCandleRange);
  });

  initLiveLine();
  renderLevelsUi();
  return true;
}

function setAuthUiState() {
  const isLoggedIn = Boolean(currentUser);
  registerBtn.classList.toggle("hidden", isLoggedIn);
  loginBtn.classList.toggle("hidden", isLoggedIn);
  logoutBtn.classList.toggle("hidden", !isLoggedIn);
  authStatus.textContent = isLoggedIn ? `В аккаунте: ${currentUser}` : "Гость";
}

async function saveProgressForCurrentUser() {
  if (!currentUser) return;
  try {
    await apiJson("PUT", "/api/progress", { progress: getSnapshot() });
  } catch (_e) {
    // ignore (offline)
  }
}

function resizeCanvas() {
  width = window.innerWidth;
  height = window.innerHeight;
  canvas.width = width;
  canvas.height = height;
}

function isMobileLayout() {
  return window.innerWidth <= 520;
}

function layoutControls() {
  if (isMobileLayout()) return;
  if (!isMobileLayout()) {
    for (const node of [modesNode, timeframeNode, viewTypesNode, candleTimeframesNode, commentControlsNode, dataControlsNode, authPanelNode, levelsPanelNode].filter(Boolean)) {
      node.style.top = "";
    }
    return;
  }

  const gap = 8;
  const startTop = 10;

  let topLeft = startTop;
  for (const node of [modesNode, timeframeNode, viewTypesNode, candleTimeframesNode, commentControlsNode]) {
    if (!node || node.classList.contains("hidden")) continue;
    node.style.top = `${topLeft}px`;
    topLeft += node.offsetHeight + gap;
  }

  let topRight = startTop;
  for (const node of [dataControlsNode, authPanelNode, levelsPanelNode]) {
    if (!node || node.classList.contains("hidden")) continue;
    node.style.top = `${topRight}px`;
    topRight += node.offsetHeight + gap;
  }
}

function renderLevelsUi() {
  if (!levelsPanelNode) return;
  if (!Array.isArray(levels)) levels = [];
  const list = levels.slice().sort((a, b) => a.points - b.points);

  pointsValueNode.textContent = String(Math.floor(totalPoints));

  let current = null;
  for (const lvl of list) {
    if (totalPoints >= lvl.points) current = lvl;
  }
  const next = list.find((lvl) => totalPoints < lvl.points) || null;

  levelNameNode.textContent = current?.name || "—";

  if (!next) {
    levelProgressBarNode.style.width = list.length ? "100%" : "0%";
    nextLevelHintNode.textContent = list.length ? "Максимальный уровень достигнут." : "Добавьте уровни для мотивации.";
  } else {
    const start = current?.points ?? 0;
    const span = Math.max(1, next.points - start);
    const done = Math.max(0, totalPoints - start);
    const percent = Math.max(0, Math.min(100, (done / span) * 100));
    levelProgressBarNode.style.width = `${percent.toFixed(1)}%`;
    nextLevelHintNode.textContent = `До уровня “${next.name}”: осталось ${Math.max(0, next.points - totalPoints)} очк.`;
  }

  levelsListNode.innerHTML = "";
  for (const lvl of list) {
    const row = document.createElement("div");
    row.className = "level-item";
    const meta = document.createElement("div");
    meta.className = "meta";
    meta.textContent = `${lvl.name} `;
    const span = document.createElement("span");
    span.textContent = `(${lvl.points})`;
    meta.appendChild(span);
    const del = document.createElement("button");
    del.type = "button";
    del.textContent = "Удалить";
    del.addEventListener("click", () => {
      const ok = window.confirm(`Удалить уровень “${lvl.name}” (${lvl.points})?`);
      if (!ok) return;
      levels = levels.filter((x) => !(x.name === lvl.name && x.points === lvl.points));
      saveProgressForCurrentUser();
      renderLevelsUi();
      layoutControls();
    });
    row.appendChild(meta);
    row.appendChild(del);
    levelsListNode.appendChild(row);
  }
}

function initLiveLine() {
  livePoints.length = 0;
  const startX = -width / 2;
  currentX = 0;
  livePoints.push({ x: startX, y: currentValue });
  const step = 12;
  for (let x = startX + step; x <= 0; x += step) {
    livePoints.push({ x, y: currentValue });
  }
}

function formatSigned(value) {
  const sign = value >= 0 ? "+" : "";
  return `${sign}${value.toFixed(2)}`;
}

function formatClock(date) {
  const hours = String(date.getHours()).padStart(2, "0");
  const minutes = String(date.getMinutes()).padStart(2, "0");
  const seconds = String(date.getSeconds()).padStart(2, "0");
  return `${hours}:${minutes}.${seconds}`;
}

function formatAxisTime(timestamp, rangeKey) {
  const d = new Date(timestamp);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  if (rangeKey === "1h" || rangeKey === "5m") return `${hh}:${mm}`;
  const dd = String(d.getDate()).padStart(2, "0");
  const mo = String(d.getMonth() + 1).padStart(2, "0");
  return `${dd}.${mo} ${hh}:${mm}`;
}

function formatOpenTime(timestamp) {
  const d = new Date(timestamp);
  const dd = String(d.getDate()).padStart(2, "0");
  const mo = String(d.getMonth() + 1).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${dd}.${mo} ${hh}:${mm}:${ss}`;
}

function formatCountdown(ms) {
  const totalSec = Math.max(0, Math.floor(ms / 1000));
  const mm = Math.floor(totalSec / 60);
  const ss = totalSec % 60;
  return `${mm}:${String(ss).padStart(2, "0")}`;
}

function getTouchDistance(touchA, touchB) {
  const dx = touchA.clientX - touchB.clientX;
  const dy = touchA.clientY - touchB.clientY;
  return Math.hypot(dx, dy);
}

function toDisplayValue(rawValue) {
  return -(rawValue / gridStepPx) * valueStepPerGrid;
}

function updateHud() {
  const currentDisplay = toDisplayValue(currentValue);
  const previousDisplay = toDisplayValue(previousValue);
  valueYNode.textContent = currentDisplay.toFixed(2);
  deltaYNode.textContent = formatSigned(currentDisplay - previousDisplay);
  clockNode.textContent = formatClock(new Date());
  if (selectedMode === "view" && selectedViewType === "candles") {
    const candleMs = candleRangeMap[selectedCandleRange];
    const now = Date.now();
    const nextOpen = Math.floor(now / candleMs) * candleMs + candleMs;
    const remaining = nextOpen - now;
    const base = hoveredCandle || selectedCandle;
    if (base) {
      const note = getCommentForCandleTime(base.t, candleMs);
      const noteText = note ? ` | Коммент: ${note.text}` : "";
      hintNode.textContent = `Свеча: O ${base.open.toFixed(2)} H ${base.high.toFixed(2)} L ${base.low.toFixed(2)} C ${base.close.toFixed(2)} | Открытие: ${formatOpenTime(base.t)}${noteText} | До новой: ${formatCountdown(remaining)}`;
    } else {
      hintNode.textContent = `До открытия новой свечи: ${formatCountdown(remaining)}`;
    }
  }
}

function roundCandleTime(t, candleMs) {
  return Math.floor(t / candleMs) * candleMs;
}

function getCommentForCandleTime(t, candleMs) {
  const rounded = roundCandleTime(t, candleMs);
  for (const item of candleComments) {
    if (roundCandleTime(item.t, candleMs) === rounded) return item;
  }
  return null;
}

function deleteCommentForCandleTime(t, candleMs) {
  const rounded = roundCandleTime(t, candleMs);
  const next = [];
  for (const item of candleComments) {
    if (roundCandleTime(item.t, candleMs) !== rounded) next.push(item);
  }
  candleComments.length = 0;
  for (const item of next) candleComments.push(item);
}

function openCandleCommentModal(candleTime) {
  if (!candleCommentModalNode) return;
  const candleMs = candleRangeMap[selectedCandleRange];
  commentEditingCandleTime = roundCandleTime(candleTime, candleMs);
  const existing = getCommentForCandleTime(commentEditingCandleTime, candleMs);
  candleCommentMetaNode.textContent = `Открытие: ${formatOpenTime(commentEditingCandleTime)}`;
  candleCommentTextNode.value = existing?.text || "";
  candleCommentDeleteBtn.classList.toggle("hidden", !existing);
  candleCommentModalNode.classList.remove("hidden");
  setTimeout(() => candleCommentTextNode.focus(), 0);
}

function closeCandleCommentModal() {
  if (!candleCommentModalNode) return;
  candleCommentModalNode.classList.add("hidden");
  commentEditingCandleTime = null;
}

function findCandleByScreenX(screenX) {
  if (!Array.isArray(lastCandleHitboxes) || lastCandleHitboxes.length === 0) return null;
  let best = null;
  let bestDx = Infinity;
  for (const hb of lastCandleHitboxes) {
    const dx = Math.abs(screenX - hb.x);
    if (dx <= hb.w && dx < bestDx) {
      bestDx = dx;
      best = hb;
    }
  }
  return best;
}

function closeMobilePanels() {
  if (mobileOverlayNode) mobileOverlayNode.classList.add("hidden");
  for (const node of [modesNode, timeframeNode, viewTypesNode, candleTimeframesNode, commentControlsNode, dataControlsNode, authPanelNode, levelsPanelNode]) {
    node?.classList.remove("mobile-open");
  }
}

function openMobilePanel(id) {
  closeMobilePanels();
  const map = {
    modes: modesNode,
    timeframes: timeframeNode,
    viewTypes: viewTypesNode,
    candleTimeframes: candleTimeframesNode,
    commentControls: commentControlsNode,
    dataControls: dataControlsNode,
    authPanel: authPanelNode,
    levelsPanel: levelsPanelNode,
  };
  const node = map[id];
  if (!node) return;
  if (mobileOverlayNode) mobileOverlayNode.classList.remove("hidden");
  node.classList.add("mobile-open");
}

function setShareLink(text) {
  if (!shareLinkNode) return;
  shareLinkNode.textContent = text;
}

async function detectLocalIpsViaWebRTC() {
  if (!("RTCPeerConnection" in window)) return [];
  const ips = new Set();
  const pc = new RTCPeerConnection({ iceServers: [] });
  try {
    pc.createDataChannel("x");
    pc.onicecandidate = (event) => {
      const cand = event.candidate?.candidate || "";
      const match = cand.match(/(\d{1,3}(?:\.\d{1,3}){3})/);
      if (match) ips.add(match[1]);
    };
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    await new Promise((resolve) => setTimeout(resolve, 900));
  } catch (_e) {
    // ignore
  } finally {
    pc.close();
  }
  return Array.from(ips);
}

function addHistoryPoint(timestamp) {
  if (history.length === 0 || timestamp - lastPointAt >= pointIntervalMs) {
    history.push({ t: timestamp, y: currentValue });
    lastPointAt = timestamp;
  } else {
    history[history.length - 1] = { t: timestamp, y: currentValue };
  }

  const minAllowed = timestamp - maxHistoryMs;
  while (history.length > 2 && history[1].t < minAllowed) {
    history.shift();
  }
}

function updateLivePoints() {
  livePoints.push({ x: currentX, y: currentValue });
  const minX = currentX - liveTailLength;
  while (livePoints.length > 2 && livePoints[1].x < minX) {
    livePoints.shift();
  }
}

function getVisibleHistory(now, rangeMs) {
  const start = now - rangeMs;
  const visible = [];
  let i = 0;
  while (i < history.length && history[i].t < start) i += 1;
  if (i > 0) visible.push(history[i - 1]);
  while (i < history.length && history[i].t <= now) {
    visible.push(history[i]);
    i += 1;
  }
  if (visible.length === 0 && history.length > 0) visible.push(history[history.length - 1]);
  return visible;
}

function drawLiveGrid(head) {
  ctx.save();
  ctx.translate(width / 2 - head.x, height / 2 - head.y);
  const startX = Math.floor((head.x - width) / gridStepPx) * gridStepPx;
  const endX = Math.ceil((head.x + width) / gridStepPx) * gridStepPx;
  const startY = Math.floor((head.y - height) / gridStepPx) * gridStepPx;
  const endY = Math.ceil((head.y + height) / gridStepPx) * gridStepPx;

  ctx.strokeStyle = "rgba(115, 130, 220, 0.12)";
  ctx.lineWidth = 1;
  for (let x = startX; x <= endX; x += gridStepPx) {
    ctx.beginPath();
    ctx.moveTo(x, startY);
    ctx.lineTo(x, endY);
    ctx.stroke();
  }
  for (let y = startY; y <= endY; y += gridStepPx) {
    ctx.beginPath();
    ctx.moveTo(startX, y);
    ctx.lineTo(endX, y);
    ctx.stroke();
  }
  ctx.restore();
}

function drawLiveLine(head) {
  ctx.save();
  ctx.translate(width / 2 - head.x, height / 2 - head.y);
  ctx.lineJoin = "round";
  ctx.lineCap = "round";
  ctx.lineWidth = 4;
  ctx.strokeStyle = "#79ffb2";
  ctx.beginPath();
  ctx.moveTo(livePoints[0].x, livePoints[0].y);
  for (let i = 1; i < livePoints.length; i += 1) {
    ctx.lineTo(livePoints[i].x, livePoints[i].y);
  }
  ctx.stroke();
  ctx.fillStyle = "#c4ffd8";
  ctx.beginPath();
  ctx.arc(head.x, head.y, 5, 0, Math.PI * 2);
  ctx.fill();
  ctx.restore();
}

function drawLiveCrosshair() {
  const cx = width / 2;
  const cy = height / 2;
  ctx.strokeStyle = "rgba(220, 225, 255, 0.35)";
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(cx - 12, cy);
  ctx.lineTo(cx + 12, cy);
  ctx.moveTo(cx, cy - 12);
  ctx.lineTo(cx, cy + 12);
  ctx.stroke();
}

function drawLiveAxes(head) {
  const leftPadding = 52;
  const bottomPadding = 34;
  const startY = Math.floor((head.y - height) / gridStepPx) * gridStepPx;
  const endY = Math.ceil((head.y + height) / gridStepPx) * gridStepPx;
  const startX = Math.floor((head.x - width) / gridStepPx) * gridStepPx;
  const endX = Math.ceil((head.x + width) / gridStepPx) * gridStepPx;

  ctx.save();
  ctx.fillStyle = "rgba(8, 11, 23, 0.82)";
  ctx.fillRect(0, 0, leftPadding, height);
  ctx.fillRect(0, height - bottomPadding, width, bottomPadding);

  ctx.strokeStyle = "rgba(155, 170, 255, 0.45)";
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(leftPadding, 0);
  ctx.lineTo(leftPadding, height);
  ctx.moveTo(0, height - bottomPadding);
  ctx.lineTo(width, height - bottomPadding);
  ctx.stroke();

  ctx.fillStyle = "#d9ddff";
  ctx.font = "12px Arial";
  for (let worldY = startY; worldY <= endY; worldY += gridStepPx) {
    const screenY = height / 2 + (worldY - head.y);
    if (screenY < 8 || screenY > height - bottomPadding - 4) continue;
    const value = -(worldY / gridStepPx) * valueStepPerGrid;
    ctx.fillText(value.toFixed(0), 8, screenY + 4);
  }

  const now = Date.now();
  for (let worldX = startX; worldX <= endX; worldX += gridStepPx) {
    const screenX = width / 2 + (worldX - head.x);
    if (screenX < leftPadding + 4 || screenX > width - 42) continue;
    const secondsOffset = (worldX - head.x) / speedX;
    const tickDate = new Date(now + secondsOffset * 1000);
    ctx.fillText(formatClock(tickDate), screenX - 22, height - 12);
  }
  ctx.restore();
}

function drawViewChart(points, now, rangeMs) {
  const left = 62;
  const right = 24;
  const top = 56;
  const bottom = 76;
  const chartW = width - left - right;
  const chartH = height - top - bottom;

  ctx.fillStyle = "rgba(8, 11, 23, 0.82)";
  ctx.fillRect(left, top, chartW, chartH);

  let minY = Infinity;
  let maxY = -Infinity;
  for (const p of points) {
    const displayY = toDisplayValue(p.y);
    minY = Math.min(minY, displayY);
    maxY = Math.max(maxY, displayY);
  }
  if (!Number.isFinite(minY)) {
    minY = -10;
    maxY = 10;
  }
  if (Math.abs(maxY - minY) < 1) {
    maxY += 0.5;
    minY -= 0.5;
  }
  const padY = (maxY - minY) * 0.1;
  maxY += padY;
  minY -= padY;

  const xStart = now - rangeMs;
  const yToScreen = (y) => top + ((maxY - y) / (maxY - minY)) * chartH;
  const xToScreen = (t) => left + ((t - xStart) / rangeMs) * chartW;

  ctx.strokeStyle = "rgba(115, 130, 220, 0.2)";
  ctx.lineWidth = 1;
  ctx.beginPath();
  for (let i = 0; i <= 6; i += 1) {
    const y = top + (i / 6) * chartH;
    ctx.moveTo(left, y);
    ctx.lineTo(left + chartW, y);
  }
  for (let i = 0; i <= 6; i += 1) {
    const x = left + (i / 6) * chartW;
    ctx.moveTo(x, top);
    ctx.lineTo(x, top + chartH);
  }
  ctx.stroke();

  ctx.strokeStyle = "#79ffb2";
  ctx.lineWidth = 3;
  ctx.lineCap = "round";
  ctx.lineJoin = "round";
  ctx.beginPath();
  for (let i = 0; i < points.length; i += 1) {
    const sx = xToScreen(points[i].t);
    const sy = yToScreen(toDisplayValue(points[i].y));
    if (i === 0) ctx.moveTo(sx, sy);
    else ctx.lineTo(sx, sy);
  }
  ctx.stroke();

  if (points.length > 0) {
    const last = points[points.length - 1];
    ctx.fillStyle = "#c4ffd8";
    ctx.beginPath();
    ctx.arc(xToScreen(last.t), yToScreen(toDisplayValue(last.y)), 4.5, 0, Math.PI * 2);
    ctx.fill();
  }

  ctx.fillStyle = "#d9ddff";
  ctx.font = "12px Arial";
  for (let i = 0; i <= 6; i += 1) {
    const value = maxY - ((maxY - minY) * i) / 6;
    const y = top + (i / 6) * chartH;
    ctx.fillText(value.toFixed(1), 8, y + 4);
  }
  for (let i = 0; i <= 6; i += 1) {
    const t = xStart + (rangeMs * i) / 6;
    const x = left + (i / 6) * chartW;
    ctx.fillText(formatAxisTime(t, selectedRange), x - 28, top + chartH + 20);
  }

  ctx.strokeStyle = "rgba(155, 170, 255, 0.45)";
  ctx.beginPath();
  ctx.moveTo(left, top);
  ctx.lineTo(left, top + chartH);
  ctx.lineTo(left + chartW, top + chartH);
  ctx.stroke();
}

function buildCandles(now, candleMs, candleCount) {
  const totalRange = candleMs * candleCount;
  const end = now - candleOffset;
  const start = end - totalRange;
  const grouped = new Map();

  for (const point of history) {
    if (point.t < start || point.t > end) continue;
    const bucket = Math.floor(point.t / candleMs) * candleMs;
    const displayY = toDisplayValue(point.y);
    const candle = grouped.get(bucket);
    if (!candle) {
      grouped.set(bucket, {
        t: bucket,
        open: displayY,
        high: displayY,
        low: displayY,
        close: displayY,
      });
    } else {
      candle.high = Math.max(candle.high, displayY);
      candle.low = Math.min(candle.low, displayY);
      candle.close = displayY;
    }
  }

  let lastKnown = null;
  let historyIdx = 0;
  while (historyIdx < history.length && history[historyIdx].t < start) historyIdx += 1;
  if (historyIdx > 0) lastKnown = toDisplayValue(history[historyIdx - 1].y);

  const candles = [];
  const firstBucket = Math.floor(start / candleMs) * candleMs;
  const lastBucket = Math.floor((end - 1) / candleMs) * candleMs;
  for (let bucket = firstBucket; bucket <= lastBucket; bucket += candleMs) {
    while (historyIdx < history.length && history[historyIdx].t < bucket + candleMs) {
      lastKnown = toDisplayValue(history[historyIdx].y);
      historyIdx += 1;
    }
    const existing = grouped.get(bucket);
    if (existing) {
      lastKnown = existing.close;
      candles.push(existing);
      continue;
    }
    if (!Number.isFinite(lastKnown)) continue;
    candles.push({
      t: bucket,
      open: lastKnown,
      high: lastKnown,
      low: lastKnown,
      close: lastKnown,
    });
  }
  return { candles, start, end };
}

function drawCandleChart(now, candleMs) {
  const left = 62;
  const right = 24;
  const top = 56;
  const bottom = 76;
  const chartW = width - left - right;
  const chartH = height - top - bottom;
  const candleCount = Math.max(20, Math.round(60 / candleZoom));
  const { candles, start, end } = buildCandles(now, candleMs, candleCount);
  hoveredCandle = null;
  lastCandleHitboxes = [];

  ctx.fillStyle = "rgba(8, 11, 23, 0.82)";
  ctx.fillRect(left, top, chartW, chartH);

  if (candles.length === 0) {
    ctx.fillStyle = "#d9ddff";
    ctx.font = "14px Arial";
    ctx.fillText("Недостаточно данных для свечей", left + 20, top + 24);
    return;
  }
  latestCandleHover = candles[candles.length - 1];

  let minY = Infinity;
  let maxY = -Infinity;
  for (const c of candles) {
    minY = Math.min(minY, c.low);
    maxY = Math.max(maxY, c.high);
  }

  const spread = Math.max(maxY - minY, 1);
  minY -= spread * 0.1;
  maxY += spread * 0.1;

  const yToScreen = (y) => top + ((maxY - y) / (maxY - minY)) * chartH;
  const candleAreaRatio = 0.65;
  const xToScreen = (t) => left + ((t - start) / (end - start || 1)) * chartW * candleAreaRatio;
  const candleWidth = Math.max((chartW * candleAreaRatio / candleCount) * 0.9, 3);
  const candleScreenIndex = new Map();

  ctx.strokeStyle = "rgba(115, 130, 220, 0.2)";
  ctx.lineWidth = 1;
  ctx.beginPath();
  for (let i = 0; i <= 6; i += 1) {
    const y = top + (i / 6) * chartH;
    ctx.moveTo(left, y);
    ctx.lineTo(left + chartW, y);
  }
  for (let i = 0; i <= 6; i += 1) {
    const x = left + (i / 6) * chartW * candleAreaRatio;
    ctx.moveTo(x, top);
    ctx.lineTo(x, top + chartH);
  }
  ctx.stroke();

  for (const candle of candles) {
    const x = xToScreen(candle.t + candleMs / 2);
    const yOpen = yToScreen(candle.open);
    const yClose = yToScreen(candle.close);
    const yHigh = yToScreen(candle.high);
    const yLow = yToScreen(candle.low);
    const isUp = candle.close >= candle.open;
    const color = isUp ? "#79ffb2" : "#ff7d96";
    candleScreenIndex.set(candle.t, { x, yHigh, yLow });
    lastCandleHitboxes.push({ t: candle.t, x, w: candleWidth * 0.6, candle });

    ctx.strokeStyle = color;
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.moveTo(x, yHigh);
    ctx.lineTo(x, yLow);
    ctx.stroke();

    ctx.fillStyle = color;
    const bodyTop = Math.min(yOpen, yClose);
    const bodyH = Math.max(Math.abs(yClose - yOpen), 2);
    ctx.fillRect(x - candleWidth / 2, bodyTop, candleWidth, bodyH);

    if (mouseChartX >= x - candleWidth && mouseChartX <= x + candleWidth && mouseChartY >= top && mouseChartY <= top + chartH) {
      hoveredCandle = candle;
      latestCandleHover = candle;
    }
  }

  ctx.fillStyle = "#d9ddff";
  ctx.font = "12px Arial";
  for (let i = 0; i <= 6; i += 1) {
    const value = maxY - ((maxY - minY) * i) / 6;
    const y = top + (i / 6) * chartH;
    ctx.fillText(value.toFixed(1), 8, y + 4);
  }

  if (commentsVisible) {
    ctx.font = "11px Arial";
    for (const note of candleComments) {
      const rounded = Math.floor(note.t / candleMs) * candleMs;
      const point = candleScreenIndex.get(rounded);
      if (!point) continue;
      const textY = Math.max(top + 12, point.yHigh - 10);
      ctx.fillStyle = "#ffd86b";
      ctx.beginPath();
      ctx.arc(point.x, point.yHigh - 3, 3, 0, Math.PI * 2);
      ctx.fill();
      ctx.fillStyle = "rgba(255, 216, 107, 0.9)";
      ctx.fillText(note.text, point.x + 6, textY);
    }
  }
  for (let i = 0; i <= 6; i += 1) {
    const t = start + ((end - start) * i) / 6;
    const x = left + (i / 6) * chartW * candleAreaRatio;
    ctx.fillText(formatAxisTime(t, selectedCandleRange), x - 28, top + chartH + 20);
  }

  ctx.strokeStyle = "rgba(155, 170, 255, 0.45)";
  ctx.beginPath();
  ctx.moveTo(left, top);
  ctx.lineTo(left, top + chartH);
  ctx.lineTo(left + chartW, top + chartH);
  ctx.stroke();
}

let mouseChartX = -1;
let mouseChartY = -1;

function render() {
  ctx.clearRect(0, 0, width, height);
  if (selectedMode === "live") {
    const head = livePoints[livePoints.length - 1];
    drawLiveGrid(head);
    drawLiveLine(head);
    drawLiveCrosshair();
    drawLiveAxes(head);
    return;
  }
  const now = Date.now();
  if (selectedViewType === "candles") {
    drawCandleChart(now, candleRangeMap[selectedCandleRange]);
  } else {
    const rangeMs = rangeMap[selectedRange];
    const visible = getVisibleHistory(now, rangeMs);
    drawViewChart(visible, now, rangeMs);
  }
}

function setMode(mode) {
  selectedMode = mode;
  modesNode.querySelectorAll("button").forEach((button) => {
    button.classList.toggle("active", button.dataset.mode === mode);
  });
  timeframeNode.classList.toggle("hidden", mode !== "view");
  viewTypesNode.classList.toggle("hidden", mode !== "view");
  const showLineTf = mode === "view" && selectedViewType === "line";
  const showCandleTf = mode === "view" && selectedViewType === "candles";
  timeframeNode.classList.toggle("hidden", !showLineTf);
  candleTimeframesNode.classList.toggle("hidden", !showCandleTf);
  commentControlsNode.classList.toggle("hidden", !showCandleTf);
  hintNode.textContent = mode === "live"
    ? "Зажмите левую кнопку мыши и ведите курсор вверх/вниз, чтобы менять направление."
    : "Просмотр: выберите тип графика и таймфрейм.";
  layoutControls();
  render();
}

function frame(now) {
  const dt = Math.min((now - lastTime) / 1000, 0.05);
  lastTime = now;
  previousValue = currentValue;
  if (selectedMode === "live") {
    const deltaPx = pendingVerticalDelta;
    currentValue += deltaPx;
    pendingVerticalDelta = 0;
    const pointsNow = toDisplayValue(currentValue);
    if (Number.isFinite(pointsNow)) {
      totalPoints = Math.max(0, pointsNow);
    }
    currentX += speedX * dt;
    updateLivePoints();
    renderLevelsUi();
  } else {
    pendingVerticalDelta = 0;
  }
  addHistoryPoint(Date.now());
  if (currentUser && now - lastAutosaveAt >= AUTOSAVE_MS) {
    saveProgressForCurrentUser();
    lastAutosaveAt = now;
  }
  updateHud();
  render();
  requestAnimationFrame(frame);
}

canvas.addEventListener("mousedown", (event) => {
  if (event.button !== 0) return;
  if (selectedMode !== "live") return;
  isMouseDown = true;
  pointerDownX = event.clientX;
  pointerDownY = event.clientY;
  pointerDidDrag = false;
  lastMouseY = event.clientY;
});

window.addEventListener("mouseup", () => {
  isMouseDown = false;
});

window.addEventListener("mousemove", (event) => {
  mouseChartX = event.clientX;
  mouseChartY = event.clientY;
  if (!isMouseDown) return;
  if (selectedMode !== "live") return;
  if (Math.abs(event.clientX - pointerDownX) > 6 || Math.abs(event.clientY - pointerDownY) > 6) {
    pointerDidDrag = true;
  }
  const deltaY = event.clientY - lastMouseY;
  pendingVerticalDelta += deltaY;
  lastMouseY = event.clientY;
});

canvas.addEventListener("wheel", (event) => {
  if (selectedMode !== "view" || selectedViewType !== "candles") return;
  event.preventDefault();
  const delta = event.deltaY > 0 ? -0.1 : 0.1;
  candleZoom = Math.max(0.5, Math.min(4, candleZoom + delta));
}, { passive: false });

canvas.addEventListener("touchstart", (event) => {
  const touches = event.touches;
  if (selectedMode === "live") {
    if (touches.length === 1) {
      isMouseDown = true;
      lastMouseY = touches[0].clientY;
      mouseChartX = touches[0].clientX;
      mouseChartY = touches[0].clientY;
      event.preventDefault();
    }
    return;
  }

  if (selectedMode === "view" && selectedViewType === "candles") {
    if (touches.length === 1) {
      touchCandlePanX = touches[0].clientX;
      mouseChartX = touches[0].clientX;
      mouseChartY = touches[0].clientY;
      touchPinchStartDistance = 0;
      event.preventDefault();
    } else if (touches.length === 2) {
      touchPinchStartDistance = getTouchDistance(touches[0], touches[1]);
      touchPinchStartZoom = candleZoom;
      event.preventDefault();
    }
  }
}, { passive: false });

canvas.addEventListener("touchmove", (event) => {
  const touches = event.touches;
  if (selectedMode === "live") {
    if (touches.length === 1 && isMouseDown) {
      const touch = touches[0];
      const deltaY = touch.clientY - lastMouseY;
      pendingVerticalDelta += deltaY;
      lastMouseY = touch.clientY;
      mouseChartX = touch.clientX;
      mouseChartY = touch.clientY;
      event.preventDefault();
    }
    return;
  }

  if (selectedMode === "view" && selectedViewType === "candles") {
    if (touches.length === 1 && touchPinchStartDistance === 0) {
      const touch = touches[0];
      const candleMs = candleRangeMap[selectedCandleRange];
      const deltaX = touch.clientX - touchCandlePanX;
      touchCandlePanX = touch.clientX;
      mouseChartX = touch.clientX;
      mouseChartY = touch.clientY;
      const panStep = candleMs * (deltaX / 8);
      candleOffset = Math.max(0, candleOffset - panStep);
      render();
      event.preventDefault();
    } else if (touches.length === 2) {
      const distance = getTouchDistance(touches[0], touches[1]);
      if (touchPinchStartDistance <= 0) {
        touchPinchStartDistance = distance;
        touchPinchStartZoom = candleZoom;
      }
      const scale = distance / touchPinchStartDistance;
      candleZoom = Math.max(0.5, Math.min(4, touchPinchStartZoom * scale));
      mouseChartX = (touches[0].clientX + touches[1].clientX) / 2;
      mouseChartY = (touches[0].clientY + touches[1].clientY) / 2;
      render();
      event.preventDefault();
    }
  }
}, { passive: false });

canvas.addEventListener("touchend", (event) => {
  if (selectedMode === "live") {
    if (event.touches.length === 0) {
      isMouseDown = false;
    } else {
      lastMouseY = event.touches[0].clientY;
    }
    return;
  }

  if (selectedMode === "view" && selectedViewType === "candles") {
    if (event.touches.length === 1) {
      touchCandlePanX = event.touches[0].clientX;
      touchPinchStartDistance = 0;
    } else if (event.touches.length === 0) {
      touchPinchStartDistance = 0;
    }
  }
});

window.addEventListener("resize", () => {
  resizeCanvas();
  if (selectedMode === "live" && livePoints.length === 0) {
    initLiveLine();
  }
});

modesNode.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-mode]");
  if (!button) return;
  isMouseDown = false;
  setMode(button.dataset.mode);
});

timeframeNode.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-range]");
  if (!button) return;
  selectedRange = button.dataset.range;
  timeframeNode.querySelectorAll("button").forEach((item) => {
    item.classList.toggle("active", item === button);
  });
  if (selectedMode === "view") render();
});

viewTypesNode.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-view-type]");
  if (!button) return;
  selectedViewType = button.dataset.viewType;
  viewTypesNode.querySelectorAll("button").forEach((item) => {
    item.classList.toggle("active", item === button);
  });
  const isView = selectedMode === "view";
  timeframeNode.classList.toggle("hidden", !(isView && selectedViewType === "line"));
  candleTimeframesNode.classList.toggle("hidden", !(isView && selectedViewType === "candles"));
  commentControlsNode.classList.toggle("hidden", !(isView && selectedViewType === "candles"));
  layoutControls();
  if (isView) render();
});

candleTimeframesNode.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-candle-range]");
  if (!button) return;
  selectedCandleRange = button.dataset.candleRange;
  candleOffset = 0;
  candleTimeframesNode.querySelectorAll("button").forEach((item) => {
    item.classList.toggle("active", item === button);
  });
  layoutControls();
  if (selectedMode === "view" && selectedViewType === "candles") render();
});

canvas.addEventListener("mousedown", (event) => {
  if (event.button !== 1) return;
  if (selectedMode !== "view" || selectedViewType !== "candles") return;
  event.preventDefault();
  pointerDownX = event.clientX;
  pointerDownY = event.clientY;
  pointerDidDrag = false;
});

window.addEventListener("keydown", (event) => {
  if (selectedMode !== "view" || selectedViewType !== "candles") return;
  const candleMs = candleRangeMap[selectedCandleRange];
  const step = candleMs * 5;
  if (event.key === "ArrowLeft") {
    candleOffset += step;
    render();
  } else if (event.key === "ArrowRight") {
    candleOffset = Math.max(0, candleOffset - step);
    render();
  }
});

canvas.addEventListener("mousemove", (event) => {
  if (selectedMode !== "view" || selectedViewType !== "candles") return;
  if ((event.buttons & 1) !== 1) return;
  if (Math.abs(event.clientX - pointerDownX) > 6 || Math.abs(event.clientY - pointerDownY) > 6) {
    pointerDidDrag = true;
  }
  const candleMs = candleRangeMap[selectedCandleRange];
  const panStep = candleMs * (event.movementX / 8);
  candleOffset = Math.max(0, candleOffset - panStep);
  render();
});

canvas.addEventListener("click", (event) => {
  if (selectedMode !== "view" || selectedViewType !== "candles") return;
  if (candleCommentModalNode && !candleCommentModalNode.classList.contains("hidden")) return;
  if (pointerDidDrag) return;
  const hb = findCandleByScreenX(event.clientX);
  if (!hb) return;
  selectedCandle = hb.candle;
  updateHud();
  openCandleCommentModal(hb.t);
});

addCommentBtn.addEventListener("click", () => {
  if (selectedMode !== "view" || selectedViewType !== "candles") return;
  const baseTime = selectedCandle?.t ?? hoveredCandle?.t ?? latestCandleHover?.t ?? Date.now();
  openCandleCommentModal(baseTime);
});

toggleCommentsBtn.addEventListener("click", () => {
  commentsVisible = !commentsVisible;
  toggleCommentsBtn.textContent = commentsVisible ? "Скрыть комментарии" : "Показать комментарии";
  render();
});

addLevelBtn?.addEventListener("click", () => {
  const name = String(levelNameInput?.value || "").trim().slice(0, 30);
  const ptsRaw = Number(levelPointsInput?.value);
  const pts = Math.max(0, Math.floor(toSafeNumber(ptsRaw, NaN)));
  if (!name || !Number.isFinite(pts)) return;
  levels = levels.concat([{ name, points: pts }]).sort((a, b) => a.points - b.points);
  if (levelNameInput) levelNameInput.value = "";
  if (levelPointsInput) levelPointsInput.value = "";
  saveProgressForCurrentUser();
  renderLevelsUi();
  layoutControls();
});

mobileToolbarNode?.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-mobile-open]");
  if (!button) return;
  openMobilePanel(button.dataset.mobileOpen);
});

mobileOverlayNode?.addEventListener("click", () => {
  closeMobilePanels();
});

window.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    closeMobilePanels();
  }
});

if (candleCommentModalNode) {
  candleCommentModalNode.addEventListener("click", (event) => {
    if (event.target?.dataset?.closeModal) closeCandleCommentModal();
  });
}

candleCommentCancelBtn?.addEventListener("click", closeCandleCommentModal);

candleCommentSaveBtn?.addEventListener("click", () => {
  if (commentEditingCandleTime == null) return;
  const candleMs = candleRangeMap[selectedCandleRange];
  const text = String(candleCommentTextNode.value || "").trim().slice(0, 140);
  deleteCommentForCandleTime(commentEditingCandleTime, candleMs);
  if (text) {
    candleComments.push({ t: commentEditingCandleTime, text });
  }
  saveProgressForCurrentUser();
  closeCandleCommentModal();
  updateHud();
  render();
});

candleCommentDeleteBtn?.addEventListener("click", () => {
  if (commentEditingCandleTime == null) return;
  const candleMs = candleRangeMap[selectedCandleRange];
  deleteCommentForCandleTime(commentEditingCandleTime, candleMs);
  saveProgressForCurrentUser();
  closeCandleCommentModal();
  updateHud();
  render();
});

function exportData() {
  const payload = getSnapshot();
  payload.exportedAt = Date.now();
  payload.account = currentUser;

  const blob = new Blob([JSON.stringify(payload)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  link.href = url;
  link.download = `graph-export-${stamp}.json`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

function importData(file) {
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const parsed = JSON.parse(String(reader.result || "{}"));
      const ok = applySnapshot(parsed);
      if (!ok) {
        window.alert("Файл импорта пустой или неверный.");
        return;
      }
      saveProgressForCurrentUser();
      updateHud();
      render();
    } catch (_error) {
      window.alert("Не удалось прочитать файл импорта.");
    }
  };
  reader.readAsText(file);
}

exportBtn.addEventListener("click", exportData);

importBtn.addEventListener("click", () => {
  importInput.value = "";
  importInput.click();
});

importInput.addEventListener("change", (event) => {
  const file = event.target.files?.[0];
  if (!file) return;
  importData(file);
});

window.addEventListener("beforeunload", () => {
  saveProgressForCurrentUser();
});

registerBtn.addEventListener("click", async () => {
  const username = normalizeUsername(authUsernameInput.value);
  const password = String(authPasswordInput.value || "");
  if (username.length < 3) {
    window.alert("Логин должен быть минимум 3 символа.");
    return;
  }
  if (password.length < 4) {
    window.alert("Пароль должен быть минимум 4 символа.");
    return;
  }
  try {
    await apiJson("POST", "/api/register", { username, password });
    await apiJson("POST", "/api/login", { username, password });
    currentUser = username;
    authPasswordInput.value = "";
    setAuthUiState();
    await saveProgressForCurrentUser();
  } catch (e) {
    if (e?.data?.error === "user_exists") window.alert("Такой пользователь уже существует.");
    else window.alert("Не удалось зарегистрироваться.");
  }
});

loginBtn.addEventListener("click", async () => {
  const username = normalizeUsername(authUsernameInput.value);
  const password = String(authPasswordInput.value || "");
  try {
    const data = await apiJson("POST", "/api/login", { username, password });
    currentUser = data?.user || username;
    const progress = await apiJson("GET", "/api/progress");
    if (progress?.progress) {
      applySnapshot(progress.progress);
      updateHud();
    }
    authPasswordInput.value = "";
    setAuthUiState();
    render();
  } catch (_e) {
    window.alert("Неверный логин или пароль.");
  }
});

logoutBtn.addEventListener("click", async () => {
  await saveProgressForCurrentUser();
  try { await apiJson("POST", "/api/logout"); } catch (_e) { /* ignore */ }
  currentUser = null;
  setAuthUiState();
});

resizeCanvas();
initLiveLine();
addHistoryPoint(Date.now());
layoutControls();
renderLevelsUi();
if (location.protocol.startsWith("http")) {
  setShareLink(`Ссылка: ${location.origin}/`);
  detectLocalIpsViaWebRTC().then((ips) => {
    if (!ips.length) return;
    const port = location.port || (location.protocol === "https:" ? "443" : "80");
    const list = ips.map((ip) => `http://${ip}:${port}/`).join(" · ");
    setShareLink(`Ссылка: ${list}`);
  });
} else {
  setShareLink("Ссылка: запустите через сервер (npm run start)");
}
(async () => {
  try {
    const me = await apiJson("GET", "/api/me");
    if (me?.user) {
      currentUser = me.user;
      const progress = await apiJson("GET", "/api/progress");
      if (progress?.progress) applySnapshot(progress.progress);
    }
  } catch (_e) {
    // ignore
  }
  setAuthUiState();
  updateHud();
  setMode("live");
})();
requestAnimationFrame(frame);
