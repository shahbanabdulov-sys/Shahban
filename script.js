const canvas = document.getElementById("scene");
const ctx = canvas.getContext("2d");
const appBrandNode = document.getElementById("appBrand");
const valueYNode = document.getElementById("valueY");
const deltaYNode = document.getElementById("deltaY");
const clockNode = document.getElementById("clock");
const timeframeNode = document.getElementById("timeframes");
const viewTypesNode = document.getElementById("viewTypes");
const candleTimeframesNode = document.getElementById("candleTimeframes");
const commentControlsNode = document.getElementById("commentControls");
const addCommentBtn = document.getElementById("addCommentBtn");
const toggleCommentsBtn = document.getElementById("toggleCommentsBtn");
const tasksTabNode = document.getElementById("tasksTab");
const openTasksBtn = document.getElementById("openTasksBtn");
const soundsTabNode = document.getElementById("soundsTab");
const openSoundsBtn = document.getElementById("openSoundsBtn");
const tasksPageNode = document.getElementById("tasksPage");
const closeTasksBtn = document.getElementById("closeTasksBtn");
const soundsPageNode = document.getElementById("soundsPage");
const closeSoundsBtn = document.getElementById("closeSoundsBtn");
const tasksGlobalEnabledInput = document.getElementById("tasksGlobalEnabled");
const soundsEnabledInput = document.getElementById("soundsEnabled");
const soundVolumeInput = document.getElementById("soundVolumeInput");
const soundFileInput = document.getElementById("soundFileInput");
const soundsListNode = document.getElementById("soundsList");
const soundsTabBadgeNode = document.getElementById("soundsTabBadge");
const soundsStatusNode = document.getElementById("soundsStatus");
const taskFormNode = document.getElementById("taskForm");
const taskTitleInput = document.getElementById("taskTitleInput");
const taskDescriptionInput = document.getElementById("taskDescriptionInput");
const taskRewardInput = document.getElementById("taskRewardInput");
const taskPenaltyInput = document.getElementById("taskPenaltyInput");
const taskTimeInput = document.getElementById("taskTimeInput");
const tasksListNode = document.getElementById("tasksList");
const tasksTabBadgeNode = document.getElementById("tasksTabBadge");
const activeTasksCountNode = document.getElementById("activeTasksCount");
const dueTasksCountNode = document.getElementById("dueTasksCount");
const nextTaskTimeNode = document.getElementById("nextTaskTime");
const taskReportModalNode = document.getElementById("taskReportModal");
const taskReportTimeNode = document.getElementById("taskReportTime");
const taskReportNameNode = document.getElementById("taskReportName");
const taskReportDescriptionNode = document.getElementById("taskReportDescription");
const taskReportPointsNode = document.getElementById("taskReportPoints");
const taskDoneBtn = document.getElementById("taskDoneBtn");
const taskFailedBtn = document.getElementById("taskFailedBtn");
const taskIgnoreBtn = document.getElementById("taskIgnoreBtn");
const modesNode = document.getElementById("modes");
const hintNode = document.querySelector(".hint");
const dataControlsNode = document.getElementById("dataControls") || document.querySelector(".data-controls");
const shareLinkNode = document.getElementById("shareLink");
const authPanelNode = document.getElementById("authPanel");
const levelsPanelNode = document.getElementById("levelsPanel");
const currentLevelToggleNode = document.getElementById("currentLevelToggle");
const levelNameNode = document.getElementById("levelName");
const currentLevelPointsNode = document.getElementById("currentLevelPoints");
const currentLevelChevronNode = document.getElementById("currentLevelChevron");
const levelsDetailsNode = document.getElementById("levelsDetails");
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
const authEmail = document.getElementById("authEmail");
const authPassword = document.getElementById("authPassword");
const registerBtn = document.getElementById("registerBtn");
const loginBtn = document.getElementById("loginBtn");
const logoutBtn = document.getElementById("logoutBtn");
const authStatus = document.getElementById("authStatus");
const mobileToolbarNode = document.getElementById("mobileToolbar");
const mobileOverlayNode = document.getElementById("mobileOverlay");
const appPanelsForAuth = [
  appBrandNode,
  modesNode,
  timeframeNode,
  viewTypesNode,
  candleTimeframesNode,
  commentControlsNode,
  tasksTabNode,
  soundsTabNode,
  dataControlsNode,
  levelsPanelNode,
  mobileToolbarNode
];

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
const valueStepPerGrid = 5;

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
let isProgressLoaded = false;
let isApplyingRemoteProgress = false;
let lastAutosaveAt = 0;
let totalPoints = 0;
let levelsExpanded = false;
let tasksGlobalEnabled = true;
let taskReportQueue = [];
let activeTaskReport = null;
let lastTaskCheckAt = 0;
let soundsEnabled = false;
let soundVolume = 0.65;
let soundRecords = [];
let soundDbPromise = null;
let soundCurrentUrl = null;
let soundCurrentIndex = 0;
let isSoundLoopStarting = false;
let levels = [
  { name: "Новичок", points: 0 },
  { name: "Уверенный", points: 200 },
  { name: "Профи", points: 600 },
];
let tasks = [];
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
const FAST_SAVE_MS = 250;
const LOCAL_PROGRESS_PREFIX = "productiv-line-progress:";
const LOCAL_FAST_PROGRESS_PREFIX = "productiv-line-fast:";
const SOUND_DB_NAME = "productiv-line-sounds";
const SOUND_STORE_NAME = "sounds";
const SUPABASE_AUTH_STORAGE_KEY = "productiv-line-auth";
const FAST_HISTORY_LIMIT = 5000;

let saveInFlight = false;
let pendingCloudSaveSnapshot = null;
let latestLoadToken = 0;
let lastSessionUserId = null;
let lastFastSaveAt = 0;
let lastFastSavedValue = currentValue;
let soundsLoadedForUserId = null;
let isLoadingSounds = false;

const soundPlayer = new Audio();
soundPlayer.preload = "auto";

let supabase = null;
let supabaseClientPromise = null;

function withTimeout(promise, ms, label = "operation") {
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      setTimeout(() => reject(new Error(`${label} timeout`)), ms);
    }),
  ]);
}

function getSupabaseClient() {
  if (supabase) return Promise.resolve(supabase);
  if (!supabaseClientPromise) {
    supabaseClientPromise = import("./supabaseClient.js")
      .then((module) => {
        supabase = module.supabase;
        return supabase;
      })
      .catch((error) => {
        supabaseClientPromise = null;
        throw error;
      });
  }
  return supabaseClientPromise;
}

function setAuthBusy(isBusy) {
  if (loginBtn) loginBtn.disabled = isBusy;
  if (registerBtn) registerBtn.disabled = isBusy;
  if (logoutBtn) logoutBtn.disabled = isBusy;
}

function toSafeNumber(value, fallback = 0) {
  return Number.isFinite(value) ? value : fallback;
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function getLocalProgressKey(userId) {
  return `${LOCAL_PROGRESS_PREFIX}${userId}`;
}

function getLocalFastProgressKey(userId) {
  return `${LOCAL_FAST_PROGRESS_PREFIX}${userId}`;
}

function getSnapshotSavedAt(snapshot) {
  const numericSavedAt = Number(snapshot?.savedAt);
  if (Number.isFinite(numericSavedAt)) return numericSavedAt;
  const parsedSavedAt = Date.parse(snapshot?.savedAt || "");
  return Number.isFinite(parsedSavedAt) ? parsedSavedAt : 0;
}

function readLocalSnapshotForUser(userId) {
  try {
    const raw = localStorage.getItem(getLocalProgressKey(userId));
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch (error) {
    console.warn("readLocalSnapshotForUser error:", error);
    return null;
  }
}

function writeLocalSnapshotForUser(userId, snapshot) {
  try {
    localStorage.setItem(getLocalProgressKey(userId), JSON.stringify(snapshot));
  } catch (error) {
    console.warn("writeLocalSnapshotForUser error:", error);
  }
}

function readLocalFastSnapshotForUser(userId) {
  try {
    const raw = localStorage.getItem(getLocalFastProgressKey(userId));
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch (error) {
    console.warn("readLocalFastSnapshotForUser error:", error);
    return null;
  }
}

function writeLocalFastSnapshotForUser(userId, snapshot) {
  try {
    localStorage.setItem(getLocalFastProgressKey(userId), JSON.stringify(toFastSnapshot(snapshot)));
  } catch (error) {
    console.warn("writeLocalFastSnapshotForUser error:", error);
  }
}

function getNewestSnapshot(...snapshots) {
  return snapshots
    .filter((snapshot) => snapshot && typeof snapshot === "object")
    .sort((a, b) => getSnapshotSavedAt(b) - getSnapshotSavedAt(a))[0] || null;
}

function readCachedAuthUser() {
  try {
    const raw = localStorage.getItem(SUPABASE_AUTH_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    const session = parsed?.currentSession || parsed?.session || parsed;
    const user = session?.user || parsed?.user || null;
    if (!user?.id) return null;
    return {
      id: user.id,
      email: user.email || "",
      app_metadata: user.app_metadata || {},
      user_metadata: user.user_metadata || {},
    };
  } catch (error) {
    console.warn("readCachedAuthUser error:", error);
    return null;
  }
}

function saveLocalProgressForCurrentUser(snapshot = null) {
  const userId = currentUser?.id;
  if (!userId || !isProgressLoaded || isApplyingRemoteProgress) return null;
  const nextSnapshot = snapshot ?? getSnapshot();
  writeLocalFastSnapshotForUser(userId, nextSnapshot);
  writeLocalSnapshotForUser(userId, nextSnapshot);
  return nextSnapshot;
}

function saveFastProgressForCurrentUser(snapshot = null) {
  const userId = currentUser?.id;
  if (!userId || !isProgressLoaded || isApplyingRemoteProgress) return null;
  const nextSnapshot = snapshot ? toFastSnapshot(snapshot) : getFastSnapshot();
  writeLocalFastSnapshotForUser(userId, nextSnapshot);
  return nextSnapshot;
}

function createTaskId() {
  return `task-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

function normalizeTime(value) {
  const text = String(value || "").trim();
  return /^\d{2}:\d{2}$/.test(text) ? text : "";
}

function normalizeTask(item) {
  const title = String(item?.title || "").trim().slice(0, 60);
  const time = normalizeTime(item?.time);
  if (!title || !time) return null;
  const reports = item?.reports && typeof item.reports === "object" ? item.reports : {};
  return {
    id: String(item?.id || createTaskId()),
    title,
    description: String(item?.description || "").trim().slice(0, 300),
    reward: Math.max(0, Math.floor(toSafeNumber(Number(item?.reward), 0))),
    penalty: Math.max(0, Math.floor(toSafeNumber(Number(item?.penalty), 0))),
    time,
    enabled: item?.enabled !== false,
    reports,
  };
}

function getLocalDateKey(timestamp = Date.now()) {
  const d = new Date(timestamp);
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd}`;
}

function getScheduledTimestampForDate(time, timestamp = Date.now()) {
  const [hours, minutes] = normalizeTime(time).split(":").map(Number);
  const d = new Date(timestamp);
  d.setHours(hours || 0, minutes || 0, 0, 0);
  return d.getTime();
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
    tasksGlobalEnabled,
    tasks,
    soundsEnabled,
    soundVolume,
    history: history.slice(-50000),
  };
}

function toFastSnapshot(snapshot = null) {
  const source = snapshot || {};
  const sourceHistory = Array.isArray(source.history) ? source.history : history;
  return {
    version: source.version || 1,
    savedAt: source.savedAt || Date.now(),
    currentValue: toSafeNumber(source.currentValue, currentValue),
    currentX: toSafeNumber(source.currentX, currentX),
    selectedRange: source.selectedRange || selectedRange,
    selectedViewType: source.selectedViewType || selectedViewType,
    selectedCandleRange: source.selectedCandleRange || selectedCandleRange,
    candleOffset: toSafeNumber(source.candleOffset, candleOffset),
    candleZoom: toSafeNumber(source.candleZoom, candleZoom),
    commentsVisible: source.commentsVisible !== false,
    candleComments: Array.isArray(source.candleComments) ? source.candleComments : candleComments,
    totalPoints: Math.max(0, toSafeNumber(source.totalPoints, totalPoints)),
    levels: Array.isArray(source.levels) ? source.levels : levels,
    tasksGlobalEnabled: source.tasksGlobalEnabled !== false,
    tasks: Array.isArray(source.tasks) ? source.tasks : tasks,
    soundsEnabled: source.soundsEnabled === true,
    soundVolume: Math.max(0, Math.min(1, toSafeNumber(Number(source.soundVolume), soundVolume))),
    history: sourceHistory.slice(-FAST_HISTORY_LIMIT),
  };
}

function getFastSnapshot() {
  return toFastSnapshot({
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
    tasksGlobalEnabled,
    tasks,
    soundsEnabled,
    soundVolume,
    history,
  });
}

function applySnapshot(parsed, options = {}) {
  const shouldUpdateSounds = options.updateSounds === true;
  const rawHistory = Array.isArray(parsed.history) ? parsed.history : [];
  const nextHistory = rawHistory
    .map((item) => ({
      t: toSafeNumber(item?.t, NaN),
      y: toSafeNumber(item?.y, NaN),
    }))
    .filter((item) => Number.isFinite(item.t) && Number.isFinite(item.y))
    .sort((a, b) => a.t - b.t);

  if (nextHistory.length > 0) {
    history.length = 0;
    for (const item of nextHistory) history.push(item);
    lastPointAt = history[history.length - 1].t;
  } else if (history.length === 0) {
    history.push({ t: Date.now(), y: toSafeNumber(parsed.currentValue, currentValue) });
    lastPointAt = history[history.length - 1].t;
  }

  currentValue = toSafeNumber(parsed.currentValue, history[history.length - 1].y);
  previousValue = currentValue;
  currentX = toSafeNumber(parsed.currentX, currentX);
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
  tasksGlobalEnabled = parsed.tasksGlobalEnabled !== false;
  if (Array.isArray(parsed.tasks)) {
    tasks = parsed.tasks
      .map(normalizeTask)
      .filter(Boolean)
      .sort((a, b) => a.time.localeCompare(b.time));
  }
  soundsEnabled = parsed.soundsEnabled === true;
  soundVolume = Math.max(0, Math.min(1, toSafeNumber(Number(parsed.soundVolume), 0.65)));

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
  renderTasksUi();
  renderSoundsUi();
  if (shouldUpdateSounds) updateSoundPlayback();
  return true;
}

function setAuthUiState() {
  const isLoggedIn = Boolean(currentUser);
  const canUseApp = isLoggedIn && isProgressLoaded;
  registerBtn.classList.toggle("hidden", isLoggedIn);
  loginBtn.classList.toggle("hidden", isLoggedIn);
  logoutBtn.classList.toggle("hidden", !isLoggedIn);
  authStatus.textContent = isLoggedIn
    ? (isProgressLoaded ? `В аккаунте: ${currentUser.email || currentUser.id}` : "Загрузка аккаунта...")
    : "Гость";
  for (const node of appPanelsForAuth) {
    if (!node) continue;
    if (canUseApp) node.classList.remove("hidden");
    else node.classList.add("hidden");
  }
  if (!isLoggedIn) {
    closeMobilePanels();
    closeTasksPage();
    closeSoundsPage();
    closeTaskReportModal();
    stopSoundLoop();
    hintNode.textContent = "Войдите или зарегистрируйтесь, чтобы открыть график и прогресс.";
  }
}

async function saveProgressForCurrentUser(snapshot = null) {
  if (!currentUser || !isProgressLoaded || isApplyingRemoteProgress) {
    console.log("saveProgressForCurrentUser: нет залогиненного пользователя");
    return null;
  }
  let ownsSaveLock = false;
  try {
    const userId = currentUser.id;
    if (!userId) {
      console.log("saveProgressForCurrentUser: user id не найден");
      return null;
    }
    const snapshotToSave = snapshot ? toFastSnapshot(snapshot) : getFastSnapshot();
    writeLocalFastSnapshotForUser(userId, snapshotToSave);
    pendingCloudSaveSnapshot = snapshotToSave;
    if (saveInFlight) return null;

    saveInFlight = true;
    ownsSaveLock = true;
    let lastData = null;
    while (pendingCloudSaveSnapshot) {
      const queuedSnapshot = pendingCloudSaveSnapshot;
      pendingCloudSaveSnapshot = null;
      const payload = {
        user_id: userId,
        data: queuedSnapshot,
        updated_at: new Date().toISOString()
      };
      const client = await getSupabaseClient();
      const { data, error } = await client.from("user_data").upsert(payload, { onConflict: "user_id" });
      console.log("saveUserData result:", { userId, savedAt: queuedSnapshot.savedAt, data, error });
      if (error) throw error;
      lastData = data;
    }
    return lastData;
  } catch (error) {
    console.error("saveUserData error:", error);
    return null;
  } finally {
    if (ownsSaveLock) saveInFlight = false;
    if (ownsSaveLock && pendingCloudSaveSnapshot && currentUser?.id) {
      setTimeout(() => saveProgressForCurrentUser(pendingCloudSaveSnapshot), 0);
    }
  }
}
const saveUserData = saveProgressForCurrentUser;

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
    for (const node of [modesNode, timeframeNode, viewTypesNode, candleTimeframesNode, commentControlsNode, tasksTabNode, soundsTabNode, dataControlsNode, authPanelNode, levelsPanelNode].filter(Boolean)) {
      node.style.top = "";
    }
    return;
  }

  const gap = 8;
  const startTop = 10;

  let topLeft = startTop;
  for (const node of [modesNode, timeframeNode, viewTypesNode, candleTimeframesNode, commentControlsNode, tasksTabNode, soundsTabNode]) {
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

  const roundedPoints = Math.floor(totalPoints);
  let current = null;
  for (const lvl of list) {
    if (totalPoints >= lvl.points) current = lvl;
  }
  const next = list.find((lvl) => totalPoints < lvl.points) || null;

  if (levelNameNode) levelNameNode.textContent = current?.name || "Пока нет уровня";
  if (currentLevelPointsNode) currentLevelPointsNode.textContent = `${roundedPoints} очк.`;
  if (currentLevelToggleNode) {
    currentLevelToggleNode.classList.toggle("expanded", levelsExpanded);
    currentLevelToggleNode.setAttribute("aria-expanded", String(levelsExpanded));
  }
  if (currentLevelChevronNode) currentLevelChevronNode.textContent = levelsExpanded ? "⌃" : "⌄";
  if (levelsDetailsNode) levelsDetailsNode.hidden = !levelsExpanded;

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
    const isCurrent = current && lvl.name === current.name && lvl.points === current.points;
    row.classList.toggle("current", Boolean(isCurrent));
    const meta = document.createElement("div");
    meta.className = "meta";
    meta.textContent = `${lvl.name} `;
    const span = document.createElement("span");
    span.textContent = isCurrent ? `(${lvl.points}) · мой уровень` : `(${lvl.points})`;
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

function renderTasksUi() {
  if (tasksGlobalEnabledInput) tasksGlobalEnabledInput.checked = tasksGlobalEnabled;
  const activeCount = tasks.filter((task) => task.enabled).length;
  const dueCount = getDueTasks(Date.now()).length;
  const nextTask = getNextPendingTask();
  if (tasksTabBadgeNode) tasksTabBadgeNode.textContent = String(dueCount || activeCount);
  if (activeTasksCountNode) activeTasksCountNode.textContent = String(activeCount);
  if (dueTasksCountNode) dueTasksCountNode.textContent = String(dueCount);
  if (nextTaskTimeNode) {
    nextTaskTimeNode.textContent = nextTask ? `${nextTask.time} · ${nextTask.title}` : "—";
  }
  if (!tasksListNode) return;
  const list = tasks.slice().sort((a, b) => a.time.localeCompare(b.time));
  tasksListNode.innerHTML = "";
  if (list.length === 0) {
    const empty = document.createElement("div");
    empty.className = "tasks-empty";
    empty.textContent = "Заданий пока нет.";
    tasksListNode.appendChild(empty);
    return;
  }

  for (const task of list) {
    const item = document.createElement("div");
    item.className = "task-item";
    item.classList.toggle("disabled", !task.enabled || !tasksGlobalEnabled);

    const head = document.createElement("div");
    head.className = "task-item-head";

    const meta = document.createElement("div");
    meta.className = "task-item-meta";
    const title = document.createElement("div");
    title.className = "task-item-title";
    title.textContent = task.title;
    const sub = document.createElement("div");
    sub.className = "task-item-sub";
    sub.textContent = `${task.time} · +${task.reward} / -${task.penalty}`;
    meta.appendChild(title);
    meta.appendChild(sub);

    const switchLabel = document.createElement("label");
    switchLabel.className = "switch";
    const switchInput = document.createElement("input");
    switchInput.type = "checkbox";
    switchInput.checked = task.enabled;
    switchInput.addEventListener("change", () => {
      task.enabled = switchInput.checked;
      saveProgressForCurrentUser();
      renderTasksUi();
      checkDueTasks(true);
    });
    const switchSpan = document.createElement("span");
    switchLabel.appendChild(switchInput);
    switchLabel.appendChild(switchSpan);

    head.appendChild(meta);
    head.appendChild(switchLabel);
    item.appendChild(head);

    if (task.description) {
      const desc = document.createElement("div");
      desc.className = "task-item-description";
      desc.textContent = task.description;
      item.appendChild(desc);
    }

    const actions = document.createElement("div");
    actions.className = "task-item-actions";
    const remove = document.createElement("button");
    remove.type = "button";
    remove.textContent = "Удалить";
    remove.addEventListener("click", () => {
      const ok = window.confirm(`Удалить задание “${task.title}”?`);
      if (!ok) return;
      tasks = tasks.filter((itemTask) => itemTask.id !== task.id);
      taskReportQueue = taskReportQueue.filter((itemTask) => itemTask.id !== task.id);
      if (activeTaskReport?.id === task.id) closeTaskReportModal();
      saveProgressForCurrentUser();
      renderTasksUi();
    });
    actions.appendChild(remove);
    item.appendChild(actions);

    tasksListNode.appendChild(item);
  }
}

function getNextPendingTask(now = Date.now()) {
  if (!tasksGlobalEnabled) return null;
  return tasks
    .filter((task) => task.enabled && !task.reports?.[getLocalDateKey(now)])
    .sort((a, b) => {
      const aTime = getScheduledTimestampForDate(a.time, now);
      const bTime = getScheduledTimestampForDate(b.time, now);
      return aTime - bTime;
    })[0] || null;
}

function openTasksPage() {
  renderTasksUi();
  tasksPageNode?.classList.remove("hidden");
}

function closeTasksPage() {
  tasksPageNode?.classList.add("hidden");
}

function openSoundsPage() {
  renderSoundsUi();
  soundsPageNode?.classList.remove("hidden");
  loadSoundsForCurrentUser();
}

function closeSoundsPage() {
  soundsPageNode?.classList.add("hidden");
}

function createSoundId() {
  return `sound-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

function formatBytes(bytes) {
  const value = Number(bytes) || 0;
  if (value < 1024 * 1024) return `${Math.max(1, Math.round(value / 1024))} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function openSoundDb() {
  if (soundDbPromise) return soundDbPromise;
  soundDbPromise = new Promise((resolve, reject) => {
    if (!("indexedDB" in window)) {
      reject(new Error("IndexedDB is not available"));
      return;
    }
    const request = indexedDB.open(SOUND_DB_NAME, 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      const store = db.objectStoreNames.contains(SOUND_STORE_NAME)
        ? request.transaction.objectStore(SOUND_STORE_NAME)
        : db.createObjectStore(SOUND_STORE_NAME, { keyPath: "id" });
      if (!store.indexNames.contains("userId")) store.createIndex("userId", "userId", { unique: false });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error("IndexedDB open failed"));
  });
  return soundDbPromise;
}

async function readSoundRecordsForUser(userId) {
  try {
    const db = await openSoundDb();
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(SOUND_STORE_NAME, "readonly");
      const store = tx.objectStore(SOUND_STORE_NAME);
      const index = store.index("userId");
      const request = index.getAll(userId);
      request.onsuccess = () => resolve((request.result || []).sort((a, b) => a.createdAt - b.createdAt));
      request.onerror = () => reject(request.error);
    });
  } catch (error) {
    console.warn("readSoundRecordsForUser error:", error);
    return [];
  }
}

async function writeSoundRecord(record) {
  const db = await openSoundDb();
  await new Promise((resolve, reject) => {
    const tx = db.transaction(SOUND_STORE_NAME, "readwrite");
    tx.objectStore(SOUND_STORE_NAME).put(record);
    tx.oncomplete = resolve;
    tx.onerror = () => reject(tx.error);
  });
}

async function deleteSoundRecord(id) {
  const db = await openSoundDb();
  await new Promise((resolve, reject) => {
    const tx = db.transaction(SOUND_STORE_NAME, "readwrite");
    tx.objectStore(SOUND_STORE_NAME).delete(id);
    tx.oncomplete = resolve;
    tx.onerror = () => reject(tx.error);
  });
}

async function loadSoundsForCurrentUser() {
  if (!currentUser?.id) {
    soundRecords = [];
    soundsLoadedForUserId = null;
    renderSoundsUi();
    return;
  }
  if (soundsLoadedForUserId === currentUser.id || isLoadingSounds) return;
  isLoadingSounds = true;
  soundRecords = await readSoundRecordsForUser(currentUser.id);
  soundsLoadedForUserId = currentUser.id;
  isLoadingSounds = false;
  renderSoundsUi();
  updateSoundPlayback();
}

function renderSoundsUi() {
  if (soundsEnabledInput) soundsEnabledInput.checked = soundsEnabled;
  if (soundVolumeInput) soundVolumeInput.value = String(soundVolume);
  if (soundsTabBadgeNode) soundsTabBadgeNode.textContent = String(soundRecords.length);
  if (soundsStatusNode) {
    if (!soundRecords.length) {
      soundsStatusNode.textContent = "Р—Р°РїРёСЃРµР№ РїРѕРєР° РЅРµС‚.";
    } else if (soundsEnabled) {
      soundsStatusNode.textContent = "Р—РІСѓРєРё РІРєР»СЋС‡РµРЅС‹. РќР° С‚РµР»РµС„РѕРЅРµ РёРЅРѕРіРґР° РЅСѓР¶РЅРѕ РЅР°Р¶Р°С‚СЊ РїРµСЂРµРєР»СЋС‡Р°С‚РµР»СЊ РїРѕСЃР»Рµ РІРѕР·РІСЂР°С‚Р° РЅР° СЃР°Р№С‚.";
    } else {
      soundsStatusNode.textContent = "Р—РІСѓРєРё РІС‹РєР»СЋС‡РµРЅС‹.";
    }
  }
  if (!soundsListNode) return;
  soundsListNode.innerHTML = "";
  if (!soundRecords.length) {
    const empty = document.createElement("div");
    empty.className = "sounds-empty";
    empty.textContent = "Р”РѕР±Р°РІСЊС‚Рµ Р°СѓРґРёРѕС„Р°Р№Р»С‹, Рё РѕРЅРё РѕСЃС‚Р°РЅСѓС‚СЃСЏ РїРѕСЃР»Рµ РѕР±РЅРѕРІР»РµРЅРёСЏ СЃС‚СЂР°РЅРёС†С‹.";
    soundsListNode.appendChild(empty);
    return;
  }
  for (const record of soundRecords) {
    const item = document.createElement("div");
    item.className = "sound-item";
    const meta = document.createElement("div");
    meta.className = "sound-item-meta";
    const name = document.createElement("div");
    name.className = "sound-item-name";
    name.textContent = record.name || "Аудио";
    const sub = document.createElement("div");
    sub.className = "sound-item-sub";
    sub.textContent = formatBytes(record.size);
    meta.appendChild(name);
    meta.appendChild(sub);
    const remove = document.createElement("button");
    remove.type = "button";
    remove.textContent = "РЈРґР°Р»РёС‚СЊ";
    remove.addEventListener("click", async () => {
      await deleteSoundRecord(record.id);
      soundRecords = soundRecords.filter((itemRecord) => itemRecord.id !== record.id);
      soundCurrentIndex = 0;
      renderSoundsUi();
      updateSoundPlayback();
    });
    item.appendChild(meta);
    item.appendChild(remove);
    soundsListNode.appendChild(item);
  }
}

function localizeSoundsStaticUi() {
  const openSoundsText = openSoundsBtn?.firstChild;
  if (openSoundsText) openSoundsText.textContent = "Звуки ";
  const title = document.querySelector(".sounds-page-title");
  if (title) title.textContent = "Звуки";
  const subtitle = document.querySelector(".sounds-page-subtitle");
  if (subtitle) subtitle.textContent = "Аудиозаписи для фонового воспроизведения";
  if (closeSoundsBtn) closeSoundsBtn.textContent = "Закрыть";
  const globalLabel = document.querySelector(".sounds-global-row > span");
  if (globalLabel) globalLabel.textContent = "Проигрывать звуки";
  const volumeLabel = document.querySelector(".sounds-controls label:first-child > span");
  if (volumeLabel) volumeLabel.textContent = "Громкость";
  const uploadLabel = document.querySelector(".sound-upload > span");
  if (uploadLabel) uploadLabel.textContent = "Добавить аудио";
}

renderSoundsUi = function renderSoundsUiRu() {
  localizeSoundsStaticUi();
  if (soundsEnabledInput) soundsEnabledInput.checked = soundsEnabled;
  if (soundVolumeInput) soundVolumeInput.value = String(soundVolume);
  if (soundsTabBadgeNode) soundsTabBadgeNode.textContent = String(soundRecords.length);
  if (soundsStatusNode) {
    if (!soundRecords.length) {
      soundsStatusNode.textContent = "Записей пока нет.";
    } else if (soundsEnabled) {
      soundsStatusNode.textContent = "Звуки включены. На телефоне иногда нужно нажать переключатель после возврата на сайт.";
    } else {
      soundsStatusNode.textContent = "Звуки выключены.";
    }
  }
  if (!soundsListNode) return;
  soundsListNode.innerHTML = "";
  if (!soundRecords.length) {
    const empty = document.createElement("div");
    empty.className = "sounds-empty";
    empty.textContent = "Добавьте аудиофайлы, и они останутся после обновления страницы.";
    soundsListNode.appendChild(empty);
    return;
  }
  for (const record of soundRecords) {
    const item = document.createElement("div");
    item.className = "sound-item";
    const meta = document.createElement("div");
    meta.className = "sound-item-meta";
    const name = document.createElement("div");
    name.className = "sound-item-name";
    name.textContent = record.name || "audio";
    const sub = document.createElement("div");
    sub.className = "sound-item-sub";
    sub.textContent = formatBytes(record.size);
    meta.appendChild(name);
    meta.appendChild(sub);
    const remove = document.createElement("button");
    remove.type = "button";
    remove.textContent = "Удалить";
    remove.addEventListener("click", async () => {
      await deleteSoundRecord(record.id);
      soundRecords = soundRecords.filter((itemRecord) => itemRecord.id !== record.id);
      soundCurrentIndex = 0;
      renderSoundsUi();
      updateSoundPlayback();
    });
    item.appendChild(meta);
    item.appendChild(remove);
    soundsListNode.appendChild(item);
  }
};

function stopSoundLoop() {
  soundPlayer.pause();
  soundPlayer.removeAttribute("src");
  soundPlayer.load();
  if (soundCurrentUrl) URL.revokeObjectURL(soundCurrentUrl);
  soundCurrentUrl = null;
  isSoundLoopStarting = false;
}

function playNextSound() {
  if (!soundsEnabled || !soundRecords.length) {
    stopSoundLoop();
    return;
  }
  const record = soundRecords[soundCurrentIndex % soundRecords.length];
  soundCurrentIndex = (soundCurrentIndex + 1) % soundRecords.length;
  if (soundCurrentUrl) URL.revokeObjectURL(soundCurrentUrl);
  soundCurrentUrl = URL.createObjectURL(record.blob);
  soundPlayer.src = soundCurrentUrl;
  soundPlayer.volume = soundVolume;
  soundPlayer.play().catch((error) => {
    console.warn("sound playback blocked:", error);
    stopSoundLoop();
    if (soundsStatusNode) {
      soundsStatusNode.textContent = "Р‘СЂР°СѓР·РµСЂ Р·Р°Р±Р»РѕРєРёСЂРѕРІР°Р» Р°РІС‚РѕР·Р°РїСѓСЃРє. РћС‚РєСЂРѕР№С‚Рµ РІРєР»Р°РґРєСѓ Рё РЅР°Р¶РјРёС‚Рµ РїРµСЂРµРєР»СЋС‡Р°С‚РµР»СЊ Р·РІСѓРєРѕРІ.";
    }
  });
}

function updateSoundPlayback() {
  soundPlayer.volume = soundVolume;
  if (!soundsEnabled || !soundRecords.length) {
    stopSoundLoop();
    return;
  }
  if (isSoundLoopStarting || !soundPlayer.paused) return;
  isSoundLoopStarting = true;
  playNextSound();
  isSoundLoopStarting = false;
}

soundPlayer.addEventListener("ended", playNextSound);

function insertHistoryPoint(timestamp, value) {
  history.push({ t: timestamp, y: value });
  history.sort((a, b) => a.t - b.t);
  lastPointAt = Math.max(lastPointAt, timestamp);
  const minAllowed = Date.now() - maxHistoryMs;
  while (history.length > 2 && history[1].t < minAllowed) {
    history.shift();
  }
}

function applyTaskScore(deltaPoints, timestamp) {
  const nextPoints = Math.max(0, totalPoints + deltaPoints);
  totalPoints = nextPoints;
  previousValue = currentValue;
  currentValue = -(nextPoints / valueStepPerGrid) * gridStepPx;
  insertHistoryPoint(timestamp, currentValue);
  addHistoryPoint(Date.now());
  initLiveLine();
  renderLevelsUi();
  updateHud();
  render();
}

function getDueTasks(now = Date.now()) {
  if (!tasksGlobalEnabled) return [];
  const today = getLocalDateKey(now);
  return tasks
    .filter((task) => {
      if (!task.enabled) return false;
      if (task.reports?.[today]) return false;
      return getScheduledTimestampForDate(task.time, now) <= now;
    })
    .sort((a, b) => a.time.localeCompare(b.time));
}

function checkDueTasks(force = false) {
  if (!currentUser || !isProgressLoaded) return;
  const now = Date.now();
  if (!force && now - lastTaskCheckAt < 5000) return;
  lastTaskCheckAt = now;
  if (activeTaskReport) return;
  taskReportQueue = getDueTasks(now);
  openNextTaskReport();
}

function openNextTaskReport() {
  if (activeTaskReport || !taskReportModalNode) return;
  const next = taskReportQueue.shift();
  if (!next) return;
  activeTaskReport = next;
  const scheduledAt = getScheduledTimestampForDate(next.time);
  taskReportTimeNode.textContent = `Нужно было выполнить: ${formatOpenTime(scheduledAt)}`;
  taskReportNameNode.textContent = next.title;
  taskReportDescriptionNode.textContent = next.description || "";
  taskReportDescriptionNode.classList.toggle("hidden", !next.description);
  taskReportPointsNode.textContent = `Да: +${next.reward} · Нет: -${next.penalty} · Игнор: 0`;
  taskReportModalNode.classList.remove("hidden");
}

function closeTaskReportModal() {
  taskReportModalNode?.classList.add("hidden");
  activeTaskReport = null;
}

function answerActiveTask(status) {
  if (!activeTaskReport) return;
  const task = tasks.find((item) => item.id === activeTaskReport.id);
  if (!task) {
    closeTaskReportModal();
    openNextTaskReport();
    return;
  }
  const now = Date.now();
  const dateKey = getLocalDateKey(now);
  const scheduledAt = getScheduledTimestampForDate(task.time, now);
  task.reports = task.reports && typeof task.reports === "object" ? task.reports : {};
  task.reports[dateKey] = { status, answeredAt: now, scheduledAt };
  if (status === "done") applyTaskScore(task.reward, scheduledAt);
  if (status === "failed") applyTaskScore(-task.penalty, scheduledAt);
  closeTaskReportModal();
  saveProgressForCurrentUser();
  renderTasksUi();
  openNextTaskReport();
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
  for (const node of [modesNode, timeframeNode, viewTypesNode, candleTimeframesNode, commentControlsNode, tasksTabNode, soundsTabNode, dataControlsNode, authPanelNode, levelsPanelNode]) {
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
    tasksTab: tasksTabNode,
    soundsTab: soundsTabNode,
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
  checkDueTasks();
  addHistoryPoint(Date.now());
  if (currentUser && isProgressLoaded && now - lastFastSaveAt >= FAST_SAVE_MS && currentValue !== lastFastSavedValue) {
    saveFastProgressForCurrentUser();
    lastFastSaveAt = now;
    lastFastSavedValue = currentValue;
  }
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
  const shouldSave = isMouseDown && selectedMode === "live" && pointerDidDrag;
  isMouseDown = false;
  if (shouldSave) saveProgressForCurrentUser();
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
      pointerDidDrag = false;
      pointerDownX = touches[0].clientX;
      pointerDownY = touches[0].clientY;
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
      if (Math.abs(touch.clientX - pointerDownX) > 6 || Math.abs(touch.clientY - pointerDownY) > 6) {
        pointerDidDrag = true;
      }
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
      const shouldSave = isMouseDown && pointerDidDrag;
      isMouseDown = false;
      if (shouldSave) saveProgressForCurrentUser();
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

openTasksBtn?.addEventListener("click", openTasksPage);
closeTasksBtn?.addEventListener("click", closeTasksPage);
openSoundsBtn?.addEventListener("click", openSoundsPage);
closeSoundsBtn?.addEventListener("click", closeSoundsPage);

tasksGlobalEnabledInput?.addEventListener("change", () => {
  tasksGlobalEnabled = tasksGlobalEnabledInput.checked;
  saveProgressForCurrentUser();
  renderTasksUi();
  if (tasksGlobalEnabled) checkDueTasks(true);
});

soundsEnabledInput?.addEventListener("change", () => {
  soundsEnabled = soundsEnabledInput.checked;
  saveProgressForCurrentUser();
  renderSoundsUi();
  if (soundsLoadedForUserId !== currentUser?.id) {
    loadSoundsForCurrentUser().then(updateSoundPlayback);
  } else {
    updateSoundPlayback();
  }
});

soundVolumeInput?.addEventListener("input", () => {
  soundVolume = Math.max(0, Math.min(1, Number(soundVolumeInput.value) || 0));
  soundPlayer.volume = soundVolume;
});

soundVolumeInput?.addEventListener("change", () => {
  soundVolume = Math.max(0, Math.min(1, Number(soundVolumeInput.value) || 0));
  saveProgressForCurrentUser();
  renderSoundsUi();
});

soundFileInput?.addEventListener("change", (event) => {
  const files = Array.from(event.target.files || []).filter((file) => file.type.startsWith("audio/"));
  if (!files.length || !currentUser?.id) return;
  const records = files.map((file) => ({
    id: createSoundId(),
    userId: currentUser.id,
    name: file.name,
    type: file.type || "audio/mpeg",
    size: file.size,
    createdAt: Date.now(),
    blob: file,
  }));

  soundsEnabled = true;
  soundRecords.push(...records);
  soundRecords.sort((a, b) => a.createdAt - b.createdAt);
  soundFileInput.value = "";
  saveProgressForCurrentUser();
  renderSoundsUi();
  updateSoundPlayback();

  Promise.all(records.map(writeSoundRecord)).catch((error) => {
    console.warn("writeSoundRecord error:", error);
    const failedIds = new Set(records.map((record) => record.id));
    soundRecords = soundRecords.filter((record) => !failedIds.has(record.id));
    soundCurrentIndex = 0;
    renderSoundsUi();
    updateSoundPlayback();
  });
});

taskFormNode?.addEventListener("submit", (event) => {
  event.preventDefault();
  const task = normalizeTask({
    title: taskTitleInput?.value,
    description: taskDescriptionInput?.value,
    reward: Number(taskRewardInput?.value),
    penalty: Number(taskPenaltyInput?.value),
    time: taskTimeInput?.value,
    enabled: true,
    reports: {},
  });
  if (!task) return;
  tasks = tasks.concat(task).sort((a, b) => a.time.localeCompare(b.time));
  taskFormNode.reset();
  saveProgressForCurrentUser();
  renderTasksUi();
  checkDueTasks(true);
});

taskDoneBtn?.addEventListener("click", () => answerActiveTask("done"));
taskFailedBtn?.addEventListener("click", () => answerActiveTask("failed"));
taskIgnoreBtn?.addEventListener("click", () => answerActiveTask("ignored"));

currentLevelToggleNode?.addEventListener("click", () => {
  levelsExpanded = !levelsExpanded;
  renderLevelsUi();
  layoutControls();
});

addLevelBtn?.addEventListener("click", () => {
  const name = String(levelNameInput?.value || "").trim().slice(0, 30);
  const ptsRaw = Number(levelPointsInput?.value);
  const pts = Math.max(0, Math.floor(toSafeNumber(ptsRaw, NaN)));
  if (!name || !Number.isFinite(pts)) return;
  levelsExpanded = true;
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

window.addEventListener("beforeunload", () => {
  const snapshot = saveFastProgressForCurrentUser();
  if (snapshot) pendingCloudSaveSnapshot = snapshot;
  saveProgressForCurrentUser(snapshot);
});

window.addEventListener("pagehide", () => {
  saveFastProgressForCurrentUser();
});

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "hidden") {
    saveFastProgressForCurrentUser();
  }
});

registerBtn.addEventListener("click", async () => {
  const email = authEmail.value;
  const password = authPassword.value;

  const client = await getSupabaseClient();
  const { error } = await client.auth.signUp({
    email,
    password
  });

  if (error) {
    authStatus.textContent = "Ошибка регистрации: " + error.message;
    return;
  }

  authStatus.textContent = "Регистрация успешна. Проверьте email.";
});

loginBtn.addEventListener("click", async () => {
  const email = authEmail.value;
  const password = authPassword.value;
  isProgressLoaded = false;

  const client = await getSupabaseClient();
  const { data, error } = await client.auth.signInWithPassword({
    email,
    password
  });

  if (error) {
    authStatus.textContent = "Ошибка входа: " + error.message;
    return;
  }

  currentUser = data.user;
  authStatus.textContent = "Вы вошли: " + currentUser.email;
  await loadCurrentUserData(data.session);
});

logoutBtn.addEventListener("click", async () => {
  await saveProgressForCurrentUser();
  const client = await getSupabaseClient();
  await client.auth.signOut();
  currentUser = null;
  lastSessionUserId = null;
  isProgressLoaded = false;
  soundRecords = [];
  soundsLoadedForUserId = null;
  soundsEnabled = false;
  stopSoundLoop();
  authStatus.textContent = "Вы вышли";
  setAuthUiState();
  renderSoundsUi();
});

async function handleRegisterClick(event) {
  event.preventDefault();
  event.stopImmediatePropagation();
  const email = authEmail.value;
  const password = authPassword.value;
  authStatus.textContent = "Регистрация...";
  setAuthBusy(true);
  try {
    const client = await withTimeout(getSupabaseClient(), 10000, "supabase");
    const { error } = await withTimeout(client.auth.signUp({ email, password }), 15000, "sign up");
    if (error) {
      authStatus.textContent = "Ошибка регистрации: " + error.message;
      return;
    }
    authStatus.textContent = "Регистрация успешна. Проверьте email.";
  } catch (error) {
    console.error("register error:", error);
    if (!supabase) supabaseClientPromise = null;
    authStatus.textContent = "Не удалось зарегистрироваться. Проверьте интернет и настройки Supabase.";
  } finally {
    setAuthBusy(false);
  }
}

async function handleLoginClick(event) {
  event.preventDefault();
  event.stopImmediatePropagation();
  const email = authEmail.value;
  const password = authPassword.value;
  authStatus.textContent = "Вход...";
  setAuthBusy(true);
  try {
    const client = await withTimeout(getSupabaseClient(), 10000, "supabase");
    const { data, error } = await withTimeout(client.auth.signInWithPassword({ email, password }), 15000, "sign in");
    if (error) {
      authStatus.textContent = "Ошибка входа: " + error.message;
      isProgressLoaded = Boolean(currentUser?.id);
      setAuthUiState();
      return;
    }

    currentUser = data.user;
    lastSessionUserId = data.user?.id || null;
    isProgressLoaded = true;
    authStatus.textContent = "Вы вошли: " + (currentUser.email || currentUser.id);

    const cachedSnapshot = getNewestSnapshot(
      readLocalFastSnapshotForUser(currentUser.id),
      readLocalSnapshotForUser(currentUser.id)
    );
    if (cachedSnapshot) {
      isApplyingRemoteProgress = true;
      applySnapshot(cachedSnapshot);
      isApplyingRemoteProgress = false;
    }
    setAuthUiState();
    render();
    checkDueTasks(true);
    loadCurrentUserData(data.session);
  } catch (error) {
    console.error("login error:", error);
    if (!supabase) supabaseClientPromise = null;
    authStatus.textContent = "Не удалось войти. Проверьте интернет и настройки Supabase.";
    isProgressLoaded = Boolean(currentUser?.id);
    setAuthUiState();
  } finally {
    setAuthBusy(false);
  }
}

async function handleLogoutClick(event) {
  event.preventDefault();
  event.stopImmediatePropagation();
  const snapshot = saveFastProgressForCurrentUser();
  if (snapshot) pendingCloudSaveSnapshot = snapshot;
  const previousUserId = currentUser?.id || null;

  currentUser = null;
  lastSessionUserId = null;
  isProgressLoaded = false;
  soundRecords = [];
  soundsLoadedForUserId = null;
  soundsEnabled = false;
  stopSoundLoop();
  try {
    localStorage.removeItem(SUPABASE_AUTH_STORAGE_KEY);
  } catch (error) {
    console.warn("clear auth storage error:", error);
  }
  authStatus.textContent = "Вы вышли";
  setAuthUiState();
  renderSoundsUi();

  try {
    const client = await withTimeout(getSupabaseClient(), 10000, "supabase");
    await withTimeout(client.auth.signOut(), 10000, "sign out");
  } catch (error) {
    console.warn("remote sign out failed:", error);
    if (!supabase) supabaseClientPromise = null;
  }
  if (previousUserId) pendingCloudSaveSnapshot = null;
}

registerBtn.addEventListener("click", handleRegisterClick, true);
loginBtn.addEventListener("click", handleLoginClick, true);
logoutBtn.addEventListener("click", handleLogoutClick, true);

resizeCanvas();
initLiveLine();
addHistoryPoint(Date.now());
layoutControls();
renderLevelsUi();
renderTasksUi();
renderSoundsUi();
if (location.protocol.startsWith("http")) {
  setShareLink(`Ссылка: ${location.origin}/`);
} else {
  setShareLink("Ссылка: опубликуйте сайт на Netlify");
}

async function loadCurrentUserData(session = null) {
  const loadToken = ++latestLoadToken;
  const hadReadyUser = Boolean(currentUser?.id && isProgressLoaded);
  if (!hadReadyUser) isProgressLoaded = false;
  try {
    let activeSession = session;
    const client = await getSupabaseClient();
    if (!activeSession) {
      const { data: sessionData, error: sessionError } = await client.auth.getSession();
      console.log("Supabase getSession result:", sessionData, sessionError);
      if (sessionError) throw sessionError;
      activeSession = sessionData?.session || null;
    }
    if (loadToken !== latestLoadToken) return;
    const user = activeSession?.user || null;
    console.log("Supabase session user result:", user);
    if (!user) {
      lastSessionUserId = null;
      currentUser = null;
      soundRecords = [];
      soundsLoadedForUserId = null;
      soundsEnabled = false;
      setAuthUiState();
      renderSoundsUi();
      updateHud();
      setMode("live");
      return;
    }
    lastSessionUserId = user.id;
    currentUser = user;
    setAuthUiState();
    const { data, error } = await client
      .from("user_data")
      .select("data")
      .eq("user_id", user.id)
      .maybeSingle();
    console.log("loadUserData result:", { userId: user.id, data, error });
    if (error) throw error;
    if (loadToken !== latestLoadToken) return;
    const localSnapshot = readLocalSnapshotForUser(user.id);
    const localFastSnapshot = readLocalFastSnapshotForUser(user.id);
    const localNewestSnapshot = getNewestSnapshot(localFastSnapshot, localSnapshot);
    const newestSnapshot = hadReadyUser && localNewestSnapshot
      ? localNewestSnapshot
      : getNewestSnapshot(data?.data, localSnapshot, localFastSnapshot);
    if (newestSnapshot) {
      isApplyingRemoteProgress = true;
      applySnapshot(newestSnapshot);
      isApplyingRemoteProgress = false;
      writeLocalFastSnapshotForUser(user.id, newestSnapshot);
      updateHud();
    }
    isProgressLoaded = true;
    if (newestSnapshot && newestSnapshot !== data?.data && getSnapshotSavedAt(newestSnapshot) > getSnapshotSavedAt(data?.data)) {
      saveProgressForCurrentUser(newestSnapshot);
    }
    setAuthUiState();
    render();
    checkDueTasks(true);
  } catch (error) {
    console.error("loadUserData error:", error);
    isApplyingRemoteProgress = false;
    if (currentUser?.id) {
      const localSnapshot = getNewestSnapshot(readLocalSnapshotForUser(currentUser.id), readLocalFastSnapshotForUser(currentUser.id));
      if (localSnapshot) {
        isApplyingRemoteProgress = true;
        applySnapshot(localSnapshot);
        isApplyingRemoteProgress = false;
        writeLocalFastSnapshotForUser(currentUser.id, localSnapshot);
      }
      isProgressLoaded = true;
    } else {
      isProgressLoaded = false;
    }
    setAuthUiState();
  }
}

function bootstrapCachedAccount() {
  const cachedUser = readCachedAuthUser();
  if (!cachedUser?.id) {
    setAuthUiState();
    return false;
  }

  currentUser = cachedUser;
  lastSessionUserId = cachedUser.id;
  isProgressLoaded = true;

  const snapshot = getNewestSnapshot(
    readLocalFastSnapshotForUser(cachedUser.id),
    readLocalSnapshotForUser(cachedUser.id)
  );

  if (snapshot) {
    isApplyingRemoteProgress = true;
    applySnapshot(snapshot);
    isApplyingRemoteProgress = false;
    saveFastProgressForCurrentUser(snapshot);
  }

  updateHud();
  setAuthUiState();
  render();
  checkDueTasks(true);
  return true;
}

async function initializeAuth() {
  try {
    const client = await getSupabaseClient();
    const { data: sessionData, error: sessionError } = await client.auth.getSession();
    console.log("Supabase initializeAuth getSession:", sessionData, sessionError);
    if (sessionError) throw sessionError;
    await loadCurrentUserData(sessionData?.session || null);
  } catch (error) {
    console.error("Supabase initializeAuth error:", error);
    await loadCurrentUserData();
  }
}
bootstrapCachedAccount();
initializeAuth();
getSupabaseClient()
  .then((client) => {
    client.auth.onAuthStateChange((event, session) => {
      console.log("Supabase auth state change:", event, session);
      const sessionUserId = session?.user?.id || null;
      if (sessionUserId === lastSessionUserId && currentUser?.id === sessionUserId && isProgressLoaded) {
        return;
      }
      if (!sessionUserId && !lastSessionUserId && !currentUser) {
        return;
      }
      loadCurrentUserData(session);
    });
  })
  .catch((error) => {
    console.error("Supabase auth listener error:", error);
  });
setMode("live");
requestAnimationFrame(frame);
