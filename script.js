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
const disciplineTabNode = document.getElementById("disciplineTab");
const openDisciplineBtn = document.getElementById("openDisciplineBtn");
const disciplineTabBadgeNode = document.getElementById("disciplineTabBadge");
const soundsTabNode = document.getElementById("soundsTab");
const openSoundsBtn = document.getElementById("openSoundsBtn");
const tasksPageNode = document.getElementById("tasksPage");
const closeTasksBtn = document.getElementById("closeTasksBtn");
const disciplinePageNode = document.getElementById("disciplinePage");
const closeDisciplineBtn = document.getElementById("closeDisciplineBtn");
const disciplinePenaltyBtn = document.getElementById("disciplinePenaltyBtn");
const disciplineTodaySummaryNode = document.getElementById("disciplineTodaySummary");
const disciplineDaysNode = document.getElementById("disciplineDays");
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
const marathonFormNode = document.getElementById("marathonForm");
const marathonTitleInput = document.getElementById("marathonTitleInput");
const marathonDaysInput = document.getElementById("marathonDaysInput");
const marathonTaskCountInput = document.getElementById("marathonTaskCountInput");
const marathonsListNode = document.getElementById("marathonsList");
const tasksListNode = document.getElementById("tasksList");
const tasksTabBadgeNode = document.getElementById("tasksTabBadge");
const activeTasksCountNode = document.getElementById("activeTasksCount");
const dueTasksCountNode = document.getElementById("dueTasksCount");
const nextTaskTimeNode = document.getElementById("nextTaskTime");
const regularTasksCountNode = document.getElementById("regularTasksCount");
const marathonsCountNode = document.getElementById("marathonsCount");
const marathonCompletedCountNode = document.getElementById("marathonCompletedCount");
const marathonFailedCountNode = document.getElementById("marathonFailedCount");
const marathonCompletedListNode = document.getElementById("marathonCompletedList");
const marathonFailedListNode = document.getElementById("marathonFailedList");
const taskReportModalNode = document.getElementById("taskReportModal");
const taskReportTimeNode = document.getElementById("taskReportTime");
const taskReportNameNode = document.getElementById("taskReportName");
const taskReportDescriptionNode = document.getElementById("taskReportDescription");
const taskReportPointsNode = document.getElementById("taskReportPoints");
const taskDeleteBtn = document.getElementById("taskDeleteBtn");
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
  disciplineTabNode,
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
const history = [];
let lastPointAt = 0;

const rangeMap = {
  "1h": 60 * 60 * 1000,
  "1d": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
  "15d": 15 * 24 * 60 * 60 * 1000,
  "30d": 30 * 24 * 60 * 60 * 1000,
};

const DEFAULT_LEVELS = [
  { name: "Новичок", points: 0 },
  { name: "Уверенный", points: 200 },
  { name: "Профи", points: 600 },
];
const DISCIPLINE_START_DATE = "2026-06-11";
const DISCIPLINE_RESET_VERSION = "discipline-2026-06-11-v1";

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
let isCloudProgressReconciled = false;
let isApplyingRemoteProgress = false;
let authStatusOverride = "";
let lastAutosaveAt = 0;
let totalPoints = 0;
let levelsExpanded = false;
let tasksGlobalEnabled = true;
let taskReportQueue = [];
let activeTaskReport = null;
let lastTaskCheckAt = 0;
let disciplineStartDate = DISCIPLINE_START_DATE;
let disciplineDays = {};
let disciplineSavedAt = 0;
let disciplineResetVersion = DISCIPLINE_RESET_VERSION;
let pendingDisciplineCloudSave = false;
let lastDisciplineAutoKey = "";
let soundsEnabled = false;
let soundVolume = 0.65;
let soundRecords = [];
let soundDbPromise = null;
let soundCurrentUrl = null;
let soundCurrentIndex = -1;
let isSoundLoopStarting = false;
let levels = DEFAULT_LEVELS.map((level) => ({ ...level }));
let tasks = [];
let marathons = [];
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
const LOCAL_DISCIPLINE_PREFIX = "productiv-line-discipline:";
const SOUND_DB_NAME = "productiv-line-sounds";
const SOUND_STORE_NAME = "sounds";
const SUPABASE_AUTH_STORAGE_KEY = "productiv-line-auth";
const FAST_HISTORY_LIMIT = 5000;
const RECENT_HISTORY_LIMIT = 5000;
const HISTORY_PAGE_LIMIT = 5000;
const HISTORY_LOAD_MARGIN_MS = 2 * 60 * 1000;
const HISTORY_UPSERT_CHUNK_SIZE = 500;
const MOBILE_LAYOUT_MAX = 760;
const DISCIPLINE_SLOTS_PER_HOUR = 3;
const DISCIPLINE_HOURS_PER_DAY = 24;
const DISCIPLINE_SLOT_COUNT = DISCIPLINE_SLOTS_PER_HOUR * DISCIPLINE_HOURS_PER_DAY;
const DISCIPLINE_SLOT_MS = 20 * 60 * 1000;

let saveInFlight = false;
let pendingCloudSaveSnapshot = null;
const pendingHistoryPointMap = new Map();
let latestLoadToken = 0;
let lastSessionUserId = null;
let lastFastSaveAt = 0;
let lastFastSavedValue = currentValue;
let soundsLoadedForUserId = null;
let isLoadingSounds = false;
let isLoadingOlderHistory = false;
let hasMoreOlderHistory = true;

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

function getLocalDisciplineKey(userId = null) {
  return `${LOCAL_DISCIPLINE_PREFIX}${userId || "guest"}`;
}

function getSnapshotSavedAt(snapshot) {
  if (!snapshot || typeof snapshot !== "object") return 0;
  const numericSavedAt = Number(snapshot.savedAt);
  if (Number.isFinite(numericSavedAt)) return numericSavedAt;
  const parsedSavedAt = Date.parse(snapshot.savedAt || "");
  return Number.isFinite(parsedSavedAt) ? parsedSavedAt : 0;
}

function describeSnapshotSavedAt(snapshot) {
  const timestamp = getSnapshotSavedAt(snapshot);
  const date = new Date(timestamp);
  const iso = timestamp > 0 && Number.isFinite(date.getTime()) ? date.toISOString() : null;
  return {
    raw: snapshot?.savedAt ?? null,
    timestamp,
    iso,
  };
}

function getSnapshotSourceName(snapshot, supabaseSnapshot, localFastSnapshot, localSnapshot) {
  if (!snapshot) return "none";
  if (snapshot === supabaseSnapshot) return "supabase";
  if (snapshot === localFastSnapshot) return "localStorage fast";
  if (snapshot === localSnapshot) return "localStorage";
  return "unknown";
}

function logProgressSnapshotChoice(userId, supabaseSnapshot, localSnapshot, localFastSnapshot, selectedSnapshot) {
  console.log("progress snapshot choice:", {
    userId,
    supabaseSavedAt: describeSnapshotSavedAt(supabaseSnapshot),
    localStorageSavedAt: describeSnapshotSavedAt(localSnapshot),
    localFastStorageSavedAt: describeSnapshotSavedAt(localFastSnapshot),
    selected: getSnapshotSourceName(selectedSnapshot, supabaseSnapshot, localFastSnapshot, localSnapshot),
    selectedSavedAt: describeSnapshotSavedAt(selectedSnapshot),
  });
}

function getProgressLoadErrorMessage(error) {
  const message = String(error?.message || "");
  if (message.includes("Supabase is not configured")) return message;
  return "Не удалось загрузить прогресс из Supabase. Проверьте интернет и настройки Supabase.";
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

function normalizeHistoryPoint(item) {
  const t = toSafeNumber(Number(item?.t), NaN);
  const y = toSafeNumber(Number(item?.y), NaN);
  if (!Number.isFinite(t) || !Number.isFinite(y)) return null;
  return { t: Math.floor(t), y };
}

function normalizeHistoryPoints(points) {
  if (!Array.isArray(points)) return [];
  return points.map(normalizeHistoryPoint).filter(Boolean);
}

function getHistoryPointKey(point) {
  return String(Math.floor(point.t));
}

function mergeHistoryPoints(...groups) {
  const byTime = new Map();
  for (const group of groups) {
    for (const point of normalizeHistoryPoints(group)) {
      byTime.set(getHistoryPointKey(point), point);
    }
  }
  return Array.from(byTime.values()).sort((a, b) => a.t - b.t);
}

function replaceHistoryPoints(points) {
  const merged = mergeHistoryPoints(points);
  history.length = 0;
  for (const point of merged) history.push(point);
  if (history.length > 0) lastPointAt = history[history.length - 1].t;
}

function mergeIntoHistory(points) {
  const merged = mergeHistoryPoints(history, points);
  history.length = 0;
  for (const point of merged) history.push(point);
  if (history.length > 0) lastPointAt = Math.max(lastPointAt, history[history.length - 1].t);
  return merged.length;
}

function queueHistoryPointForCloud(point) {
  const normalized = normalizeHistoryPoint(point);
  if (!normalized || !currentUser?.id || !isProgressLoaded || !isCloudProgressReconciled || isApplyingRemoteProgress) return;
  pendingHistoryPointMap.set(getHistoryPointKey(normalized), normalized);
}

function queueHistoryPointsForCloud(points) {
  for (const point of normalizeHistoryPoints(points)) queueHistoryPointForCloud(point);
}

async function upsertHistoryPointsForUser(userId, points) {
  const normalized = mergeHistoryPoints(points);
  if (!userId || normalized.length === 0) return 0;
  const client = await getSupabaseClient();
  let savedCount = 0;
  for (let i = 0; i < normalized.length; i += HISTORY_UPSERT_CHUNK_SIZE) {
    const chunk = normalized.slice(i, i + HISTORY_UPSERT_CHUNK_SIZE);
    const rows = chunk.map((point) => ({
      user_id: userId,
      t: point.t,
      y: point.y,
    }));
    const { error } = await client.from("history_points").upsert(rows, { onConflict: "user_id,t" });
    if (error) throw error;
    savedCount += rows.length;
  }
  if (savedCount > 0) console.log("saveHistoryPoints result:", { userId, savedCount });
  return savedCount;
}

async function flushPendingHistoryPointsForUser(userId) {
  if (!userId || pendingHistoryPointMap.size === 0) return 0;
  const points = Array.from(pendingHistoryPointMap.values()).sort((a, b) => a.t - b.t);
  pendingHistoryPointMap.clear();
  try {
    return await upsertHistoryPointsForUser(userId, points);
  } catch (error) {
    for (const point of points) pendingHistoryPointMap.set(getHistoryPointKey(point), point);
    throw error;
  }
}

async function loadRecentHistoryPointsForUser(userId) {
  const client = await getSupabaseClient();
  const { data, error } = await client
    .from("history_points")
    .select("t,y")
    .eq("user_id", userId)
    .order("t", { ascending: false })
    .limit(RECENT_HISTORY_LIMIT);
  if (error) throw error;
  const points = normalizeHistoryPoints(data).sort((a, b) => a.t - b.t);
  console.log("loadRecentHistoryPoints result:", { userId, count: points.length });
  hasMoreOlderHistory = points.length >= RECENT_HISTORY_LIMIT;
  return points;
}

async function loadOlderHistoryPointsForCurrentUser() {
  if (!currentUser?.id || !isProgressLoaded || !isCloudProgressReconciled) return 0;
  if (isLoadingOlderHistory || !hasMoreOlderHistory || history.length === 0) return 0;
  isLoadingOlderHistory = true;
  const userId = currentUser.id;
  const beforeT = history[0].t;
  try {
    const client = await getSupabaseClient();
    const { data, error } = await client
      .from("history_points")
      .select("t,y")
      .eq("user_id", userId)
      .lt("t", beforeT)
      .order("t", { ascending: false })
      .limit(HISTORY_PAGE_LIMIT);
    if (error) throw error;
    const points = normalizeHistoryPoints(data).sort((a, b) => a.t - b.t);
    if (points.length < HISTORY_PAGE_LIMIT) hasMoreOlderHistory = false;
    mergeIntoHistory(points);
    console.log("loadOlderHistoryPoints result:", { userId, beforeT, count: points.length, hasMoreOlderHistory });
    if (points.length > 0) render();
    return points.length;
  } catch (error) {
    console.warn("loadOlderHistoryPoints error:", error);
    return 0;
  } finally {
    isLoadingOlderHistory = false;
  }
}

function ensureHistoryWindowLoaded(startTimestamp) {
  if (!currentUser?.id || !isProgressLoaded || !isCloudProgressReconciled) return;
  if (history.length === 0) return;
  if (startTimestamp <= history[0].t + HISTORY_LOAD_MARGIN_MS) {
    loadOlderHistoryPointsForCurrentUser();
  }
}

function createTaskId() {
  return `task-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

function createMarathonId() {
  return `marathon-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
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

function normalizeDateKey(value) {
  const text = String(value || "").trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(text)) return "";
  const [year, month, day] = text.split("-").map(Number);
  const d = new Date(year, month - 1, day);
  if (d.getFullYear() !== year || d.getMonth() !== month - 1 || d.getDate() !== day) return "";
  return text;
}

function dateKeyToLocalDate(dateKey) {
  const normalized = normalizeDateKey(dateKey);
  if (!normalized) return null;
  const [year, month, day] = normalized.split("-").map(Number);
  return new Date(year, month - 1, day);
}

function dateKeyToUtcDay(dateKey) {
  const normalized = normalizeDateKey(dateKey);
  if (!normalized) return NaN;
  const [year, month, day] = normalized.split("-").map(Number);
  return Math.floor(Date.UTC(year, month - 1, day) / (24 * 60 * 60 * 1000));
}

function addDaysToDateKey(dateKey, days) {
  const start = dateKeyToLocalDate(dateKey);
  if (!start) return getLocalDateKey();
  start.setDate(start.getDate() + Math.floor(toSafeNumber(Number(days), 0)));
  return getLocalDateKey(start.getTime());
}

function diffDateKeys(laterDateKey, earlierDateKey) {
  const later = dateKeyToUtcDay(laterDateKey);
  const earlier = dateKeyToUtcDay(earlierDateKey);
  if (!Number.isFinite(later) || !Number.isFinite(earlier)) return NaN;
  return later - earlier;
}

function getScheduledTimestampForDateKey(time, dateKey) {
  const d = dateKeyToLocalDate(dateKey);
  if (!d) return NaN;
  const [hours, minutes] = normalizeTime(time).split(":").map(Number);
  d.setHours(hours || 0, minutes || 0, 0, 0);
  return d.getTime();
}

function normalizeDisciplineCellState(value) {
  return value === "green" || value === "red" || value === "gray" ? value : "";
}

function normalizeDisciplineDay(item) {
  const cells = {};
  const rawCells = item?.cells && typeof item.cells === "object" ? item.cells : {};
  for (const [key, value] of Object.entries(rawCells)) {
    const index = Math.floor(toSafeNumber(Number(key), NaN));
    const state = normalizeDisciplineCellState(value);
    if (Number.isInteger(index) && index >= 0 && index < DISCIPLINE_SLOT_COUNT && state) {
      cells[index] = state;
    }
  }

  const rawPenalties = Array.isArray(item?.penalties) ? item.penalties : [];
  const penalties = rawPenalties
    .map((penalty) => {
      const t = toSafeNumber(Number(penalty?.t ?? penalty), NaN);
      const hour = Math.max(0, Math.min(23, Math.floor(toSafeNumber(Number(penalty?.hour), Number.isFinite(t) ? new Date(t).getHours() : 0))));
      return Number.isFinite(t) ? { t, hour } : null;
    })
    .filter(Boolean);

  return { cells, penalties };
}

function normalizeDisciplineDays(source) {
  const result = {};
  const raw = source && typeof source === "object" ? source : {};
  for (const [dateKey, value] of Object.entries(raw)) {
    const normalizedDate = normalizeDateKey(dateKey);
    if (normalizedDate) result[normalizedDate] = normalizeDisciplineDay(value);
  }
  return result;
}

function normalizeDisciplineSnapshot(source, fallbackSavedAt = 0) {
  const item = source && typeof source === "object" ? source : {};
  const resetVersion = String(item.disciplineResetVersion || "");
  if (resetVersion !== DISCIPLINE_RESET_VERSION) {
    return {
      savedAt: Date.now(),
      disciplineStartDate: DISCIPLINE_START_DATE,
      disciplineDays: {},
      disciplineResetVersion: DISCIPLINE_RESET_VERSION,
      wasReset: true,
    };
  }
  return {
    savedAt: Math.max(0, toSafeNumber(Number(item.disciplineSavedAt ?? item.savedAt), fallbackSavedAt)),
    disciplineStartDate: DISCIPLINE_START_DATE,
    disciplineDays: normalizeDisciplineDays(item.disciplineDays),
    disciplineResetVersion: DISCIPLINE_RESET_VERSION,
    wasReset: false,
  };
}

function readLocalDisciplineForUser(userId = null) {
  try {
    const raw = localStorage.getItem(getLocalDisciplineKey(userId));
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;
    return normalizeDisciplineSnapshot(parsed);
  } catch (error) {
    console.warn("readLocalDisciplineForUser error:", error);
    return null;
  }
}

function writeLocalDisciplineForUser(userId = null, snapshot = null) {
  try {
    const payload = snapshot || {
      savedAt: disciplineSavedAt || Date.now(),
      disciplineStartDate,
      disciplineDays,
    };
    localStorage.setItem(getLocalDisciplineKey(userId), JSON.stringify({
      savedAt: Math.max(0, toSafeNumber(Number(payload.savedAt), Date.now())),
      disciplineStartDate: DISCIPLINE_START_DATE,
      disciplineDays: normalizeDisciplineDays(payload.disciplineDays),
      disciplineResetVersion: DISCIPLINE_RESET_VERSION,
    }));
  } catch (error) {
    console.warn("writeLocalDisciplineForUser error:", error);
  }
}

function writeLocalDisciplineForCurrentUser() {
  writeLocalDisciplineForUser(currentUser?.id || null);
}

function applyLocalDisciplineIfNewer(userId = null) {
  const local = readLocalDisciplineForUser(userId);
  if (!local || local.savedAt < disciplineSavedAt) return false;
  disciplineStartDate = local.disciplineStartDate;
  disciplineDays = local.disciplineDays;
  disciplineSavedAt = local.savedAt;
  disciplineResetVersion = local.disciplineResetVersion;
  return true;
}

function getDisciplineDay(dateKey, shouldCreate = false) {
  const normalizedDate = normalizeDateKey(dateKey);
  if (!normalizedDate) return { cells: {}, penalties: [] };
  if (!disciplineDays[normalizedDate] && shouldCreate) {
    disciplineDays[normalizedDate] = { cells: {}, penalties: [] };
  }
  return disciplineDays[normalizedDate] || { cells: {}, penalties: [] };
}

function getDisciplineDayStart(dateKey) {
  const d = dateKeyToLocalDate(dateKey);
  return d ? d.getTime() : NaN;
}

function isDisciplineSlotAutoGreen(dateKey, slotIndex, now = Date.now()) {
  const start = getDisciplineDayStart(dateKey);
  if (!Number.isFinite(start)) return false;
  return start + (slotIndex + 1) * DISCIPLINE_SLOT_MS <= now;
}

function getDisciplineSlotState(dateKey, slotIndex, now = Date.now()) {
  const day = getDisciplineDay(dateKey);
  const override = normalizeDisciplineCellState(day.cells?.[slotIndex]);
  if (override) return override;
  return "gray";
}

function getNextDisciplineCellState(currentState) {
  if (currentState === "green") return "red";
  if (currentState === "red") return "gray";
  return "green";
}

function getDisciplineDayStats(dateKey, now = Date.now()) {
  const day = getDisciplineDay(dateKey);
  let green = 0;
  let red = Array.isArray(day.penalties) ? day.penalties.length : 0;
  for (let index = 0; index < DISCIPLINE_SLOT_COUNT; index += 1) {
    const state = getDisciplineSlotState(dateKey, index, now);
    if (state === "green") green += 1;
    if (state === "red") red += 1;
  }
  return { green, red };
}

function getDisciplineDateKeys(now = Date.now()) {
  const today = getLocalDateKey(now);
  const start = normalizeDateKey(disciplineStartDate) || DISCIPLINE_START_DATE;
  const days = Math.max(0, diffDateKeys(today, start));
  const keys = [];
  for (let offset = 0; offset <= days; offset += 1) {
    keys.push(addDaysToDateKey(start, offset));
  }
  for (const dateKey of Object.keys(disciplineDays)) {
    if (normalizeDateKey(dateKey) && !keys.includes(dateKey)) keys.push(dateKey);
  }
  return keys.sort((a, b) => b.localeCompare(a));
}

function getMarathonEndDate(marathon) {
  return addDaysToDateKey(marathon.startDate, marathon.durationDays - 1);
}

function getMarathonProgress(marathon, now = Date.now()) {
  const today = getLocalDateKey(now);
  const started = diffDateKeys(today, marathon.startDate) + 1;
  return Math.max(0, Math.min(marathon.durationDays, started));
}

function normalizeMarathonTask(item, durationDays = 1) {
  const title = String(item?.title || "").trim().slice(0, 60);
  const time = normalizeTime(item?.time);
  if (!title || !time) return null;
  const repeat = item?.repeat === "once" ? "once" : "daily";
  const day = Math.max(1, Math.min(durationDays, Math.floor(toSafeNumber(Number(item?.day), 1))));
  const reports = item?.reports && typeof item.reports === "object" ? item.reports : {};
  return {
    id: String(item?.id || createTaskId()),
    title,
    description: String(item?.description || "").trim().slice(0, 300),
    reward: Math.max(0, Math.floor(toSafeNumber(Number(item?.reward), 0))),
    penalty: Math.max(0, Math.floor(toSafeNumber(Number(item?.penalty), 0))),
    time,
    repeat,
    day,
    enabled: item?.enabled !== false,
    reports,
  };
}

function normalizeMarathon(item) {
  const title = String(item?.title || "").trim().slice(0, 60);
  if (!title) return null;
  const durationDays = Math.max(1, Math.min(365, Math.floor(toSafeNumber(Number(item?.durationDays ?? item?.days), 1))));
  const plannedTaskCount = Math.max(0, Math.min(100, Math.floor(toSafeNumber(Number(item?.plannedTaskCount), 0))));
  const startDate = normalizeDateKey(item?.startDate) || getLocalDateKey();
  const rawTasks = Array.isArray(item?.tasks) ? item.tasks : [];
  return {
    id: String(item?.id || createMarathonId()),
    title,
    startDate,
    durationDays,
    plannedTaskCount,
    enabled: item?.enabled !== false,
    tasks: rawTasks.map((task) => normalizeMarathonTask(task, durationDays)).filter(Boolean),
  };
}

function getEmptySnapshot() {
  const now = Date.now();
  return {
    version: 1,
    savedAt: now,
    currentValue: 0,
    currentX: 0,
    selectedRange: "1h",
    selectedViewType: "line",
    selectedCandleRange: "5m",
    candleOffset: 0,
    candleZoom: 1,
    commentsVisible: true,
    candleComments: [],
    totalPoints: 0,
    levels: DEFAULT_LEVELS.map((level) => ({ ...level })),
    tasksGlobalEnabled: true,
    tasks: [],
    marathons: [],
    disciplineStartDate: DISCIPLINE_START_DATE,
    disciplineDays: {},
    disciplineSavedAt: now,
    disciplineResetVersion: DISCIPLINE_RESET_VERSION,
    soundsEnabled: false,
    soundVolume: 0.65,
    history: [{ t: now, y: 0 }],
  };
}

function getStateSnapshot(source = null) {
  const item = source && typeof source === "object" ? source : {};
  const disciplineSource = source && typeof source === "object"
    ? item
    : {
        disciplineStartDate,
        disciplineDays,
        disciplineSavedAt,
        disciplineResetVersion,
      };
  const normalizedDiscipline = normalizeDisciplineSnapshot(disciplineSource, disciplineSavedAt);
  return {
    version: item.version || 1,
    savedAt: item.savedAt || Date.now(),
    currentValue: toSafeNumber(item.currentValue, currentValue),
    currentX: toSafeNumber(item.currentX, currentX),
    selectedRange: item.selectedRange || selectedRange,
    selectedViewType: item.selectedViewType || selectedViewType,
    selectedCandleRange: item.selectedCandleRange || selectedCandleRange,
    candleOffset: toSafeNumber(item.candleOffset, candleOffset),
    candleZoom: Math.max(0.5, Math.min(4, toSafeNumber(Number(item.candleZoom), candleZoom))),
    commentsVisible: item.commentsVisible !== false,
    candleComments: Array.isArray(item.candleComments) ? item.candleComments : candleComments,
    totalPoints: toSafeNumber(item.totalPoints, totalPoints),
    levels: Array.isArray(item.levels) ? item.levels : levels,
    tasksGlobalEnabled: item.tasksGlobalEnabled !== false,
    tasks: Array.isArray(item.tasks) ? item.tasks : tasks,
    marathons: Array.isArray(item.marathons) ? item.marathons : marathons,
    disciplineStartDate: normalizedDiscipline.disciplineStartDate,
    disciplineDays: normalizedDiscipline.disciplineDays,
    disciplineSavedAt: normalizedDiscipline.savedAt,
    disciplineResetVersion: normalizedDiscipline.disciplineResetVersion,
    soundsEnabled: item.soundsEnabled === true,
    soundVolume: Math.max(0, Math.min(1, toSafeNumber(Number(item.soundVolume), soundVolume))),
  };
}

function getSnapshot() {
  return {
    ...getStateSnapshot(),
    history: history.slice(-50000),
  };
}

function toFastSnapshot(snapshot = null) {
  const source = snapshot || {};
  const sourceHistory = Array.isArray(source.history) ? source.history : history;
  return {
    ...getStateSnapshot(source),
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
    marathons,
    disciplineStartDate,
    disciplineDays,
    disciplineSavedAt,
    disciplineResetVersion,
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
  totalPoints = toSafeNumber(parsed.totalPoints, toDisplayValue(currentValue));
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
  marathons = Array.isArray(parsed.marathons)
    ? parsed.marathons
      .map(normalizeMarathon)
      .filter(Boolean)
      .sort((a, b) => a.startDate.localeCompare(b.startDate) || a.title.localeCompare(b.title))
    : [];
  const parsedDiscipline = normalizeDisciplineSnapshot(parsed);
  disciplineStartDate = parsedDiscipline.disciplineStartDate;
  disciplineDays = parsedDiscipline.disciplineDays;
  disciplineSavedAt = parsedDiscipline.savedAt;
  disciplineResetVersion = parsedDiscipline.disciplineResetVersion;
  if (parsedDiscipline.wasReset && currentUser?.id) pendingDisciplineCloudSave = true;
  if (applyLocalDisciplineIfNewer(currentUser?.id || null) && currentUser?.id) {
    pendingDisciplineCloudSave = true;
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
  renderDisciplineUi();
  renderSoundsUi();
  if (shouldUpdateSounds) updateSoundPlayback();
  return true;
}

function updateBodyUiClasses() {
  const isLoggedIn = Boolean(currentUser);
  const canUseApp = isLoggedIn && isProgressLoaded;
  document.body.classList.toggle("is-authenticated", isLoggedIn);
  document.body.classList.toggle("is-app-ready", canUseApp);
  document.body.classList.toggle("is-mobile-layout", isMobileLayout());
}

function setAuthUiState() {
  const isLoggedIn = Boolean(currentUser);
  const canUseApp = isLoggedIn && isProgressLoaded;
  updateBodyUiClasses();
  registerBtn.classList.toggle("hidden", isLoggedIn);
  loginBtn.classList.toggle("hidden", isLoggedIn);
  logoutBtn.classList.toggle("hidden", !isLoggedIn);
  authStatus.textContent = authStatusOverride || (isLoggedIn
    ? (isProgressLoaded ? `В аккаунте: ${currentUser.email || currentUser.id}` : "Загрузка аккаунта...")
    : "Гость");
  for (const node of appPanelsForAuth) {
    if (!node) continue;
    if (canUseApp) node.classList.remove("hidden");
    else node.classList.add("hidden");
  }
  syncMobileToolbarButtons();
  if (!canUseApp) {
    closeMobilePanels();
    closeTasksPage();
    closeDisciplinePage();
    closeSoundsPage();
    closeTaskReportModal();
    stopSoundLoop();
    if (!isLoggedIn) {
      hintNode.textContent = "Войдите или зарегистрируйтесь, чтобы открыть график и прогресс.";
    }
  }
}

async function saveProgressForCurrentUser(snapshot = null) {
  if (!currentUser || !isProgressLoaded || isApplyingRemoteProgress) {
    console.log("saveProgressForCurrentUser: нет залогиненного пользователя");
    return null;
  }
  if (!isCloudProgressReconciled) {
    console.log("saveProgressForCurrentUser: ожидание сверки прогресса с Supabase");
    return null;
  }
  let ownsSaveLock = false;
  try {
    const userId = currentUser.id;
    if (!userId) {
      console.log("saveProgressForCurrentUser: user id не найден");
      return null;
    }
    const localFastSnapshot = snapshot ? toFastSnapshot(snapshot) : getFastSnapshot();
    const cloudStateSnapshot = getStateSnapshot(snapshot);
    if (Array.isArray(snapshot?.history)) queueHistoryPointsForCloud(snapshot.history);
    writeLocalFastSnapshotForUser(userId, localFastSnapshot);
    pendingCloudSaveSnapshot = cloudStateSnapshot;
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
      await flushPendingHistoryPointsForUser(userId);
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
  return window.innerWidth <= MOBILE_LAYOUT_MAX;
}

function syncMobileToolbarButtons() {
  if (!mobileToolbarNode) return;
  const canUseApp = Boolean(currentUser && isProgressLoaded);
  const visibleByPanel = {
    modes: canUseApp,
    timeframes: canUseApp && selectedMode === "view" && selectedViewType === "line",
    viewTypes: canUseApp && selectedMode === "view",
    candleTimeframes: canUseApp && selectedMode === "view" && selectedViewType === "candles",
    commentControls: canUseApp && selectedMode === "view" && selectedViewType === "candles",
    tasksTab: canUseApp,
    disciplineTab: canUseApp,
    soundsTab: canUseApp,
    levelsPanel: canUseApp,
    dataControls: canUseApp,
    authPanel: canUseApp,
  };
  mobileToolbarNode.querySelectorAll("button[data-mobile-open]").forEach((button) => {
    button.hidden = visibleByPanel[button.dataset.mobileOpen] === false;
  });
}

function syncResponsiveUi() {
  updateBodyUiClasses();
  syncMobileToolbarButtons();
  if (!isMobileLayout()) closeMobilePanels();
}

function layoutControls() {
  syncResponsiveUi();
  if (isMobileLayout()) return;
  if (!isMobileLayout()) {
    for (const node of [modesNode, timeframeNode, viewTypesNode, candleTimeframesNode, commentControlsNode, tasksTabNode, disciplineTabNode, soundsTabNode, dataControlsNode, authPanelNode, levelsPanelNode].filter(Boolean)) {
      node.style.top = "";
    }
    return;
  }

  const gap = 8;
  const startTop = 10;

  let topLeft = startTop;
  for (const node of [modesNode, timeframeNode, viewTypesNode, candleTimeframesNode, commentControlsNode, tasksTabNode, disciplineTabNode, soundsTabNode]) {
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

function formatDateKeyShort(dateKey) {
  const d = dateKeyToLocalDate(dateKey);
  if (!d) return dateKey || "";
  return d.toLocaleDateString("ru-RU", { day: "2-digit", month: "2-digit" });
}

function formatDateKeyLong(dateKey) {
  const d = dateKeyToLocalDate(dateKey);
  if (!d) return dateKey || "";
  return d.toLocaleDateString("ru-RU", { day: "2-digit", month: "2-digit", year: "numeric" });
}

function isMarathonActiveOnDate(marathon, dateKey) {
  const dayIndex = diffDateKeys(dateKey, marathon.startDate);
  return dayIndex >= 0 && dayIndex < marathon.durationDays;
}

function getMarathonStatusText(marathon, now = Date.now()) {
  const today = getLocalDateKey(now);
  const dayIndex = diffDateKeys(today, marathon.startDate);
  if (dayIndex < 0) return `Старт ${formatDateKeyShort(marathon.startDate)}`;
  if (dayIndex >= marathon.durationDays) return "Завершен";
  return `День ${dayIndex + 1} из ${marathon.durationDays}`;
}

function formatMarathonTaskSchedule(task, marathon) {
  if (task.repeat === "daily") return `Каждый день в ${task.time}`;
  const dateKey = addDaysToDateKey(marathon.startDate, task.day - 1);
  return `День ${task.day}, ${formatDateKeyShort(dateKey)} в ${task.time}`;
}

function getActiveTaskCount(now = Date.now()) {
  const today = getLocalDateKey(now);
  const activeRegular = tasks.filter((task) => task.enabled).length;
  const activeMarathon = marathons.reduce((sum, marathon) => {
    if (!marathon.enabled || !isMarathonActiveOnDate(marathon, today)) return sum;
    return sum + marathon.tasks.filter((task) => task.enabled).length;
  }, 0);
  return activeRegular + activeMarathon;
}

function createRegularTaskOccurrence(task, dateKey) {
  if (!task.enabled || task.reports?.[dateKey]) return null;
  const scheduledAt = getScheduledTimestampForDateKey(task.time, dateKey);
  if (!Number.isFinite(scheduledAt)) return null;
  return {
    source: "task",
    id: task.id,
    taskId: task.id,
    title: task.title,
    description: task.description,
    reward: task.reward,
    penalty: task.penalty,
    time: task.time,
    dateKey,
    reportKey: dateKey,
    scheduledAt,
  };
}

function createMarathonTaskOccurrence(marathon, task, dateKey) {
  if (!marathon.enabled || !task.enabled) return null;
  const dayIndex = diffDateKeys(dateKey, marathon.startDate);
  if (dayIndex < 0 || dayIndex >= marathon.durationDays) return null;
  if (task.repeat === "once" && task.day !== dayIndex + 1) return null;
  if (task.reports?.[dateKey]) return null;
  const scheduledAt = getScheduledTimestampForDateKey(task.time, dateKey);
  if (!Number.isFinite(scheduledAt)) return null;
  return {
    source: "marathon",
    id: task.id,
    taskId: task.id,
    marathonId: marathon.id,
    marathonTitle: marathon.title,
    marathonDay: dayIndex + 1,
    title: task.title,
    description: task.description,
    reward: task.reward,
    penalty: task.penalty,
    time: task.time,
    dateKey,
    reportKey: dateKey,
    scheduledAt,
  };
}

function getTaskOccurrencesForDate(dateKey) {
  const regular = tasks
    .map((task) => createRegularTaskOccurrence(task, dateKey))
    .filter(Boolean);
  const marathonItems = [];
  for (const marathon of marathons) {
    for (const task of marathon.tasks) {
      const occurrence = createMarathonTaskOccurrence(marathon, task, dateKey);
      if (occurrence) marathonItems.push(occurrence);
    }
  }
  return regular.concat(marathonItems).sort((a, b) => a.scheduledAt - b.scheduledAt);
}

function formatNextTaskLabel(occurrence, now = Date.now()) {
  const today = getLocalDateKey(now);
  const dateText = occurrence.dateKey === today
    ? occurrence.time
    : `${formatDateKeyShort(occurrence.dateKey)} ${occurrence.time}`;
  const title = occurrence.source === "marathon"
    ? `${occurrence.marathonTitle}: ${occurrence.title}`
    : occurrence.title;
  return `${dateText} · ${title}`;
}

function sortMarathonTasks(list) {
  return list.slice().sort((a, b) => {
    if (a.repeat !== b.repeat) return a.repeat === "daily" ? -1 : 1;
    return a.day - b.day || a.time.localeCompare(b.time) || a.title.localeCompare(b.title);
  });
}

function createTaskField(labelText, control) {
  const label = document.createElement("label");
  label.className = "task-field";
  const text = document.createElement("span");
  text.textContent = labelText;
  label.appendChild(text);
  label.appendChild(control);
  return label;
}

function renderMarathonTaskForm(marathon) {
  const form = document.createElement("form");
  form.className = "marathon-task-form";

  const titleInput = document.createElement("input");
  titleInput.type = "text";
  titleInput.maxLength = 60;
  titleInput.placeholder = "Название задания марафона *";
  titleInput.required = true;

  const descriptionInput = document.createElement("textarea");
  descriptionInput.rows = 2;
  descriptionInput.maxLength = 300;
  descriptionInput.placeholder = "Описание";

  const grid = document.createElement("div");
  grid.className = "marathon-task-form-grid";

  const rewardInput = document.createElement("input");
  rewardInput.type = "number";
  rewardInput.min = "0";
  rewardInput.step = "1";
  rewardInput.placeholder = "+ баллы";

  const penaltyInput = document.createElement("input");
  penaltyInput.type = "number";
  penaltyInput.min = "0";
  penaltyInput.step = "1";
  penaltyInput.placeholder = "- баллы";

  const timeInput = document.createElement("input");
  timeInput.type = "time";
  timeInput.required = true;

  grid.appendChild(createTaskField("Награда", rewardInput));
  grid.appendChild(createTaskField("Штраф", penaltyInput));
  grid.appendChild(createTaskField("Время отчета", timeInput));

  const options = document.createElement("div");
  options.className = "marathon-task-options";

  const dailyLabel = document.createElement("label");
  dailyLabel.className = "marathon-task-repeat";
  const dailyInput = document.createElement("input");
  dailyInput.type = "checkbox";
  dailyInput.checked = true;
  const dailyText = document.createElement("span");
  dailyText.textContent = "Каждый день марафона";
  dailyLabel.appendChild(dailyInput);
  dailyLabel.appendChild(dailyText);

  const daySelect = document.createElement("select");
  daySelect.disabled = true;
  for (let day = 1; day <= marathon.durationDays; day += 1) {
    const option = document.createElement("option");
    option.value = String(day);
    option.textContent = `День ${day} · ${formatDateKeyShort(addDaysToDateKey(marathon.startDate, day - 1))}`;
    daySelect.appendChild(option);
  }

  dailyInput.addEventListener("change", () => {
    daySelect.disabled = dailyInput.checked;
  });

  options.appendChild(dailyLabel);
  options.appendChild(createTaskField("День запуска", daySelect));

  const button = document.createElement("button");
  button.type = "submit";
  button.className = "task-primary-button";
  const isFull = marathon.plannedTaskCount > 0 && marathon.tasks.length >= marathon.plannedTaskCount;
  button.disabled = isFull;
  button.textContent = isFull ? "Лимит заданий набран" : "Добавить задание в марафон";

  form.appendChild(createTaskField("Название задания", titleInput));
  form.appendChild(createTaskField("Описание", descriptionInput));
  form.appendChild(grid);
  form.appendChild(options);
  form.appendChild(button);

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (marathon.plannedTaskCount > 0 && marathon.tasks.length >= marathon.plannedTaskCount) return;
    const task = normalizeMarathonTask({
      title: titleInput.value,
      description: descriptionInput.value,
      reward: Number(rewardInput.value),
      penalty: Number(penaltyInput.value),
      time: timeInput.value,
      repeat: dailyInput.checked ? "daily" : "once",
      day: Number(daySelect.value),
      enabled: true,
      reports: {},
    }, marathon.durationDays);
    if (!task) return;
    marathon.tasks = sortMarathonTasks(marathon.tasks.concat(task));
    saveProgressForCurrentUser();
    renderTasksUi();
    checkDueTasks(true);
  });

  return form;
}

function renderMarathonTaskRow(marathon, task) {
  const row = document.createElement("div");
  row.className = "marathon-task-row";
  row.classList.toggle("disabled", !task.enabled || !marathon.enabled || !tasksGlobalEnabled);

  const head = document.createElement("div");
  head.className = "marathon-task-row-head";

  const meta = document.createElement("div");
  meta.className = "marathon-task-meta";
  const title = document.createElement("div");
  title.className = "marathon-task-title";
  title.textContent = task.title;
  const sub = document.createElement("div");
  sub.className = "marathon-task-sub";
  sub.textContent = `${formatMarathonTaskSchedule(task, marathon)} · +${task.reward} / -${task.penalty}`;
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
  row.appendChild(head);

  if (task.description) {
    const desc = document.createElement("div");
    desc.className = "marathon-task-description";
    desc.textContent = task.description;
    row.appendChild(desc);
  }

  const actions = document.createElement("div");
  actions.className = "marathon-task-actions";
  const remove = document.createElement("button");
  remove.type = "button";
  remove.textContent = "Удалить";
  remove.addEventListener("click", () => {
    const ok = window.confirm(`Удалить задание “${task.title}” из марафона?`);
    if (!ok) return;
    marathon.tasks = marathon.tasks.filter((itemTask) => itemTask.id !== task.id);
    taskReportQueue = taskReportQueue.filter((itemTask) => itemTask.source !== "marathon" || itemTask.taskId !== task.id || itemTask.marathonId !== marathon.id);
    if (activeTaskReport?.source === "marathon" && activeTaskReport.taskId === task.id && activeTaskReport.marathonId === marathon.id) closeTaskReportModal();
    saveProgressForCurrentUser();
    renderTasksUi();
  });
  actions.appendChild(remove);
  row.appendChild(actions);

  return row;
}

function renderMarathonsUi() {
  if (!marathonsListNode) return;
  marathonsListNode.innerHTML = "";
  if (marathons.length === 0) {
    const empty = document.createElement("div");
    empty.className = "marathons-empty";
    empty.textContent = "Марафонов пока нет.";
    marathonsListNode.appendChild(empty);
    return;
  }

  const today = getLocalDateKey();
  const list = marathons.slice().sort((a, b) => b.startDate.localeCompare(a.startDate) || a.title.localeCompare(b.title));
  for (const marathon of list) {
    const card = document.createElement("div");
    card.className = "marathon-card";
    card.classList.toggle("disabled", !marathon.enabled || !tasksGlobalEnabled);

    const head = document.createElement("div");
    head.className = "marathon-card-head";

    const meta = document.createElement("div");
    meta.className = "marathon-card-meta";
    const title = document.createElement("div");
    title.className = "marathon-card-title";
    title.textContent = marathon.title;
    const sub = document.createElement("div");
    sub.className = "marathon-card-sub";
    const taskLimit = marathon.plannedTaskCount > 0 ? ` из ${marathon.plannedTaskCount}` : "";
    sub.textContent = `${getMarathonStatusText(marathon)} · ${formatDateKeyLong(marathon.startDate)} - ${formatDateKeyLong(getMarathonEndDate(marathon))} · ${marathon.tasks.length}${taskLimit} заданий`;
    meta.appendChild(title);
    meta.appendChild(sub);

    const switchLabel = document.createElement("label");
    switchLabel.className = "switch";
    const switchInput = document.createElement("input");
    switchInput.type = "checkbox";
    switchInput.checked = marathon.enabled;
    switchInput.addEventListener("change", () => {
      marathon.enabled = switchInput.checked;
      saveProgressForCurrentUser();
      renderTasksUi();
      checkDueTasks(true);
    });
    const switchSpan = document.createElement("span");
    switchLabel.appendChild(switchInput);
    switchLabel.appendChild(switchSpan);

    head.appendChild(meta);
    head.appendChild(switchLabel);
    card.appendChild(head);

    const progress = document.createElement("div");
    progress.className = "marathon-card-progress";
    const progressFill = document.createElement("span");
    const progressPercent = (getMarathonProgress(marathon) / marathon.durationDays) * 100;
    progressFill.style.width = `${Math.max(0, Math.min(100, progressPercent))}%`;
    progress.appendChild(progressFill);
    card.appendChild(progress);

    const taskList = document.createElement("div");
    taskList.className = "marathon-task-list";
    if (marathon.tasks.length === 0) {
      const empty = document.createElement("div");
      empty.className = "marathon-task-empty";
      empty.textContent = "Внутри марафона пока нет заданий.";
      taskList.appendChild(empty);
    } else {
      for (const task of sortMarathonTasks(marathon.tasks)) {
        taskList.appendChild(renderMarathonTaskRow(marathon, task));
      }
    }
    card.appendChild(taskList);
    card.appendChild(renderMarathonTaskForm(marathon));

    const actions = document.createElement("div");
    actions.className = "marathon-card-actions";
    const remove = document.createElement("button");
    remove.type = "button";
    remove.textContent = "Удалить марафон";
    remove.addEventListener("click", () => {
      const ok = window.confirm(`Удалить марафон “${marathon.title}”?`);
      if (!ok) return;
      marathons = marathons.filter((item) => item.id !== marathon.id);
      taskReportQueue = taskReportQueue.filter((itemTask) => itemTask.marathonId !== marathon.id);
      if (activeTaskReport?.marathonId === marathon.id) closeTaskReportModal();
      saveProgressForCurrentUser();
      renderTasksUi();
    });
    actions.appendChild(remove);
    card.appendChild(actions);

    if (diffDateKeys(today, marathon.startDate) >= marathon.durationDays) {
      card.classList.add("completed");
    }

    marathonsListNode.appendChild(card);
  }
}

function formatDisciplineHour(hour) {
  return `${String(hour).padStart(2, "0")}:00`;
}

function renderDisciplineUi() {
  const now = Date.now();
  const today = getLocalDateKey(now);
  if (!normalizeDateKey(disciplineStartDate)) disciplineStartDate = DISCIPLINE_START_DATE;

  const todayStats = getDisciplineDayStats(today, now);
  if (disciplineTabBadgeNode) disciplineTabBadgeNode.textContent = String(todayStats.red);
  if (disciplineTodaySummaryNode) {
    disciplineTodaySummaryNode.textContent = `Сегодня: ${todayStats.green} зеленых / ${todayStats.red} красных`;
  }
  if (!disciplineDaysNode) return;

  const dateKeys = getDisciplineDateKeys(now);
  disciplineDaysNode.innerHTML = "";
  for (const dateKey of dateKeys) {
    const stats = getDisciplineDayStats(dateKey, now);
    const dayNumber = Math.max(1, diffDateKeys(dateKey, disciplineStartDate) + 1);
    const card = document.createElement("section");
    card.className = "discipline-day";
    card.classList.toggle("today", dateKey === today);

    const head = document.createElement("div");
    head.className = "discipline-day-head";

    const title = document.createElement("div");
    title.className = "discipline-day-title";
    title.textContent = `День ${dayNumber} - ${formatDateKeyLong(dateKey)}`;

    const summary = document.createElement("div");
    summary.className = "discipline-day-summary";
    summary.textContent = `${stats.green} зеленых / ${stats.red} красных`;

    head.appendChild(title);
    head.appendChild(summary);
    card.appendChild(head);

    const grid = document.createElement("div");
    grid.className = "discipline-hours";

    const day = getDisciplineDay(dateKey);
    for (let hour = 0; hour < DISCIPLINE_HOURS_PER_DAY; hour += 1) {
      const row = document.createElement("div");
      row.className = "discipline-hour";
      row.classList.toggle("current", dateKey === today && hour === new Date(now).getHours());

      const label = document.createElement("div");
      label.className = "discipline-hour-label";
      label.textContent = formatDisciplineHour(hour);
      row.appendChild(label);

      const squares = document.createElement("div");
      squares.className = "discipline-squares";
      for (let segment = 0; segment < DISCIPLINE_SLOTS_PER_HOUR; segment += 1) {
        const slotIndex = hour * DISCIPLINE_SLOTS_PER_HOUR + segment;
        const state = getDisciplineSlotState(dateKey, slotIndex, now);
        const square = document.createElement("button");
        square.type = "button";
        square.className = `discipline-square ${state}`;
        square.dataset.dateKey = dateKey;
        square.dataset.slotIndex = String(slotIndex);
        square.setAttribute("aria-label", `${formatDisciplineHour(hour)} блок ${segment + 1}: ${state}`);
        squares.appendChild(square);
      }

      const penalties = Array.isArray(day.penalties)
        ? day.penalties.filter((penalty) => penalty.hour === hour)
        : [];
      for (let extraIndex = 0; extraIndex < penalties.length; extraIndex += 1) {
        const square = document.createElement("span");
        square.className = "discipline-square red penalty";
        squares.appendChild(square);
      }

      row.appendChild(squares);
      grid.appendChild(row);
    }

    card.appendChild(grid);
    disciplineDaysNode.appendChild(card);
  }
}

function updateDisciplineAutoProgress(now = Date.now()) {
  const today = getLocalDateKey(now);
  const start = getDisciplineDayStart(today);
  const slot = Number.isFinite(start)
    ? Math.max(0, Math.min(DISCIPLINE_SLOT_COUNT, Math.floor((now - start) / DISCIPLINE_SLOT_MS)))
    : 0;
  const autoKey = `${today}:${slot}`;
  if (autoKey === lastDisciplineAutoKey) return;
  lastDisciplineAutoKey = autoKey;
  renderDisciplineUi();
}

function saveDisciplineProgress() {
  disciplineSavedAt = Date.now();
  writeLocalDisciplineForCurrentUser();
  const snapshot = saveLocalProgressForCurrentUser() || saveFastProgressForCurrentUser();
  if (currentUser?.id) pendingDisciplineCloudSave = true;
  flushPendingDisciplineCloudSave(snapshot || getFastSnapshot());
}

function flushPendingDisciplineCloudSave(snapshot = null) {
  if (!pendingDisciplineCloudSave) return;
  if (!currentUser?.id || !isProgressLoaded || !isCloudProgressReconciled || isApplyingRemoteProgress) return;
  const nextSnapshot = snapshot || saveLocalProgressForCurrentUser() || getSnapshot();
  pendingDisciplineCloudSave = false;
  saveProgressForCurrentUser(nextSnapshot);
}

function collectMarathonResultItems(status) {
  const rows = [];
  for (const marathon of marathons) {
    for (const task of marathon.tasks || []) {
      const reports = task.reports && typeof task.reports === "object" ? task.reports : {};
      for (const [reportKey, report] of Object.entries(reports)) {
        if (report?.status !== status) continue;
        const dateKey = normalizeDateKey(reportKey) || (Number.isFinite(Number(report?.scheduledAt)) ? getLocalDateKey(Number(report.scheduledAt)) : "");
        const dayNumber = normalizeDateKey(dateKey)
          ? Math.max(1, diffDateKeys(dateKey, marathon.startDate) + 1)
          : task.day;
        const scheduledAt = toSafeNumber(
          Number(report?.scheduledAt),
          dateKey ? getScheduledTimestampForDateKey(task.time, dateKey) : 0
        );
        rows.push({
          marathonTitle: marathon.title,
          taskTitle: task.title,
          dateKey,
          dayNumber,
          answeredAt: Math.max(0, toSafeNumber(Number(report?.answeredAt), 0)),
          scheduledAt: Math.max(0, toSafeNumber(scheduledAt, 0)),
        });
      }
    }
  }
  return rows.sort((a, b) => (b.answeredAt || b.scheduledAt) - (a.answeredAt || a.scheduledAt));
}

function renderMarathonResultList(container, rows, emptyText) {
  if (!container) return;
  container.innerHTML = "";
  if (!rows.length) {
    const empty = document.createElement("div");
    empty.className = "marathon-result-empty";
    empty.textContent = emptyText;
    container.appendChild(empty);
    return;
  }
  for (const row of rows) {
    const item = document.createElement("div");
    item.className = "marathon-result-item";
    const title = document.createElement("div");
    title.className = "marathon-result-title";
    title.textContent = `${row.marathonTitle}: ${row.taskTitle}`;
    const meta = document.createElement("div");
    meta.className = "marathon-result-meta";
    const dateText = row.dateKey ? formatDateKeyLong(row.dateKey) : "дата не указана";
    const answerText = row.answeredAt ? ` · ответ ${formatOpenTime(row.answeredAt)}` : "";
    meta.textContent = `День ${row.dayNumber} · ${dateText}${answerText}`;
    item.appendChild(title);
    item.appendChild(meta);
    container.appendChild(item);
  }
}

function renderMarathonResultsUi() {
  const doneRows = collectMarathonResultItems("done");
  const failedRows = collectMarathonResultItems("failed");
  if (marathonCompletedCountNode) marathonCompletedCountNode.textContent = String(doneRows.length);
  if (marathonFailedCountNode) marathonFailedCountNode.textContent = String(failedRows.length);
  renderMarathonResultList(marathonCompletedListNode, doneRows, "Пока нет выполненных задач марафона.");
  renderMarathonResultList(marathonFailedListNode, failedRows, "Пока нет проваленных задач марафона.");
}

function renderTasksUi() {
  if (tasksGlobalEnabledInput) tasksGlobalEnabledInput.checked = tasksGlobalEnabled;
  const activeCount = getActiveTaskCount();
  const dueCount = getDueTasks(Date.now()).length;
  const nextTask = getNextPendingTask();
  if (tasksTabBadgeNode) tasksTabBadgeNode.textContent = String(dueCount || activeCount);
  if (activeTasksCountNode) activeTasksCountNode.textContent = String(activeCount);
  if (dueTasksCountNode) dueTasksCountNode.textContent = String(dueCount);
  if (regularTasksCountNode) regularTasksCountNode.textContent = String(tasks.length);
  if (marathonsCountNode) marathonsCountNode.textContent = String(marathons.length);
  if (nextTaskTimeNode) {
    nextTaskTimeNode.textContent = nextTask ? formatNextTaskLabel(nextTask) : "—";
  }
  if (tasksListNode) {
    const list = tasks.slice().sort((a, b) => a.time.localeCompare(b.time));
    tasksListNode.innerHTML = "";
    if (list.length === 0) {
      const empty = document.createElement("div");
      empty.className = "tasks-empty";
      empty.textContent = "Заданий пока нет.";
      tasksListNode.appendChild(empty);
    } else {
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
          taskReportQueue = taskReportQueue.filter((itemTask) => itemTask.source !== "task" || itemTask.taskId !== task.id);
          if (activeTaskReport?.source === "task" && activeTaskReport.taskId === task.id) closeTaskReportModal();
          saveProgressForCurrentUser();
          renderTasksUi();
        });
        actions.appendChild(remove);
        item.appendChild(actions);

        tasksListNode.appendChild(item);
      }
    }
  }
  renderMarathonsUi();
  renderMarathonResultsUi();
}

function getNextPendingTask(now = Date.now()) {
  if (!tasksGlobalEnabled) return null;
  const today = getLocalDateKey(now);
  for (let dayOffset = 0; dayOffset <= 366; dayOffset += 1) {
    const dateKey = addDaysToDateKey(today, dayOffset);
    const list = getTaskOccurrencesForDate(dateKey);
    if (list.length === 0) continue;
    if (dayOffset === 0) return list[0];
    return list.find((occurrence) => occurrence.scheduledAt >= now) || list[0];
  }
  return null;
}

function openTasksPage() {
  closeMobilePanels();
  renderTasksUi();
  tasksPageNode?.classList.remove("hidden");
}

function closeTasksPage() {
  tasksPageNode?.classList.add("hidden");
}

function openDisciplinePage() {
  closeMobilePanels();
  renderDisciplineUi();
  disciplinePageNode?.classList.remove("hidden");
}

function closeDisciplinePage() {
  disciplinePageNode?.classList.add("hidden");
}

function openSoundsPage() {
  closeMobilePanels();
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
    name.textContent = record.name || "Аудио";
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
      soundCurrentIndex = -1;
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
      soundCurrentIndex = -1;
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

function isSiteVisible() {
  return document.visibilityState !== "hidden";
}

function getRandomSoundRecord() {
  if (!soundRecords.length) return null;
  let nextIndex = Math.floor(Math.random() * soundRecords.length);
  if (soundRecords.length > 1 && nextIndex === soundCurrentIndex) {
    nextIndex = (nextIndex + 1 + Math.floor(Math.random() * (soundRecords.length - 1))) % soundRecords.length;
  }
  soundCurrentIndex = nextIndex;
  return soundRecords[nextIndex];
}

function playNextSound() {
  if (!soundsEnabled || !soundRecords.length || !isSiteVisible()) {
    stopSoundLoop();
    return;
  }
  const record = getRandomSoundRecord();
  if (!record) {
    stopSoundLoop();
    return;
  }
  if (soundCurrentUrl) URL.revokeObjectURL(soundCurrentUrl);
  soundCurrentUrl = URL.createObjectURL(record.blob);
  soundPlayer.src = soundCurrentUrl;
  soundPlayer.volume = soundVolume;
  soundPlayer.play().catch((error) => {
    console.warn("sound playback blocked:", error);
    stopSoundLoop();
    if (soundsStatusNode) {
      soundsStatusNode.textContent = "Браузер заблокировал автозапуск. Откройте вкладку и нажмите переключатель звуков.";
    }
  });
}

function updateSoundPlayback() {
  soundPlayer.volume = soundVolume;
  if (!soundsEnabled || !soundRecords.length) {
    stopSoundLoop();
    return;
  }
  if (!isSiteVisible()) {
    soundPlayer.pause();
    return;
  }
  if (isSoundLoopStarting || !soundPlayer.paused) return;
  isSoundLoopStarting = true;
  playNextSound();
  isSoundLoopStarting = false;
}

soundPlayer.addEventListener("ended", playNextSound);

function insertHistoryPoint(timestamp, value) {
  const point = { t: timestamp, y: value };
  history.push(point);
  history.sort((a, b) => a.t - b.t);
  lastPointAt = Math.max(lastPointAt, timestamp);
  queueHistoryPointForCloud(point);
}

function applyTaskScore(deltaPoints, timestamp) {
  const nextPoints = totalPoints + deltaPoints;
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
  return getTaskOccurrencesForDate(today)
    .filter((occurrence) => occurrence.scheduledAt <= now)
    .sort((a, b) => a.scheduledAt - b.scheduledAt);
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
  const scheduledAt = Number.isFinite(next.scheduledAt) ? next.scheduledAt : getScheduledTimestampForDate(next.time);
  const marathonPrefix = next.source === "marathon" ? `Марафон “${next.marathonTitle}” · День ${next.marathonDay}. ` : "";
  taskReportTimeNode.textContent = `${marathonPrefix}Нужно было выполнить: ${formatOpenTime(scheduledAt)}`;
  taskReportNameNode.textContent = next.title;
  taskReportDescriptionNode.textContent = next.description || "";
  taskReportDescriptionNode.classList.toggle("hidden", !next.description);
  taskReportPointsNode.textContent = `Выполнено: +${next.reward} · Не выполнено: -${next.penalty} · Игнор: 0`;
  taskReportModalNode.classList.remove("hidden");
}

function closeTaskReportModal() {
  taskReportModalNode?.classList.add("hidden");
  activeTaskReport = null;
}

function findTaskSourceTitle(report) {
  if (!report) return "задача";
  return report.source === "marathon" && report.marathonTitle
    ? `марафон “${report.marathonTitle}” · ${report.title}`
    : report.title || "задача";
}

function removeTaskByReport(report) {
  if (!report) return false;
  if (report.source === "marathon") {
    const marathon = marathons.find((item) => item.id === report.marathonId);
    if (!marathon) return false;
    marathon.tasks = marathon.tasks.filter((task) => task.id !== report.taskId);
    taskReportQueue = taskReportQueue.filter((itemTask) => itemTask.source !== "marathon" || itemTask.taskId !== report.taskId || itemTask.marathonId !== report.marathonId);
    return true;
  }
  tasks = tasks.filter((task) => task.id !== report.taskId && task.id !== report.id);
  taskReportQueue = taskReportQueue.filter((itemTask) => itemTask.source !== "task" || (itemTask.taskId !== report.taskId && itemTask.id !== report.id));
  return true;
}

function deleteActiveTaskReport() {
  if (!activeTaskReport) return;
  const title = findTaskSourceTitle(activeTaskReport);
  if (!window.confirm(`Удалить ${title}?`)) return;
  const removed = removeTaskByReport(activeTaskReport);
  if (!removed) return;
  closeTaskReportModal();
  saveProgressForCurrentUser();
  renderTasksUi();
  openNextTaskReport();
}

function answerActiveTask(status) {
  if (!activeTaskReport) return;
  let task = null;
  let reportKey = activeTaskReport.reportKey;
  let scheduledAt = activeTaskReport.scheduledAt;
  if (activeTaskReport.source === "marathon") {
    const marathon = marathons.find((item) => item.id === activeTaskReport.marathonId);
    task = marathon?.tasks.find((item) => item.id === activeTaskReport.taskId) || null;
    if (!reportKey) reportKey = activeTaskReport.dateKey;
    if (!Number.isFinite(scheduledAt) && reportKey) scheduledAt = getScheduledTimestampForDateKey(task?.time, reportKey);
  } else {
    task = tasks.find((item) => item.id === activeTaskReport.taskId || item.id === activeTaskReport.id);
    if (!reportKey) reportKey = getLocalDateKey();
    if (!Number.isFinite(scheduledAt)) scheduledAt = getScheduledTimestampForDate(task?.time);
  }
  if (!task) {
    closeTaskReportModal();
    openNextTaskReport();
    return;
  }
  const now = Date.now();
  task.reports = task.reports && typeof task.reports === "object" ? task.reports : {};
  task.reports[reportKey || getLocalDateKey(now)] = { status, answeredAt: now, scheduledAt };
  if (status === "done") applyTaskScore(task.reward, now);
  if (status === "failed") applyTaskScore(-task.penalty, now);
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
  document.body.classList.remove("is-mobile-panel-open");
  if (mobileOverlayNode) mobileOverlayNode.classList.add("hidden");
  for (const node of [modesNode, timeframeNode, viewTypesNode, candleTimeframesNode, commentControlsNode, tasksTabNode, disciplineTabNode, soundsTabNode, dataControlsNode, authPanelNode, levelsPanelNode]) {
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
    disciplineTab: disciplineTabNode,
    soundsTab: soundsTabNode,
    dataControls: dataControlsNode,
    authPanel: authPanelNode,
    levelsPanel: levelsPanelNode,
  };
  const node = map[id];
  if (!node) return;
  if (mobileOverlayNode) mobileOverlayNode.classList.remove("hidden");
  document.body.classList.add("is-mobile-panel-open");
  node.classList.add("mobile-open");
}

function setShareLink(text) {
  if (!shareLinkNode) return;
  shareLinkNode.textContent = text;
}

function addHistoryPoint(timestamp) {
  let point = null;
  if (history.length === 0 || timestamp - lastPointAt >= pointIntervalMs) {
    point = { t: timestamp, y: currentValue };
    history.push(point);
    lastPointAt = timestamp;
  } else {
    const previousPoint = history[history.length - 1];
    if (previousPoint) pendingHistoryPointMap.delete(getHistoryPointKey(previousPoint));
    point = { t: timestamp, y: currentValue };
    history[history.length - 1] = point;
    lastPointAt = timestamp;
  }
  queueHistoryPointForCloud(point);
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
  ensureHistoryWindowLoaded(start);
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

  ctx.strokeStyle = "rgba(145, 173, 160, 0.14)";
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
  const gradient = ctx.createLinearGradient(head.x - liveTailLength, head.y, head.x + 120, head.y);
  gradient.addColorStop(0, "rgba(242, 201, 109, 0.38)");
  gradient.addColorStop(0.58, "#69e6a3");
  gradient.addColorStop(1, "#ecf6ef");
  ctx.shadowColor = "rgba(105, 230, 163, 0.32)";
  ctx.shadowBlur = 16;
  ctx.strokeStyle = gradient;
  ctx.beginPath();
  ctx.moveTo(livePoints[0].x, livePoints[0].y);
  for (let i = 1; i < livePoints.length; i += 1) {
    ctx.lineTo(livePoints[i].x, livePoints[i].y);
  }
  ctx.stroke();
  ctx.shadowBlur = 18;
  ctx.fillStyle = "#ecf6ef";
  ctx.beginPath();
  ctx.arc(head.x, head.y, 5, 0, Math.PI * 2);
  ctx.fill();
  ctx.restore();
}

function drawLiveCrosshair() {
  const cx = width / 2;
  const cy = height / 2;
  ctx.strokeStyle = "rgba(236, 246, 239, 0.42)";
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(cx - 12, cy);
  ctx.lineTo(cx + 12, cy);
  ctx.moveTo(cx, cy - 12);
  ctx.lineTo(cx, cy + 12);
  ctx.stroke();
}

function drawLiveAxes(head) {
  const compact = isMobileLayout();
  const leftPadding = compact ? 44 : 52;
  const bottomPadding = compact ? 118 : 34;
  const startY = Math.floor((head.y - height) / gridStepPx) * gridStepPx;
  const endY = Math.ceil((head.y + height) / gridStepPx) * gridStepPx;
  const startX = Math.floor((head.x - width) / gridStepPx) * gridStepPx;
  const endX = Math.ceil((head.x + width) / gridStepPx) * gridStepPx;

  ctx.save();
  ctx.fillStyle = compact ? "rgba(5, 12, 12, 0.78)" : "rgba(5, 12, 12, 0.84)";
  ctx.fillRect(0, 0, leftPadding, height);
  ctx.fillRect(0, height - bottomPadding, width, bottomPadding);

  ctx.strokeStyle = "rgba(176, 209, 193, 0.4)";
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(leftPadding, 0);
  ctx.lineTo(leftPadding, height);
  ctx.moveTo(0, height - bottomPadding);
  ctx.lineTo(width, height - bottomPadding);
  ctx.stroke();

  ctx.fillStyle = "#ecf6ef";
  ctx.font = `${compact ? 10 : 12}px Arial`;
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
    ctx.fillText(formatClock(tickDate), screenX - 22, height - (compact ? 94 : 12));
  }
  ctx.restore();
}

function drawViewChart(points, now, rangeMs) {
  const compact = isMobileLayout();
  const left = compact ? 46 : 62;
  const right = compact ? 12 : 24;
  const top = compact ? 84 : 56;
  const bottom = compact ? 126 : 76;
  const chartW = width - left - right;
  const chartH = height - top - bottom;

  ctx.fillStyle = "rgba(5, 12, 12, 0.82)";
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

  ctx.strokeStyle = "rgba(145, 173, 160, 0.18)";
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

  const lineGradient = ctx.createLinearGradient(left, top, left + chartW, top);
  lineGradient.addColorStop(0, "#f2c96d");
  lineGradient.addColorStop(0.55, "#69e6a3");
  lineGradient.addColorStop(1, "#ecf6ef");
  ctx.strokeStyle = lineGradient;
  ctx.lineWidth = 3;
  ctx.lineCap = "round";
  ctx.lineJoin = "round";
  ctx.shadowColor = "rgba(105, 230, 163, 0.22)";
  ctx.shadowBlur = compact ? 8 : 12;
  ctx.beginPath();
  for (let i = 0; i < points.length; i += 1) {
    const sx = xToScreen(points[i].t);
    const sy = yToScreen(toDisplayValue(points[i].y));
    if (i === 0) ctx.moveTo(sx, sy);
    else ctx.lineTo(sx, sy);
  }
  ctx.stroke();
  ctx.shadowBlur = 0;

  if (points.length > 0) {
    const last = points[points.length - 1];
    ctx.fillStyle = "#ecf6ef";
    ctx.beginPath();
    ctx.arc(xToScreen(last.t), yToScreen(toDisplayValue(last.y)), 4.5, 0, Math.PI * 2);
    ctx.fill();
  }

  ctx.fillStyle = "#ecf6ef";
  ctx.font = `${compact ? 10 : 12}px Arial`;
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

  ctx.strokeStyle = "rgba(176, 209, 193, 0.42)";
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
  const candles = [];
  const firstBucket = Math.floor(start / candleMs) * candleMs;
  const lastBucket = Math.floor((end - 1) / candleMs) * candleMs;
  ensureHistoryWindowLoaded(firstBucket);

  let lastKnown = null;
  let historyIdx = 0;
  while (historyIdx < history.length && history[historyIdx].t < firstBucket) historyIdx += 1;
  if (historyIdx > 0) lastKnown = toDisplayValue(history[historyIdx - 1].y);

  for (let bucket = firstBucket; bucket <= lastBucket; bucket += candleMs) {
    const bucketEnd = bucket + candleMs;
    let open = Number.isFinite(lastKnown) ? lastKnown : null;
    let high = open;
    let low = open;
    let close = open;

    while (historyIdx < history.length && history[historyIdx].t < bucketEnd && history[historyIdx].t <= end) {
      const displayY = toDisplayValue(history[historyIdx].y);
      if (!Number.isFinite(open)) {
        open = displayY;
        high = displayY;
        low = displayY;
      } else {
        high = Math.max(high, displayY);
        low = Math.min(low, displayY);
      }
      close = displayY;
      lastKnown = displayY;
      historyIdx += 1;
    }
    if (!Number.isFinite(open)) continue;
    candles.push({
      t: bucket,
      open,
      high,
      low,
      close,
    });
    lastKnown = close;
  }
  return { candles, start, end };
}

function drawCandleChart(now, candleMs) {
  const compact = isMobileLayout();
  const left = compact ? 46 : 62;
  const right = compact ? 12 : 24;
  const top = compact ? 84 : 56;
  const bottom = compact ? 126 : 76;
  const chartW = width - left - right;
  const chartH = height - top - bottom;
  const candleCount = Math.max(20, Math.round(60 / candleZoom));
  const { candles, start, end } = buildCandles(now, candleMs, candleCount);
  hoveredCandle = null;
  lastCandleHitboxes = [];

  ctx.fillStyle = "rgba(5, 12, 12, 0.82)";
  ctx.fillRect(left, top, chartW, chartH);

  if (candles.length === 0) {
    ctx.fillStyle = "#ecf6ef";
    ctx.font = `${compact ? 12 : 14}px Arial`;
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

  ctx.strokeStyle = "rgba(145, 173, 160, 0.18)";
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
    const color = isUp ? "#69e6a3" : "#ff6f8c";
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

  ctx.fillStyle = "#ecf6ef";
  ctx.font = `${compact ? 10 : 12}px Arial`;
  for (let i = 0; i <= 6; i += 1) {
    const value = maxY - ((maxY - minY) * i) / 6;
    const y = top + (i / 6) * chartH;
    ctx.fillText(value.toFixed(1), 8, y + 4);
  }

  if (commentsVisible) {
    ctx.font = `${compact ? 10 : 11}px Arial`;
    for (const note of candleComments) {
      const rounded = Math.floor(note.t / candleMs) * candleMs;
      const point = candleScreenIndex.get(rounded);
      if (!point) continue;
      const textY = Math.max(top + 12, point.yHigh - 10);
      ctx.fillStyle = "#f2c96d";
      ctx.beginPath();
      ctx.arc(point.x, point.yHigh - 3, 3, 0, Math.PI * 2);
      ctx.fill();
      ctx.fillStyle = "rgba(242, 201, 109, 0.9)";
      ctx.fillText(note.text, point.x + 6, textY);
    }
  }
  for (let i = 0; i <= 6; i += 1) {
    const t = start + ((end - start) * i) / 6;
    const x = left + (i / 6) * chartW * candleAreaRatio;
    ctx.fillText(formatAxisTime(t, selectedCandleRange), x - 28, top + chartH + 20);
  }

  ctx.strokeStyle = "rgba(176, 209, 193, 0.42)";
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
  syncMobileToolbarButtons();
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
      totalPoints = pointsNow;
    }
    currentX += speedX * dt;
    updateLivePoints();
    renderLevelsUi();
  } else {
    pendingVerticalDelta = 0;
  }
  checkDueTasks();
  updateDisciplineAutoProgress(Date.now());
  addHistoryPoint(Date.now());
  if (currentUser && isProgressLoaded && now - lastFastSaveAt >= FAST_SAVE_MS && currentValue !== lastFastSavedValue) {
    saveFastProgressForCurrentUser();
    lastFastSaveAt = now;
    lastFastSavedValue = currentValue;
  }
  if (currentUser && isProgressLoaded && isCloudProgressReconciled && now - lastAutosaveAt >= AUTOSAVE_MS) {
    saveProgressForCurrentUser();
    lastAutosaveAt = now;
  }
  updateHud();
  render();
  requestAnimationFrame(frame);
}

canvas.addEventListener("mousedown", (event) => {
  if (event.button !== 0) return;
  if (selectedMode === "live") {
    isMouseDown = true;
    pointerDownX = event.clientX;
    pointerDownY = event.clientY;
    pointerDidDrag = false;
    lastMouseY = event.clientY;
    return;
  }
  if (selectedMode === "view" && selectedViewType === "candles") {
    pointerDownX = event.clientX;
    pointerDownY = event.clientY;
    pointerDidDrag = false;
  }
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
  layoutControls();
  render();
});

modesNode.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-mode]");
  if (!button) return;
  isMouseDown = false;
  setMode(button.dataset.mode);
  if (isMobileLayout()) closeMobilePanels();
});

timeframeNode.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-range]");
  if (!button) return;
  selectedRange = button.dataset.range;
  timeframeNode.querySelectorAll("button").forEach((item) => {
    item.classList.toggle("active", item === button);
  });
  if (selectedMode === "view") render();
  if (isMobileLayout()) closeMobilePanels();
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
  syncMobileToolbarButtons();
  if (isView) render();
  if (isMobileLayout()) closeMobilePanels();
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
  if (isMobileLayout()) closeMobilePanels();
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
  closeMobilePanels();
  const baseTime = selectedCandle?.t ?? hoveredCandle?.t ?? latestCandleHover?.t ?? Date.now();
  openCandleCommentModal(baseTime);
});

toggleCommentsBtn.addEventListener("click", () => {
  commentsVisible = !commentsVisible;
  toggleCommentsBtn.textContent = commentsVisible ? "Скрыть комментарии" : "Показать комментарии";
  render();
  if (isMobileLayout()) closeMobilePanels();
});

openTasksBtn?.addEventListener("click", openTasksPage);
closeTasksBtn?.addEventListener("click", closeTasksPage);
openDisciplineBtn?.addEventListener("click", openDisciplinePage);
closeDisciplineBtn?.addEventListener("click", closeDisciplinePage);
openSoundsBtn?.addEventListener("click", openSoundsPage);
closeSoundsBtn?.addEventListener("click", closeSoundsPage);

disciplinePenaltyBtn?.addEventListener("click", () => {
  const now = Date.now();
  const today = getLocalDateKey(now);
  const day = getDisciplineDay(today, true);
  day.penalties.push({ t: now, hour: new Date(now).getHours() });
  saveDisciplineProgress();
  renderDisciplineUi();
});

disciplineDaysNode?.addEventListener("click", (event) => {
  const square = event.target.closest(".discipline-square[data-date-key][data-slot-index]");
  if (!square) return;
  const dateKey = normalizeDateKey(square.dataset.dateKey);
  const slotIndex = Math.floor(toSafeNumber(Number(square.dataset.slotIndex), NaN));
  if (!dateKey || !Number.isInteger(slotIndex) || slotIndex < 0 || slotIndex >= DISCIPLINE_SLOT_COUNT) return;
  const currentState = getDisciplineSlotState(dateKey, slotIndex);
  const nextState = getNextDisciplineCellState(currentState);
  const day = getDisciplineDay(dateKey, true);
  day.cells[slotIndex] = nextState;
  saveDisciplineProgress();
  renderDisciplineUi();
});

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
    soundCurrentIndex = -1;
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

marathonFormNode?.addEventListener("submit", (event) => {
  event.preventDefault();
  const plannedTaskCountRaw = String(marathonTaskCountInput?.value || "").trim();
  const marathon = normalizeMarathon({
    title: marathonTitleInput?.value,
    durationDays: Number(marathonDaysInput?.value),
    plannedTaskCount: plannedTaskCountRaw ? Number(plannedTaskCountRaw) : 0,
    startDate: getLocalDateKey(),
    enabled: true,
    tasks: [],
  });
  if (!marathon) return;
  marathons = marathons.concat(marathon).sort((a, b) => a.startDate.localeCompare(b.startDate) || a.title.localeCompare(b.title));
  marathonFormNode.reset();
  saveProgressForCurrentUser();
  renderTasksUi();
  checkDueTasks(true);
});

taskDoneBtn?.addEventListener("click", () => answerActiveTask("done"));
taskFailedBtn?.addEventListener("click", () => answerActiveTask("failed"));
taskIgnoreBtn?.addEventListener("click", () => answerActiveTask("ignored"));
taskDeleteBtn?.addEventListener("click", deleteActiveTaskReport);

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
  if (snapshot) {
    saveProgressForCurrentUser(snapshot);
  }
});

window.addEventListener("pagehide", () => {
  saveFastProgressForCurrentUser();
});

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "hidden") {
    saveFastProgressForCurrentUser();
    soundPlayer.pause();
    return;
  }
  updateSoundPlayback();
});

async function handleRegisterClick(event) {
  event.preventDefault();
  event.stopImmediatePropagation();
  authStatusOverride = "";
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
  authStatusOverride = "";
  const email = authEmail.value;
  const password = authPassword.value;
  authStatus.textContent = "Вход...";
  setAuthBusy(true);
  try {
    const client = await withTimeout(getSupabaseClient(), 10000, "supabase");
    const { data, error } = await withTimeout(client.auth.signInWithPassword({ email, password }), 15000, "sign in");
    if (error) {
      authStatusOverride = "Ошибка входа: " + error.message;
      isProgressLoaded = Boolean(currentUser?.id && isCloudProgressReconciled);
      setAuthUiState();
      return;
    }

    currentUser = data.user;
    lastSessionUserId = data.user?.id || null;
    isProgressLoaded = false;
    isCloudProgressReconciled = false;
    authStatus.textContent = "Загрузка аккаунта...";

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
    authStatusOverride = "Не удалось войти. Проверьте интернет и настройки Supabase.";
    isProgressLoaded = Boolean(currentUser?.id && isCloudProgressReconciled);
    setAuthUiState();
  } finally {
    setAuthBusy(false);
  }
}

async function handleLogoutClick(event) {
  event.preventDefault();
  event.stopImmediatePropagation();
  authStatusOverride = "";
  const previousUserId = currentUser?.id || null;
  latestLoadToken += 1;
  const snapshot = saveFastProgressForCurrentUser();
  if (snapshot) await saveProgressForCurrentUser(snapshot);

  currentUser = null;
  lastSessionUserId = null;
  isProgressLoaded = false;
  isCloudProgressReconciled = false;
  pendingHistoryPointMap.clear();
  hasMoreOlderHistory = true;
  isLoadingOlderHistory = false;
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
renderDisciplineUi();
renderSoundsUi();
if (location.protocol.startsWith("http")) {
  setShareLink(`Ссылка: ${location.origin}/`);
} else {
  setShareLink("Ссылка: опубликуйте сайт на Netlify");
}

async function loadCurrentUserData(session = null) {
  const loadToken = ++latestLoadToken;
  const hadReconciledUser = Boolean(currentUser?.id && isProgressLoaded && isCloudProgressReconciled);
  if (!hadReconciledUser) {
    isProgressLoaded = false;
    isCloudProgressReconciled = false;
  }
  authStatusOverride = "";
  setAuthUiState();
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
      isProgressLoaded = false;
      isCloudProgressReconciled = false;
      pendingHistoryPointMap.clear();
      hasMoreOlderHistory = true;
      isLoadingOlderHistory = false;
      authStatusOverride = "";
      soundRecords = [];
      soundsLoadedForUserId = null;
      soundsEnabled = false;
      setAuthUiState();
      renderSoundsUi();
      updateHud();
      setMode("live");
      return;
    }
    if (currentUser?.id && currentUser.id !== user.id) {
      pendingHistoryPointMap.clear();
      hasMoreOlderHistory = true;
      isLoadingOlderHistory = false;
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
    const supabaseSnapshot = data?.data && typeof data.data === "object" ? data.data : null;
    const localSnapshot = readLocalSnapshotForUser(user.id);
    const localFastSnapshot = readLocalFastSnapshotForUser(user.id);
    const newestSnapshot = getNewestSnapshot(supabaseSnapshot, localFastSnapshot, localSnapshot);
    logProgressSnapshotChoice(user.id, supabaseSnapshot, localSnapshot, localFastSnapshot, newestSnapshot);
    const embeddedHistory = mergeHistoryPoints(
      supabaseSnapshot?.history,
      localFastSnapshot?.history,
      localSnapshot?.history
    );
    const recentHistory = await loadRecentHistoryPointsForUser(user.id);
    if (loadToken !== latestLoadToken) return;
    const nextHistory = mergeHistoryPoints(recentHistory, embeddedHistory);
    const fallbackSnapshot = nextHistory.length > 0
      ? {
          savedAt: nextHistory[nextHistory.length - 1].t,
          currentValue: nextHistory[nextHistory.length - 1].y,
          totalPoints: toDisplayValue(nextHistory[nextHistory.length - 1].y),
          history: nextHistory,
        }
      : getEmptySnapshot();
    const newestSnapshotHistory = nextHistory.length > 0
      ? nextHistory
      : [{
          t: getSnapshotSavedAt(newestSnapshot) || Date.now(),
          y: toSafeNumber(Number(newestSnapshot?.currentValue), 0),
        }];
    const snapshotToApply = newestSnapshot
      ? { ...newestSnapshot, history: newestSnapshotHistory }
      : fallbackSnapshot;
    if (snapshotToApply) {
      isApplyingRemoteProgress = true;
      applySnapshot(snapshotToApply);
      isApplyingRemoteProgress = false;
      const localSnapshotToWrite = { ...getStateSnapshot(snapshotToApply), history: history.slice(-50000) };
      writeLocalFastSnapshotForUser(user.id, localSnapshotToWrite);
      writeLocalSnapshotForUser(user.id, localSnapshotToWrite);
      updateHud();
    }
    isProgressLoaded = true;
    isCloudProgressReconciled = true;
    authStatusOverride = "";
    flushPendingDisciplineCloudSave();
    const supabaseHasEmbeddedHistory = Object.prototype.hasOwnProperty.call(supabaseSnapshot || {}, "history");
    if (embeddedHistory.length > 0) queueHistoryPointsForCloud(embeddedHistory);
    if (newestSnapshot && (
      supabaseHasEmbeddedHistory ||
      (newestSnapshot !== supabaseSnapshot && getSnapshotSavedAt(newestSnapshot) > getSnapshotSavedAt(supabaseSnapshot))
    )) {
      saveProgressForCurrentUser({ ...newestSnapshot, history: embeddedHistory });
    } else {
      flushPendingHistoryPointsForUser(user.id).catch((historyError) => {
        console.warn("flushPendingHistoryPoints error:", historyError);
      });
    }
    setAuthUiState();
    render();
    checkDueTasks(true);
  } catch (error) {
    console.error("loadUserData error:", error);
    isApplyingRemoteProgress = false;
    if (hadReconciledUser && currentUser?.id) {
      isProgressLoaded = true;
      isCloudProgressReconciled = true;
      authStatusOverride = "";
    } else if (currentUser?.id) {
      const localSnapshot = getNewestSnapshot(readLocalSnapshotForUser(currentUser.id), readLocalFastSnapshotForUser(currentUser.id));
      if (localSnapshot) {
        isApplyingRemoteProgress = true;
        applySnapshot(localSnapshot);
        isApplyingRemoteProgress = false;
        updateHud();
        render();
      }
      isProgressLoaded = false;
      isCloudProgressReconciled = false;
      authStatusOverride = getProgressLoadErrorMessage(error);
    } else {
      isProgressLoaded = false;
      isCloudProgressReconciled = false;
      authStatusOverride = getProgressLoadErrorMessage(error);
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
  isProgressLoaded = false;
  isCloudProgressReconciled = false;
  hasMoreOlderHistory = true;
  isLoadingOlderHistory = false;
  authStatusOverride = "";

  const snapshot = getNewestSnapshot(
    readLocalFastSnapshotForUser(cachedUser.id),
    readLocalSnapshotForUser(cachedUser.id)
  );

  if (snapshot) {
    isApplyingRemoteProgress = true;
    applySnapshot(snapshot);
    isApplyingRemoteProgress = false;
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
      if (sessionUserId === lastSessionUserId && currentUser?.id === sessionUserId && isProgressLoaded && isCloudProgressReconciled) {
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
