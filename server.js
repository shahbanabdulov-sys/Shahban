import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import express from "express";
import cookieParser from "cookie-parser";

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);

const PORT = Number(process.env.PORT || 5173);
const isProd = process.env.NODE_ENV === "production";
const DATA_DIR = process.env.DATA_DIR || (isProd ? "/app/data" : path.join(process.cwd(), "data"));
const DB_PATH = process.env.DB_PATH || path.join(DATA_DIR, "db.json");
const DB_BACKUP_PATH = `${DB_PATH}.bak`;
const SESSION_COOKIE = "sid";
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function normalizeDbShape(parsed) {
  if (!parsed || typeof parsed !== "object") return null;
  const out = { ...parsed };
  if (!out.users || typeof out.users !== "object") out.users = {};
  if (!out.sessions || typeof out.sessions !== "object") out.sessions = {};
  return out;
}

function tryReadDbFile(filePath) {
  if (!fs.existsSync(filePath)) return null;
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    const parsed = JSON.parse(raw);
    return normalizeDbShape(parsed);
  } catch {
    return null;
  }
}

function readDb() {
  ensureDataDir();
  const primary = tryReadDbFile(DB_PATH);
  if (primary) return primary;

  const backup = tryReadDbFile(DB_BACKUP_PATH);
  if (backup) {
    // Best effort recovery when primary got corrupted.
    writeDb(backup);
    return backup;
  }

  return { users: {}, sessions: {} };
}

function writeDb(db) {
  ensureDataDir();
  const normalized = normalizeDbShape(db) || { users: {}, sessions: {} };
  const payload = JSON.stringify(normalized, null, 2);

  const tmp = `${DB_PATH}.tmp`;
  const bakTmp = `${DB_BACKUP_PATH}.tmp`;
  fs.writeFileSync(bakTmp, payload);
  fs.renameSync(bakTmp, DB_BACKUP_PATH);
  fs.writeFileSync(tmp, payload);
  fs.renameSync(tmp, DB_PATH);
}

function normalizeUsername(value) {
  return String(value || "").trim().toLowerCase();
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(String(password), salt, 32);
  return `scrypt$${salt.toString("hex")}$${key.toString("hex")}`;
}

function verifyPassword(password, stored) {
  try {
    const [algo, saltHex, keyHex] = String(stored || "").split("$");
    if (algo !== "scrypt") return false;
    const salt = Buffer.from(saltHex, "hex");
    const expected = Buffer.from(keyHex, "hex");
    const actual = crypto.scryptSync(String(password), salt, expected.length);
    return crypto.timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

function newSessionId() {
  return crypto.randomBytes(24).toString("hex");
}

function nowMs() {
  return Date.now();
}

function isRequestSecure(req) {
  if (req.secure) return true;
  const proto = req.headers["x-forwarded-proto"];
  return typeof proto === "string" && proto.toLowerCase().includes("https");
}

function cleanupExpiredSessions(db) {
  const cutoff = nowMs() - SESSION_TTL_MS;
  for (const [sid, sess] of Object.entries(db.sessions)) {
    if (!sess || typeof sess !== "object") {
      delete db.sessions[sid];
      continue;
    }
    if (typeof sess.lastSeenAt !== "number" || sess.lastSeenAt < cutoff) {
      delete db.sessions[sid];
    }
  }
}

function getAuthUser(req) {
  const sid = req.cookies?.[SESSION_COOKIE];
  if (!sid) return null;
  const db = readDb();
  cleanupExpiredSessions(db);
  const sess = db.sessions[sid];
  if (!sess || typeof sess.username !== "string") {
    if (db.sessions[sid]) {
      delete db.sessions[sid];
      writeDb(db);
    }
    return null;
  }
  sess.lastSeenAt = nowMs();
  db.sessions[sid] = sess;
  writeDb(db);
  return sess.username;
}

app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

app.post("/api/register", (req, res) => {
  const username = normalizeUsername(req.body?.username);
  const password = String(req.body?.password || "");
  if (username.length < 3) return res.status(400).json({ error: "username_min_3" });
  if (password.length < 4) return res.status(400).json({ error: "password_min_4" });

  const db = readDb();
  cleanupExpiredSessions(db);
  if (db.users[username]) return res.status(409).json({ error: "user_exists" });

  db.users[username] = {
    passwordHash: hashPassword(password),
    createdAt: nowMs(),
    progress: null
  };
  writeDb(db);
  return res.json({ ok: true });
});

app.post("/api/login", (req, res) => {
  const username = normalizeUsername(req.body?.username);
  const password = String(req.body?.password || "");
  const db = readDb();
  cleanupExpiredSessions(db);
  const user = db.users[username];
  if (!user || !verifyPassword(password, user.passwordHash)) {
    return res.status(401).json({ error: "invalid_credentials" });
  }
  const sid = newSessionId();
  db.sessions[sid] = { username, createdAt: nowMs(), lastSeenAt: nowMs() };
  writeDb(db);

  const secureCookie = isProd ? isRequestSecure(req) : false;
  res.cookie(SESSION_COOKIE, sid, {
    httpOnly: true,
    sameSite: "lax",
    secure: secureCookie,
    maxAge: SESSION_TTL_MS,
    path: "/"
  });
  return res.json({ ok: true, user: username });
});

app.post("/api/logout", (req, res) => {
  const sid = req.cookies?.[SESSION_COOKIE];
  if (sid) {
    const db = readDb();
    if (db.sessions[sid]) {
      delete db.sessions[sid];
      writeDb(db);
    }
  }
  res.clearCookie(SESSION_COOKIE, { path: "/" });
  res.json({ ok: true });
});

app.get("/api/me", (req, res) => {
  const user = getAuthUser(req);
  if (!user) return res.json({ user: null });
  return res.json({ user });
});

app.get("/api/progress", (req, res) => {
  const username = getAuthUser(req);
  if (!username) return res.status(401).json({ error: "unauthorized" });
  const db = readDb();
  const user = db.users[username];
  if (!user) return res.status(401).json({ error: "unauthorized" });
  return res.json({ progress: user.progress || null });
});

app.put("/api/progress", (req, res) => {
  const username = getAuthUser(req);
  if (!username) return res.status(401).json({ error: "unauthorized" });
  const db = readDb();
  const user = db.users[username];
  if (!user) return res.status(401).json({ error: "unauthorized" });
  user.progress = req.body?.progress ?? null;
  db.users[username] = user;
  writeDb(db);
  return res.json({ ok: true });
});

app.use(express.static(process.cwd(), { extensions: ["html"] }));

app.listen(PORT, "0.0.0.0", () => {
  // eslint-disable-next-line no-console
  console.log(`Server running on http://0.0.0.0:${PORT}`);
  // eslint-disable-next-line no-console
  console.log(`Data dir: ${DATA_DIR}`);
  // eslint-disable-next-line no-console
  console.log(`DB path: ${DB_PATH}`);
});

