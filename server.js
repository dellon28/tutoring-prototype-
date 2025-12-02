// server.js
const express = require("express");
const http = require("http");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { Server } = require("socket.io");
const { v4: uuidv4 } = require("uuid");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;

const PUBLIC_DIR = path.join(__dirname, "public");
const DB_PATH = path.join(__dirname, "db.json");   // users + chat rooms
const DB1_PATH = path.join(__dirname, "db1.json"); // sessions + bookings

// -------------------------
// Idempotency (prevents accidental double POSTs)
// -------------------------
const idemStore = new Map(); // key -> { ts, status, body }
function cleanupIdem() {
  const now = Date.now();
  for (const [k, v] of idemStore.entries()) {
    if (!v?.ts || now - v.ts > 2 * 60 * 1000) idemStore.delete(k); // 2 min TTL
  }
}
function getIdempotencyKey(req) {
  const k = req.headers["x-idempotency-key"];
  return k ? String(k) : null;
}
function idemKey(req, routeTag) {
  const idem = getIdempotencyKey(req);
  if (!idem) return null;
  return `${req.user?.id || "anon"}|${routeTag}|${idem}`;
}
function idemReplay(res, stored) {
  return res.status(stored.status).json(stored.body);
}
function idemRemember(key, status, body) {
  cleanupIdem();
  idemStore.set(key, { ts: Date.now(), status, body });
}

// -------------------------
// Generic JSON helpers
// -------------------------
function safeReadJson(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return null;
  }
}
function writeJson(filePath, obj) {
  fs.writeFileSync(filePath, JSON.stringify(obj, null, 2), "utf8");
}

// -------------------------
// Password helpers (db.json users)
// -------------------------
function scryptHash(password, saltHex) {
  return crypto.scryptSync(password, saltHex, 64).toString("hex");
}
function makePasswordRecord(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = scryptHash(password, salt);
  return { salt, hash, algo: "scrypt" };
}
function verifyPassword(password, record) {
  if (!record?.salt || !record?.hash) return false;
  const hash = scryptHash(password, record.salt);
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(record.hash, "hex"));
}

// -------------------------
// Seeded demo users (db.json)
// -------------------------
const SEEDED = [
  { id: "admin-1", name: "Admin Doe", role: "Admin", status: "active", pass: "admin123" },
  { id: "tutor-1", name: "Dr. Smith", role: "Tutor", status: "active", pass: "tutor123" },
  { id: "student-1", name: "Student John", role: "Student", status: "active", pass: "student123" },
];

// -------------------------
// db.json (users + rooms) helpers
// -------------------------
function writeDb(db) {
  writeJson(DB_PATH, db);
}

function ensureDb() {
  if (!fs.existsSync(DB_PATH)) {
    const db = { users: [], rooms: {} };
    for (const u of SEEDED) {
      db.users.push({
        id: u.id,
        name: u.name,
        role: u.role,
        status: u.status,
        password: makePasswordRecord(u.pass),
        createdAt: Date.now(),
      });
    }
    writeDb(db);
    console.log("✅ db.json created with seeded users:");
    SEEDED.forEach(u => console.log(`   ${u.name} / ${u.pass}`));
    return;
  }

  const db = safeReadJson(DB_PATH);
  if (!db || typeof db !== "object") {
    const bak = DB_PATH + ".bak-" + Date.now();
    try { fs.copyFileSync(DB_PATH, bak); } catch {}
    const fresh = { users: [], rooms: {} };
    for (const u of SEEDED) {
      fresh.users.push({
        id: u.id,
        name: u.name,
        role: u.role,
        status: u.status,
        password: makePasswordRecord(u.pass),
        createdAt: Date.now(),
      });
    }
    writeDb(fresh);
    console.log("⚠️ db.json was invalid. Backed up and recreated seeded db.");
    return;
  }

  if (!Array.isArray(db.users)) db.users = [];
  if (!db.rooms || typeof db.rooms !== "object") db.rooms = {};

  let changed = false;

  for (const su of SEEDED) {
    let user =
      db.users.find(u => u.id === su.id) ||
      db.users.find(u => String(u.name).trim().toLowerCase() === su.name.toLowerCase());

    if (!user) {
      db.users.push({
        id: su.id,
        name: su.name,
        role: su.role,
        status: su.status,
        password: makePasswordRecord(su.pass),
        createdAt: Date.now(),
      });
      changed = true;
      continue;
    }

    if (!user.password?.salt || !user.password?.hash) {
      user.password = makePasswordRecord(su.pass);
      changed = true;
    }
    if (user.role !== su.role) { user.role = su.role; changed = true; }
    if (user.status !== "active") { user.status = "active"; changed = true; }
  }

  if (changed) {
    writeDb(db);
    console.log("✅ db.json repaired/updated so seeded logins work.");
  }
}

function readDb() {
  ensureDb();
  return safeReadJson(DB_PATH);
}

function findUserByName(db, name) {
  const needle = String(name || "").trim().toLowerCase();
  return db.users.find(u => String(u.name).trim().toLowerCase() === needle);
}
function getUserById(db, id) {
  return db.users.find(u => u.id === id);
}

// -------------------------
// db1.json (sessions + bookings)
// -------------------------
function ensureDb1() {
  if (!fs.existsSync(DB1_PATH)) {
    const db1 = { sessions: [], bookings: [] };
    writeJson(DB1_PATH, db1);
    console.log("✅ db1.json created (sessions + bookings).");
    return;
  }

  const db1 = safeReadJson(DB1_PATH);
  if (!db1 || typeof db1 !== "object") {
    const bak = DB1_PATH + ".bak-" + Date.now();
    try { fs.copyFileSync(DB1_PATH, bak); } catch {}
    const fresh = { sessions: [], bookings: [] };
    writeJson(DB1_PATH, fresh);
    console.log("⚠️ db1.json was invalid. Backed up and recreated.");
    return;
  }

  if (!Array.isArray(db1.sessions)) db1.sessions = [];
  if (!Array.isArray(db1.bookings)) db1.bookings = [];

  // ✅ Dedup sessions by id
  const seenSess = new Set();
  const dedupedSessions = [];
  for (const s of db1.sessions) {
    if (!s?.id) continue;
    if (seenSess.has(s.id)) continue;
    seenSess.add(s.id);
    dedupedSessions.push(s);
  }
  db1.sessions = dedupedSessions;

  // ✅ Dedup bookings by (studentId, sessionId)
  const seen = new Set();
  const dedupedBookings = [];
  for (const b of db1.bookings) {
    const key = `${b.studentId}|${b.sessionId}`;
    if (seen.has(key)) continue;
    seen.add(key);
    dedupedBookings.push(b);
  }
  db1.bookings = dedupedBookings;

  writeJson(DB1_PATH, db1);
}

function readDb1() {
  ensureDb1();
  return safeReadJson(DB1_PATH);
}
function writeDb1(db1) {
  writeJson(DB1_PATH, db1);
}

// -------------------------
// Token auth (simple demo)
// -------------------------
const activeTokens = new Map(); // token -> { userId, createdAt }

function issueToken(userId) {
  const token = crypto.randomBytes(24).toString("hex");
  activeTokens.set(token, { userId, createdAt: Date.now() });
  return token;
}

function getAuthToken(req) {
  const hdr = req.headers.authorization || "";
  if (hdr.toLowerCase().startsWith("bearer ")) return hdr.slice(7).trim();
  return req.headers["x-auth-token"];
}

function authRequired(req, res, next) {
  const token = getAuthToken(req);
  if (!token || !activeTokens.has(token)) return res.status(401).json({ message: "Not logged in." });

  const { userId } = activeTokens.get(token);
  const db = readDb();
  const user = getUserById(db, userId);
  if (!user) return res.status(401).json({ message: "Invalid session." });

  req.user = { id: user.id, name: user.name, role: user.role, status: user.status };
  req.token = token;
  next();
}

function adminOnly(req, res, next) {
  if (req.user.role !== "Admin") return res.status(403).json({ message: "Admins only." });
  next();
}
function tutorOnly(req, res, next) {
  if (req.user.role !== "Tutor") return res.status(403).json({ message: "Tutors only." });
  next();
}
function studentOnly(req, res, next) {
  if (req.user.role !== "Student") return res.status(403).json({ message: "Students only." });
  next();
}

// -------------------------
// Small helper: sessions + bookings logic
// -------------------------
function countBookingsForSession(db1, sessionId) {
  return db1.bookings.filter(b => b.sessionId === sessionId).length;
}

function studentHasBookedTutor(db1, studentId, tutorId) {
  const tutorSessionIds = new Set(db1.sessions.filter(s => s.tutorId === tutorId).map(s => s.id));
  return db1.bookings.some(b => b.studentId === studentId && tutorSessionIds.has(b.sessionId));
}

function canChatPair(db1, me, other) {
  if (me.role === "Student" && other.role === "Tutor") {
    return studentHasBookedTutor(db1, me.id, other.id);
  }
  if (me.role === "Tutor" && other.role === "Student") {
    return studentHasBookedTutor(db1, other.id, me.id);
  }
  return false;
}

// -------------------------
// middleware / static
// -------------------------
app.use(express.json());
app.use(express.static(PUBLIC_DIR));

app.get("/", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

// -------------------------
// AUTH endpoints
// -------------------------
app.post("/api/auth/signup", (req, res) => {
  const { name, password, role } = req.body || {};
  const cleanName = String(name || "").trim();
  const cleanRole = String(role || "").trim();

  if (!cleanName || !password) return res.status(400).json({ message: "Name and password required." });
  if (!["Student", "Tutor"].includes(cleanRole)) return res.status(400).json({ message: "Role must be Student or Tutor." });

  const db = readDb();
  const existing = findUserByName(db, cleanName);
  if (existing) return res.status(409).json({ message: "A user with that name already exists." });

  const user = {
    id: uuidv4(),
    name: cleanName,
    role: cleanRole,
    status: "pending",
    password: makePasswordRecord(String(password)),
    createdAt: Date.now(),
  };

  db.users.push(user);
  writeDb(db);

  io.emit("db:changed", { reason: "signup_submitted", ts: Date.now() });

  res.status(201).json({
    message: "Signup submitted. Waiting for admin approval.",
    user: { id: user.id, name: user.name, role: user.role, status: user.status },
  });
});

app.post("/api/auth/login", (req, res) => {
  const { name, password } = req.body || {};
  const cleanName = String(name || "").trim();
  if (!cleanName || !password) return res.status(400).json({ message: "Name and password required." });

  const db = readDb();
  const user = findUserByName(db, cleanName);
  if (!user) return res.status(401).json({ message: "Invalid credentials." });

  if (user.status !== "active") return res.status(403).json({ message: `Account is ${user.status}.`, status: user.status });

  if (!verifyPassword(String(password), user.password)) return res.status(401).json({ message: "Invalid credentials." });

  const token = issueToken(user.id);
  res.json({
    message: "Login successful.",
    token,
    user: { id: user.id, name: user.name, role: user.role, status: user.status },
  });
});

app.get("/api/me", authRequired, (req, res) => {
  res.json({ user: req.user });
});

app.post("/api/auth/logout", authRequired, (req, res) => {
  activeTokens.delete(req.token);
  res.json({ message: "Logged out." });
});

// -------------------------
// Admin endpoints
// -------------------------
app.get("/api/admin/pending", authRequired, adminOnly, (req, res) => {
  const db = readDb();
  const pending = db.users
    .filter(u => u.status === "pending" && (u.role === "Student" || u.role === "Tutor"))
    .map(u => ({ id: u.id, name: u.name, role: u.role, status: u.status, createdAt: u.createdAt }));

  res.json({ pending });
});

app.post("/api/admin/users/:id/approve", authRequired, adminOnly, (req, res) => {
  const db = readDb();
  const u = getUserById(db, req.params.id);
  if (!u) return res.status(404).json({ message: "User not found." });

  u.status = "active";
  writeDb(db);

  io.emit("db:changed", { reason: "user_approved", ts: Date.now() });

  res.json({ message: "User approved.", user: { id: u.id, name: u.name, role: u.role, status: u.status } });
});

app.post("/api/admin/users/:id/deny", authRequired, adminOnly, (req, res) => {
  const db = readDb();
  const idx = db.users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ message: "User not found." });

  const [removed] = db.users.splice(idx, 1);
  writeDb(db);

  io.emit("db:changed", { reason: "user_denied", ts: Date.now() });

  res.json({ message: "User denied/removed.", removed: { id: removed.id, name: removed.name, role: removed.role } });
});

// -------------------------
// Sessions API (db1.json)
// -------------------------
app.get("/api/sessions", authRequired, (req, res) => {
  const db1 = readDb1();

  const sessions = db1.sessions
    .map(s => {
      const booked = countBookingsForSession(db1, s.id);
      const bookedByMe =
        req.user.role === "Student"
          ? db1.bookings.some(b => b.sessionId === s.id && b.studentId === req.user.id)
          : false;

      return {
        id: s.id,
        tutorId: s.tutorId,
        tutorName: s.tutorName,
        topic: s.topic,
        date: s.date,
        time: s.time,
        capacity: s.capacity,
        bookings: booked,
        bookedByMe,
      };
    })
    .sort((a, b) => {
      const ta = `${a.date}T${a.time}`;
      const tb = `${b.date}T${b.time}`;
      return ta.localeCompare(tb);
    });

  res.json({ sessions });
});

app.post("/api/sessions", authRequired, tutorOnly, (req, res) => {
  const idem = idemKey(req, "create_session");
  if (idem && idemStore.has(idem)) return idemReplay(res, idemStore.get(idem));

  const topic = String(req.body?.topic || "").trim();
  const date = String(req.body?.date || "").trim(); // YYYY-MM-DD
  const time = String(req.body?.time || "").trim(); // HH:MM
  const capacity = parseInt(req.body?.capacity, 10);

  if (!topic || !date || !time || !Number.isFinite(capacity) || capacity < 1) {
    const body = { message: "topic, date, time, capacity are required." };
    if (idem) idemRemember(idem, 400, body);
    return res.status(400).json(body);
  }

  const db1 = readDb1();
  const now = Date.now();

  // Anti-double-submit: same tutor/topic/date/time/capacity within 2 seconds => treat as duplicate
  const dup = db1.sessions.find(s =>
    s.tutorId === req.user.id &&
    s.topic === topic &&
    s.date === date &&
    s.time === time &&
    s.capacity === capacity &&
    (now - (s.createdAt || 0)) < 2000
  );

  if (dup) {
    const body = { message: "Session created (deduped).", session: dup, deduped: true };
    if (idem) idemRemember(idem, 200, body);
    return res.status(200).json(body);
  }

  const session = {
    id: uuidv4(),
    tutorId: req.user.id,
    tutorName: req.user.name,
    topic,
    date,
    time,
    capacity,
    createdAt: now,
    status: "active",
  };

  db1.sessions.push(session);
  writeDb1(db1);

  const body = { message: "Session created.", session };
  if (idem) idemRemember(idem, 201, body);
  return res.status(201).json(body);
});

app.post("/api/sessions/:id/book", authRequired, studentOnly, (req, res) => {
  const idem = idemKey(req, `book_${req.params.id}`);
  if (idem && idemStore.has(idem)) return idemReplay(res, idemStore.get(idem));

  const sessionId = req.params.id;
  const db1 = readDb1();
  const session = db1.sessions.find(s => s.id === sessionId);
  if (!session) {
    const body = { message: "Session not found." };
    if (idem) idemRemember(idem, 404, body);
    return res.status(404).json(body);
  }

  // prevent double booking
  const already = db1.bookings.find(b => b.sessionId === sessionId && b.studentId === req.user.id);
  if (already) {
    const body = { message: "Already booked.", booking: already, deduped: true, session };
    if (idem) idemRemember(idem, 200, body);
    return res.status(200).json(body);
  }

  const bookedCount = countBookingsForSession(db1, sessionId);
  if (bookedCount >= session.capacity) {
    const body = { message: "Session is fully booked." };
    if (idem) idemRemember(idem, 409, body);
    return res.status(409).json(body);
  }

  const booking = {
    id: uuidv4(),
    sessionId,
    studentId: req.user.id,
    studentName: req.user.name,
    createdAt: Date.now(),
  };

  db1.bookings.push(booking);
  writeDb1(db1);

  io.emit("db:changed", { reason: "booking_created", ts: Date.now() });

  const body = { message: "Booked.", booking, session };
  if (idem) idemRemember(idem, 201, body);
  return res.status(201).json(body);
});

// ✅ CANCEL SESSION (Tutor) — removes session + all bookings for it
app.post("/api/sessions/:id/cancel", authRequired, tutorOnly, (req, res) => {
  const sessionId = req.params.id;

  const idem = idemKey(req, `cancel_${sessionId}`);
  if (idem && idemStore.has(idem)) return idemReplay(res, idemStore.get(idem));

  const db1 = readDb1();
  const idx = db1.sessions.findIndex(s => s.id === sessionId);

  if (idx === -1) {
    const body = { message: "Session not found." };
    if (idem) idemRemember(idem, 404, body);
    return res.status(404).json(body);
  }

  const session = db1.sessions[idx];
  if (session.tutorId !== req.user.id) {
    const body = { message: "You can only cancel your own sessions." };
    if (idem) idemRemember(idem, 403, body);
    return res.status(403).json(body);
  }

  // remove session
  db1.sessions.splice(idx, 1);

  // remove bookings for the cancelled session
  const before = db1.bookings.length;
  db1.bookings = db1.bookings.filter(b => b.sessionId !== sessionId);
  const removedBookings = before - db1.bookings.length;

  writeDb1(db1);

  // notify UIs to refresh sessions/schedules/chat partners
  io.emit("db:changed", { reason: "session_cancelled", sessionId, tutorId: req.user.id, ts: Date.now() });

  const body = { message: "Session cancelled.", sessionId, removedBookings, session };
  if (idem) idemRemember(idem, 200, body);
  return res.status(200).json(body);
});

// -------------------------
// Schedule endpoints (db1.json)
// -------------------------
app.get("/api/schedule/student", authRequired, studentOnly, (req, res) => {
  const db1 = readDb1();

  const myBookings = db1.bookings.filter(b => b.studentId === req.user.id);
  const sessionsById = new Map(db1.sessions.map(s => [s.id, s]));

  const sessions = myBookings
    .map(b => {
      const s = sessionsById.get(b.sessionId);
      if (!s) return null;
      return {
        bookingId: b.id,
        sessionId: s.id,
        topic: s.topic,
        tutorId: s.tutorId,
        tutorName: s.tutorName,
        date: s.date,
        time: s.time,
      };
    })
    .filter(Boolean)
    .sort((a, b) => `${a.date}T${a.time}`.localeCompare(`${b.date}T${b.time}`));

  res.json({ sessions });
});

app.get("/api/schedule/tutor", authRequired, tutorOnly, (req, res) => {
  const db1 = readDb1();

  const mySessions = db1.sessions
    .filter(s => s.tutorId === req.user.id)
    .sort((a, b) => `${a.date}T${a.time}`.localeCompare(`${b.date}T${b.time}`));

  const bySession = new Map();
  for (const s of mySessions) bySession.set(s.id, []);

  for (const b of db1.bookings) {
    if (bySession.has(b.sessionId)) {
      bySession.get(b.sessionId).push({ studentId: b.studentId, studentName: b.studentName, bookingId: b.id });
    }
  }

  const sessions = mySessions.map(s => ({
    id: s.id,
    topic: s.topic,
    date: s.date,
    time: s.time,
    capacity: s.capacity,
    bookings: (bySession.get(s.id) || []).length,
    students: (bySession.get(s.id) || []).sort((a, b) => a.studentName.localeCompare(b.studentName)),
  }));

  res.json({ sessions });
});

// -------------------------
// Chat partner restriction endpoint (based on bookings)
// -------------------------
app.get("/api/chat/partners", authRequired, (req, res) => {
  const db = readDb();
  const db1 = readDb1();

  if (!(req.user.role === "Student" || req.user.role === "Tutor")) {
    return res.json({ users: [] });
  }

  let allowedIds = new Set();

  if (req.user.role === "Student") {
    const myBookings = db1.bookings.filter(b => b.studentId === req.user.id);
    const sessionsById = new Map(db1.sessions.map(s => [s.id, s]));
    for (const b of myBookings) {
      const s = sessionsById.get(b.sessionId);
      if (s?.tutorId) allowedIds.add(s.tutorId);
    }
  } else {
    const mySessionIds = new Set(db1.sessions.filter(s => s.tutorId === req.user.id).map(s => s.id));
    for (const b of db1.bookings) {
      if (mySessionIds.has(b.sessionId)) allowedIds.add(b.studentId);
    }
  }

  const wantRole = req.user.role === "Student" ? "Tutor" : "Student";
  const users = db.users
    .filter(u => u.status === "active" && u.role === wantRole && allowedIds.has(u.id))
    .map(u => ({ id: u.id, name: u.name, role: u.role }))
    .sort((a, b) => a.name.localeCompare(b.name));

  res.json({ users });
});

// -------------------------
// Chat via Socket.IO (restricted by bookings)
// -------------------------
function dmRoomId(a, b) {
  const [x, y] = [a, b].sort();
  return `dm:${x}:${y}`;
}
function sanitizeMessage(text) {
  const t = String(text ?? "").trim();
  if (!t) return null;
  return t.slice(0, 500);
}

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    if (!token || !activeTokens.has(token)) return next(new Error("unauthorized"));

    const { userId } = activeTokens.get(token);
    const db = readDb();
    const user = getUserById(db, userId);
    if (!user || user.status !== "active") return next(new Error("unauthorized"));

    socket.data.user = { id: user.id, name: user.name, role: user.role };
    next();
  } catch {
    next(new Error("unauthorized"));
  }
});

io.on("connection", (socket) => {
  socket.on("chat:join", ({ otherUserId }, ack) => {
    const me = socket.data.user;
    const db = readDb();
    const db1 = readDb1();
    const other = getUserById(db, otherUserId);

    if (!other || other.status !== "active") return ack?.({ ok: false, error: "user_not_found" });

    const pairOk =
      (me.role === "Student" && other.role === "Tutor") ||
      (me.role === "Tutor" && other.role === "Student");
    if (!pairOk) return ack?.({ ok: false, error: "invalid_pair" });

    if (!canChatPair(db1, me, other)) return ack?.({ ok: false, error: "not_booked" });

    const roomId = dmRoomId(me.id, other.id);

    for (const r of socket.rooms) if (String(r).startsWith("dm:")) socket.leave(r);
    socket.join(roomId);

    const mainDb = readDb();
    if (!mainDb.rooms[roomId]) {
      mainDb.rooms[roomId] = { participants: [me.id, other.id], messages: [] };
      writeDb(mainDb);
    }

    socket.emit("chat:history", { roomId, history: mainDb.rooms[roomId].messages || [] });
    ack?.({ ok: true, roomId });
  });

  socket.on("chat:send", ({ roomId, text }, ack) => {
    const me = socket.data.user;
    const clean = sanitizeMessage(text);
    if (!clean) return ack?.({ ok: false, error: "empty" });

    const db = readDb();
    const room = db.rooms[roomId];
    if (!room || !room.participants?.includes(me.id)) return ack?.({ ok: false, error: "not_in_room" });

    const msg = {
      id: uuidv4(),
      roomId,
      senderId: me.id,
      senderName: me.name,
      senderRole: me.role,
      text: clean,
      ts: Date.now(),
    };

    room.messages.push(msg);
    if (room.messages.length > 200) room.messages.shift();
    writeDb(db);

    io.to(roomId).emit("chat:message", msg);
    ack?.({ ok: true });
  });

  // ✅ CLEAR CHAT HISTORY for the current DM room
  socket.on("chat:clear", ({ roomId }, ack) => {
    const me = socket.data.user;
    if (!roomId) return ack?.({ ok: false, error: "missing_roomId" });

    const db = readDb();
    const room = db.rooms?.[roomId];
    if (!room || !room.participants?.includes(me.id)) {
      return ack?.({ ok: false, error: "not_in_room" });
    }

    room.messages = [];
    writeDb(db);

    io.to(roomId).emit("chat:history", { roomId, history: [] });
    ack?.({ ok: true });
  });
});

// -------------------------
server.listen(PORT, () => {
  ensureDb();
  ensureDb1();
  console.log(`✅ Server running at http://localhost:${PORT}`);
});
