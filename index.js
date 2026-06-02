/**
 * ============================================================
 *  MarinaPark — Backend Completo v2
 *  Gestão de Acessos por Cartão / PIN
 * ============================================================
 *  Novos campos suportados no Excel de importação:
 *    Data/Hora, Nome, Departamento, ID/Cracha, Tipo de Acesso,
 *    Ponto de Controlo (ENTRADA / SAIDA)
 *
 *  Endpoints:
 *    AUTH        POST /api/auth/register
 *                POST /api/auth/login
 *                POST /api/auth/logout
 *                GET  /api/auth/me
 *
 *    CARTÕES     GET    /api/cards
 *                POST   /api/cards
 *                GET    /api/cards/:id
 *                PUT    /api/cards/:id
 *                DELETE /api/cards/:id
 *
 *    REGISTOS    GET    /api/records
 *                POST   /api/records
 *                GET    /api/records/:id
 *                PUT    /api/records/:id
 *                PATCH  /api/records/:id/status
 *                PATCH  /api/records/:id/exit
 *                DELETE /api/records/:id
 *
 *    IMPORTAÇÃO  POST   /api/records/import
 *                POST   /api/records/import-access-log  ← formato Excel da marina
 *
 *    STATS       GET    /api/stats
 *    CONFIG      GET    /api/config/price
 *                PUT    /api/config/price
 * ============================================================
 */

"use strict";

const { MongoClient, ObjectId } = require("mongodb");
const bcrypt   = require("bcryptjs");
const jwt      = require("jsonwebtoken");
const cookie   = require("cookie");
const Cors     = require("cors");
const http     = require("http");
const crypto   = require("crypto");
const path     = require("path");
const fs       = require("fs");
const Database = require("better-sqlite3");

// ─── ENV / CONSTANTS ────────────────────────────────────────
const MONGODB_URI     = process.env.MONGODB_URI  || "mongodb+srv://marinapark:s6zbDqaM1r1j0Odv@cluster0.p5prkfu.mongodb.net/";
const DB_NAME         = process.env.DB_NAME      || "marinapark";
const JWT_SECRET      = process.env.JWT_SECRET   || "MARINAPARK_SECRET_CHANGE_ME";
const COOKIE_NAME     = process.env.COOKIE_NAME  || "mp_sid";
const PORT            = process.env.PORT         || 5000;
const COOKIE_MAX_AGE  = 60 * 60 * 24 * 7;
const SESSION_MAX_AGE = 60 * 60 * 24 * 7;
const SESSION_CLEANUP = 60 * 60 * 1000;

const ALLOWED_ORIGINS = [
  "http://127.0.0.1:5500",
  "http://localhost:5500",
  "http://localhost:3000",
  "http://localhost:4000",
  "http://localhost:5000",
  "https://marinapark.pt",
  "https://www.marinapark.pt",
];

const VALID_STATUSES = ["paid", "unpaid", "debt", "free", "parked"];

// Palavras-chave para detetar ENTRADA / SAÍDA na coluna Ponto de Controlo
const ENTRADA_KEYWORDS = ["entrada", "entry", "in",  "access in",  "barreira marina entrada"];
const SAIDA_KEYWORDS   = ["saida",   "saída", "exit", "out", "access out", "barreira marina saida", "barreira marina saída"];

// ─── SESSION STORE (SQLite) ──────────────────────────────────
const SESSION_DB = path.join(__dirname, "mp_sessions.db");
let _sdb, _sInsert, _sGet, _sRenew, _sDelete, _sClean;
let sessBackend = "sqlite";
const _memSess  = {};

try {
  _sdb = new Database(SESSION_DB);
  _sdb.pragma("journal_mode = WAL");
  _sdb.exec(`CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT, email TEXT, role TEXT,
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
  )`);
  _sInsert = _sdb.prepare("INSERT OR REPLACE INTO sessions (id,user_id,name,email,role,created_at,expires_at) VALUES (?,?,?,?,?,?,?)");
  _sGet    = _sdb.prepare("SELECT * FROM sessions WHERE id=?");
  _sRenew  = _sdb.prepare("UPDATE sessions SET expires_at=? WHERE id=?");
  _sDelete = _sdb.prepare("DELETE FROM sessions WHERE id=?");
  _sClean  = _sdb.prepare("DELETE FROM sessions WHERE expires_at<?");
  const _t = "__test__";
  _sInsert.run(_t,"test","T","t@t.com","admin",Date.now(),Date.now()+5000);
  const _tr = _sGet.get(_t); _sDelete.run(_t);
  if (!_tr) throw new Error("Sessao de teste nao lida");
  console.log("[SESSION]  SQLite OK —", SESSION_DB);
} catch (e) {
  console.error("[SESSION]  SQLite falhou:", e.message, "— a usar memoria");
  sessBackend = "memory"; _sdb = null;
}

function sessionCreate(userId, meta = {}) {
  const id = crypto.randomBytes(32).toString("hex");
  const now = Date.now(), exp = now + SESSION_MAX_AGE * 1000;
  if (sessBackend === "sqlite") _sInsert.run(id, String(userId), meta.name||null, meta.email||null, meta.role||null, now, exp);
  else _memSess[id] = { userId: String(userId), ...meta, createdAt: now, expiresAt: exp };
  return id;
}
function sessionGet(id) {
  if (!id) return null;
  if (sessBackend === "sqlite") {
    const r = _sGet.get(id);
    if (!r) return null;
    if (Date.now() > r.expires_at) { _sDelete.run(id); return null; }
    return { userId: r.user_id, name: r.name, email: r.email, role: r.role };
  }
  const s = _memSess[id];
  if (!s) return null;
  if (Date.now() > s.expiresAt) { delete _memSess[id]; return null; }
  return s;
}
function sessionRenew(id) {
  if (!id) return;
  if (sessBackend === "sqlite") { try { _sRenew.run(Date.now() + SESSION_MAX_AGE * 1000, id); } catch(e){} }
  else if (_memSess[id]) _memSess[id].expiresAt = Date.now() + SESSION_MAX_AGE * 1000;
}
function sessionDestroy(id) {
  if (!id) return;
  if (sessBackend === "sqlite") { try { _sDelete.run(id); } catch(e){} }
  else delete _memSess[id];
}
setInterval(() => {
  if (sessBackend === "sqlite") { try { _sClean.run(Date.now()); } catch(e){} }
  else { const now = Date.now(); for (const [k,v] of Object.entries(_memSess)) if (now > v.expiresAt) delete _memSess[k]; }
}, SESSION_CLEANUP);

// ─── MONGODB ─────────────────────────────────────────────────
let _client, _clientPromise;
let usersCol, cardsCol, recordsCol, configCol;

async function getDb() {
  if (!_clientPromise) {
    _client = new MongoClient(MONGODB_URI, { tls: true });
    _clientPromise = _client.connect();
  }
  const conn = await _clientPromise;
  const db   = conn.db(DB_NAME);
  usersCol   = usersCol   || db.collection("users");
  cardsCol   = cardsCol   || db.collection("cards");
  recordsCol = recordsCol || db.collection("records");
  configCol  = configCol  || db.collection("config");
  await usersCol.createIndex({ email: 1 },      { unique: true, background: true });
  await cardsCol.createIndex({ cardNumber: 1 }, { unique: true, background: true });
  await cardsCol.createIndex({ name: 1 },       { background: true });
  await recordsCol.createIndex({ cardId: 1 },   { background: true });
  await recordsCol.createIndex({ entry: -1 },   { background: true });
  await recordsCol.createIndex({ cardId: 1, entry: 1 }, { background: true });
  // Índices novos
  await recordsCol.createIndex({ department: 1 },    { background: true });
  await recordsCol.createIndex({ accessType: 1 },    { background: true });
  await recordsCol.createIndex({ controlPoint: 1 },  { background: true });
  return db;
}

// ─── CORS ─────────────────────────────────────────────────────
const corsMiddleware = Cors({
  origin: true,
  methods: ["GET","POST","PUT","DELETE","OPTIONS","PATCH"],
  allowedHeaders: ["Content-Type","Authorization"],
  credentials: true,
  preflightContinue: false,
  optionsSuccessStatus: 204,
});
function runCors(req, res) {
  return new Promise((ok, fail) => corsMiddleware(req, res, r => r instanceof Error ? fail(r) : ok(r)));
}
function setCorsHeaders(req, res) {
  const origin = req.headers.origin;
  if (!origin || !ALLOWED_ORIGINS.includes(origin)) return;
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS,PATCH");
}

// ─── HELPERS ─────────────────────────────────────────────────
function toId(id) { try { return new ObjectId(id); } catch { return null; } }

function isSecure(req) {
  if (req.headers["x-forwarded-proto"] === "https") return true;
  if ((req.headers.origin  || "").startsWith("https://")) return true;
  return false;
}
function setSessionCookie(res, sid, req) {
  const secure = isSecure(req), sameSite = secure ? "none" : "lax";
  res.setHeader("Set-Cookie", cookie.serialize(COOKIE_NAME, sid, { httpOnly: true, secure, sameSite, path: "/", maxAge: COOKIE_MAX_AGE }));
}
function clearSessionCookie(res, req) {
  const secure = req ? isSecure(req) : false;
  res.setHeader("Set-Cookie", cookie.serialize(COOKIE_NAME, "", { httpOnly: true, secure, sameSite: secure ? "none" : "lax", path: "/", expires: new Date(0) }));
}
function readSession(req) {
  const auth = req.headers["authorization"] || "";
  if (auth.startsWith("Bearer ")) {
    const sid = auth.slice(7).trim(), data = sessionGet(sid);
    return { sid, data };
  }
  const parsed = cookie.parse(req.headers.cookie || "");
  const sid    = parsed[COOKIE_NAME];
  if (sid) { const data = sessionGet(sid); return { sid, data }; }
  return { sid: null, data: null };
}
function parseBody(req) {
  return new Promise((ok, fail) => {
    let raw = "";
    req.on("data", c => raw += c);
    req.on("end",  () => { try { ok(raw ? JSON.parse(raw) : {}); } catch { ok({}); } });
    req.on("error", fail);
  });
}
function buildRes(res) {
  res.status = code => { res.statusCode = code; return res; };
  res.json   = obj  => { res.setHeader("Content-Type","application/json"); res.end(JSON.stringify(obj)); };
  return res;
}
function err500(res, endpoint, e) {
  console.error(`[ERROR] ${endpoint}:`, e);
  if (!res.writableEnded) res.status(500).json({ error: "Erro interno", detail: e?.message || String(e) });
}

// ─── AUTH MIDDLEWARE ─────────────────────────────────────────
async function requireAuth(req, res) {
  const { sid, data } = readSession(req);
  if (sid && data) {
    const _id = toId(data.userId);
    if (!_id) { res.status(401).json({ error: "Sessao invalida" }); return null; }
    const user = await usersCol.findOne({ _id }, { projection: { password: 0 } });
    if (!user)              { res.status(401).json({ error: "Utilizador nao encontrado" }); return null; }
    if (user.active===false){ res.status(403).json({ error: "Conta desativada" }); return null; }
    sessionRenew(sid);
    return user;
  }
  const auth = req.headers["authorization"] || "";
  if (auth.startsWith("Bearer ")) {
    try {
      const payload = jwt.verify(auth.slice(7).trim(), JWT_SECRET);
      if (payload?.uid) {
        const _id = toId(payload.uid);
        const user = _id && await usersCol.findOne({ _id }, { projection: { password: 0 } });
        if (user) return user;
      }
    } catch {}
  }
  res.status(401).json({ error: "Nao autenticado" });
  return null;
}

// ─── PRICE CONFIG ────────────────────────────────────────────
const DEFAULT_PRICE = { pricePerHour: 1.5, freeHoursPerVisit: 1 };
async function getPriceConfig() {
  const doc = await configCol.findOne({ _key: "price" });
  return doc ? { pricePerHour: doc.pricePerHour, freeHoursPerVisit: doc.freeHoursPerVisit } : { ...DEFAULT_PRICE };
}

// ─── CALC RECORD ─────────────────────────────────────────────
function calcRecord(r, cfg) {
  const { pricePerHour, freeHoursPerVisit } = cfg;
  if (!r.entry || !r.exit) return { ...r, durationMin: null, durationLabel: "—", freeHours: 0, paidHours: 0, amountDue: 0 };
  const ms = new Date(r.exit) - new Date(r.entry);
  if (ms < 0) return { ...r, durationMin: null, durationLabel: "Erro", freeHours: 0, paidHours: 0, amountDue: 0 };
  const totalH    = ms / 3_600_000;
  const freeHours = Math.min(totalH, freeHoursPerVisit);
  const paidHours = Math.max(0, totalH - freeHoursPerVisit);
  const amountDue = parseFloat((paidHours * pricePerHour).toFixed(2));
  const h = Math.floor(totalH), m = Math.round((totalH - h) * 60);
  return { ...r, durationMin: ms / 60_000, durationLabel: h > 0 ? `${h}h ${m}min` : `${m}min`, freeHours, paidHours, amountDue };
}

// ─── DETECT ENTRY/EXIT from Ponto de Controlo ────────────────
function detectDirection(controlPoint) {
  if (!controlPoint) return null;
  const cp = String(controlPoint).toLowerCase().trim();
  if (SAIDA_KEYWORDS.some(k => cp.includes(k)))   return "exit";
  if (ENTRADA_KEYWORDS.some(k => cp.includes(k))) return "entry";
  return null;
}

// ─── PARSE DATE from Excel (string ou número serial) ────────
function parseExcelDate(val) {
  if (!val) return null;
  // Excel serial number
  if (typeof val === "number") {
    const d = new Date(Math.round((val - 25569) * 86400 * 1000));
    return isNaN(d) ? null : d;
  }
  // String: "04/27/2026 03:02:31 PM" or "2026-04-27T15:02:31"
  const s = String(val).trim();
  // Tentar formato MM/DD/YYYY HH:MM:SS AM/PM
  const m1 = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})\s*(AM|PM)?$/i);
  if (m1) {
    let [,mo,dy,yr,hh,mm,ss,ampm] = m1;
    hh = parseInt(hh); mm = parseInt(mm); ss = parseInt(ss);
    if (ampm) {
      if (ampm.toUpperCase() === "PM" && hh !== 12) hh += 12;
      if (ampm.toUpperCase() === "AM" && hh === 12) hh = 0;
    }
    const d = new Date(parseInt(yr), parseInt(mo)-1, parseInt(dy), hh, mm, ss);
    return isNaN(d) ? null : d;
  }
  const d = new Date(s);
  return isNaN(d) ? null : d;
}

// ──────────────────────────────────────────────────────────────
//  HANDLER PRINCIPAL
// ──────────────────────────────────────────────────────────────
async function handler(req, res) {
  buildRes(res);
  try { await runCors(req, res); setCorsHeaders(req, res); } catch (e) { return res.status(403).json({ error: e.message || "CORS bloqueado" }); }
  if (req.method === "OPTIONS") { res.statusCode = 204; return res.end(); }
  try { await getDb(); } catch (e) { return res.status(503).json({ error: "Falha a ligar ao MongoDB", detail: e.message }); }

  const method = req.method;
  const urlObj = new URL(req.url || "/", `http://localhost:${PORT}`);
  const path_  = urlObj.pathname;
  const query  = {};
  urlObj.searchParams.forEach((v, k) => (query[k] = v));

  const cardIdMatch     = path_.match(/^\/api\/cards\/([\w\d]+)$/);
  const recordIdMatch   = path_.match(/^\/api\/records\/([\w\d]+)$/);
  const recordExitMatch = path_.match(/^\/api\/records\/([\w\d]+)\/exit$/);
  const recordStatMatch = path_.match(/^\/api\/records\/([\w\d]+)\/status$/);

  let body = {};
  if (!["GET","HEAD","OPTIONS"].includes(method)) {
    try { body = await parseBody(req); } catch { body = {}; }
  }

  // ══════════════════════════════════════
  //  AUTH
  // ══════════════════════════════════════
  if (path_ === "/api/auth/register" && method === "POST") {
    try {
      const { name, email, password, role } = body;
      if (!name || !email || !password) return res.status(400).json({ error: "name, email e password sao obrigatorios" });
      if (password.length < 8)          return res.status(400).json({ error: "Password minimo 8 caracteres" });
      const exists = await usersCol.findOne({ email: email.toLowerCase().trim() });
      if (exists) return res.status(409).json({ error: "Email ja registado" });
      const validRoles = ["admin","operator","viewer"];
      const hash = await bcrypt.hash(password, 10);
      const now  = new Date();
      const doc  = { name: name.trim(), email: email.toLowerCase().trim(), password: hash, role: validRoles.includes(role) ? role : "operator", active: true, createdAt: now, updatedAt: now };
      const result = await usersCol.insertOne(doc);
      const { password: _, ...safe } = doc;
      return res.status(201).json({ status: "ok", user: { ...safe, id: result.insertedId } });
    } catch (e) { return err500(res, "POST /api/auth/register", e); }
  }

  if (path_ === "/api/auth/login" && method === "POST") {
    try {
      const { email, password } = body;
      if (!email || !password) return res.status(400).json({ error: "email e password sao obrigatorios" });
      const user = await usersCol.findOne({ email: email.toLowerCase().trim() });
      if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: "Credenciais invalidas" });
      if (user.active === false) return res.status(403).json({ error: "Conta desativada" });
      const sid = sessionCreate(String(user._id), { name: user.name, email: user.email, role: user.role });
      setSessionCookie(res, sid, req);
      return res.json({ status: "ok", sessionId: sid, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
    } catch (e) { return err500(res, "POST /api/auth/login", e); }
  }

  if (path_ === "/api/auth/logout" && method === "POST") {
    try {
      const { sid } = readSession(req);
      if (sid) sessionDestroy(sid);
      clearSessionCookie(res, req);
      return res.json({ status: "ok", message: "Sessao terminada" });
    } catch (e) { return err500(res, "POST /api/auth/logout", e); }
  }

  if (path_ === "/api/auth/me" && method === "GET") {
    try {
      const { sid, data } = readSession(req);
      if (sid && data) {
        const _id = toId(data.userId);
        if (_id) {
          const user = await usersCol.findOne({ _id }, { projection: { password: 0 } });
          if (user) { sessionRenew(sid); return res.json({ status: "ok", user: { id: user._id, name: user.name, email: user.email, role: user.role, active: user.active } }); }
        }
      }
      return res.status(401).json({ error: "Sem sessao" });
    } catch (e) { return err500(res, "GET /api/auth/me", e); }
  }

  // ══════════════════════════════════════
  //  CONFIG DE PREÇO
  // ══════════════════════════════════════
  if (path_ === "/api/config/price" && method === "GET") {
    try { const cfg = await getPriceConfig(); return res.json({ status: "ok", config: cfg }); }
    catch (e) { return err500(res, "GET /api/config/price", e); }
  }
  if (path_ === "/api/config/price" && method === "PUT") {
    try {
      const authUser = await requireAuth(req, res); if (!authUser) return;
      const { pricePerHour, freeHoursPerVisit } = body;
      if (pricePerHour === undefined || isNaN(Number(pricePerHour)))     return res.status(400).json({ error: "pricePerHour deve ser um numero" });
      if (freeHoursPerVisit === undefined || isNaN(Number(freeHoursPerVisit))) return res.status(400).json({ error: "freeHoursPerVisit deve ser um numero" });
      const cfg = { pricePerHour: parseFloat(Number(pricePerHour).toFixed(2)), freeHoursPerVisit: Math.max(0, parseInt(freeHoursPerVisit)) };
      await configCol.updateOne({ _key: "price" }, { $set: { _key: "price", ...cfg, updatedAt: new Date(), updatedBy: String(authUser._id) } }, { upsert: true });
      return res.json({ status: "ok", config: cfg });
    } catch (e) { return err500(res, "PUT /api/config/price", e); }
  }

  // ══════════════════════════════════════
  //  CARTÕES
  // ══════════════════════════════════════
  if (path_ === "/api/cards" && method === "GET") {
    try {
      const authUser = await requireAuth(req, res); if (!authUser) return;
      const page  = Math.max(1, parseInt(query.page  || "1",  10));
      const limit = Math.min(200, parseInt(query.limit || "50", 10));
      const skip  = (page - 1) * limit;
      const filter = {};
      if (query.search) filter.$or = [{ cardNumber: { $regex: query.search, $options: "i" } }, { name: { $regex: query.search, $options: "i" } }];
      if (query.active !== undefined) filter.active = query.active === "true";
      const items = await cardsCol.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray();
      const total = await cardsCol.countDocuments(filter);
      return res.json({ status: "ok", total, page, limit, cards: items.map(c => ({ ...c, id: c._id })) });
    } catch (e) { return err500(res, "GET /api/cards", e); }
  }

  if (path_ === "/api/cards" && method === "POST") {
    try {
      const authUser = await requireAuth(req, res); if (!authUser) return;
      const { cardNumber, name, notes, department, accessType } = body;
      if (!cardNumber || !String(cardNumber).trim()) return res.status(400).json({ error: "cardNumber e obrigatorio" });
      if (!name || !String(name).trim())             return res.status(400).json({ error: "name e obrigatorio" });
      const cleanCardNumber = String(cardNumber).trim().toUpperCase();
      const existing = await cardsCol.findOne({ cardNumber: cleanCardNumber });
      if (existing) return res.status(409).json({ error: `Ja existe um cartao com o numero "${cleanCardNumber}"` });
      const now = new Date();
      const doc = {
        cardNumber:  cleanCardNumber,
        name:        String(name).trim(),
        notes:       notes       ? String(notes).trim()       : "",
        department:  department  ? String(department).trim()  : "",
        accessType:  accessType  ? String(accessType).trim()  : "Card",
        active:      true,
        createdBy:   String(authUser._id),
        createdAt:   now,
        updatedAt:   now,
      };
      const result = await cardsCol.insertOne(doc);
      return res.status(201).json({ status: "ok", card: { ...doc, id: result.insertedId } });
    } catch (e) { return err500(res, "POST /api/cards", e); }
  }

  if (cardIdMatch && method === "GET") {
    try {
      const authUser = await requireAuth(req, res); if (!authUser) return;
      const _id = toId(cardIdMatch[1]);
      if (!_id) return res.status(400).json({ error: "ID invalido" });
      const card = await cardsCol.findOne({ _id });
      if (!card) return res.status(404).json({ error: "Cartao nao encontrado" });
      return res.json({ status: "ok", card: { ...card, id: card._id } });
    } catch (e) { return err500(res, "GET /api/cards/:id", e); }
  }

  if (cardIdMatch && method === "PUT") {
    try {
      const authUser = await requireAuth(req, res); if (!authUser) return;
      const _id = toId(cardIdMatch[1]);
      if (!_id) return res.status(400).json({ error: "ID invalido" });
      const { cardNumber, name, notes, active, department, accessType } = body;
      if (!name || !String(name).trim()) return res.status(400).json({ error: "name e obrigatorio" });
      const update = { name: String(name).trim(), notes: notes ? String(notes).trim() : "", updatedAt: new Date() };
      if (department !== undefined) update.department = String(department).trim();
      if (accessType !== undefined) update.accessType  = String(accessType).trim();
      if (typeof active === "boolean") update.active = active;
      if (cardNumber) {
        const cn = String(cardNumber).trim().toUpperCase();
        const dup = await cardsCol.findOne({ cardNumber: cn, _id: { $ne: _id } });
        if (dup) return res.status(409).json({ error: `Numero de cartao "${cn}" ja existe noutro registo` });
        update.cardNumber = cn;
      }
      const result  = await cardsCol.findOneAndUpdate({ _id }, { $set: update }, { returnDocument: "after" });
      const updated = result?.value ?? result;
      if (!updated) return res.status(404).json({ error: "Cartao nao encontrado" });
      return res.json({ status: "ok", card: { ...updated, id: updated._id } });
    } catch (e) { return err500(res, "PUT /api/cards/:id", e); }
  }

  if (cardIdMatch && method === "DELETE") {
    try {
      const authUser = await requireAuth(req, res); if (!authUser) return;
      const _id = toId(cardIdMatch[1]);
      if (!_id) return res.status(400).json({ error: "ID invalido" });
      const openRecord = await recordsCol.findOne({ cardId: String(_id), exit: null });
      if (openRecord) return res.status(409).json({ error: "Este cartao tem uma visita em aberto — nao e possivel eliminar" });
      const del = await cardsCol.deleteOne({ _id });
      if (!del.deletedCount) return res.status(404).json({ error: "Cartao nao encontrado" });
      return res.json({ status: "ok", message: "Cartao eliminado" });
    } catch (e) { return err500(res, "DELETE /api/cards/:id", e); }
  }

  // ══════════════════════════════════════
  //  REGISTOS
  // ══════════════════════════════════════
  if (path_ === "/api/records" && method === "GET") {
    try {
      const authUser = await requireAuth(req, res); if (!authUser) return;
      const page  = Math.max(1, parseInt(query.page  || "1",   10));
      const limit = Math.min(500, parseInt(query.limit || "100", 10));
      const skip  = (page - 1) * limit;
      const filter = {};
      if (query.status)     filter.status     = query.status;
      if (query.cardId)     filter.cardId     = query.cardId;
      if (query.department) filter.department = { $regex: query.department, $options: "i" };
      if (query.dateFrom || query.dateTo) {
        filter.entry = {};
        if (query.dateFrom) filter.entry.$gte = new Date(query.dateFrom);
        if (query.dateTo)   filter.entry.$lte = new Date(query.dateTo);
      }
      if (query.search) {
        const matchingCards = await cardsCol.find({ $or: [
          { cardNumber:  { $regex: query.search, $options: "i" } },
          { name:        { $regex: query.search, $options: "i" } },
          { department:  { $regex: query.search, $options: "i" } },
        ]}, { projection: { _id: 1 } }).toArray();
        const ids = matchingCards.map(c => String(c._id));
        filter.cardId = { $in: ids };
      }
      const items = await recordsCol.find(filter).sort({ entry: -1 }).skip(skip).limit(limit).toArray();
      const total = await recordsCol.countDocuments(filter);
      const cfg   = await getPriceConfig();
      const cardIds  = [...new Set(items.map(r => r.cardId).filter(Boolean))];
      const cardDocs = await cardsCol.find({ _id: { $in: cardIds.map(id => toId(id)).filter(Boolean) } }).toArray();
      const cardMap  = {};
      cardDocs.forEach(c => { cardMap[String(c._id)] = c; });
      const enriched = items.map(r => {
        const card   = cardMap[r.cardId] || null;
        const calced = calcRecord({ ...r, entry: r.entry?.toISOString?.() || r.entry, exit: r.exit?.toISOString?.() || r.exit }, cfg);
        return { ...calced, id: r._id, card: card ? { id: card._id, cardNumber: card.cardNumber, name: card.name, department: card.department, accessType: card.accessType } : null };
      });
      return res.json({ status: "ok", total, page, limit, records: enriched });
    } catch (e) { return err500(res, "GET /api/records", e); }
  }

  if (path_ === "/api/records" && method === "POST") {
    try {
      const authUser = await requireAuth(req, res); if (!authUser) return;
      const { cardId, entry, exit, status, notes, department, controlPoint, accessType } = body;
      if (!cardId) return res.status(400).json({ error: "cardId e obrigatorio" });
      const cardOid = toId(cardId);
      if (!cardOid) return res.status(400).json({ error: "cardId invalido" });
      const card = await cardsCol.findOne({ _id: cardOid });
      if (!card)        return res.status(404).json({ error: "Cartao nao encontrado" });
      if (!card.active) return res.status(409).json({ error: "Este cartao esta desativado" });
      const entryDate = entry ? new Date(entry) : new Date();
      if (isNaN(entryDate)) return res.status(400).json({ error: "Data de entrada invalida" });
      let exitDate = null;
      if (exit) {
        exitDate = new Date(exit);
        if (isNaN(exitDate))       return res.status(400).json({ error: "Data de saida invalida" });
        if (exitDate <= entryDate) return res.status(400).json({ error: "A saida deve ser posterior a entrada" });
      }
      const openVisit = await recordsCol.findOne({ cardId: String(cardOid), exit: null });
      if (openVisit) return res.status(409).json({ error: `O cartao "${card.cardNumber}" ja tem uma visita em aberto`, openVisitId: openVisit._id });
      const dup = await recordsCol.findOne({ cardId: String(cardOid), entry: entryDate });
      if (dup) return res.status(409).json({ error: "Registo duplicado" });
      const validStatus = exitDate ? (VALID_STATUSES.includes(status) ? status : "unpaid") : "parked";
      const cfg = await getPriceConfig();
      const now = new Date();
      const baseDoc = {
        cardId:       String(cardOid),
        entry:        entryDate,
        exit:         exitDate,
        status:       validStatus,
        notes:        notes        ? String(notes).trim()        : "",
        department:   department   ? String(department).trim()   : (card.department || ""),
        controlPoint: controlPoint ? String(controlPoint).trim() : "",
        accessType:   accessType   ? String(accessType).trim()   : (card.accessType || "Card"),
        createdBy:    String(authUser._id),
        createdAt:    now,
        updatedAt:    now,
      };
      const calced = calcRecord({ ...baseDoc, entry: entryDate.toISOString(), exit: exitDate?.toISOString() || null }, cfg);
      const insertDoc = { ...baseDoc, durationMin: calced.durationMin, durationLabel: calced.durationLabel, freeHours: calced.freeHours, paidHours: calced.paidHours, amountDue: calced.amountDue };
      const result = await recordsCol.insertOne(insertDoc);
      return res.status(201).json({ status: "ok", record: { ...insertDoc, id: result.insertedId, card: { id: card._id, cardNumber: card.cardNumber, name: card.name, department: card.department } } });
    } catch (e) { return err500(res, "POST /api/records", e); }
  }

  if (recordIdMatch && method === "GET") {
    try {
      const authUser = await requireAuth(req, res); if (!authUser) return;
      const _id = toId(recordIdMatch[1]);
      if (!_id) return res.status(400).json({ error: "ID invalido" });
      const rec = await recordsCol.findOne({ _id });
      if (!rec)  return res.status(404).json({ error: "Registo nao encontrado" });
      const cfg  = await getPriceConfig();
      const card = rec.cardId ? await cardsCol.findOne({ _id: toId(rec.cardId) }) : null;
      const calced = calcRecord({ ...rec, entry: rec.entry?.toISOString?.() || rec.entry, exit: rec.exit?.toISOString?.() || rec.exit }, cfg);
      return res.json({ status: "ok", record: { ...calced, id: rec._id, card: card ? { id: card._id, cardNumber: card.cardNumber, name: card.name, department: card.department, accessType: card.accessType } : null } });
    } catch (e) { return err500(res, "GET /api/records/:id", e); }
  }

  if (recordIdMatch && method === "PUT") {
    try {
      const authUser = await requireAuth(req, res); if (!authUser) return;
      const _id = toId(recordIdMatch[1]);
      if (!_id) return res.status(400).json({ error: "ID invalido" });
      const rec = await recordsCol.findOne({ _id });
      if (!rec)  return res.status(404).json({ error: "Registo nao encontrado" });
      const { cardId, entry, exit, status, notes, department, controlPoint, accessType } = body;
      let cardOid = toId(rec.cardId);
      if (cardId && cardId !== rec.cardId) {
        cardOid = toId(cardId);
        if (!cardOid) return res.status(400).json({ error: "cardId invalido" });
        const card = await cardsCol.findOne({ _id: cardOid });
        if (!card) return res.status(404).json({ error: "Cartao nao encontrado" });
        if (!card.active) return res.status(409).json({ error: "Cartao desativado" });
      }
      const entryDate = entry ? new Date(entry) : rec.entry;
      if (isNaN(new Date(entryDate))) return res.status(400).json({ error: "Data de entrada invalida" });
      let exitDate = null;
      if (exit !== undefined) {
        if (exit) {
          exitDate = new Date(exit);
          if (isNaN(exitDate)) return res.status(400).json({ error: "Data de saida invalida" });
          if (exitDate <= new Date(entryDate)) return res.status(400).json({ error: "A saida deve ser posterior a entrada" });
        }
      } else { exitDate = rec.exit || null; }
      const cfg = await getPriceConfig();
      const calced = calcRecord({ entry: new Date(entryDate).toISOString(), exit: exitDate ? new Date(exitDate).toISOString() : null }, cfg);
      const update = {
        cardId: String(cardOid), entry: new Date(entryDate), exit: exitDate ? new Date(exitDate) : null,
        status: VALID_STATUSES.includes(status) ? status : rec.status,
        notes:  notes !== undefined ? String(notes).trim() : rec.notes,
        department:   department   !== undefined ? String(department).trim()   : rec.department,
        controlPoint: controlPoint !== undefined ? String(controlPoint).trim() : rec.controlPoint,
        accessType:   accessType   !== undefined ? String(accessType).trim()   : rec.accessType,
        durationMin: calced.durationMin, durationLabel: calced.durationLabel,
        freeHours: calced.freeHours, paidHours: calced.paidHours, amountDue: calced.amountDue,
        updatedAt: new Date(),
      };
      const result  = await recordsCol.findOneAndUpdate({ _id }, { $set: update }, { returnDocument: "after" });
      const updated = result?.value ?? result;
      if (!updated) return res.status(404).json({ error: "Registo nao encontrado" });
      const card = await cardsCol.findOne({ _id: toId(updated.cardId) });
      return res.json({ status: "ok", record: { ...updated, id: updated._id, card: card ? { id: card._id, cardNumber: card.cardNumber, name: card.name, department: card.department } : null } });
    } catch (e) { return err500(res, "PUT /api/records/:id", e); }
  }

  if (recordStatMatch && method === "PATCH") {
    try {
      const authUser = await requireAuth(req, res); if (!authUser) return;
      const _id = toId(recordStatMatch[1]);
      if (!_id) return res.status(400).json({ error: "ID invalido" });
      const { status } = body;
      if (!status || !VALID_STATUSES.includes(status)) return res.status(400).json({ error: "Status invalido" });
      const result  = await recordsCol.findOneAndUpdate({ _id }, { $set: { status, updatedAt: new Date() } }, { returnDocument: "after" });
      const updated = result?.value ?? result;
      if (!updated) return res.status(404).json({ error: "Registo nao encontrado" });
      return res.json({ status: "ok", record: { ...updated, id: updated._id } });
    } catch (e) { return err500(res, "PATCH /api/records/:id/status", e); }
  }

  if (recordExitMatch && method === "PATCH") {
    try {
      const authUser = await requireAuth(req, res); if (!authUser) return;
      const _id = toId(recordExitMatch[1]);
      if (!_id) return res.status(400).json({ error: "ID invalido" });
      const rec = await recordsCol.findOne({ _id });
      if (!rec) return res.status(404).json({ error: "Registo nao encontrado" });
      if (rec.exit) return res.status(409).json({ error: "Este registo ja tem saida registada" });
      const exitDate  = body.exit ? new Date(body.exit) : new Date();
      if (isNaN(exitDate)) return res.status(400).json({ error: "Data de saida invalida" });
      const entryDate = rec.entry instanceof Date ? rec.entry : new Date(rec.entry);
      if (exitDate <= entryDate) return res.status(400).json({ error: "A saida deve ser posterior a entrada" });
      const cfg    = await getPriceConfig();
      const calced = calcRecord({ entry: entryDate.toISOString(), exit: exitDate.toISOString() }, cfg);
      const update = { exit: exitDate, status: body.status && VALID_STATUSES.includes(body.status) ? body.status : "unpaid", durationMin: calced.durationMin, durationLabel: calced.durationLabel, freeHours: calced.freeHours, paidHours: calced.paidHours, amountDue: calced.amountDue, updatedAt: new Date() };
      const result  = await recordsCol.findOneAndUpdate({ _id }, { $set: update }, { returnDocument: "after" });
      const updated = result?.value ?? result;
      const card    = await cardsCol.findOne({ _id: toId(updated.cardId) });
      return res.json({ status: "ok", record: { ...updated, id: updated._id, card: card ? { id: card._id, cardNumber: card.cardNumber, name: card.name } : null } });
    } catch (e) { return err500(res, "PATCH /api/records/:id/exit", e); }
  }

  if (recordIdMatch && method === "DELETE") {
    try {
      const authUser = await requireAuth(req, res); if (!authUser) return;
      const _id = toId(recordIdMatch[1]);
      if (!_id) return res.status(400).json({ error: "ID invalido" });
      const del = await recordsCol.deleteOne({ _id });
      if (!del.deletedCount) return res.status(404).json({ error: "Registo nao encontrado" });
      return res.json({ status: "ok", message: "Registo eliminado" });
    } catch (e) { return err500(res, "DELETE /api/records/:id", e); }
  }

  // ══════════════════════════════════════════════════════════════
  //  IMPORTAÇÃO FORMATO MARINA (Excel com Ponto de Controlo)
  //  POST /api/records/import-access-log
  //
  //  Cada linha do Excel é um evento (entrada OU saída).
  //  O sistema agrupa por cartão e emparelha entradas com saídas.
  // ══════════════════════════════════════════════════════════════
  if (path_ === "/api/records/import-access-log" && method === "POST") {
    try {
      const authUser = await requireAuth(req, res); if (!authUser) return;
      const { rows, createMissingCards = true } = body;

      if (!Array.isArray(rows) || rows.length === 0)
        return res.status(400).json({ error: "rows deve ser um array nao vazio" });
      if (rows.length > 10000)
        return res.status(400).json({ error: "Maximo 10000 linhas por importacao" });

      const cfg = await getPriceConfig();
      const now = new Date();
      const errors   = [];
      const toInsert = [];
      const cardCache = {};  // cardNumber → card doc

      // Pré-carregar cartões existentes
      const allCardNums = [...new Set(rows.map(r => String(r.cardNumber || r.id || r.cracha || "").trim().toUpperCase()).filter(Boolean))];
      if (allCardNums.length) {
        const existingCards = await cardsCol.find({ cardNumber: { $in: allCardNums } }).toArray();
        existingCards.forEach(c => { cardCache[c.cardNumber] = c; });
      }

      // Normalizar e separar eventos
      const events = [];
      for (let i = 0; i < rows.length; i++) {
        const row    = rows[i];
        const rowNum = i + 1;

        // Normalizar data
        const dateVal = row.dataHora || row.date || row.data || row.datetime || row["Data/Hora"] || row["Data Hora"];
        const dt      = parseExcelDate(dateVal);
        if (!dt) { errors.push({ row: rowNum, reason: `Data invalida: "${dateVal}"` }); continue; }

        // Normalizar cartão
        const rawCard = String(row.cardNumber || row.id || row.cracha || row["ID / Cracha"] || row["ID/Cracha"] || row.badge || "").trim();
        const cardNum = rawCard.toUpperCase() || null;

        // Normalizar nome
        const name = String(row.nome || row.name || row.Name || row.Nome || "").trim() || (cardNum || "Desconhecido");

        // Normalizar departamento
        const dept = String(row.departamento || row.department || row.Departamento || row.Department || "").trim();

        // Normalizar tipo de acesso
        const accessType = String(row.tipoAcesso || row.accessType || row["Tipo de Acesso"] || row.tipo || "").trim() || "Card";

        // Normalizar ponto de controlo
        const cp        = String(row.pontoControlo || row.controlPoint || row["Ponto de Controlo"] || row.ponto || "").trim();
        const direction = detectDirection(cp);
        if (!direction) { errors.push({ row: rowNum, name, reason: `Ponto de Controlo desconhecido: "${cp}"` }); continue; }

        events.push({ rowNum, dt, cardNum, name, dept, accessType, cp, direction });
      }

      // Ordenar por cartão e data
      events.sort((a, b) => {
        if (a.cardNum < b.cardNum) return -1;
        if (a.cardNum > b.cardNum) return  1;
        return a.dt - b.dt;
      });

      // Emparelhar entrada → saída por cartão
      const byCard = {};
      for (const ev of events) {
        if (!byCard[ev.cardNum]) byCard[ev.cardNum] = [];
        byCard[ev.cardNum].push(ev);
      }

      for (const [cardNum, evs] of Object.entries(byCard)) {
        // Garantir/criar cartão
        let card = cardCache[cardNum];
        if (!card && createMissingCards) {
          const name  = evs[0].name;
          const dept  = evs[0].dept;
          const newCard = { cardNumber: cardNum, name, notes: "Criado via importacao de acessos", department: dept, accessType: evs[0].accessType, active: true, createdBy: String(authUser._id), createdAt: now, updatedAt: now };
          const ins = await cardsCol.insertOne(newCard);
          card = { ...newCard, _id: ins.insertedId };
          cardCache[cardNum] = card;
        }
        if (!card) {
          evs.forEach(ev => errors.push({ row: ev.rowNum, cardNumber: cardNum, reason: `Cartao "${cardNum}" nao existe (createMissingCards=false)` }));
          continue;
        }

        // Emparelhar: andar os eventos em sequência e casar entrada com próxima saída
        let openEntry = null;
        for (const ev of evs) {
          if (ev.direction === "entry") {
            if (openEntry) {
              // Entrada sem saída — guardar como registo em aberto
              const calced = calcRecord({ entry: openEntry.dt.toISOString(), exit: null }, cfg);
              const dup = await recordsCol.findOne({ cardId: String(card._id), entry: openEntry.dt });
              if (!dup) {
                toInsert.push({ cardId: String(card._id), entry: openEntry.dt, exit: null, status: "parked", notes: "", department: openEntry.dept || card.department || "", controlPoint: openEntry.cp, accessType: openEntry.accessType, durationMin: null, durationLabel: "—", freeHours: 0, paidHours: 0, amountDue: 0, importedBy: String(authUser._id), importedAt: now, createdAt: now, updatedAt: now });
              }
            }
            openEntry = ev;
          } else if (ev.direction === "exit") {
            if (openEntry) {
              // Par entrada → saída
              if (ev.dt <= openEntry.dt) { errors.push({ row: ev.rowNum, cardNumber: cardNum, reason: "Saida anterior ou igual a entrada — ignorado" }); openEntry = null; continue; }
              const calced = calcRecord({ entry: openEntry.dt.toISOString(), exit: ev.dt.toISOString() }, cfg);
              const dup = await recordsCol.findOne({ cardId: String(card._id), entry: openEntry.dt });
              if (!dup) {
                toInsert.push({ cardId: String(card._id), entry: openEntry.dt, exit: ev.dt, status: "unpaid", notes: "", department: openEntry.dept || card.department || "", controlPoint: ev.cp, accessType: openEntry.accessType, durationMin: calced.durationMin, durationLabel: calced.durationLabel, freeHours: calced.freeHours, paidHours: calced.paidHours, amountDue: calced.amountDue, importedBy: String(authUser._id), importedAt: now, createdAt: now, updatedAt: now });
              }
              openEntry = null;
            } else {
              errors.push({ row: ev.rowNum, cardNumber: cardNum, reason: "Saida sem entrada correspondente — ignorado" });
            }
          }
        }
        // Entrada sem saída no final
        if (openEntry) {
          const dup = await recordsCol.findOne({ cardId: String(card._id), entry: openEntry.dt });
          if (!dup) {
            toInsert.push({ cardId: String(card._id), entry: openEntry.dt, exit: null, status: "parked", notes: "", department: openEntry.dept || card.department || "", controlPoint: openEntry.cp, accessType: openEntry.accessType, durationMin: null, durationLabel: "—", freeHours: 0, paidHours: 0, amountDue: 0, importedBy: String(authUser._id), importedAt: now, createdAt: now, updatedAt: now });
          }
        }
      }

      let inserted = 0;
      if (toInsert.length) {
        const bulkResult = await recordsCol.insertMany(toInsert, { ordered: false });
        inserted = bulkResult.insertedCount;
      }

      return res.json({ status: "ok", imported: inserted, skipped: errors.length, total: rows.length, pairs: toInsert.length, errors });
    } catch (e) { return err500(res, "POST /api/records/import-access-log", e); }
  }

  // ══════════════════════════════════════
  //  IMPORTAÇÃO GENÉRICA  (manter compatibilidade)
  // ══════════════════════════════════════
  if (path_ === "/api/records/import" && method === "POST") {
    try {
      const authUser = await requireAuth(req, res); if (!authUser) return;
      const { records: rows, createMissingCards = true } = body;
      if (!Array.isArray(rows) || rows.length === 0) return res.status(400).json({ error: "O campo records deve ser um array nao vazio" });
      if (rows.length > 5000) return res.status(400).json({ error: "Maximo 5000 registos" });
      const cfg = await getPriceConfig(); const errors = []; const toInsert = []; const createdCards = {}; const now = new Date();
      const cardNumbers = [...new Set(rows.map(r => r.cardNumber).filter(Boolean).map(s => String(s).trim().toUpperCase()))];
      const existingCards = cardNumbers.length ? await cardsCol.find({ cardNumber: { $in: cardNumbers } }).toArray() : [];
      const cardByNumber = {}; existingCards.forEach(c => { cardByNumber[c.cardNumber] = c; });
      const seenKeys = new Set();
      for (let i = 0; i < rows.length; i++) {
        const row = rows[i]; const rowNum = i + 1; const rowErrors = [];
        let card = null;
        if (row.cardId) { const oid = toId(row.cardId); if (!oid) { rowErrors.push("cardId invalido"); } else { card = await cardsCol.findOne({ _id: oid }); if (!card) rowErrors.push(`Cartao "${row.cardId}" nao encontrado`); } }
        else if (row.cardNumber) {
          const cn = String(row.cardNumber).trim().toUpperCase();
          card = cardByNumber[cn] || createdCards[cn] || null;
          if (!card && createMissingCards) { const newCard = { cardNumber: cn, name: row.name ? String(row.name).trim() : cn, notes: "Criado via importação", department: row.department || "", accessType: "Card", active: true, createdBy: String(authUser._id), createdAt: now, updatedAt: now }; const ins = await cardsCol.insertOne(newCard); card = { ...newCard, _id: ins.insertedId }; cardByNumber[cn] = card; createdCards[cn] = card; }
          else if (!card) rowErrors.push(`Cartao "${cn}" nao existe`);
        } else rowErrors.push("Necessario cardNumber ou cardId");
        const entryDate = row.entry ? new Date(row.entry) : null;
        if (!entryDate || isNaN(entryDate)) rowErrors.push(`Data de entrada invalida: "${row.entry}"`);
        let exitDate = null;
        if (row.exit) { exitDate = new Date(row.exit); if (isNaN(exitDate)) rowErrors.push("Data de saida invalida"); else if (entryDate && exitDate <= entryDate) rowErrors.push("Saida deve ser posterior a entrada"); }
        if (card && entryDate && !isNaN(entryDate)) { const key = `${card._id}|${entryDate.toISOString()}`; if (seenKeys.has(key)) rowErrors.push("Duplicado no lote"); else { const dbDup = await recordsCol.findOne({ cardId: String(card._id), entry: entryDate }); if (dbDup) rowErrors.push("Duplicado na BD"); else seenKeys.add(key); } }
        if (rowErrors.length) { errors.push({ row: rowNum, cardNumber: row.cardNumber || "?", reasons: rowErrors }); continue; }
        const resolvedStatus = exitDate ? (VALID_STATUSES.includes(row.status) ? row.status : "unpaid") : "parked";
        const calced = calcRecord({ entry: entryDate.toISOString(), exit: exitDate?.toISOString() || null }, cfg);
        toInsert.push({ cardId: String(card._id), entry: entryDate, exit: exitDate || null, status: resolvedStatus, notes: row.notes ? String(row.notes).trim() : "", department: row.department || card.department || "", controlPoint: row.controlPoint || "", accessType: row.accessType || card.accessType || "Card", durationMin: calced.durationMin, durationLabel: calced.durationLabel, freeHours: calced.freeHours, paidHours: calced.paidHours, amountDue: calced.amountDue, importedBy: String(authUser._id), importedAt: now, createdAt: now, updatedAt: now });
      }
      let inserted = 0;
      if (toInsert.length) { const bulkResult = await recordsCol.insertMany(toInsert, { ordered: false }); inserted = bulkResult.insertedCount; }
      return res.json({ status: "ok", imported: inserted, skipped: errors.length, total: rows.length, errors });
    } catch (e) { return err500(res, "POST /api/records/import", e); }
  }

  // ══════════════════════════════════════
  //  STATS
  // ══════════════════════════════════════
  if (path_ === "/api/stats" && method === "GET") {
    try {
      const authUser = await requireAuth(req, res); if (!authUser) return;
      const cfg = await getPriceConfig();
      const matchDate = {};
      if (query.dateFrom) matchDate.entry = { ...matchDate.entry, $gte: new Date(query.dateFrom) };
      if (query.dateTo)   matchDate.entry = { ...matchDate.entry, $lte: new Date(query.dateTo) };

      const [totalRecords, openRecords, statusAgg, monthlyAgg, topCards, deptAgg] = await Promise.all([
        recordsCol.countDocuments(matchDate),
        recordsCol.countDocuments({ ...matchDate, exit: null }),
        recordsCol.aggregate([{ $match: matchDate }, { $group: { _id: "$status", count: { $sum: 1 }, totalAmount: { $sum: "$amountDue" } } }]).toArray(),
        recordsCol.aggregate([
          { $match: { ...matchDate, exit: { $ne: null } } },
          { $group: { _id: { year: { $year: "$entry" }, month: { $month: "$entry" } }, revenue: { $sum: { $cond: [{ $eq: ["$status","paid"] }, "$amountDue", 0] } }, visits: { $sum: 1 }, freeHours: { $sum: "$freeHours" }, paidHours: { $sum: "$paidHours" } } },
          { $sort: { "_id.year": -1, "_id.month": -1 } }, { $limit: 24 },
        ]).toArray(),
        recordsCol.aggregate([{ $match: matchDate }, { $group: { _id: "$cardId", visits: { $sum: 1 }, totalPaid: { $sum: { $cond: [{ $eq: ["$status","paid"] }, "$amountDue", 0] } } } }, { $sort: { visits: -1 } }, { $limit: 10 }]).toArray(),
        // Agrupamento por departamento
        recordsCol.aggregate([{ $match: matchDate }, { $group: { _id: "$department", visits: { $sum: 1 }, totalAmount: { $sum: "$amountDue" } } }, { $sort: { visits: -1 } }]).toArray(),
      ]);

      const topCardIds  = topCards.map(t => toId(t._id)).filter(Boolean);
      const topCardDocs = await cardsCol.find({ _id: { $in: topCardIds } }).toArray();
      const topCardMap  = {}; topCardDocs.forEach(c => { topCardMap[String(c._id)] = c; });
      const topEnriched = topCards.map(t => ({ cardId: t._id, cardNumber: topCardMap[t._id]?.cardNumber || "?", name: topCardMap[t._id]?.name || "?", department: topCardMap[t._id]?.department || "", visits: t.visits, totalPaid: t.totalPaid }));

      const totalRevenue = await recordsCol.aggregate([{ $match: { ...matchDate, status: "paid" } }, { $group: { _id: null, total: { $sum: "$amountDue" } } }]).toArray();
      const totalPending = await recordsCol.aggregate([{ $match: { ...matchDate, status: { $in: ["unpaid","debt"] } } }, { $group: { _id: null, total: { $sum: "$amountDue" } } }]).toArray();

      return res.json({ status: "ok", stats: {
        totalRecords, openRecords,
        totalCards:   await cardsCol.countDocuments({ active: true }),
        totalRevenue: totalRevenue[0]?.total || 0,
        totalPending: totalPending[0]?.total || 0,
        byStatus:     statusAgg.map(s => ({ status: s._id, count: s.count, totalAmount: s.totalAmount })),
        byDepartment: deptAgg.map(d => ({ department: d._id || "Sem Depto", visits: d.visits, totalAmount: d.totalAmount })),
        monthly:      monthlyAgg.map(m => ({ year: m._id.year, month: m._id.month, revenue: m.revenue, visits: m.visits, freeHours: parseFloat((m.freeHours||0).toFixed(2)), paidHours: parseFloat((m.paidHours||0).toFixed(2)) })),
        topCards:     topEnriched,
        priceConfig:  cfg,
      }});
    } catch (e) { return err500(res, "GET /api/stats", e); }
  }

  // ─── Ficheiros estáticos ────────────────────────────────────
  if (!path_.startsWith("/api/")) {
    const FRONTEND_DIR = process.env.FRONTEND_DIR || path.join(__dirname, "..", "FRONTEND");
    const relPath  = path_ === "/" ? "index.html" : path_.slice(1);
    const fullPath = path.join(FRONTEND_DIR, relPath);
    if (!fullPath.startsWith(path.resolve(FRONTEND_DIR))) return res.status(403).json({ error: "Acesso negado" });
    if (fs.existsSync(fullPath) && fs.statSync(fullPath).isFile()) {
      const ext   = path.extname(fullPath).toLowerCase();
      const mimes = { ".html":"text/html",".css":"text/css",".js":"application/javascript",".json":"application/json",".png":"image/png",".jpg":"image/jpeg",".svg":"image/svg+xml",".ico":"image/x-icon",".webp":"image/webp" };
      res.setHeader("Content-Type", mimes[ext] || "application/octet-stream");
      res.setHeader("Cache-Control", "no-cache");
      fs.createReadStream(fullPath).pipe(res); return;
    }
    const idx = path.join(FRONTEND_DIR, "index.html");
    if (fs.existsSync(idx)) { res.setHeader("Content-Type","text/html"); res.setHeader("Cache-Control","no-cache"); fs.createReadStream(idx).pipe(res); return; }
  }

  return res.status(404).json({ error: "Rota nao encontrada" });
}

// ─── AUTO-SEED ──────────────────────────────────────────────
async function seedDefaultUser() {
  try {
    await getDb();
    const count = await usersCol.countDocuments();
    if (count > 0) { console.log("[SEED]  Utilizadores ja existem — seed ignorado."); return; }
    const hash = await bcrypt.hash("Admin1234!", 10);
    const now  = new Date();
    await usersCol.insertOne({ name: "Admin", email: "admin@marinapark.pt", password: hash, role: "admin", active: true, createdAt: now, updatedAt: now });
    console.log("[SEED]  Utilizador inicial criado:");
    console.log("[SEED]    Email:    admin@marinapark.pt");
    console.log("[SEED]    Password: Admin1234!");
  } catch (e) { console.error("[SEED]  Erro:", e.message); }
}

// ─── SERVER ─────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  try { await handler(req, res); }
  catch (e) {
    console.error("[FATAL]", e);
    if (!res.writableEnded) { res.statusCode = 500; res.end(JSON.stringify({ error: "Erro interno", detail: e?.message })); }
  }
});
server.listen(PORT, async () => {
  console.log(`\n MarinaPark backend a correr em http://localhost:${PORT}\n`);
  await seedDefaultUser();
});