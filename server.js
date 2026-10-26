// 空域主宰 伺服器：網頁檔案、雲端存檔、連線房間與語音訊號轉送
// 遊戲製作 Eric Hu
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DB_URL = process.env.DATABASE_URL || '';

/* ---------- 存檔資料庫（有 DATABASE_URL 就用 Postgres，否則存在記憶體） ---------- */
let pool = null;
const memStore = new Map();
async function dbInit() {
  if (!DB_URL) { console.log('未設定 DATABASE_URL：存檔只保存在記憶體，伺服器重開就會消失'); return; }
  const { Pool } = require('pg');
  pool = new Pool({ connectionString: DB_URL, ssl: { rejectUnauthorized: false }, max: 5 });
  await pool.query(`CREATE TABLE IF NOT EXISTS sky_dominion_saves (
    name TEXT PRIMARY KEY, salt TEXT NOT NULL, pin_hash TEXT NOT NULL,
    data JSONB NOT NULL DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now())`);
  console.log('資料庫已連線');
}
async function getUser(name) {
  if (!pool) return memStore.get(name) || null;
  const r = await pool.query('SELECT name,salt,pin_hash,data FROM sky_dominion_saves WHERE name=$1', [name]);
  return r.rows[0] || null;
}
async function createUser(name, pin) {
  const salt = crypto.randomBytes(12).toString('hex');
  const u = { name, salt, pin_hash: hashPin(pin, salt), data: {} };
  if (!pool) { if (memStore.has(name)) return null; memStore.set(name, u); return u; }
  const r = await pool.query('INSERT INTO sky_dominion_saves(name,salt,pin_hash,data) VALUES($1,$2,$3,$4) ON CONFLICT (name) DO NOTHING RETURNING name',
    [name, salt, u.pin_hash, '{}']);
  return r.rowCount ? u : null;
}
async function saveData(name, data) {
  if (!pool) { const u = memStore.get(name); if (u) u.data = data; return; }
  await pool.query('UPDATE sky_dominion_saves SET data=$2, updated_at=now() WHERE name=$1', [name, JSON.stringify(data)]);
}
function hashPin(pin, salt) { return crypto.scryptSync(String(pin), salt, 32).toString('hex'); }
function pinOk(u, pin) {
  const a = Buffer.from(hashPin(pin, u.salt), 'hex'), b = Buffer.from(u.pin_hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const cleanName = n => (typeof n === 'string' ? n.trim().replace(/[\u0000-\u001f<>]/g, '') : '');
const nameOk = n => n.length >= 1 && n.length <= 8;
const pinValid = p => typeof p === 'string' && /^\d{4}$/.test(p);

// 密碼嘗試次數限制：同一 IP＋名稱 10 分鐘內最多錯 8 次
const fails = new Map();
function limited(key) { const f = fails.get(key); return f && f.n >= 8 && Date.now() - f.t < 600000; }
function addFail(key) { const f = fails.get(key); if (!f || Date.now() - f.t > 600000) fails.set(key, { n: 1, t: Date.now() }); else f.n++; }

async function verify(name, pin, ip) {
  name = cleanName(name);
  if (!nameOk(name) || !pinValid(pin)) return { code: 'bad' };
  const key = ip + '|' + name;
  if (limited(key)) return { code: 'limit' };
  const u = await getUser(name);
  if (!u) return { code: 'notfound' };
  if (!pinOk(u, pin)) { addFail(key); return { code: 'badpin' }; }
  return { user: u };
}

/* ---------- 網頁與 API ---------- */
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json',
  '.mp3': 'audio/mpeg', '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.webp': 'image/webp' };
const PUBLIC = /^\/(index\.html|m\d{2}\.mp3|[\w-]+\.(png|jpg|svg|ico|webp|css))$/;

function readBody(req) {
  return new Promise((res, rej) => {
    let s = ''; req.on('data', c => { s += c; if (s.length > 200000) { rej(new Error('too big')); req.destroy(); } });
    req.on('end', () => { try { res(JSON.parse(s || '{}')); } catch (e) { rej(e); } });
  });
}
function sendJSON(res, code, obj) { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(obj)); }
const ipOf = req => (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '';

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  let p = decodeURIComponent(url.pathname);
  try {
    if (p === '/api/ping') return sendJSON(res, 200, { ok: true, db: !!pool });
    if (p === '/api/login' && req.method === 'POST') {
      const b = await readBody(req), ip = ipOf(req), name = cleanName(b.name);
      if (!nameOk(name) || !pinValid(b.pin)) return sendJSON(res, 200, { ok: false, code: 'bad' });
      if (b.create) {
        const u = await createUser(name, b.pin);
        return sendJSON(res, 200, u ? { ok: true, data: {} } : { ok: false, code: 'exists' });
      }
      const v = await verify(name, b.pin, ip);
      return sendJSON(res, 200, v.user ? { ok: true, data: v.user.data || {} } : { ok: false, code: v.code });
    }
    if (p === '/api/save' && req.method === 'POST') {
      const b = await readBody(req), v = await verify(b.name, b.pin, ipOf(req));
      if (!v.user) return sendJSON(res, 200, { ok: false, code: v.code });
      if (!b.data || typeof b.data !== 'object') return sendJSON(res, 200, { ok: false, code: 'bad' });
      await saveData(v.user.name, b.data);
      return sendJSON(res, 200, { ok: true });
    }
    if (p === '/' ) p = '/index.html';
    if (!PUBLIC.test(p)) { res.writeHead(404); return res.end('找不到'); }
    const file = path.join(ROOT, p);
    fs.stat(file, (err, st) => {
      if (err) { res.writeHead(404); return res.end('找不到'); }
      const type = TYPES[path.extname(file)] || 'application/octet-stream';
      const cache = p.endsWith('.mp3') ? 'public, max-age=604800' : 'no-cache';
      const range = req.headers.range;
      if (range && /^bytes=\d*-\d*$/.test(range)) {
        let [s, e] = range.slice(6).split('-'); s = s ? +s : 0; e = e ? Math.min(+e, st.size - 1) : st.size - 1;
        if (s > e || s >= st.size) { res.writeHead(416, { 'Content-Range': `bytes */${st.size}` }); return res.end(); }
        res.writeHead(206, { 'Content-Type': type, 'Content-Range': `bytes ${s}-${e}/${st.size}`, 'Accept-Ranges': 'bytes', 'Content-Length': e - s + 1, 'Cache-Control': cache });
        return fs.createReadStream(file, { start: s, end: e }).pipe(res);
      }
      res.writeHead(200, { 'Content-Type': type, 'Content-Length': st.size, 'Accept-Ranges': 'bytes', 'Cache-Control': cache });
      fs.createReadStream(file).pipe(res);
    });
  } catch (e) {
    console.error(e); sendJSON(res, 500, { ok: false, code: 'server' });
  }
});

/* ---------- 連線房間 ---------- */
const rooms = new Map();   // code -> {code, host, members:[client], settings, inGame}
let nextId = 1;
const DIR_IDS = ['up', 'down', 'right', 'left', 'diag', 'diagl'];
function send(c, o) { if (c && c.ws.readyState === 1) c.ws.send(typeof o === 'string' ? o : JSON.stringify(o)); }
function memberInfo(c) {
  return { id: c.id, name: c.name, verified: c.verified, online: true, ready: !!c.ready, load: c.load || null, ship: c.load && c.load.ship,
    god: !!c.god, coins: (c.data && c.data.coins) || 0, prog: (c.data && c.data.prog) || 0 };
}
function roomMembers(r) { return r.members.map(memberInfo); }
function broadcast(r, o, except) { const s = JSON.stringify(o); for (const m of r.members) if (m !== except) send(m, s); }
function newCode() { for (let i = 0; i < 2000; i++) { const c = String(Math.floor(1000 + Math.random() * 9000)); if (!rooms.has(c)) return c; } return null; }
function roomMsg(r) { return { t: 'room', code: r.code, host: r.host, members: roomMembers(r), settings: r.settings, inGame: r.inGame }; }

function leaveRoom(c, why) {
  const r = c.room && rooms.get(c.room); c.room = null; c.ready = false;
  if (!r) return;
  r.members = r.members.filter(m => m !== c);
  if (!r.members.length) { rooms.delete(r.code); return; }
  if (r.inGame) broadcast(r, { t: 'left', id: c.id, why });
  if (r.host === c.id) {           // 房主離開：交給下一位玩家
    r.host = r.members[0].id;
    broadcast(r, { t: 'host', id: r.host });
  }
  broadcast(r, { t: 'members', members: roomMembers(r), host: r.host });
}

const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 4 * 1024 * 1024 });
wss.on('connection', (ws, req) => {
  const c = { ws, id: 'p' + (nextId++), name: null, verified: false, room: null, ready: false, load: null, god: false, data: null, ip: ipOf(req) };
  ws.on('message', async raw => {
    let m; try { m = JSON.parse(raw); } catch (e) { return; }
    try { await handle(c, m); } catch (e) { console.error('訊息處理錯誤', e); }
  });
  ws.on('close', () => leaveRoom(c, 'disconnect'));
});
// 每 30 秒檢查一次斷線
/* 每 20 秒送一次心跳訊息，避免主機或代理伺服器把閒置連線切斷 */
setInterval(() => { const s = JSON.stringify({ t: 'hb' }); wss.clients.forEach(ws => { if (ws.readyState === 1) ws.send(s); }); }, 20000);
setInterval(() => {
  wss.clients.forEach(ws => { if (ws._dead) return ws.terminate(); ws._dead = true; try { ws.ping(); } catch (e) {} });
}, 30000);
wss.on('connection', ws => { ws.on('pong', () => { ws._dead = false; }); ws.on('message', () => { ws._dead = false; }); });

async function handle(c, m) {
  const r = c.room ? rooms.get(c.room) : null;
  switch (m.t) {
    case 'hello': {
      const v = await verify(m.name, m.pin, c.ip);
      if (!v.user) return send(c, { t: 'err', msg: { notfound: '伺服器上找不到這個存檔', badpin: '密碼不正確', limit: '嘗試次數太多，請稍後再試', bad: '名稱或密碼格式不正確' }[v.code] || '無法驗證存檔' });
      c.name = v.user.name; c.verified = true; c.data = v.user.data || {};
      return send(c, { t: 'welcome', id: c.id });
    }
    case 'create': {
      if (!c.verified) return;
      if (r) leaveRoom(c, 'leave');
      /* 斷線重連時可以要求沿用原本的房號，遊戲直接接續 */
      const want = typeof m.code === 'string' && /^\d{4}$/.test(m.code) && !rooms.has(m.code) ? m.code : null;
      const code = want || newCode(); if (!code) return send(c, { t: 'joinFail', code: 'busy' });
      const room = { code, host: c.id, members: [c], settings: Object.assign({ diff: 1, dir: 'rand', dirs: ['up', 'down', 'right', 'left', 'diag', 'diagl'], zone: 0, endless: true, camp: false, inf: false, aiFill: true }, m.resume && m.settings ? m.settings : {}), inGame: !!m.resume };
      rooms.set(code, room); c.room = code; c.load = m.load || c.load; c.god = false; c.ready = false;
      return send(c, roomMsg(room));
    }
    case 'join': {
      if (!c.verified) return;
      const room = rooms.get(String(m.code || ''));
      if (!room) return send(c, { t: 'joinFail', code: 'nf' });
      if (room.members.includes(c)) return send(c, roomMsg(room));
      if (room.members.length >= 4) return send(c, { t: 'joinFail', code: 'full' });
      if (room.members.some(x => x.name === c.name)) return send(c, { t: 'joinFail', code: 'dup' });
      if (r) leaveRoom(c, 'leave');
      c.room = room.code; c.load = m.load || c.load; c.god = !!m.god && !!(c.data && c.data.cleared); c.ready = false;
      room.members.push(c);
      send(c, roomMsg(room));
      broadcast(room, { t: 'members', members: roomMembers(room), host: room.host }, c);
      if (room.inGame) send(room.members.find(x => x.id === room.host), { t: 'joined', m: memberInfo(c) });
      return;
    }
    case 'leave': case 'leaveGame': return leaveRoom(c, m.t);
    case 'ready': {
      if (!r) return;
      c.ready = !!m.ready; if (m.load && typeof m.load === 'object') c.load = m.load;
      return broadcast(r, { t: 'members', members: roomMembers(r), host: r.host });
    }
    case 'lobby': {
      if (!r || r.host !== c.id || !m.settings) return;
      r.settings = Object.assign({}, r.settings, m.settings);
      return broadcast(r, { t: 'lobby', settings: r.settings }, c);
    }
    case 'startReq': {
      if (!r || r.host !== c.id) return;
      c.ready = true; if (m.settings) r.settings = Object.assign({}, r.settings, m.settings);
      const issues = [];
      for (const x of r.members) {
        if (!x.verified) issues.push([x.name || '玩家', '存檔尚未通過伺服器驗證']);
        else if (x.ws.readyState !== 1) issues.push([x.name, '連線中斷']);
        else if (!x.ready) issues.push([x.name, '尚未按「準備完成」']);
      }
      if (issues.length) return send(c, { t: 'startFail', issues });
      const s = r.settings;
      const pool = Array.isArray(s.dirs) && s.dirs.length ? s.dirs.filter(d => DIR_IDS.includes(d)) : (s.dir === 'rand' ? DIR_IDS : [s.dir]);
      const dir = pool.length ? pool[Math.floor(Math.random() * pool.length)] : 'up';
      const zone = s.endless && !s.fixZone ? Math.floor(Math.random() * 21) : (s.zone || 0);
      r.inGame = true;
      const players = Array.isArray(m.players) ? m.players.slice(0, 4) : r.members.map((x, i) => ({ id: x.id, slot: i, name: x.name, human: true, load: x.load, god: x.god, coins: (x.data && x.data.coins) || 0 }));
      return broadcast(r, { t: 'start', players, settings: s, zone, dir });
    }
    case 's': if (r && r.host === c.id) broadcast(r, { t: 's', d: m.d }, c); return;
    case 'in': if (r && r.host !== c.id) { m.from = c.id; send(r.members.find(x => x.id === r.host), m); } return;
    case 'to': if (r && r.host === c.id && m.msg) send(r.members.find(x => x.id === m.to), m.msg); return;
    case 'chat': if (r) broadcast(r, { t: 'chat', from: c.id, i: m.i | 0 }, c); return;
    case 'rtc': if (r) send(r.members.find(x => x.id === m.to), { t: 'rtc', from: c.id, data: m.data }); return;
    case 'voice': if (r) broadcast(r, { t: 'voice', from: c.id, on: m.on ? 1 : 0 }, c); return;
    case 'endGame': if (r && r.host === c.id) { r.inGame = false; for (const x of r.members) x.ready = false; } return;
  }
}

dbInit().catch(e => { console.error('資料庫連線失敗，改用記憶體存檔：', e.message); pool = null; })
  .finally(() => server.listen(PORT, () => console.log('空域主宰 伺服器啟動：連接埠 ' + PORT)));
