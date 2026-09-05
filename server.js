const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const pino = require('pino');
const { Pool } = require('pg');
const {
  default: makeWASocket,
  initAuthCreds,
  BufferJSON,
  DisconnectReason,
  makeCacheableSignalKeyStore,
  Browsers,
  jidNormalizedUser
} = require('@whiskeysockets/baileys');
require('dotenv').config();

const PORT = Number(process.env.PORT || 10000);
const GROUP_JIDS = [...new Set((process.env.GROUP_JIDS || process.env.GROUP_JID || '120363406004829027@g.us')
  .split(',').map(s => s.trim()).filter(Boolean))];
const DATA_DIR = path.resolve(process.env.DATA_DIR || './data');
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'change-me';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '*').split(',').map(s => s.trim()).filter(Boolean);
fs.mkdirSync(DATA_DIR, { recursive: true });

const logger = pino({ level: process.env.LOG_LEVEL || 'info' });
const configFile = path.join(DATA_DIR, 'bot-config.json');
const AUTH_SESSION_ID = process.env.AUTH_SESSION_ID || 'default';
const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) logger.warn('DATABASE_URL is not set. PostgreSQL persistence is unavailable.');
const pool = DATABASE_URL ? new Pool({ connectionString: DATABASE_URL, ssl: process.env.PGSSL === 'false' ? false : { rejectUnauthorized: false } }) : null;

const defaults = {
  welcomeEnabled: false,
  welcomeText: 'Welcome @user to the group! 🎉',
  greetEnabled: false,
  greetText: 'Hello @user 👋',
  welcomeNewAdmins: false,
  newAdminText: 'Congratulations @user, you are now an admin. 👑',
  antiLinkEnabled: false,
  autoPromoteEnabled: false,
  autoPromoteNumbers: []
};

function cleanNumber(v) { return String(v || '').replace(/\D/g, ''); }
function numberFromJid(jid) { return String(jid || '').split('@')[0].split(':')[0]; }
function normalizeJid(jid) { return String(jid || '').trim(); }
function toUserJid(value) { const n = cleanNumber(value); return n ? `${n}@s.whatsapp.net` : null; }
function mentionsFor(text, userJid) { return String(text).replace(/@user/g, `@${numberFromJid(userJid)}`); }
function isLink(text) { return /(https?:\/\/|www\.|chat\.whatsapp\.com\/|t\.me\/|discord\.gg\/|\.com\b|\.net\b|\.org\b)/i.test(text || ''); }
function isAdminParticipant(p) { return p && (p.admin === 'admin' || p.admin === 'superadmin'); }
function isBotJid(jid) { return sock?.user?.id && jidNormalizedUser(jid) === jidNormalizedUser(sock.user.id); }
function messageText(message) {
  const m = message?.message;
  if (!m) return '';
  return m.conversation || m.extendedTextMessage?.text || m.imageMessage?.caption || m.videoMessage?.caption || '';
}
function makeGroupConfig(jid, old = {}) {
  return { jid, ...defaults, ...old, autoPromoteNumbers: [...new Set((old.autoPromoteNumbers || []).map(cleanNumber).filter(Boolean))] };
}
function loadConfig() {
  try {
    const saved = JSON.parse(fs.readFileSync(configFile, 'utf8'));
    if (Array.isArray(saved.groups)) {
      const byJid = new Map(saved.groups.map(g => [normalizeJid(g.jid), makeGroupConfig(g.jid, g)]));
      for (const jid of GROUP_JIDS) if (!byJid.has(jid)) byJid.set(jid, makeGroupConfig(jid));
      return { groups: [...byJid.values()] };
    }
    const legacy = { ...saved };
    const groupJid = legacy.groupJid || GROUP_JIDS[0];
    delete legacy.groupJid;
    return { groups: GROUP_JIDS.map(jid => makeGroupConfig(jid, jid === groupJid ? legacy : {})) };
  } catch {
    const fresh = { groups: GROUP_JIDS.map(jid => makeGroupConfig(jid)) };
    fs.writeFileSync(configFile, JSON.stringify(fresh, null, 2));
    return fresh;
  }
}
function saveConfig() { fs.writeFileSync(configFile, JSON.stringify(config, null, 2)); }
function getGroupConfig(jid) {
  const target = normalizeJid(jid || GROUP_JIDS[0]);
  let group = config.groups.find(g => g.jid === target);
  if (!group) {
    group = makeGroupConfig(target);
    config.groups.push(group);
    saveConfig();
  }
  return group;
}

let config = loadConfig();
let sock = null;
let connectionState = 'disconnected';
let pairingCode = null;
let lastError = null;
let reconnectTimer = null;
let dbReady = false;

// The public pairing screen intentionally asks only for the WhatsApp number.
// Keep the pairing endpoint rate-limited because it does not require the admin token.
const pairAttempts = new Map();
const PAIR_WINDOW_MS = 15 * 60 * 1000;
const PAIR_MAX_ATTEMPTS = 5;
function pairingRateLimit(req, res, next) {
  const key = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const old = pairAttempts.get(key);
  if (!old || now - old.startedAt > PAIR_WINDOW_MS) {
    pairAttempts.set(key, { startedAt: now, count: 1 });
    return next();
  }
  if (old.count >= PAIR_MAX_ATTEMPTS) {
    const retryAfter = Math.ceil((PAIR_WINDOW_MS - (now - old.startedAt)) / 1000);
    res.set('Retry-After', String(retryAfter));
    return res.status(429).json({ error: 'Too many pairing attempts. Try again later.' });
  }
  old.count += 1;
  return next();
}

async function initDatabase() {
  if (!pool) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS baileys_auth_creds (
      session_id TEXT PRIMARY KEY,
      creds JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS baileys_auth_keys (
      session_id TEXT NOT NULL,
      key_type TEXT NOT NULL,
      key_id TEXT NOT NULL,
      value JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (session_id, key_type, key_id)
    );
  `);
  dbReady = true;
  logger.info('PostgreSQL auth storage ready');
}

function encode(value) { return JSON.parse(JSON.stringify(value, BufferJSON.replacer)); }
function decode(value) { return JSON.parse(JSON.stringify(value), BufferJSON.reviver); }

async function saveCredsToPostgres(creds) {
  if (!dbReady) throw new Error('PostgreSQL is not ready');
  await pool.query(
    `INSERT INTO baileys_auth_creds(session_id, creds, updated_at) VALUES($1,$2,NOW())
     ON CONFLICT(session_id) DO UPDATE SET creds=EXCLUDED.creds, updated_at=NOW()`,
    [AUTH_SESSION_ID, encode(creds)]
  );
}

function makePostgresAuthState() {
  if (!dbReady) throw new Error('PostgreSQL auth storage is not ready');
  const credsPromise = pool.query('SELECT creds FROM baileys_auth_creds WHERE session_id=$1', [AUTH_SESSION_ID]);
  const state = {
    creds: null,
    keys: {
      get: async (type, ids) => {
        const result = await pool.query(
          'SELECT key_id, value FROM baileys_auth_keys WHERE session_id=$1 AND key_type=$2 AND key_id = ANY($3::text[])',
          [AUTH_SESSION_ID, type, ids]
        );
        const map = new Map(result.rows.map(r => [r.key_id, decode(r.value)]));
        return Object.fromEntries(ids.map(id => [id, map.get(id)]));
      },
      set: async data => {
        const client = await pool.connect();
        try {
          await client.query('BEGIN');
          for (const [type, entries] of Object.entries(data)) {
            for (const [id, value] of Object.entries(entries)) {
              if (value === null || value === undefined) {
                await client.query('DELETE FROM baileys_auth_keys WHERE session_id=$1 AND key_type=$2 AND key_id=$3', [AUTH_SESSION_ID, type, id]);
              } else {
                await client.query(
                  `INSERT INTO baileys_auth_keys(session_id,key_type,key_id,value,updated_at) VALUES($1,$2,$3,$4,NOW())
                   ON CONFLICT(session_id,key_type,key_id) DO UPDATE SET value=EXCLUDED.value, updated_at=NOW()`,
                  [AUTH_SESSION_ID, type, id, encode(value)]
                );
              }
            }
          }
          await client.query('COMMIT');
        } catch (e) {
          await client.query('ROLLBACK');
          throw e;
        } finally { client.release(); }
      }
    }
  };
  return { credsPromise, state };
}

async function loadPostgresAuthState() {
  if (!dbReady) throw new Error('PostgreSQL auth storage is not ready');
  const credsResult = await pool.query('SELECT creds FROM baileys_auth_creds WHERE session_id=$1', [AUTH_SESSION_ID]);
  const auth = makePostgresAuthState();
  auth.state.creds = credsResult.rows[0] ? decode(credsResult.rows[0].creds) : initAuthCreds();
  return auth.state;
}

async function clearPostgresAuthState() {
  if (!dbReady) return;
  await pool.query('DELETE FROM baileys_auth_keys WHERE session_id=$1', [AUTH_SESSION_ID]);
  await pool.query('DELETE FROM baileys_auth_creds WHERE session_id=$1', [AUTH_SESSION_ID]);
}

async function getGroupMetadata(jid) {
  if (!sock) throw new Error('WhatsApp is not connected');
  return await sock.groupMetadata(normalizeJid(jid));
}
async function groupAdmins(jid) {
  const meta = await getGroupMetadata(jid);
  return new Set(meta.participants.filter(isAdminParticipant).map(p => jidNormalizedUser(p.id)));
}
async function applyAutoPromotions(jid) {
  const group = getGroupConfig(jid);
  if (!group.autoPromoteEnabled || !sock) return [];
  const admins = await groupAdmins(jid);
  const promoted = [];
  for (const num of group.autoPromoteNumbers) {
    const userJid = toUserJid(num);
    if (userJid && !admins.has(jidNormalizedUser(userJid))) {
      try { await sock.groupParticipantsUpdate(jid, [userJid], 'promote'); promoted.push(num); }
      catch (e) { logger.warn({ err: e, num, jid }, 'Auto-promotion failed'); }
    }
  }
  return promoted;
}
async function applyAllAutoPromotions() {
  const results = {};
  for (const group of config.groups) {
    try { results[group.jid] = await applyAutoPromotions(group.jid); }
    catch (e) { logger.warn({ err: e, jid: group.jid }, 'Group auto-promotion failed'); }
  }
  return results;
}

async function connectWhatsApp() {
  if (sock) return;
  connectionState = 'connecting'; lastError = null;
  const state = await loadPostgresAuthState();
  sock = makeWASocket({
    logger,
    auth: { creds: state.creds, keys: makeCacheableSignalKeyStore(state.keys, logger) },
    browser: Browsers.ubuntu('Chrome'),
    printQRInTerminal: false,
    markOnlineOnConnect: false,
    generateHighQualityLinkPreview: false
  });
  sock.ev.on('creds.update', async creds => {
    try { Object.assign(state.creds, creds); await saveCredsToPostgres(state.creds); }
    catch (e) { logger.error({ err: e }, 'Failed to persist Baileys credentials'); }
  });
  sock.ev.on('connection.update', async ({ connection, lastDisconnect }) => {
    connectionState = connection || connectionState;
    if (connection === 'open') {
      pairingCode = null; lastError = null; connectionState = 'connected';
      logger.info({ jid: sock.user?.id, groups: GROUP_JIDS }, 'WhatsApp connected');
      await applyAllAutoPromotions();
    }
    if (connection === 'close') {
      const code = lastDisconnect?.error?.output?.statusCode;
      const shouldReconnect = code !== DisconnectReason.loggedOut;
      connectionState = shouldReconnect ? 'reconnecting' : 'logged_out';
      sock = null;
      if (shouldReconnect && !reconnectTimer) {
        reconnectTimer = setTimeout(() => { reconnectTimer = null; connectWhatsApp().catch(e => logger.error(e)); }, 3000);
      }
    }
  });
  sock.ev.on('group-participants.update', async ({ id, participants, action }) => {
    const jid = normalizeJid(id);
    if (!GROUP_JIDS.includes(jid) || !sock) return;
    const group = getGroupConfig(jid);
    try {
      if (action === 'add' && group.welcomeEnabled) {
        for (const p of participants) await sock.sendMessage(jid, { text: mentionsFor(group.welcomeText, p.id || p), mentions: [jidNormalizedUser(p.id || p)] });
      }
      if (action === 'add' && group.greetEnabled) {
        for (const p of participants) await sock.sendMessage(jid, { text: mentionsFor(group.greetText, p.id || p), mentions: [jidNormalizedUser(p.id || p)] });
      }
      if (action === 'promote' && group.welcomeNewAdmins) {
        for (const p of participants) await sock.sendMessage(jid, { text: mentionsFor(group.newAdminText, p.id || p), mentions: [jidNormalizedUser(p.id || p)] });
      }
    } catch (e) { logger.warn({ err: e, jid }, 'Participant automation failed'); }
  });
  sock.ev.on('messages.upsert', async ({ messages }) => {
    if (!sock) return;
    for (const msg of messages) {
      try {
        const jid = normalizeJid(msg.key?.remoteJid);
        if (!jid) continue;
        const text = messageText(msg.message).trim();

        // .menu is the only chat command handled by the bot. It works in
        // private chats and groups, including when sent from the linked account.
        if (/^\.menu\s*$/i.test(text)) {
          const menuImagePath = path.join(__dirname, '..', 'frontend-public', 'ciscoB.jpg');
          const menuTextPath = path.join(__dirname, '..', 'frontend-public', 'menu.txt');
          const caption = fs.readFileSync(menuTextPath, 'utf8').trim();
          if (!fs.existsSync(menuImagePath)) throw new Error('Hero/menu image not found');
          await sock.sendMessage(jid, {
            image: fs.readFileSync(menuImagePath),
            caption
          });
          continue;
        }

        // Ignore other messages sent by the linked account. All actual group
        // management is intentionally controlled from admin.html/API.
        if (msg.key?.fromMe) continue;

        if (!jid.endsWith('@g.us') || !GROUP_JIDS.includes(jid)) continue;
        const group = getGroupConfig(jid);

        if (!group.antiLinkEnabled) continue;
        if (!isLink(text)) continue;
        const admins = await groupAdmins(jid);
        const sender = jidNormalizedUser(msg.key.participant || msg.key.remoteJid);
        if (!admins.has(sender) && !isBotJid(sender)) {
          await sock.sendMessage(jid, { delete: msg.key });
          await sock.sendMessage(jid, { text: 'Link removed. Only group admins may send links. 🚫' });
        }
      } catch (e) { logger.warn({ err: e }, 'Message handler failed'); }
    }
  });
}

async function requestPairing(phone) {
  const clean = cleanNumber(phone);
  if (!/^\d{8,15}$/.test(clean)) throw new Error('Enter a valid international phone number using digits only.');
  if (!sock) await connectWhatsApp();
  if (sock.user) return { alreadyConnected: true };
  pairingCode = await sock.requestPairingCode(clean);
  connectionState = 'pairing';
  return { code: pairingCode };
}
function auth(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '') || req.headers['x-admin-token'];
  if (!token || token !== ADMIN_TOKEN) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

async function requireSocket() {
  if (!sock || connectionState !== 'connected') throw new Error('WhatsApp is not connected');
  return sock;
}
function participantJid(value) {
  const n = cleanNumber(value);
  return n ? `${n}@s.whatsapp.net` : null;
}

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));
app.use(cors({ origin: (origin, cb) => {
  if (!origin || ALLOWED_ORIGINS.includes('*') || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
  return cb(new Error('Origin not allowed'));
}}));

app.get('/health', (req, res) => res.json({ ok: true, service: 'cisco-main-bot', connection: connectionState, groups: GROUP_JIDS, postgres: dbReady }));
app.get('/api/status', auth, (req, res) => res.json({ connection: connectionState, phone: sock?.user?.id || null, pairingCode, lastError, groups: config.groups, postgres: dbReady }));
app.post('/api/pair', pairingRateLimit, async (req, res) => { try { res.json(await requestPairing(req.body.phone)); } catch (e) { lastError = e.message; res.status(400).json({ error: e.message }); } });
app.post('/api/connect', auth, async (req, res) => { try { await connectWhatsApp(); res.json({ ok: true, connection: connectionState }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/logout', auth, async (req, res) => { try { if (sock) await sock.logout(); await clearPostgresAuthState(); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.get('/api/groups', auth, async (req, res) => {
  const groups = [];
  for (const jid of GROUP_JIDS) {
    try {
      const meta = await getGroupMetadata(jid);
      groups.push({ jid, subject: meta.subject, owner: meta.owner || null, size: meta.participants.length, configured: getGroupConfig(jid) });
    } catch (e) {
      groups.push({ jid, subject: 'Unavailable', owner: null, size: 0, configured: getGroupConfig(jid), error: e.message });
    }
  }
  res.json({ groups });
});
app.get('/api/config', auth, (req, res) => res.json(getGroupConfig(req.query.jid)));
app.put('/api/config', auth, async (req, res) => {
  const group = getGroupConfig(req.body.jid || req.query.jid);
  const allowed = ['welcomeEnabled','welcomeText','greetEnabled','greetText','welcomeNewAdmins','newAdminText','antiLinkEnabled','autoPromoteEnabled','autoPromoteNumbers'];
  for (const key of allowed) if (req.body[key] !== undefined) group[key] = req.body[key];
  group.autoPromoteNumbers = [...new Set((group.autoPromoteNumbers || []).map(cleanNumber).filter(Boolean))];
  saveConfig();
  let promoted = [];
  if (group.autoPromoteEnabled) { try { promoted = await applyAutoPromotions(group.jid); } catch (e) {} }
  res.json({ config: group, promoted });
});
app.get('/api/group', auth, async (req, res) => {
  try {
    const jid = req.query.jid || GROUP_JIDS[0];
    const meta = await getGroupMetadata(jid);
    res.json({ id: meta.id, subject: meta.subject, description: meta.desc || meta.description || '', owner: meta.owner, participants: meta.participants.map(p => ({ jid: p.id, phone: numberFromJid(p.id), admin: p.admin || null })) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/action', auth, async (req, res) => {
  try {
    const wa = await requireSocket();
    const groupJid = normalizeJid(req.body.jid || GROUP_JIDS[0]);
    const action = String(req.body.action || '');
    const jid = participantJid(req.body.phone || req.body.participant);
    if (!groupJid.endsWith('@g.us')) return res.status(400).json({ error: 'Valid group JID required' });
    if (!jid) return res.status(400).json({ error: 'Valid phone number required' });
    if (!['remove', 'kick', 'promote', 'demote', 'add'].includes(action)) return res.status(400).json({ error: 'Unsupported action' });
    const baileysAction = action === 'kick' ? 'remove' : action;
    await wa.groupParticipantsUpdate(groupJid, [jid], baileysAction);
    res.json({ ok: true, action: baileysAction, phone: numberFromJid(jid), jid: groupJid });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/group/subject', auth, async (req, res) => {
  try {
    const wa = await requireSocket();
    const jid = normalizeJid(req.body.jid);
    const subject = String(req.body.subject || '').trim();
    if (!jid.endsWith('@g.us')) throw new Error('Valid group JID required');
    if (!subject) throw new Error('Group name is empty');
    await wa.groupUpdateSubject(jid, subject.slice(0, 100));
    res.json({ ok: true, subject: subject.slice(0, 100), jid });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/group/description', auth, async (req, res) => {
  try {
    const wa = await requireSocket();
    const jid = normalizeJid(req.body.jid);
    if (!jid.endsWith('@g.us')) throw new Error('Valid group JID required');
    await wa.groupUpdateDescription(jid, String(req.body.description || ''));
    res.json({ ok: true, jid });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/group/setting', auth, async (req, res) => {
  try {
    const wa = await requireSocket();
    const jid = normalizeJid(req.body.jid);
    const setting = String(req.body.setting || '');
    const allowed = ['announcement', 'not_announcement', 'locked', 'unlocked'];
    if (!jid.endsWith('@g.us')) throw new Error('Valid group JID required');
    if (!allowed.includes(setting)) throw new Error(`setting must be one of ${allowed.join(', ')}`);
    await wa.groupSettingUpdate(jid, setting);
    res.json({ ok: true, setting, jid });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/group/invite', auth, async (req, res) => {
  try {
    const wa = await requireSocket();
    const jid = normalizeJid(req.query.jid);
    if (!jid.endsWith('@g.us')) throw new Error('Valid group JID required');
    const code = await wa.groupInviteCode(jid);
    res.json({ ok: true, code, inviteLink: `https://chat.whatsapp.com/${code}` });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/group/invite/revoke', auth, async (req, res) => {
  try {
    const wa = await requireSocket();
    const jid = normalizeJid(req.body.jid);
    if (!jid.endsWith('@g.us')) throw new Error('Valid group JID required');
    const code = await wa.groupRevokeInvite(jid);
    res.json({ ok: true, code, inviteLink: `https://chat.whatsapp.com/${code}` });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/group/leave', auth, async (req, res) => {
  try {
    const wa = await requireSocket();
    const jid = normalizeJid(req.body.jid);
    if (!jid.endsWith('@g.us')) throw new Error('Valid group JID required');
    await wa.groupLeave(jid);
    res.json({ ok: true, jid });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/group/create', auth, async (req, res) => {
  try {
    const wa = await requireSocket();
    const subject = String(req.body.subject || 'New group').trim().slice(0, 100);
    const participants = Array.isArray(req.body.participants) ? req.body.participants.map(participantJid).filter(Boolean) : [];
    const group = await wa.groupCreate(subject, participants);
    res.json({ ok: true, jid: group.id, subject: group.subject || subject });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/send', auth, async (req, res) => {
  try {
    const wa = await requireSocket();
    const jid = normalizeJid(req.body.jid || GROUP_JIDS[0]);
    const text = String(req.body.text || '').trim();
    if (!jid) throw new Error('Recipient JID is required');
    if (!text) throw new Error('Message is empty');
    await wa.sendMessage(jid, { text });
    res.json({ ok: true, jid });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.listen(PORT, async () => {
  logger.info(`Cisco Main Bot listening on ${PORT}`);
  try {
    await initDatabase();
    await connectWhatsApp();
  } catch (e) { logger.error({ err: e }, 'Startup failed'); }
});
