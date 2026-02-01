const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
require('dotenv').config();
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');

process.on('unhandledRejection', (reason) => {
  console.error('UNHANDLED_REJECTION', reason);
});
process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT_EXCEPTION', err);
});

const app = express();
// Railway/Proxies: necesario para que rate-limit y req.ip funcionen bien
app.set('trust proxy', 1);

function requestWantsHtml(req) {
  const accept = String(req.get('accept') || '').toLowerCase();
  // Si no hay Accept, lo tratamos como no-navegación.
  if (!accept) return false;
  return accept.includes('text/html');
}

// En producción, la cookie de sesión es Secure. Si el usuario entra por HTTP,
// el navegador rechazará la cookie y parecerá que “no inicia sesión”.
// Forzamos HTTPS para evitar ese bucle.
app.use((req, res, next) => {
  // Nunca forzar HTTPS en la API: healthchecks/ingest internos pueden ir por HTTP
  // y algunos checkers consideran 3xx como fallo.
  if (req.path && String(req.path).startsWith('/api/')) return next();
  // Rutas explícitas de healthcheck (algunas plataformas exigen 200 y no siguen redirects)
  if (req.path === '/healthz') return next();
  // Solo redirigir navegación (evita afectar POSTs u otros métodos)
  if (req.method !== 'GET' && req.method !== 'HEAD') return next();

  // Solo redirigir peticiones que parecen navegación de navegador (HTML).
  // Muchos healthchecks usan Accept: */* y fallan si reciben 3xx.
  const wantsHtml = requestWantsHtml(req);
  if (!wantsHtml) return next();

  const cookieSecure = envBool('COOKIE_SECURE', process.env.NODE_ENV === 'production') || COOKIE_SAMESITE === 'none';
  if (!cookieSecure) return next();

  const xfProto = String(req.get('x-forwarded-proto') || '')
    .split(',')[0]
    .trim()
    .toLowerCase();

  // Si no hay x-forwarded-proto, asumimos entorno interno y NO forzamos.
  if (!xfProto) return next();

  const isHttps = Boolean(req.secure) || xfProto === 'https';
  if (isHttps) return next();

  const host = req.get('x-forwarded-host') || req.get('host');
  if (!host) return res.status(400).send('HTTPS required');
  return res.redirect(308, `https://${host}${req.originalUrl || '/'}`);
});

function envBool(name, defaultValue) {
  const raw = process.env[name];
  if (raw == null || raw === '') return defaultValue;
  return String(raw).toLowerCase() === 'true';
}

const REQUIRE_USER_LOGIN = envBool('REQUIRE_USER_LOGIN', Boolean(process.env.DATABASE_URL));
const JWT_SECRET = process.env.JWT_SECRET || process.env.SESSION_SECRET || 'dev-insecure-jwt-secret';
const JWT_COOKIE_NAME = process.env.JWT_COOKIE_NAME || 'sid';
const COOKIE_SECURE = envBool('COOKIE_SECURE', process.env.NODE_ENV === 'production');
const COOKIE_SAMESITE_RAW = String(process.env.COOKIE_SAMESITE || 'lax').trim().toLowerCase();
const COOKIE_SAMESITE = (COOKIE_SAMESITE_RAW === 'none' || COOKIE_SAMESITE_RAW === 'strict' || COOKIE_SAMESITE_RAW === 'lax')
  ? COOKIE_SAMESITE_RAW
  : 'lax';
const COOKIE_MAX_AGE_MS = Math.max(1, Number(process.env.COOKIE_MAX_AGE_MS || 1000 * 60 * 60 * 24 * 14));

// CORS: mismo origen normalmente. Si lo sirves desde otro dominio, activa credenciales.
app.use(
  cors({
    origin: true,
    credentials: true
  })
);
app.use(express.json());
app.use(cookieParser());

// Rate limit básico para endurecer API
app.use(
  '/api/',
  rateLimit({
    windowMs: 60 * 1000,
    limit: 240,
    standardHeaders: 'draft-7',
    legacyHeaders: false
  })
);

// Log all incoming requests
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// Conexión a PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

// Forzar TZ consistente en la sesión (evita desfases al usar columnas TIMESTAMP sin zona).
pool.on('connect', (client) => {
  client.query("SET TIME ZONE 'UTC'").catch(() => {});
});

// --- Email (SMTP) ---
function hasSmtpConfigured() {
  return Boolean(process.env.SMTP_HOST && process.env.SMTP_PORT && process.env.SMTP_FROM);
}

function createMailer() {
  if (!hasSmtpConfigured()) return null;
  const port = Number(process.env.SMTP_PORT);
  const secure = envBool('SMTP_SECURE', port === 465);
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port,
    secure,
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS || '' } : undefined
  });
}

async function sendEmail({ to, subject, text, html }) {
  const transporter = createMailer();
  if (!transporter) return { sent: false, error: 'SMTP no configurado' };
  await transporter.sendMail({
    from: process.env.SMTP_FROM,
    to,
    subject,
    text,
    html
  });
  return { sent: true };
}

function publicBaseUrl(req) {
  const envBase = (process.env.PUBLIC_BASE_URL || '').trim();
  if (envBase) return envBase.replace(/\/$/, '');
  const proto = req.get('x-forwarded-proto') || req.protocol || 'https';
  const host = req.get('x-forwarded-host') || req.get('host');
  return `${proto}://${host}`;
}

// --- Zona horaria España (Europe/Madrid) en backend ---
// Devolvemos etiquetas ya formateadas para evitar dependencias del navegador.
const TZ_ES = 'Europe/Madrid';
const fmtEsParts = new Intl.DateTimeFormat('sv-SE', {
  timeZone: TZ_ES,
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hourCycle: 'h23'
});
const fmtEsLabel = new Intl.DateTimeFormat('es-ES', {
  timeZone: TZ_ES,
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false
});

function getMadridParts(date) {
  const parts = fmtEsParts.formatToParts(date);
  const m = Object.fromEntries(parts.map(p => [p.type, p.value]));
  return {
    y: m.year,
    mo: m.month,
    d: m.day,
    h: m.hour,
    mi: m.minute,
    s: m.second
  };
}

function epochMsToDate(ms) {
  const n = Number(ms);
  if (!Number.isFinite(n) || n <= 0) return null;
  const d = new Date(n);
  return Number.isNaN(d.getTime()) ? null : d;
}

function enrichRowWithMadridTs(row) {
  const d = row && row.ts_ms != null
    ? epochMsToDate(row.ts_ms)
    : (row && row.ts ? new Date(row.ts) : null);
  if (!d || Number.isNaN(d.getTime())) return row;
  const p = getMadridParts(d);
  return {
    ...row,
    ts: d.toISOString(),
    ts_madrid: fmtEsLabel.format(d),
    ts_madrid_label: `${p.d} ${p.h}:${p.mi}:${p.s}`,
    ts_madrid_day_key: `${p.y}-${p.mo}-${p.d}`,
    ts_madrid_month_key: `${p.y}-${p.mo}`
  };
}

function getDeviceTokenFromReq(req) {
  return (
    req.get('x-device-token') ||
    req.get('x-device-token'.toUpperCase()) ||
    (typeof req.query.token === 'string' ? req.query.token : null) ||
    null
  );
}

const REQUIRE_DEVICE_TOKEN = String(process.env.REQUIRE_DEVICE_TOKEN || 'false').toLowerCase() === 'true';

function setAuthCookie(res, token) {
  const secure = COOKIE_SECURE || COOKIE_SAMESITE === 'none';
  res.cookie(JWT_COOKIE_NAME, token, {
    httpOnly: true,
    secure,
    sameSite: COOKIE_SAMESITE,
    maxAge: COOKIE_MAX_AGE_MS,
    path: '/'
  });
}

function clearAuthCookie(res) {
  const secure = COOKIE_SECURE || COOKIE_SAMESITE === 'none';
  res.clearCookie(JWT_COOKIE_NAME, {
    httpOnly: true,
    secure,
    sameSite: COOKIE_SAMESITE,
    path: '/'
  });
}

function getJwtFromReq(req) {
  const c = req.cookies?.[JWT_COOKIE_NAME];
  return typeof c === 'string' && c.trim() ? c.trim() : null;
}

function getBearerJwtFromReq(req) {
  const h = String(req.get('authorization') || '').trim();
  if (!h) return null;
  const m = /^Bearer\s+(.+)$/i.exec(h);
  const token = m && m[1] ? String(m[1]).trim() : '';
  return token ? token : null;
}

app.get('/api/debug/session', (req, res) => {
  const xfProto = String(req.get('x-forwarded-proto') || '').split(',')[0].trim().toLowerCase();
  const xfHost = String(req.get('x-forwarded-host') || '').split(',')[0].trim();
  const host = String(req.get('host') || '').trim();
  const token = getJwtFromReq(req);

  res.set('Cache-Control', 'no-store');
  res.json({
    now: new Date().toISOString(),
    host,
    x_forwarded_host: xfHost || null,
    protocol: req.protocol,
    secure_req: Boolean(req.secure),
    x_forwarded_proto: xfProto || null,
    cookie: {
      name: JWT_COOKIE_NAME,
      received: Boolean(token),
      cookie_secure: Boolean(COOKIE_SECURE),
      cookie_samesite: COOKIE_SAMESITE,
      cookie_max_age_ms: COOKIE_MAX_AGE_MS
    },
    user: req.user ? { id: req.user.id || null, email: req.user.email || null } : null
  });
});

function signUserJwt(user) {
  return jwt.sign(
    { sub: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: Math.floor(COOKIE_MAX_AGE_MS / 1000) }
  );
}

function signAdminJwt() {
  return jwt.sign(
    { sub: 'admin', admin: true },
    JWT_SECRET,
    { expiresIn: Math.floor(COOKIE_MAX_AGE_MS / 1000) }
  );
}

function authMiddleware(req, _res, next) {
  const cookieToken = getJwtFromReq(req);
  const bearerToken = getBearerJwtFromReq(req);
  req.user = null;
  req.auth = {
    has_cookie: Boolean(cookieToken),
    has_bearer: Boolean(bearerToken),
    source: null,
    valid: false,
    error: null
  };

  const tryVerify = (token, source) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = { id: decoded.sub, email: decoded.email || null, admin: Boolean(decoded.admin) };
      req.auth.source = source;
      req.auth.valid = true;
      req.auth.error = null;
      return true;
    } catch (e) {
      req.user = null;
      req.auth.source = source;
      req.auth.valid = false;
      req.auth.error = 'invalid_jwt';
      return false;
    }
  };

  // Prioriza cookie (para navegación normal). Si falla y hay bearer, intenta bearer.
  if (cookieToken) {
    if (tryVerify(cookieToken, 'cookie')) return next();
  }
  if (bearerToken) {
    if (tryVerify(bearerToken, 'bearer')) return next();
  }
  if (!cookieToken && !bearerToken) req.auth.error = 'missing';
  return next();
}

app.use(authMiddleware);

function requireUser(req, res) {
  if (hasValidAdminKey(req)) return true;
  if (!REQUIRE_USER_LOGIN) return true;
  if (req.user && req.user.id) return true;
  res.status(401).json({
    error: 'No autenticado',
    auth: {
      has_cookie: Boolean(req.auth?.has_cookie),
      has_bearer: Boolean(req.auth?.has_bearer),
      source: req.auth?.source || null,
      error: req.auth?.error || null,
      cookie_samesite: COOKIE_SAMESITE,
      cookie_secure: Boolean(COOKIE_SECURE || COOKIE_SAMESITE === 'none')
    }
  });
  return false;
}

async function requireUserDevice(req, res, device_code) {
  if (hasValidAdminKey(req)) {
    const dev = await getDeviceByCode(device_code);
    if (!dev) {
      res.status(404).json({ error: 'Dispositivo no encontrado' });
      return null;
    }
    return dev;
  }

  if (!REQUIRE_USER_LOGIN) {
    const dev = await getDeviceByCode(device_code);
    if (!dev) {
      res.status(404).json({ error: 'Dispositivo no encontrado' });
      return null;
    }
    return dev;
  }

  if (!req.user?.id) {
    res.status(401).json({ error: 'No autenticado' });
    return null;
  }

  const dev = await getDeviceByCode(device_code);
  if (!dev) {
    res.status(404).json({ error: 'Dispositivo no encontrado' });
    return null;
  }

  const owned = await pool.query(
    `SELECT 1 FROM user_devices WHERE user_id = $1 AND device_id = $2 LIMIT 1`,
    [req.user.id, dev.id]
  );
  if (owned.rows.length === 0) {
    res.status(403).json({ error: 'No tienes acceso a este dispositivo' });
    return null;
  }
  return dev;
}

async function requireDeviceForConfig(req, res, device_code) {
  if (hasValidAdminKey(req)) {
    const dev = await getDeviceByCode(device_code);
    if (!dev) {
      res.status(404).json({ error: 'Dispositivo no encontrado' });
      return null;
    }
    return dev;
  }

  // Opción B: si el ESP32 llama primero a /api/config, permitimos auto-provisionar con X-Device-Token
  const token = getDeviceTokenFromReq(req);
  const dev = (await getDeviceByCode(device_code)) || (await ensureDeviceProvisionedFromToken(device_code, token));
  if (!dev) {
    res.status(404).json({ error: 'Dispositivo no encontrado' });
    return null;
  }

  // Si el panel está en modo abierto, no exigimos nada
  if (!REQUIRE_USER_LOGIN) return dev;

  // Si hay usuario logueado, exige ownership
  if (req.user?.id) {
    const owned = await pool.query(
      `SELECT 1 FROM user_devices WHERE user_id = $1 AND device_id = $2 LIMIT 1`,
      [req.user.id, dev.id]
    );
    if (owned.rows.length === 0) {
      res.status(403).json({ error: 'No tienes acceso a este dispositivo' });
      return null;
    }
    return dev;
  }

  // Si NO hay usuario, permitimos al ESP32 leer config con X-Device-Token
  if (dev.api_token && token && token === dev.api_token) return dev;

  res.status(401).json({ error: 'No autenticado' });
  return null;
}

function hasValidAdminKey(req) {
  const adminKey = process.env.ADMIN_KEY;
  if (req.user?.admin) return true;
  if (!adminKey) return false;
  return req.get('x-admin-key') === adminKey;
}

function requireAdminKey(req, res) {
  const adminKey = process.env.ADMIN_KEY;
  if (req.user?.admin) return true;
  if (!adminKey) {
    res.status(403).json({ error: 'ADMIN_KEY no configurada' });
    return false;
  }
  if (req.get('x-admin-key') !== adminKey) {
    res.status(401).json({ error: 'x-admin-key inválida' });
    return false;
  }
  return true;
}

async function enforceDeviceTokenIfRequired(req, res, device_code) {
  if (!REQUIRE_DEVICE_TOKEN) return true;
  if (hasValidAdminKey(req)) return true;

  const dev = await getDeviceByCode(device_code);
  if (!dev) {
    res.status(404).json({ error: 'Dispositivo no encontrado' });
    return false;
  }

  const token = getDeviceTokenFromReq(req);
  if (dev.api_token && token !== dev.api_token) {
    res.status(401).json({ error: 'Token inválido (X-Device-Token)' });
    return false;
  }

  return true;
}

async function getDeviceByCode(device_code) {
  const r = await pool.query('SELECT * FROM devices WHERE device_code = $1', [device_code]);
  return r.rows[0] || null;
}

async function ensureDeviceTokenForExistingRows() {
  const missing = await pool.query(`SELECT id FROM devices WHERE api_token IS NULL OR api_token = ''`);
  for (const row of missing.rows) {
    await pool.query('UPDATE devices SET api_token = $1 WHERE id = $2', [uuidv4(), row.id]);
  }
}

async function ensureClaimTokenForExistingRows() {
  // Opción B: si falta claim_token, por defecto lo igualamos a api_token (token del ESP32).
  // Si no hay api_token, generamos uno.
  const missing = await pool.query(`SELECT id, api_token FROM devices WHERE claim_token IS NULL OR claim_token = ''`);
  for (const row of missing.rows) {
    const tok = row.api_token && String(row.api_token).trim() ? String(row.api_token).trim() : uuidv4();
    await pool.query('UPDATE devices SET api_token = COALESCE(NULLIF(api_token, \'\'), $1), claim_token = $1 WHERE id = $2', [tok, row.id]);
  }
}

function isValidDeviceToken(token) {
  const t = String(token || '').trim();
  if (!t) return false;
  if (t === 'CAMBIA_ESTE_TOKEN') return false;
  // Evitar tokens triviales
  return t.length >= 12 && t.length <= 2000;
}

async function ensureDeviceProvisionedFromToken(device_code, token) {
  const t = String(token || '').trim();
  if (!isValidDeviceToken(t)) return null;

  const existing = await getDeviceByCode(device_code);
  if (existing) {
    // Si existe pero tiene otro api_token, normalmente es un error de provisioning inicial.
    // Permitimos reprovisionar SOLO si el dispositivo aún no está asignado a ningún usuario
    // y además venía del modo simple (claim_token == api_token) para no romper el flujo admin.
    if (existing.api_token && String(existing.api_token).trim() && String(existing.api_token) !== t) {
      try {
        const owned = await pool.query('SELECT 1 FROM user_devices WHERE device_id = $1 LIMIT 1', [existing.id]);
        const isOwned = owned.rows.length > 0;
        const simpleProvision = existing.claim_token && String(existing.claim_token) === String(existing.api_token);
        if (!isOwned && simpleProvision) {
          await pool.query(
            'UPDATE devices SET api_token = $1, claim_token = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
            [t, existing.id]
          );
          return await getDeviceByCode(device_code);
        }
      } catch {
        // si falla el check, no reprovisionamos
      }
    }

    // En modo Opción B, si no hay claim_token o api_token, los rellenamos con el token del ESP32.
    if (!existing.api_token || !String(existing.api_token).trim() || !existing.claim_token || !String(existing.claim_token).trim()) {
      await pool.query(
        'UPDATE devices SET api_token = COALESCE(NULLIF(api_token, \'\'), $1), claim_token = COALESCE(NULLIF(claim_token, \'\'), $1), updated_at = CURRENT_TIMESTAMP WHERE id = $2',
        [t, existing.id]
      );
      return await getDeviceByCode(device_code);
    }
    return existing;
  }

  const id = uuidv4();
  await pool.query(
    'INSERT INTO devices (id, device_code, name, location, api_token, claim_token) VALUES ($1, $2, $3, $4, $5, $6)',
    [id, device_code, 'ESP32 Riego', null, t, t]
  );
  await ensureDefaultChannels(id);
  return await getDeviceByCode(device_code);
}

async function ensureDefaultChannels(device_id) {
  // Crea canal por defecto para compatibilidad: Sensor 1 (humedad) y Válvula 1
  try {
    await pool.query(
      `INSERT INTO device_channels (id, device_id, kind, channel_index, name)
       VALUES ($1, $2, 'soil_sensor', 1, 'Sensor 1')
       ON CONFLICT (device_id, kind, channel_index)
       DO UPDATE SET deleted_at = NULL`,
      [uuidv4(), device_id]
    );
    await pool.query(
      `INSERT INTO device_channels (id, device_id, kind, channel_index, name)
       VALUES ($1, $2, 'valve', 1, 'Válvula 1')
       ON CONFLICT (device_id, kind, channel_index)
       DO UPDATE SET deleted_at = NULL`,
      [uuidv4(), device_id]
    );
  } catch (e) {
    // En despliegues con esquema antiguo, initDB aún no habrá creado deleted_at.
    if (/column .*deleted_at.* does not exist|column .* does not exist/i.test(String(e.message))) {
      try { await initDB(); } catch {}
      // Reintentar una vez
      await pool.query(
        `INSERT INTO device_channels (id, device_id, kind, channel_index, name)
         VALUES ($1, $2, 'soil_sensor', 1, 'Sensor 1')
         ON CONFLICT (device_id, kind, channel_index)
         DO UPDATE SET deleted_at = NULL`,
        [uuidv4(), device_id]
      );
      await pool.query(
        `INSERT INTO device_channels (id, device_id, kind, channel_index, name)
         VALUES ($1, $2, 'valve', 1, 'Válvula 1')
         ON CONFLICT (device_id, kind, channel_index)
         DO UPDATE SET deleted_at = NULL`,
        [uuidv4(), device_id]
      );
      return;
    }
    throw e;
  }
}

async function getChannelId(device_id, kind, channel_index) {
  const r = await pool.query(
    `SELECT id FROM device_channels WHERE device_id = $1 AND kind = $2 AND channel_index = $3`,
    [device_id, kind, channel_index]
  );
  return r.rows[0]?.id || null;
}

async function getChannelRow(device_id, kind, channel_index) {
  const r = await pool.query(
    `SELECT id, deleted_at
     FROM device_channels
     WHERE device_id = $1 AND kind = $2 AND channel_index = $3
     LIMIT 1`,
    [device_id, kind, channel_index]
  );
  return r.rows[0] || null;
}

async function ensureChannel(device_id, kind, channel_index) {
  if (kind !== 'soil_sensor' && kind !== 'valve') return null;
  const idx = Number(channel_index);
  if (!Number.isInteger(idx) || idx < 1 || idx > 32) return null;

  let existing;
  try {
    existing = await getChannelRow(device_id, kind, idx);
  } catch (e) {
    if (/column .*deleted_at.* does not exist|column .* does not exist/i.test(String(e.message))) {
      try { await initDB(); } catch {}
      existing = await getChannelRow(device_id, kind, idx);
    } else {
      throw e;
    }
  }
  // Si el canal existe pero está marcado como borrado, NO lo re-creamos automáticamente
  // y además ignoramos sus muestras (para que no “reviva solo” en la UI).
  if (existing && existing.id) {
    if (existing.deleted_at) return null;
    return existing.id;
  }

  const id = uuidv4();
  const name = kind === 'valve' ? `Válvula ${idx}` : `Sensor ${idx}`;
  await pool.query(
    `INSERT INTO device_channels (id, device_id, kind, channel_index, name)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (device_id, kind, channel_index) DO NOTHING`,
    [id, device_id, kind, idx, name]
  );
  return (await getChannelId(device_id, kind, idx)) || null;
}

async function markAlertState(device_id, kind) {
  await pool.query(
    `INSERT INTO alert_state (device_id, kind, last_sent_at)
     VALUES ($1, $2, NOW())
     ON CONFLICT (device_id, kind)
     DO UPDATE SET last_sent_at = EXCLUDED.last_sent_at`,
    [device_id, kind]
  );
}

async function wasAlertRecentlySent(device_id, kind, cooldownMinutes) {
  const r = await pool.query(
    `SELECT last_sent_at FROM alert_state WHERE device_id = $1 AND kind = $2`,
    [device_id, kind]
  );
  if (r.rows.length === 0 || !r.rows[0].last_sent_at) return false;
  const last = new Date(r.rows[0].last_sent_at).getTime();
  return Date.now() - last < cooldownMinutes * 60 * 1000;
}

async function logAlertEvent(device_id, kind, message) {
  await pool.query(
    `INSERT INTO alert_events (device_id, kind, message) VALUES ($1, $2, $3)`,
    [device_id, kind, message]
  );
}

async function sendWebhook(webhookUrl, payload) {
  if (!webhookUrl) return;
  try {
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    });
  } catch (e) {
    console.warn('Webhook notify failed:', e.message);
  }
}

async function sendTelegram(chatId, text) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  if (!token || !chatId) return;
  try {
    await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text })
    });
  } catch (e) {
    console.warn('Telegram notify failed:', e.message);
  }
}

// SSE en memoria (simple). En multi-instancia no garantiza 100%.
const sseClientsByDevice = new Map();
function sseBroadcast(device_code, event, data) {
  const set = sseClientsByDevice.get(device_code);
  if (!set || set.size === 0) return;
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of set) {
    try {
      res.write(payload);
    } catch {
      // ignore
    }
  }
}

const SensorDataSchema = z
  .object({
    device_code: z.string().min(1).max(50),
    temperature: z.coerce.number().optional().nullable(),
    humidity: z.coerce.number().optional().nullable(),
    rain_level: z.coerce.number().optional().nullable(),
    led_status: z.string().optional().nullable(),
    valve_state: z.string().optional().nullable(),
    humidity_low_threshold: z.coerce.number().optional().nullable(),
    humidity_low_color: z.string().optional().nullable(),
    humidity_good_color: z.string().optional().nullable(),
    voltage: z.coerce.number().optional().nullable(),
    // Nota: algunos firmwares envían '' cuando no hay RSSI; z.coerce.number() convertiría '' -> 0.
    // Preferimos NULL para que la UI muestre “--” en vez de 0.
    wifi_rssi: z.preprocess(
      (v) => {
        if (v === '' || v === 'null' || v === 'NULL') return null;
        return v;
      },
      z.coerce.number().int().nullable()
    ).optional(),
    uptime_s: z.coerce.number().int().optional().nullable(),
    reboot_count: z.coerce.number().int().optional().nullable(),
    heap_free: z.coerce.number().int().optional().nullable(),
    ip: z.string().optional().nullable(),
    wifi_ssid: z.string().max(80).optional().nullable(),
    // Alias por compatibilidad si el firmware envía "ssid"
    ssid: z.string().max(80).optional().nullable(),

    // Nuevo: canales múltiples (sensores/válvulas). Retrocompatible.
    channels: z
      .array(
        z
          .object({
            kind: z.enum([
              'soil_sensor',
              'valve',
              'temperature_air',
              'temperature_soil',
              'humidity_air',
              'ph_soil',
              'ec_soil'
            ]),
            index: z.coerce.number().int().min(1).max(32),
            value: z.coerce.number().optional().nullable(),
            state: z.coerce.number().int().optional().nullable()
          })
          .passthrough()
      )
      .optional()
  })
  .passthrough();

const DeviceConfigSchema = z
  .object({
    humidity_low_threshold: z.coerce.number().min(0).max(100).optional(),
    humidity_low_color: z.string().min(1).max(30).optional(),
    humidity_good_color: z.string().min(1).max(30).optional(),
    led_mode: z.string().min(1).max(10).optional(),
    led_manual_color: z.string().min(1).max(30).optional(),
    wet_v: z.coerce.number().optional(),
    dry_v: z.coerce.number().optional(),
    alert_humidity_low_minutes: z.coerce.number().int().min(0).max(1440).optional(),
    alert_valve_on_max_minutes: z.coerce.number().int().min(0).max(1440).optional(),
    alert_sensor_dead_minutes: z.coerce.number().int().min(0).max(10080).optional(),
    alert_voltage_min: z.coerce.number().optional().nullable(),
    alert_voltage_max: z.coerce.number().optional().nullable(),
    notify_webhook_url: z.string().url().optional().nullable(),
    notify_telegram_chat_id: z.string().optional().nullable(),

    // Nuevo: zonas (hasta 8) para umbrales por planta y asignación de canales por índice
    zones: z
      .array(
        z
          .object({
            zone: z.coerce.number().int().min(1).max(8),
            soil_channel_index: z.coerce.number().int().min(1).max(32).optional().nullable(),
            valve_channel_index: z.coerce.number().int().min(1).max(32).optional().nullable(),
            humidity_low_threshold: z.coerce.number().min(0).max(100).optional().nullable()
          })
          .passthrough()
      )
      .max(8)
      .optional()
  })
  .passthrough();

// --- Admin/CRM ---
const AdminCustomerCreateSchema = z
  .object({
    name: z.string().min(1).max(120),
    email: z.string().email().max(255).optional().nullable(),
    phone: z.string().min(3).max(60).optional().nullable(),
    address: z.string().min(1).max(255).optional().nullable(),
    notes: z.string().max(4000).optional().nullable()
  })
  .passthrough();

const AdminCustomerUpdateSchema = AdminCustomerCreateSchema.partial();

// --- Tickets (soporte) ---
const TicketCreateSchema = z
  .object({
    subject: z.string().min(3).max(200),
    device_code: z.string().min(1).max(50).optional().nullable(),
    message: z.string().min(3).max(4000)
  })
  .passthrough();

const TicketMessageSchema = z
  .object({
    body: z.string().min(1).max(4000)
  })
  .passthrough();

const AdminTicketUpdateSchema = z
  .object({
    subject: z.string().min(3).max(200).optional(),
    status: z.enum(['open', 'pending', 'closed']).optional(),
    priority: z.enum(['low', 'normal', 'high', 'urgent']).optional(),
    assigned_to: z.string().min(1).max(80).optional().nullable()
  })
  .passthrough();

// Inicialización automática de tablas en arranque (útil en despliegues en Railway u otros hosts)
async function initDB() {
  try {
    // Crear tabla de dispositivos
    await pool.query(`
      CREATE TABLE IF NOT EXISTS devices (
        id UUID PRIMARY KEY,
        device_code VARCHAR(20) UNIQUE NOT NULL,
        name VARCHAR(100) NOT NULL,
        location VARCHAR(120),
        api_token VARCHAR(80),
        claim_token VARCHAR(80),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name VARCHAR(160),
        phone VARCHAR(60),
        address VARCHAR(255),
        province VARCHAR(120),
        city VARCHAR(120),
        country VARCHAR(120),
        customer_id UUID,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_devices (
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
        role VARCHAR(20) DEFAULT 'owner',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id, device_id)
      )
    `);

    await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS ux_user_devices_device ON user_devices(device_id)`);

    // Crear tabla de sensores
    await pool.query(`
      CREATE TABLE IF NOT EXISTS sensor_data (
        id SERIAL PRIMARY KEY,
        device_id UUID REFERENCES devices(id),
        temperature DECIMAL(5,2),
        humidity DECIMAL(5,2),
        rain_level DECIMAL(5,2),
        led_status VARCHAR(20),
        valve_state VARCHAR(10),
        voltage DECIMAL(6,3),
        wifi_rssi INTEGER,
        uptime_s INTEGER,
        reboot_count INTEGER,
        heap_free INTEGER,
        ip VARCHAR(45),
        humidity_low_threshold DECIMAL(5,2),
        humidity_low_color VARCHAR(20),
        humidity_good_color VARCHAR(20),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Crear tabla de configuración (y aplicar migraciones seguras si faltan columnas)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS device_config (
        id UUID PRIMARY KEY,
        device_id UUID UNIQUE REFERENCES devices(id),
        humidity_low_threshold DECIMAL(5,2) DEFAULT 50,
        humidity_low_color VARCHAR(20) DEFAULT 'Rojo',
        humidity_good_color VARCHAR(20) DEFAULT 'Verde',
        led_mode VARCHAR(10) DEFAULT 'auto',
        led_manual_color VARCHAR(20) DEFAULT 'Off',
        wet_v DECIMAL(6,3),
        dry_v DECIMAL(6,3),
        reboot_count_offset INTEGER DEFAULT 0,
        alert_humidity_low_minutes INTEGER DEFAULT 0,
        alert_valve_on_max_minutes INTEGER DEFAULT 0,
        alert_sensor_dead_minutes INTEGER DEFAULT 0,
        alert_voltage_min DECIMAL(6,3),
        alert_voltage_max DECIMAL(6,3),
        notify_webhook_url TEXT,
        notify_telegram_chat_id TEXT,
        zones_json JSONB,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Canales: válvulas y sensores múltiples
    await pool.query(`
      CREATE TABLE IF NOT EXISTS device_channels (
        id UUID PRIMARY KEY,
        device_id UUID REFERENCES devices(id),
        kind VARCHAR(20) NOT NULL, -- 'soil_sensor' | 'valve' | 'temperature_air' | 'temperature_soil' | 'humidity_air' | 'ph_soil' | 'ec_soil'
        channel_index INTEGER NOT NULL,
        name VARCHAR(80) NOT NULL,
        deleted_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (device_id, kind, channel_index)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS channel_samples (
        id SERIAL PRIMARY KEY,
        channel_id UUID REFERENCES device_channels(id),
        ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        value DECIMAL(10,3),
        state INTEGER
      )
    `);

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_channel_samples_channel_time ON channel_samples(channel_id, ts DESC)`);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS alert_state (
        device_id UUID REFERENCES devices(id),
        kind VARCHAR(40) NOT NULL,
        last_sent_at TIMESTAMP,
        PRIMARY KEY (device_id, kind)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS alert_events (
        id SERIAL PRIMARY KEY,
        device_id UUID REFERENCES devices(id),
        kind VARCHAR(40) NOT NULL,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Migraciones idempotentes (aseguran columnas nuevas en instalaciones existentes)
    await pool.query(`ALTER TABLE device_config ADD COLUMN IF NOT EXISTS led_mode VARCHAR(10) DEFAULT 'auto'`);
    await pool.query(`ALTER TABLE device_config ADD COLUMN IF NOT EXISTS led_manual_color VARCHAR(20) DEFAULT 'Off'`);
    await pool.query(`ALTER TABLE sensor_data ADD COLUMN IF NOT EXISTS valve_state VARCHAR(10)`);

    await pool.query(`ALTER TABLE devices ADD COLUMN IF NOT EXISTS location VARCHAR(120)`);
    await pool.query(`ALTER TABLE devices ADD COLUMN IF NOT EXISTS api_token VARCHAR(80)`);
    await pool.query(`ALTER TABLE devices ADD COLUMN IF NOT EXISTS claim_token VARCHAR(80)`);
    await pool.query(`ALTER TABLE devices ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`);

    await pool.query(`ALTER TABLE sensor_data ADD COLUMN IF NOT EXISTS voltage DECIMAL(6,3)`);
    await pool.query(`ALTER TABLE sensor_data ADD COLUMN IF NOT EXISTS wifi_rssi INTEGER`);
    await pool.query(`ALTER TABLE sensor_data ADD COLUMN IF NOT EXISTS wifi_ssid VARCHAR(80)`);
    await pool.query(`ALTER TABLE sensor_data ADD COLUMN IF NOT EXISTS uptime_s INTEGER`);
    await pool.query(`ALTER TABLE sensor_data ADD COLUMN IF NOT EXISTS reboot_count INTEGER`);
    await pool.query(`ALTER TABLE sensor_data ADD COLUMN IF NOT EXISTS heap_free INTEGER`);
    await pool.query(`ALTER TABLE sensor_data ADD COLUMN IF NOT EXISTS ip VARCHAR(45)`);

    await pool.query(`ALTER TABLE device_config ADD COLUMN IF NOT EXISTS wet_v DECIMAL(6,3)`);
    await pool.query(`ALTER TABLE device_config ADD COLUMN IF NOT EXISTS dry_v DECIMAL(6,3)`);
    await pool.query(`ALTER TABLE device_config ADD COLUMN IF NOT EXISTS reboot_count_offset INTEGER DEFAULT 0`);
    await pool.query(`ALTER TABLE device_config ADD COLUMN IF NOT EXISTS alert_humidity_low_minutes INTEGER DEFAULT 0`);
    await pool.query(`ALTER TABLE device_config ADD COLUMN IF NOT EXISTS alert_valve_on_max_minutes INTEGER DEFAULT 0`);
    await pool.query(`ALTER TABLE device_config ADD COLUMN IF NOT EXISTS alert_sensor_dead_minutes INTEGER DEFAULT 0`);
    await pool.query(`ALTER TABLE device_config ADD COLUMN IF NOT EXISTS alert_voltage_min DECIMAL(6,3)`);
    await pool.query(`ALTER TABLE device_config ADD COLUMN IF NOT EXISTS alert_voltage_max DECIMAL(6,3)`);
    await pool.query(`ALTER TABLE device_config ADD COLUMN IF NOT EXISTS notify_webhook_url TEXT`);
    await pool.query(`ALTER TABLE device_config ADD COLUMN IF NOT EXISTS notify_telegram_chat_id TEXT`);
    await pool.query(`ALTER TABLE device_config ADD COLUMN IF NOT EXISTS zones_json JSONB`);

    // Soft-delete de canales: evita que el ESP32 los “recree” en cuanto envía lecturas
    await pool.query(`ALTER TABLE device_channels ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP`);

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_sensor_device_time ON sensor_data(device_id, created_at DESC)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_alert_events_device_time ON alert_events(device_id, created_at DESC)`);

    // CRM (admin): clientes y vínculo con dispositivos
    await pool.query(`
      CREATE TABLE IF NOT EXISTS customers (
        id UUID PRIMARY KEY,
        name VARCHAR(120) NOT NULL,
        email VARCHAR(255),
        phone VARCHAR(60),
        address VARCHAR(255),
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS customer_devices (
        customer_id UUID REFERENCES customers(id) ON DELETE CASCADE,
        device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (customer_id, device_id)
      )
    `);

    // Un dispositivo sólo puede pertenecer a un cliente (CRM)
    await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS ux_customer_devices_device ON customer_devices(device_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_customer_devices_customer ON customer_devices(customer_id)`);

    // Tickets de soporte (cliente/admin)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS tickets (
        id UUID PRIMARY KEY,
        customer_id UUID REFERENCES customers(id) ON DELETE SET NULL,
        user_id UUID REFERENCES users(id) ON DELETE SET NULL,
        device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
        subject VARCHAR(200) NOT NULL,
        status VARCHAR(20) NOT NULL DEFAULT 'open',
        priority VARCHAR(20) NOT NULL DEFAULT 'normal',
        assigned_to VARCHAR(80),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        closed_at TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS ticket_messages (
        id UUID PRIMARY KEY,
        ticket_id UUID REFERENCES tickets(id) ON DELETE CASCADE,
        author_type VARCHAR(10) NOT NULL,
        author_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
        body TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_tickets_customer_time ON tickets(customer_id, created_at DESC)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_tickets_status_time ON tickets(status, created_at DESC)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_tickets_user_time ON tickets(user_id, created_at DESC)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_ticket_messages_ticket_time ON ticket_messages(ticket_id, created_at ASC)`);

    // Tickets: estado de lectura (para badges/alertas)
    await pool.query(`ALTER TABLE tickets ADD COLUMN IF NOT EXISTS last_user_seen_at TIMESTAMP`);
    await pool.query(`ALTER TABLE tickets ADD COLUMN IF NOT EXISTS last_admin_seen_at TIMESTAMP`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_tickets_last_user_seen ON tickets(last_user_seen_at)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_tickets_last_admin_seen ON tickets(last_admin_seen_at)`);

    // Auth extra: verificación email + reset password
    // Perfil/CRM: campos extendidos en users
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name VARCHAR(160)`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(60)`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS address VARCHAR(255)`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS province VARCHAR(120)`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS city VARCHAR(120)`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS country VARCHAR(120)`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS customer_id UUID`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_users_customer_id ON users(customer_id)`);

    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS verify_token TEXT`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS verify_token_created_at TIMESTAMP`);

    await pool.query(`CREATE TABLE IF NOT EXISTS password_resets (
      id UUID PRIMARY KEY,
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      token TEXT UNIQUE NOT NULL,
      expires_at TIMESTAMP NOT NULL,
      used_at TIMESTAMP,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(token)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_resets(user_id, created_at DESC)`);

    await ensureDeviceTokenForExistingRows();
    await ensureClaimTokenForExistingRows();

    // Canales por defecto para dispositivos existentes
    try {
      const devs = await pool.query('SELECT id FROM devices');
      for (const d of devs.rows) {
        await ensureDefaultChannels(d.id);
      }
    } catch (e) {
      console.warn('ensureDefaultChannels failed:', e.message);
    }

    console.log('Database initialized (auto)');
  } catch (error) {
    console.error('Error initializing DB on startup:', error.message);
  }
}

// --- Auth (registro/login) ---
const RegisterSchema = z.object({
  email: z.string().email().max(255),
  password: z.string().min(8).max(200),
  full_name: z.string().min(2).max(160).optional(),
  phone: z.string().min(3).max(60).optional().nullable(),
  address: z.string().min(2).max(255).optional().nullable(),
  province: z.string().min(2).max(120).optional().nullable(),
  city: z.string().min(2).max(120).optional().nullable(),
  country: z.string().min(2).max(120).optional().nullable()
});

const ProfileUpdateSchema = z
  .object({
    full_name: z.string().min(2).max(160).optional(),
    phone: z.string().min(3).max(60).optional().nullable(),
    address: z.string().min(2).max(255).optional().nullable(),
    province: z.string().min(2).max(120).optional().nullable(),
    city: z.string().min(2).max(120).optional().nullable(),
    country: z.string().min(2).max(120).optional().nullable()
  })
  .passthrough();

const ChangePasswordSchema = z.object({
  current_password: z.string().min(1).max(200),
  new_password: z.string().min(8).max(200)
});

const ForgotPasswordSchema = z.object({
  email: z.string().email().max(255)
});

const ResetPasswordSchema = z.object({
  token: z.string().min(10).max(2000),
  new_password: z.string().min(8).max(200)
});

const LoginSchema = z.object({
  email: z.string().email().max(255),
  password: z.string().min(1).max(200)
});

function friendlyZodAuthError(issues) {
  const first = Array.isArray(issues) ? issues[0] : null;
  if (!first) return 'Datos inválidos. Revisa email y contraseña.';
  const field = Array.isArray(first.path) && first.path.length ? String(first.path[0]) : '';

  if (field === 'email') return 'Email inválido.';
  if (field === 'password') {
    if (first.code === 'too_small') return 'La contraseña debe tener al menos 8 caracteres.';
    return 'Contraseña inválida.';
  }
  return 'Datos inválidos. Revisa email y contraseña.';
}

app.get('/api/auth/me', async (req, res) => {
  if (!req.user?.id) return res.status(401).json({ error: 'No autenticado' });
  try {
    const r = await pool.query(
      'SELECT id, email, full_name, phone, address, province, city, country, customer_id FROM users WHERE id = $1',
      [req.user.id]
    );
    const u = r.rows[0];
    if (!u) return res.status(401).json({ error: 'No autenticado' });
    res.json({
      id: u.id,
      email: u.email,
      full_name: u.full_name || null,
      phone: u.phone || null,
      address: u.address || null,
      province: u.province || null,
      city: u.city || null,
      country: u.country || null,
      customer_id: u.customer_id || null
    });
  } catch (e) {
    console.error(e);
    res.json({ id: req.user.id, email: req.user.email });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const parsed = RegisterSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ error: friendlyZodAuthError(parsed.error.issues), details: parsed.error.issues });
    }
    const email = String(parsed.data.email).trim().toLowerCase();
    const password_hash = await bcrypt.hash(parsed.data.password, 10);
    const id = uuidv4();

    const profile = {
      full_name: parsed.data.full_name ? String(parsed.data.full_name).trim() : null,
      phone: parsed.data.phone != null ? String(parsed.data.phone || '').trim() || null : null,
      address: parsed.data.address != null ? String(parsed.data.address || '').trim() || null : null,
      province: parsed.data.province != null ? String(parsed.data.province || '').trim() || null : null,
      city: parsed.data.city != null ? String(parsed.data.city || '').trim() || null : null,
      country: parsed.data.country != null ? String(parsed.data.country || '').trim() || null : null
    };

    const verify_token = uuidv4();

    // Crear user + customer en transacción para que quede consistente
    const client = await pool.connect();
    let customer_id = null;
    try {
      await client.query('BEGIN');

      // Autocreación de cliente asociado
      customer_id = uuidv4();
      await client.query(
        `INSERT INTO customers (id, name, email, phone, address, notes)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          customer_id,
          profile.full_name || email,
          email,
          profile.phone,
          profile.address,
          null
        ]
      );

      await client.query(
        `INSERT INTO users (id, email, password_hash, email_verified, verify_token, verify_token_created_at,
                            full_name, phone, address, province, city, country, customer_id)
         VALUES ($1, $2, $3, FALSE, $4, CURRENT_TIMESTAMP, $5, $6, $7, $8, $9, $10, $11)`,
        [
          id,
          email,
          password_hash,
          verify_token,
          profile.full_name,
          profile.phone,
          profile.address,
          profile.province,
          profile.city,
          profile.country,
          customer_id
        ]
      );

      await client.query('COMMIT');
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch {}
      throw e;
    } finally {
      client.release();
    }

    // Email de bienvenida/confirmación (no bloqueante)
    let email_sent = false;
    try {
      const base = publicBaseUrl(req);
      const verifyUrl = `${base}/verify-email?token=${encodeURIComponent(verify_token)}`;
      const out = await sendEmail({
        to: email,
        subject: 'Bienvenido a AgroSense · Confirma tu cuenta',
        text: `Tu cuenta se ha creado correctamente.\n\nEmail: ${email}\n\nConfirma tu email aquí: ${verifyUrl}\n`,
        html: `<p>Tu cuenta se ha creado correctamente.</p><p><b>Email:</b> ${email}</p><p>Confirma tu email aquí: <a href="${verifyUrl}">${verifyUrl}</a></p>`
      });
      email_sent = Boolean(out.sent);
    } catch (e) {
      console.warn('sendEmail(register) failed:', e.message);
    }

    const token = signUserJwt({ id, email });
    setAuthCookie(res, token);
    res.json({ status: 'OK', user: { id, email, customer_id }, email_sent });
  } catch (e) {
    if (/duplicate key value|unique constraint/i.test(String(e.message))) {
      return res.status(409).json({ error: 'Email ya registrado' });
    }
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// --- Perfil (cliente) ---
app.get('/api/me/profile', async (req, res) => {
  try {
    if (!requireUser(req, res)) return;
    if (!req.user?.id) return res.status(401).json({ error: 'No autenticado' });
    const r = await pool.query(
      'SELECT id, email, full_name, phone, address, province, city, country, customer_id FROM users WHERE id = $1',
      [req.user.id]
    );
    const u = r.rows[0];
    if (!u) return res.status(401).json({ error: 'No autenticado' });
    res.json({
      id: u.id,
      email: u.email,
      full_name: u.full_name || null,
      phone: u.phone || null,
      address: u.address || null,
      province: u.province || null,
      city: u.city || null,
      country: u.country || null,
      customer_id: u.customer_id || null
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/me/profile', async (req, res) => {
  try {
    if (!requireUser(req, res)) return;
    if (!req.user?.id) return res.status(401).json({ error: 'No autenticado' });
    const parsed = ProfileUpdateSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ error: 'Datos inválidos', details: parsed.error.flatten() });

    const current = await pool.query(
      'SELECT id, email, full_name, phone, address, province, city, country, customer_id FROM users WHERE id = $1',
      [req.user.id]
    );
    const u = current.rows[0];
    if (!u) return res.status(401).json({ error: 'No autenticado' });

    const merged = {
      full_name: parsed.data.full_name !== undefined ? String(parsed.data.full_name || '').trim() || null : (u.full_name || null),
      phone: parsed.data.phone !== undefined ? (parsed.data.phone == null ? null : String(parsed.data.phone || '').trim() || null) : (u.phone || null),
      address: parsed.data.address !== undefined ? (parsed.data.address == null ? null : String(parsed.data.address || '').trim() || null) : (u.address || null),
      province: parsed.data.province !== undefined ? (parsed.data.province == null ? null : String(parsed.data.province || '').trim() || null) : (u.province || null),
      city: parsed.data.city !== undefined ? (parsed.data.city == null ? null : String(parsed.data.city || '').trim() || null) : (u.city || null),
      country: parsed.data.country !== undefined ? (parsed.data.country == null ? null : String(parsed.data.country || '').trim() || null) : (u.country || null)
    };

    // Mantener también el customer asociado (si existe)
    if (u.customer_id) {
      await pool.query(
        `UPDATE customers
         SET name = $1, email = $2, phone = $3, address = $4, updated_at = CURRENT_TIMESTAMP
         WHERE id = $5`,
        [merged.full_name || u.email, u.email, merged.phone, merged.address, u.customer_id]
      );
    }

    const r = await pool.query(
      `UPDATE users
       SET full_name = $1, phone = $2, address = $3, province = $4, city = $5, country = $6
       WHERE id = $7
       RETURNING id, email, full_name, phone, address, province, city, country, customer_id`,
      [merged.full_name, merged.phone, merged.address, merged.province, merged.city, merged.country, req.user.id]
    );
    res.json({ profile: r.rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/me', async (req, res) => {
  try {
    if (!requireUser(req, res)) return;
    if (!req.user?.id) return res.status(401).json({ error: 'No autenticado' });
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const r = await client.query('SELECT customer_id FROM users WHERE id = $1', [req.user.id]);
      const customerId = r.rows[0]?.customer_id || null;
      await client.query('DELETE FROM users WHERE id = $1', [req.user.id]);
      if (customerId) {
        await client.query('DELETE FROM customers WHERE id = $1', [customerId]);
      }
      await client.query('COMMIT');
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch {}
      throw e;
    } finally {
      client.release();
    }
    clearAuthCookie(res);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// --- Tickets (usuario) ---
async function getUserRow(userId) {
  const r = await pool.query('SELECT id, email, full_name, customer_id FROM users WHERE id = $1', [userId]);
  return r.rows[0] || null;
}

// Tickets: esquema (tablas + columnas de lectura) puede faltar en instalaciones antiguas si initDB se cortó.
// Auto-migramos on-demand para evitar 500 en producción.
let supportSchemaCache = { ok: null, checkedAtMs: 0 };
async function ensureSupportSchema() {
  const now = Date.now();
  if (supportSchemaCache.ok === true && now - supportSchemaCache.checkedAtMs < 5 * 60 * 1000) return true;

  try {
    // Mínimo viable para soporte: customers + tickets + ticket_messages
    await pool.query(`
      CREATE TABLE IF NOT EXISTS customers (
        id UUID PRIMARY KEY,
        name VARCHAR(120) NOT NULL,
        email VARCHAR(255),
        phone VARCHAR(60),
        address VARCHAR(255),
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS tickets (
        id UUID PRIMARY KEY,
        customer_id UUID REFERENCES customers(id) ON DELETE SET NULL,
        user_id UUID REFERENCES users(id) ON DELETE SET NULL,
        device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
        subject VARCHAR(200) NOT NULL,
        status VARCHAR(20) NOT NULL DEFAULT 'open',
        priority VARCHAR(20) NOT NULL DEFAULT 'normal',
        assigned_to VARCHAR(80),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        closed_at TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS ticket_messages (
        id UUID PRIMARY KEY,
        ticket_id UUID REFERENCES tickets(id) ON DELETE CASCADE,
        author_type VARCHAR(10) NOT NULL,
        author_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
        body TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_tickets_user_time ON tickets(user_id, created_at DESC)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_tickets_customer_time ON tickets(customer_id, created_at DESC)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_tickets_status_time ON tickets(status, created_at DESC)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_ticket_messages_ticket_time ON ticket_messages(ticket_id, created_at ASC)`);

    // Estado de lectura (badges)
    await pool.query(`ALTER TABLE tickets ADD COLUMN IF NOT EXISTS last_user_seen_at TIMESTAMP`);
    await pool.query(`ALTER TABLE tickets ADD COLUMN IF NOT EXISTS last_admin_seen_at TIMESTAMP`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_tickets_last_user_seen ON tickets(last_user_seen_at)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_tickets_last_admin_seen ON tickets(last_admin_seen_at)`);

    supportSchemaCache = { ok: true, checkedAtMs: now };
    return true;
  } catch (e) {
    console.warn('ensureSupportSchema failed:', e.message);
    supportSchemaCache = { ok: false, checkedAtMs: now };
    return false;
  }
}

// device_config: algunas columnas nuevas (notificaciones/zones) pueden faltar en DBs antiguas.
let deviceConfigSchemaCache = { ok: null, checkedAtMs: 0 };
async function ensureDeviceConfigSchema() {
  const now = Date.now();
  if (deviceConfigSchemaCache.ok === true && now - deviceConfigSchemaCache.checkedAtMs < 5 * 60 * 1000) return true;
  try {
    await pool.query(`ALTER TABLE device_config ADD COLUMN IF NOT EXISTS wet_v DECIMAL(6,3)`);
    await pool.query(`ALTER TABLE device_config ADD COLUMN IF NOT EXISTS dry_v DECIMAL(6,3)`);
    await pool.query(`ALTER TABLE device_config ADD COLUMN IF NOT EXISTS reboot_count_offset INTEGER DEFAULT 0`);
    await pool.query(`ALTER TABLE device_config ADD COLUMN IF NOT EXISTS alert_humidity_low_minutes INTEGER DEFAULT 0`);
    await pool.query(`ALTER TABLE device_config ADD COLUMN IF NOT EXISTS alert_valve_on_max_minutes INTEGER DEFAULT 0`);
    await pool.query(`ALTER TABLE device_config ADD COLUMN IF NOT EXISTS alert_sensor_dead_minutes INTEGER DEFAULT 0`);
    await pool.query(`ALTER TABLE device_config ADD COLUMN IF NOT EXISTS alert_voltage_min DECIMAL(6,3)`);
    await pool.query(`ALTER TABLE device_config ADD COLUMN IF NOT EXISTS alert_voltage_max DECIMAL(6,3)`);
    await pool.query(`ALTER TABLE device_config ADD COLUMN IF NOT EXISTS notify_webhook_url TEXT`);
    await pool.query(`ALTER TABLE device_config ADD COLUMN IF NOT EXISTS notify_telegram_chat_id TEXT`);
    await pool.query(`ALTER TABLE device_config ADD COLUMN IF NOT EXISTS zones_json JSONB`);
    deviceConfigSchemaCache = { ok: true, checkedAtMs: now };
    return true;
  } catch (e) {
    console.warn('ensureDeviceConfigSchema failed:', e.message);
    deviceConfigSchemaCache = { ok: false, checkedAtMs: now };
    return false;
  }
}

async function ensureUserHasCustomer(userRow) {
  if (!userRow) return null;
  if (userRow.customer_id) return userRow.customer_id;
  const customerId = uuidv4();
  await pool.query(
    `INSERT INTO customers (id, name, email, phone, address, notes)
     VALUES ($1, $2, $3, NULL, NULL, NULL)`,
    [customerId, userRow.full_name || userRow.email, userRow.email]
  );
  await pool.query('UPDATE users SET customer_id = $1 WHERE id = $2', [customerId, userRow.id]);
  return customerId;
}

async function requireTicketAccess(req, res, ticketId) {
  if (!req.user?.id) return null;

  // Admin bypass
  if (hasValidAdminKey(req)) {
    const t = await pool.query(
      `SELECT t.*, d.device_code
       FROM tickets t
       LEFT JOIN devices d ON d.id = t.device_id
       WHERE t.id = $1`,
      [ticketId]
    );
    return t.rows[0] || null;
  }

  const u = await getUserRow(req.user.id);
  if (!u) return null;

  const t = await pool.query(
    `SELECT t.*, d.device_code
     FROM tickets t
     LEFT JOIN devices d ON d.id = t.device_id
     WHERE t.id = $1 AND (t.user_id = $2 OR (t.customer_id IS NOT NULL AND t.customer_id = $3))`,
    [ticketId, u.id, u.customer_id]
  );
  return t.rows[0] || null;
}

app.post('/api/tickets', async (req, res) => {
  try {
    if (!requireUser(req, res)) return;
    const parsed = TicketCreateSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ error: 'Datos inválidos', details: parsed.error.flatten() });

    const userRow = await getUserRow(req.user.id);
    if (!userRow) return res.status(401).json({ error: 'No autenticado' });
    const customerId = await ensureUserHasCustomer(userRow);

    let deviceId = null;
    const deviceCode = parsed.data.device_code ? String(parsed.data.device_code || '').trim() : '';
    if (deviceCode) {
      const dev = await requireUserDevice(req, res, deviceCode);
      if (!dev) return; // requireUserDevice ya respondió
      deviceId = dev.id;
    }

    const ticketId = uuidv4();
    const msgId = uuidv4();
    const subject = String(parsed.data.subject || '').trim();
    const body = String(parsed.data.message || '').trim();

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        `INSERT INTO tickets (id, customer_id, user_id, device_id, subject, status, priority, last_user_seen_at)
         VALUES ($1, $2, $3, $4, $5, 'open', 'normal', CURRENT_TIMESTAMP)`,
        [ticketId, customerId, userRow.id, deviceId, subject]
      );
      await client.query(
        `INSERT INTO ticket_messages (id, ticket_id, author_type, author_user_id, body)
         VALUES ($1, $2, 'user', $3, $4)`,
        [msgId, ticketId, userRow.id, body]
      );
      await client.query('COMMIT');
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch {}
      throw e;
    } finally {
      client.release();
    }

    res.status(201).json({ ok: true, ticket_id: ticketId });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/tickets', async (req, res) => {
  try {
    if (!requireUser(req, res)) return;
    const userRow = await getUserRow(req.user.id);
    if (!userRow) return res.status(401).json({ error: 'No autenticado' });

    const r = await pool.query(
      `SELECT
         t.id,
         t.subject,
         t.status,
         t.priority,
         t.created_at,
         t.updated_at,
         t.closed_at,
         d.device_code,
         EXISTS(
           SELECT 1
           FROM ticket_messages tm2
           WHERE tm2.ticket_id = t.id
             AND tm2.author_type = 'admin'
             AND tm2.created_at > COALESCE(t.last_user_seen_at, '1970-01-01'::timestamp)
         ) AS has_unread,
         (SELECT tm.body FROM ticket_messages tm WHERE tm.ticket_id = t.id ORDER BY tm.created_at DESC LIMIT 1) AS last_message,
         (SELECT tm.created_at FROM ticket_messages tm WHERE tm.ticket_id = t.id ORDER BY tm.created_at DESC LIMIT 1) AS last_message_at
       FROM tickets t
       LEFT JOIN devices d ON d.id = t.device_id
       WHERE (t.user_id = $1 OR (t.customer_id IS NOT NULL AND t.customer_id = $2))
       ORDER BY COALESCE((SELECT tm.created_at FROM ticket_messages tm WHERE tm.ticket_id = t.id ORDER BY tm.created_at DESC LIMIT 1), t.updated_at) DESC`,
      [userRow.id, userRow.customer_id]
    );

    res.json({ tickets: r.rows.map(enrichRowWithMadridTs) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/tickets/:id([0-9a-fA-F-]{36})', async (req, res) => {
  try {
    if (!requireUser(req, res)) return;
    const ticketId = String(req.params.id || '').trim();
    const t = await requireTicketAccess(req, res, ticketId);
    if (!t) return res.status(404).json({ error: 'Ticket no encontrado' });

    const msgs = await pool.query(
      `SELECT id, ticket_id, author_type, author_user_id, body, created_at
       FROM ticket_messages
       WHERE ticket_id = $1
       ORDER BY created_at ASC`,
      [ticketId]
    );

    res.json({ ticket: enrichRowWithMadridTs(t), messages: msgs.rows.map(enrichRowWithMadridTs) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/tickets/:id([0-9a-fA-F-]{36})/messages', async (req, res) => {
  try {
    if (!requireUser(req, res)) return;
    const ticketId = String(req.params.id || '').trim();
    const parsed = TicketMessageSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ error: 'Datos inválidos', details: parsed.error.flatten() });

    const t = await requireTicketAccess(req, res, ticketId);
    if (!t) return res.status(404).json({ error: 'Ticket no encontrado' });
    if (String(t.status || '') === 'closed') return res.status(400).json({ error: 'El ticket está cerrado' });

    const msgId = uuidv4();
    const body = String(parsed.data.body || '').trim();
    const isAdmin = hasValidAdminKey(req);
    await pool.query(
      `INSERT INTO ticket_messages (id, ticket_id, author_type, author_user_id, body)
       VALUES ($1, $2, $3, $4, $5)`,
      [msgId, ticketId, isAdmin ? 'admin' : 'user', isAdmin ? null : req.user.id, body]
    );
    await pool.query(
      `UPDATE tickets
       SET updated_at = CURRENT_TIMESTAMP,
           last_user_seen_at = CASE WHEN $2::boolean THEN last_user_seen_at ELSE CURRENT_TIMESTAMP END,
           last_admin_seen_at = CASE WHEN $2::boolean THEN CURRENT_TIMESTAMP ELSE last_admin_seen_at END
       WHERE id = $1`,
      [ticketId, isAdmin]
    );

    res.status(201).json({ ok: true, id: msgId });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/tickets/:id([0-9a-fA-F-]{36})/close', async (req, res) => {
  try {
    if (!requireUser(req, res)) return;
    const ticketId = String(req.params.id || '').trim();
    const t = await requireTicketAccess(req, res, ticketId);
    if (!t) return res.status(404).json({ error: 'Ticket no encontrado' });

    // Usuario sólo puede cerrar su ticket (admin también puede cerrarlo)
    const r = await pool.query(
      `UPDATE tickets
       SET status = 'closed', closed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
       WHERE id = $1
       RETURNING id, status, closed_at`,
      [ticketId]
    );
    res.json({ ok: true, ticket: enrichRowWithMadridTs(r.rows[0]) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// --- Tickets (admin) ---
app.get('/api/admin/tickets', async (req, res) => {
  try {
    if (!requireAdminKey(req, res)) return;

    const status = String(req.query.status || '').trim();
    const customer_id = String(req.query.customer_id || '').trim();
    const device_code = String(req.query.device_code || '').trim();

    const where = [];
    const params = [];
    if (status) {
      params.push(status);
      where.push(`t.status = $${params.length}`);
    }
    if (customer_id) {
      params.push(customer_id);
      where.push(`t.customer_id = $${params.length}`);
    }
    if (device_code) {
      params.push(device_code);
      where.push(`d.device_code = $${params.length}`);
    }
    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const r = await pool.query(
      `SELECT
         t.*,
         c.name AS customer_name,
         u.email AS user_email,
         d.device_code,
         EXISTS(
           SELECT 1
           FROM ticket_messages tm2
           WHERE tm2.ticket_id = t.id
             AND tm2.author_type = 'user'
             AND tm2.created_at > COALESCE(t.last_admin_seen_at, '1970-01-01'::timestamp)
         ) AS has_unread,
         (SELECT tm.body FROM ticket_messages tm WHERE tm.ticket_id = t.id ORDER BY tm.created_at DESC LIMIT 1) AS last_message,
         (SELECT tm.created_at FROM ticket_messages tm WHERE tm.ticket_id = t.id ORDER BY tm.created_at DESC LIMIT 1) AS last_message_at
       FROM tickets t
       LEFT JOIN customers c ON c.id = t.customer_id
       LEFT JOIN users u ON u.id = t.user_id
       LEFT JOIN devices d ON d.id = t.device_id
       ${whereSql}
       ORDER BY COALESCE((SELECT tm.created_at FROM ticket_messages tm WHERE tm.ticket_id = t.id ORDER BY tm.created_at DESC LIMIT 1), t.updated_at) DESC
       LIMIT 500`,
      params
    );

    res.json({ tickets: r.rows.map(enrichRowWithMadridTs) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/admin/tickets/:id([0-9a-fA-F-]{36})', async (req, res) => {
  try {
    if (!requireAdminKey(req, res)) return;
    const ticketId = String(req.params.id || '').trim();
    const t = await pool.query(
      `SELECT t.*, c.name AS customer_name, u.email AS user_email, d.device_code
       FROM tickets t
       LEFT JOIN customers c ON c.id = t.customer_id
       LEFT JOIN users u ON u.id = t.user_id
       LEFT JOIN devices d ON d.id = t.device_id
       WHERE t.id = $1`,
      [ticketId]
    );
    if (!t.rows.length) return res.status(404).json({ error: 'Ticket no encontrado' });

    const msgs = await pool.query(
      `SELECT id, ticket_id, author_type, author_user_id, body, created_at
       FROM ticket_messages
       WHERE ticket_id = $1
       ORDER BY created_at ASC`,
      [ticketId]
    );

    res.json({ ticket: enrichRowWithMadridTs(t.rows[0]), messages: msgs.rows.map(enrichRowWithMadridTs) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/admin/tickets/:id([0-9a-fA-F-]{36})', async (req, res) => {
  try {
    if (!requireAdminKey(req, res)) return;
    const ticketId = String(req.params.id || '').trim();
    const parsed = AdminTicketUpdateSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ error: 'Datos inválidos', details: parsed.error.flatten() });

    const existing = await pool.query('SELECT * FROM tickets WHERE id = $1', [ticketId]);
    if (!existing.rows.length) return res.status(404).json({ error: 'Ticket no encontrado' });
    const merged = { ...existing.rows[0], ...parsed.data };

    const closing = parsed.data.status === 'closed' && existing.rows[0].status !== 'closed';
    const r = await pool.query(
      `UPDATE tickets
       SET subject = $1,
           status = $2,
           priority = $3,
           assigned_to = $4,
           updated_at = CURRENT_TIMESTAMP,
           closed_at = CASE WHEN $5::boolean THEN CURRENT_TIMESTAMP ELSE closed_at END
       WHERE id = $6
       RETURNING *`,
      [merged.subject, merged.status, merged.priority, merged.assigned_to ?? null, closing, ticketId]
    );
    res.json({ ok: true, ticket: enrichRowWithMadridTs(r.rows[0]) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/admin/tickets/:id([0-9a-fA-F-]{36})/messages', async (req, res) => {
  try {
    if (!requireAdminKey(req, res)) return;
    const ticketId = String(req.params.id || '').trim();
    const parsed = TicketMessageSchema.safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ error: 'Datos inválidos', details: parsed.error.flatten() });

    const t = await pool.query('SELECT id, status FROM tickets WHERE id = $1', [ticketId]);
    if (!t.rows.length) return res.status(404).json({ error: 'Ticket no encontrado' });
    if (String(t.rows[0].status || '') === 'closed') return res.status(400).json({ error: 'El ticket está cerrado' });

    const msgId = uuidv4();
    await pool.query(
      `INSERT INTO ticket_messages (id, ticket_id, author_type, author_user_id, body)
       VALUES ($1, $2, 'admin', NULL, $3)`,
      [msgId, ticketId, String(parsed.data.body || '').trim()]
    );
    await pool.query(
      `UPDATE tickets
       SET updated_at = CURRENT_TIMESTAMP,
           last_admin_seen_at = CURRENT_TIMESTAMP
       WHERE id = $1`,
      [ticketId]
    );
    res.status(201).json({ ok: true, id: msgId });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// --- Tickets: badges de no leídos ---
app.get('/api/tickets/unread-count', async (req, res) => {
  try {
    if (!requireUser(req, res)) return;
    const userRow = await getUserRow(req.user.id);
    if (!userRow) return res.status(401).json({ error: 'No autenticado' });

    // Asegurar esquema de soporte (si falla, devolvemos 0 en vez de romper UI)
    const schemaOk = await ensureSupportSchema();
    if (!schemaOk) return res.json({ unread_count: 0 });

    const customerId = userRow.customer_id ?? null;
    const params = [userRow.id];
    const whereOwner = customerId ? `(t.user_id = $1 OR t.customer_id = $2)` : `(t.user_id = $1)`;
    if (customerId) params.push(customerId);

    const r = await pool.query(
      `SELECT COUNT(*)::int AS unread_count
       FROM tickets t
       WHERE ${whereOwner}
         AND EXISTS(
           SELECT 1
           FROM ticket_messages tm
           WHERE tm.ticket_id = t.id
             AND tm.author_type = 'admin'
             AND tm.created_at > COALESCE(t.last_user_seen_at, to_timestamp(0)::timestamp)
         )`,
      params
    );
    res.json({ unread_count: r.rows[0]?.unread_count || 0 });
  } catch (e) {
    console.error(e);
    // Degradación total: este endpoint no debe romper el panel.
    // Si hay cualquier error de DB (esquema/permiso/etc.), respondemos 200 con 0.
    try { await ensureSupportSchema(); } catch {}
    return res.json({ unread_count: 0 });
  }
});

app.post('/api/tickets/:id([0-9a-fA-F-]{36})/mark-read', async (req, res) => {
  try {
    if (!requireUser(req, res)) return;
    const ticketId = String(req.params.id || '').trim();
    const t = await requireTicketAccess(req, res, ticketId);
    if (!t) return res.status(404).json({ error: 'Ticket no encontrado' });

    const schemaOk = await ensureSupportSchema();
    if (schemaOk) {
      await pool.query(`UPDATE tickets SET last_user_seen_at = CURRENT_TIMESTAMP WHERE id = $1`, [ticketId]);
    }
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/admin/tickets/unread-count', async (req, res) => {
  try {
    if (!requireAdminKey(req, res)) return;

    const schemaOk = await ensureSupportSchema();
    if (!schemaOk) return res.json({ unread_count: 0 });
    const existsCond = `AND tm.created_at > COALESCE(t.last_admin_seen_at, to_timestamp(0)::timestamp)`;

    const r = await pool.query(
      `SELECT COUNT(*)::int AS unread_count
       FROM tickets t
       WHERE t.status <> 'closed'
         AND EXISTS(
           SELECT 1
           FROM ticket_messages tm
           WHERE tm.ticket_id = t.id
             AND tm.author_type = 'user'
             ${existsCond}
         )`
    );
    res.json({ unread_count: r.rows[0]?.unread_count || 0 });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/admin/tickets/:id([0-9a-fA-F-]{36})/mark-read', async (req, res) => {
  try {
    if (!requireAdminKey(req, res)) return;
    const ticketId = String(req.params.id || '').trim();

    const schemaOk = await ensureSupportSchema();
    if (schemaOk) {
      await pool.query(`UPDATE tickets SET last_admin_seen_at = CURRENT_TIMESTAMP WHERE id = $1`, [ticketId]);
    }
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// --- Admin: login por cookie (para soporte/navegación a /panel) ---
app.post('/api/admin/login', async (req, res) => {
  try {
    const adminKey = process.env.ADMIN_KEY;
    if (!adminKey) return res.status(403).json({ error: 'ADMIN_KEY no configurada' });
    const key = String(req.body?.admin_key || '').trim();
    if (!key || key !== adminKey) return res.status(401).json({ error: 'admin_key inválida' });
    const token = signAdminJwt();
    setAuthCookie(res, token);
    res.json({ status: 'OK' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/admin/logout', async (_req, res) => {
  clearAuthCookie(res);
  res.json({ status: 'OK' });
});

app.post('/api/auth/resend-verification', async (req, res) => {
  try {
    // No revelar existencia de cuentas: siempre OK.
    const emailFromBody = typeof req.body?.email === 'string' ? req.body.email : '';
    let email = String(emailFromBody || '').trim().toLowerCase();

    if (req.user?.id) {
      const r = await pool.query('SELECT id, email, email_verified, verify_token FROM users WHERE id = $1', [req.user.id]);
      const u = r.rows[0];
      if (!u) return res.json({ status: 'OK' });
      if (u.email_verified) return res.json({ status: 'OK', already_verified: true });
      email = u.email;
    }

    if (!email || !email.includes('@') || email.length > 255) {
      return res.json({ status: 'OK' });
    }

    const r2 = await pool.query('SELECT id, email, email_verified, verify_token FROM users WHERE email = $1', [email]);
    const user = r2.rows[0];
    if (!user) return res.json({ status: 'OK' });
    if (user.email_verified) return res.json({ status: 'OK', already_verified: true });

    let token = user.verify_token;
    if (!token) {
      token = uuidv4();
      await pool.query(
        'UPDATE users SET verify_token = $1, verify_token_created_at = CURRENT_TIMESTAMP WHERE id = $2',
        [token, user.id]
      );
    }

    try {
      const base = publicBaseUrl(req);
      const verifyUrl = `${base}/verify-email?token=${encodeURIComponent(token)}`;
      const out = await sendEmail({
        to: email,
        subject: 'AgroSense · Confirma tu email',
        text: `Confirma tu email aquí: ${verifyUrl}\n`,
        html: `<p>Confirma tu email aquí:</p><p><a href="${verifyUrl}">${verifyUrl}</a></p>`
      });
      return res.json({ status: 'OK', email_sent: Boolean(out.sent) });
    } catch (e) {
      console.warn('sendEmail(resend-verification) failed:', e.message);
      return res.json({ status: 'OK', email_sent: false });
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const parsed = LoginSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ error: friendlyZodAuthError(parsed.error.issues), details: parsed.error.issues });
    }
    const email = String(parsed.data.email).trim().toLowerCase();
    const r = await pool.query('SELECT id, email, password_hash FROM users WHERE email = $1', [email]);
    const user = r.rows[0];
    if (!user) return res.status(401).json({ error: 'Credenciales inválidas' });
    const ok = await bcrypt.compare(parsed.data.password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Credenciales inválidas' });

    const token = signUserJwt({ id: user.id, email: user.email });
    setAuthCookie(res, token);
    res.json({ status: 'OK', user: { id: user.id, email: user.email } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/change-password', async (req, res) => {
  try {
    if (!req.user?.id) return res.status(401).json({ error: 'No autenticado' });
    const parsed = ChangePasswordSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ error: friendlyZodAuthError(parsed.error.issues), details: parsed.error.issues });
    }
    const r = await pool.query('SELECT id, password_hash, email FROM users WHERE id = $1', [req.user.id]);
    const user = r.rows[0];
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    const ok = await bcrypt.compare(parsed.data.current_password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Contraseña actual incorrecta' });
    const password_hash = await bcrypt.hash(parsed.data.new_password, 10);
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [password_hash, user.id]);
    res.json({ status: 'OK' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/request-password-reset', async (req, res) => {
  try {
    const parsed = ForgotPasswordSchema.safeParse(req.body || {});
    if (!parsed.success) {
      // No revelar demasiado
      return res.status(400).json({ error: 'Email inválido' });
    }
    const email = String(parsed.data.email).trim().toLowerCase();
    const r = await pool.query('SELECT id, email FROM users WHERE email = $1', [email]);
    const user = r.rows[0];
    if (user) {
      const token = uuidv4() + uuidv4();
      const id = uuidv4();
      const expiresMinutes = Math.max(5, Number(process.env.PASSWORD_RESET_MINUTES || 60));
      await pool.query(
        `INSERT INTO password_resets (id, user_id, token, expires_at)
         VALUES ($1, $2, $3, CURRENT_TIMESTAMP + ($4 || ' minutes')::interval)`,
        [id, user.id, token, String(expiresMinutes)]
      );

      try {
        const base = publicBaseUrl(req);
        const url = `${base}/reset-password?token=${encodeURIComponent(token)}`;
        await sendEmail({
          to: email,
          subject: 'AgroSense · Recuperar contraseña',
          text: `Para cambiar tu contraseña, abre este enlace (caduca en ${expiresMinutes} minutos):\n${url}\n`,
          html: `<p>Para cambiar tu contraseña, abre este enlace (caduca en ${expiresMinutes} minutos):</p><p><a href="${url}">${url}</a></p>`
        });
      } catch (e) {
        console.warn('sendEmail(reset) failed:', e.message);
      }
    }
    res.json({ status: 'OK' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const parsed = ResetPasswordSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ error: friendlyZodAuthError(parsed.error.issues), details: parsed.error.issues });
    }
    const token = String(parsed.data.token);
    const rr = await pool.query(
      `SELECT pr.id, pr.user_id, pr.expires_at, pr.used_at
       FROM password_resets pr
       WHERE pr.token = $1
       LIMIT 1`,
      [token]
    );
    const row = rr.rows[0];
    if (!row) return res.status(400).json({ error: 'Token inválido' });
    if (row.used_at) return res.status(400).json({ error: 'Token ya usado' });
    const exp = new Date(row.expires_at);
    if (Number.isNaN(exp.getTime()) || exp.getTime() < Date.now()) return res.status(400).json({ error: 'Token caducado' });

    const password_hash = await bcrypt.hash(parsed.data.new_password, 10);
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [password_hash, row.user_id]);
    await pool.query('UPDATE password_resets SET used_at = CURRENT_TIMESTAMP WHERE id = $1', [row.id]);
    res.json({ status: 'OK' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/verify-email', async (req, res) => {
  try {
    const token = String(req.query.token || '').trim();
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    if (!token) return res.status(400).send('Token inválido');

    const r = await pool.query('SELECT id, email_verified FROM users WHERE verify_token = $1 LIMIT 1', [token]);
    const u = r.rows[0];
    if (!u) return res.status(400).send('Token inválido o ya usado');
    if (!u.email_verified) {
      await pool.query('UPDATE users SET email_verified = TRUE, verify_token = NULL WHERE id = $1', [u.id]);
    }
    res.send('<html><body style="font-family:Arial,sans-serif;background:#0b1220;color:#e9eef7;padding:24px;"><h2>Email verificado</h2><p>Tu cuenta ya está verificada. Puedes volver a <a style="color:#b8f5c1" href="/login">iniciar sesión</a>.</p></body></html>');
  } catch (e) {
    console.error(e);
    res.status(500).send('Error verificando email');
  }
});

app.post('/api/auth/logout', async (_req, res) => {
  clearAuthCookie(res);
  res.json({ status: 'OK' });
});

// Claim de dispositivo (asignar un ESP32 a un usuario)
const ClaimSchema = z.object({
  device_code: z.string().min(1).max(50),
  claim_token: z.string().min(1).max(120)
});

app.post('/api/device/claim', async (req, res) => {
  try {
    if (!requireUser(req, res)) return;

    const parsed = ClaimSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ error: 'Payload inválido', details: parsed.error.issues });
    }

    const device_code = parsed.data.device_code;
    const claim_token = parsed.data.claim_token;
    const dev = await getDeviceByCode(device_code);
    if (!dev) return res.status(404).json({ error: 'Dispositivo no encontrado' });

    const matchesClaim = dev.claim_token && String(dev.claim_token) === String(claim_token);
    const matchesApi = dev.api_token && String(dev.api_token) === String(claim_token);
    if (!matchesClaim && !matchesApi) {
      // Si el dispositivo existe pero aún no tiene dueño, permitimos “reclamar” con el token
      // y lo fijamos como api_token/claim_token (Opción B). Evita bloqueos por provisioning inicial.
      const owned = await pool.query('SELECT 1 FROM user_devices WHERE device_id = $1 LIMIT 1', [dev.id]);
      const isOwned = owned.rows.length > 0;
      if (!isOwned && isValidDeviceToken(claim_token)) {
        await pool.query(
          'UPDATE devices SET api_token = $1, claim_token = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
          [String(claim_token).trim(), dev.id]
        );
      } else {
        return res.status(401).json({ error: 'Token inválido' });
      }
    }

    await pool.query(
      `INSERT INTO user_devices (user_id, device_id, role)
       VALUES ($1, $2, 'owner')
       ON CONFLICT (user_id, device_id) DO NOTHING`,
      [req.user.id, dev.id]
    );

    // Si claim_token es distinto del api_token (modo admin), rotamos.
    // En Opción B (claim_token == api_token del ESP32) NO rotamos para permitir re-claim tras reset.
    if (dev.claim_token && dev.api_token && String(dev.claim_token) !== String(dev.api_token)) {
      await pool.query('UPDATE devices SET claim_token = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2', [uuidv4(), dev.id]);
    }

    res.json({ status: 'OK', device_code });
  } catch (e) {
    if (/ux_user_devices_device/i.test(String(e.message))) {
      return res.status(409).json({ error: 'Este dispositivo ya está asignado a otro usuario' });
    }
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Llamar a initDB si hay DATABASE_URL (deployment) o si la variable AUTO_DB_INIT está activa
if (process.env.DATABASE_URL || process.env.AUTO_DB_INIT === 'true') {
  void initDB().catch((err) => {
    console.error('initDB failed (will keep server running):', err);
  });
} else {
  console.log('DATABASE_URL not set: skipping automatic DB init (use /api/init endpoint to initialize)');
}

// Tabla de dispositivos
app.get('/api/init', async (req, res) => {
  try {
    await initDB();
    res.json({ status: 'Base de datos inicializada (initDB)' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// Healthcheck simple (Railway)
app.get('/api/health', async (req, res) => {
  try {
    const db = await pool.query('SELECT 1 AS ok');
    res.set('Cache-Control', 'no-store');
    const build =
      process.env.RAILWAY_GIT_COMMIT_SHA ||
      process.env.RAILWAY_GIT_COMMIT ||
      process.env.GIT_COMMIT ||
      process.env.BUILD_ID ||
      null;
    res.json({ ok: true, db: db.rows[0]?.ok === 1, ts: new Date().toISOString(), build });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message, ts: new Date().toISOString() });
  }
});

// Healthcheck NO-API (por si Railway u otro proveedor comprueba "/" o una ruta pública)
app.get('/healthz', async (_req, res) => {
  try {
    const db = await pool.query('SELECT 1 AS ok');
    const build =
      process.env.RAILWAY_GIT_COMMIT_SHA ||
      process.env.RAILWAY_GIT_COMMIT ||
      process.env.GIT_COMMIT ||
      process.env.BUILD_ID ||
      null;
    res.set('Cache-Control', 'no-store');
    res.status(200).type('text/plain').send(`ok db=${db.rows[0]?.ok === 1} build=${build || 'null'}`);
  } catch (e) {
    res.status(200).type('text/plain').send('ok db=false');
  }
});

// Registrar/obtener dispositivo
app.post('/api/device/register', async (req, res) => {
  try {
    const { device_code, name, location } = req.body;

    let device = await pool.query(
      'SELECT * FROM devices WHERE device_code = $1',
      [device_code]
    );

    if (device.rows.length === 0) {
      const id = uuidv4();
      const api_token = uuidv4();
      const claim_token = api_token;
      await pool.query(
        'INSERT INTO devices (id, device_code, name, location, api_token, claim_token) VALUES ($1, $2, $3, $4, $5, $6)',
        [id, device_code, name || 'ESP32 Riego', location || null, api_token, claim_token]
      );
      await ensureDefaultChannels(id);
      device = await pool.query('SELECT * FROM devices WHERE id = $1', [id]);
    } else {
      // Asegurar claim_token en instalaciones antiguas
      const existing = device.rows[0];
      if (!existing.claim_token) {
        await pool.query('UPDATE devices SET claim_token = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2', [uuidv4(), existing.id]);
        device = await pool.query('SELECT * FROM devices WHERE id = $1', [existing.id]);
      }
    }

    // Nunca exponer claim_token públicamente
    const out = { ...device.rows[0] };
    delete out.claim_token;
    delete out.api_token;
    res.json(out);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// Enviar datos del sensor (desde ESP32)
app.post('/api/sensor/data', async (req, res) => {
  try {
    // Opción B: el ESP32 autentica con X-Device-Token (y ese mismo token sirve como claim)
    const deviceToken = getDeviceTokenFromReq(req);

    const parsed = SensorDataSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Payload inválido', details: parsed.error.issues });
    }

    const {
      device_code,
      temperature,
      humidity,
      rain_level,
      led_status,
      valve_state,
      humidity_low_threshold,
      humidity_low_color,
      humidity_good_color,
      voltage,
      wifi_rssi,
      uptime_s,
      reboot_count,
      heap_free,
      ip,
      wifi_ssid,
      channels
    } = parsed.data;
    if (!isValidDeviceToken(deviceToken)) {
      return res.status(401).json({ error: 'Falta o es inválido X-Device-Token' });
    }

    const devRow = await ensureDeviceProvisionedFromToken(device_code, deviceToken);
    if (!devRow) return res.status(404).json({ error: 'Dispositivo no encontrado' });
    if (devRow.api_token && String(devRow.api_token) !== String(deviceToken)) {
      return res.status(401).json({ error: 'Token inválido (X-Device-Token)' });
    }

    const device_id = devRow.id;

    // Asegurar canales base
    await ensureDefaultChannels(device_id);

    const resolved_valve_state = valve_state || led_status || null;

    const wifiSsid = (() => {
      const raw = wifi_ssid != null ? wifi_ssid : (parsed.data && parsed.data.ssid != null ? parsed.data.ssid : null);
      if (raw == null) return null;
      const s = String(raw).trim();
      return s ? s.slice(0, 80) : null;
    })();

    await pool.query(
      `INSERT INTO sensor_data (
          device_id, temperature, humidity, rain_level, led_status, valve_state,
          voltage, wifi_rssi, uptime_s, reboot_count, heap_free, ip, wifi_ssid,
          humidity_low_threshold, humidity_low_color, humidity_good_color
        )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
      [
        device_id,
        temperature,
        humidity,
        rain_level,
        led_status || null,
        resolved_valve_state,
        voltage,
        wifi_rssi,
        uptime_s,
        reboot_count,
        heap_free,
        ip,
        wifiSsid,
        humidity_low_threshold,
        humidity_low_color,
        humidity_good_color
      ]
    );

    // Guardar muestras por canal
    try {
      const now = new Date();

      const chArr = Array.isArray(channels) ? channels : [];
      if (chArr.length > 0) {
        let sawSoil = false;
        let sawValve = false;
        for (const c of chArr) {
          const kind = c?.kind;
          const idx = Number(c?.index);
          if (!Number.isInteger(idx)) continue;
          if (
            kind !== 'soil_sensor' &&
            kind !== 'valve' &&
            kind !== 'temperature_air' &&
            kind !== 'temperature_soil' &&
            kind !== 'humidity_air' &&
            kind !== 'ph_soil' &&
            kind !== 'ec_soil'
          ) {
            continue;
          }

          // No recrear canales automáticamente: solo guardar si el canal existe.
          const channelId = await getChannelId(device_id, kind, idx);
          if (!channelId) continue;

          if (kind === 'valve') {
            sawValve = true;
            const s = c?.state;
            const st = typeof s === 'number' ? s : Number(s);
            if (!Number.isFinite(st)) continue;
            await pool.query(
              `INSERT INTO channel_samples (channel_id, ts, state) VALUES ($1, $2, $3)`,
              [channelId, now, st >= 1 ? 1 : 0]
            );
          } else {
            sawSoil = true;
            const v = c?.value;
            const num = typeof v === 'number' ? v : Number(v);
            if (!Number.isFinite(num)) continue;
            await pool.query(
              `INSERT INTO channel_samples (channel_id, ts, value) VALUES ($1, $2, $3)`,
              [channelId, now, num]
            );
          }
        }

        // Si el payload trae solo humedad (muy típico), aseguro al menos un punto para válvula 1.
        // Esto evita que el histórico de válvula se quede “clavado” en una fecha antigua.
        if (!sawValve) {
          const ch = await getChannelId(device_id, 'valve', 1);
          if (ch) {
            const vs = String(resolved_valve_state || 'OFF').toUpperCase();
            const state = (vs === 'ON' || vs === '1' || vs === 'TRUE') ? 1 : 0;
            await pool.query(
              `INSERT INTO channel_samples (channel_id, ts, state) VALUES ($1, $2, $3)`,
              [ch, now, state]
            );
          }
        }
      } else {
        // Compatibilidad con canal 1
        if (typeof humidity === 'number' && Number.isFinite(humidity)) {
          const ch = await getChannelId(device_id, 'soil_sensor', 1);
          if (ch) {
            await pool.query(
              `INSERT INTO channel_samples (channel_id, ts, value) VALUES ($1, $2, $3)`,
              [ch, now, humidity]
            );
          }
        }
        // Registrar SIEMPRE el canal de válvula 1 (si no viene estado, asumimos OFF).
        const ch = await getChannelId(device_id, 'valve', 1);
        if (ch) {
          const vs = String(resolved_valve_state || 'OFF').toUpperCase();
          const state = vs === 'ON' || vs === '1' || vs === 'TRUE' ? 1 : 0;
          await pool.query(
            `INSERT INTO channel_samples (channel_id, ts, state) VALUES ($1, $2, $3)`,
            [ch, now, state]
          );
        }
      }
    } catch (e) {
      console.warn('channel_samples insert failed:', e.message);
    }

    // Emitir update por SSE (si hay clientes conectados)
    sseBroadcast(device_code, 'sensor', {
      device_code,
      temperature,
      humidity,
      valve_state: resolved_valve_state,
      voltage,
      wifi_rssi,
      wifi_ssid: wifiSsid,
      uptime_s,
      reboot_count,
      heap_free,
      ip,
      ts: new Date().toISOString()
    });

    // Evaluar alertas (si están configuradas)
    await evaluateAlertsOnIngest({
      device_code,
      device_id,
      humidity: typeof humidity === 'number' ? humidity : null,
      valve_state: resolved_valve_state,
      voltage: typeof voltage === 'number' ? voltage : null
    });

    res.json({ status: 'Datos guardados' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// Obtener últimos datos del sensor
app.get('/api/sensor/latest/:device_code', async (req, res) => {
  try {
    const { device_code } = req.params;

    const dev = await requireUserDevice(req, res, device_code);
    if (!dev) return;

    const result = await pool.query(
      `SELECT
         sd.*,
         (EXTRACT(EPOCH FROM (sd.created_at AT TIME ZONE current_setting('TIMEZONE'))) * 1000) AS created_at_ms,
         COALESCE(dc.reboot_count_offset, 0) AS reboot_count_offset,
         GREATEST(0, COALESCE(sd.reboot_count, 0) - COALESCE(dc.reboot_count_offset, 0))::int AS reboot_count_display
       FROM sensor_data sd
       JOIN devices d ON sd.device_id = d.id
       LEFT JOIN device_config dc ON dc.device_id = d.id
       WHERE d.device_code = $1
       ORDER BY sd.created_at DESC
       LIMIT 1`,
      [device_code]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No hay datos' });
    }

    const out = { ...result.rows[0] };
    const now = new Date();
    out.server_now = now.toISOString();
    out.server_now_madrid = fmtEsLabel.format(now);

    const createdAt = epochMsToDate(out.created_at_ms);
    if (createdAt) {
      out.created_at = createdAt.toISOString();
      out.created_at_madrid = fmtEsLabel.format(createdAt);
      out.age_ms = Math.max(0, now.getTime() - createdAt.getTime());
      out.age_minutes = Math.round(out.age_ms / 60000);
    }
    res.json(out);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// Reset lógico del contador de reinicios (offset) para UI
app.post('/api/device/reboots/reset/:device_code', async (req, res) => {
  try {
    const { device_code } = req.params;
    const dev = await requireUserDevice(req, res, device_code);
    if (!dev) return;

    const ok = await enforceDeviceTokenIfRequired(req, res, device_code);
    if (!ok) return;

    const last = await pool.query(
      `SELECT reboot_count FROM sensor_data WHERE device_id = $1 ORDER BY created_at DESC LIMIT 1`,
      [dev.id]
    );
    const current = Number(last.rows[0]?.reboot_count ?? 0);

    const existing = await pool.query('SELECT id FROM device_config WHERE device_id = $1', [dev.id]);
    if (existing.rows.length === 0) {
      const config_id = uuidv4();
      await pool.query(
        `INSERT INTO device_config (id, device_id, reboot_count_offset) VALUES ($1, $2, $3)`,
        [config_id, dev.id, current]
      );
    } else {
      await pool.query(
        `UPDATE device_config SET reboot_count_offset = $1, updated_at = CURRENT_TIMESTAMP WHERE device_id = $2`,
        [current, dev.id]
      );
    }

    res.json({ status: 'OK', device_code, reboot_count_offset: current });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// --- Dispositivos (multi-dispositivo) ---
app.get('/api/devices', async (req, res) => {
  try {
    if (REQUIRE_USER_LOGIN && !hasValidAdminKey(req)) {
      if (!req.user?.id) return res.status(401).json({ error: 'No autenticado' });
      const result = await pool.query(
        `SELECT
           d.device_code,
           d.name,
           d.location,
           d.created_at,
           (MAX(EXTRACT(EPOCH FROM (sd.created_at AT TIME ZONE current_setting('TIMEZONE')))) * 1000) AS last_seen_ms
         FROM user_devices ud
         JOIN devices d ON d.id = ud.device_id
         LEFT JOIN sensor_data sd ON sd.device_id = d.id
         WHERE ud.user_id = $1
         GROUP BY d.id
         ORDER BY d.created_at ASC`,
        [req.user.id]
      );
      return res.json(
        result.rows.map((r) => {
          const out = { ...r };
          const d = epochMsToDate(r.last_seen_ms);
          out.last_seen = d ? d.toISOString() : null;
          out.last_seen_madrid = d ? fmtEsLabel.format(d) : null;
          return out;
        })
      );
    }

    const result = await pool.query(
      `SELECT
         d.device_code,
         d.name,
         d.location,
         d.created_at,
         (MAX(EXTRACT(EPOCH FROM (sd.created_at AT TIME ZONE current_setting('TIMEZONE')))) * 1000) AS last_seen_ms
       FROM devices d
       LEFT JOIN sensor_data sd ON sd.device_id = d.id
       GROUP BY d.id
       ORDER BY d.created_at ASC`
    );
    res.json(
      result.rows.map((r) => {
        const out = { ...r };
        const d = epochMsToDate(r.last_seen_ms);
        out.last_seen = d ? d.toISOString() : null;
        out.last_seen_madrid = d ? fmtEsLabel.format(d) : null;
        return out;
      })
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// --- Canales (sensores/válvulas múltiples) ---
app.get('/api/channels/:device_code', async (req, res) => {
  try {
    const { device_code } = req.params;
    const dev = await requireUserDevice(req, res, device_code);
    if (!dev) return;
    await ensureDefaultChannels(dev.id);

    const r = await pool.query(
      `SELECT id, kind, channel_index, name, created_at
       FROM device_channels
       WHERE device_id = $1 AND deleted_at IS NULL
       ORDER BY kind ASC, channel_index ASC`,
      [dev.id]
    );
    res.json({ device_code, channels: r.rows });
  } catch (e) {
    if (/column .*deleted_at.* does not exist|column .* does not exist/i.test(String(e.message))) {
      try {
        await initDB();
        const { device_code } = req.params;
        const dev = await requireUserDevice(req, res, device_code);
        if (!dev) return;
        await ensureDefaultChannels(dev.id);
        const r = await pool.query(
          `SELECT id, kind, channel_index, name, created_at
           FROM device_channels
           WHERE device_id = $1 AND deleted_at IS NULL
           ORDER BY kind ASC, channel_index ASC`,
          [dev.id]
        );
        return res.json({ device_code, channels: r.rows });
      } catch (ie) {
        console.warn('initDB retry failed:', ie.message);
      }
    }
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Último valor/estado por canal (para UI multi-zona)
app.get('/api/channels/:device_code/latest', async (req, res) => {
  try {
    const { device_code } = req.params;
    const dev = await requireUserDevice(req, res, device_code);
    if (!dev) return;
    await ensureDefaultChannels(dev.id);

    const serverNow = new Date();
    const nowMs = serverNow.getTime();

    const r = await pool.query(
      `SELECT
         dc.id,
         dc.kind,
         dc.channel_index,
         dc.name,
         s.ts AS ts_raw,
         (s.ts AT TIME ZONE current_setting('TIMEZONE')) AS ts,
         s.value,
         s.state
       FROM device_channels dc
       LEFT JOIN LATERAL (
         SELECT ts, value, state
         FROM channel_samples
         WHERE channel_id = dc.id
         ORDER BY ts DESC
         LIMIT 1
       ) s ON TRUE
       WHERE dc.device_id = $1 AND dc.deleted_at IS NULL
       ORDER BY dc.kind ASC, dc.channel_index ASC`,
      [dev.id]
    );

    const out = r.rows.map((row) => {
      const ts = (() => {
        const raw = row.ts;
        if (!raw) return null;
        const d = raw instanceof Date ? raw : new Date(raw);
        return Number.isNaN(d.getTime()) ? null : d;
      })();
      return {
        id: row.id,
        kind: row.kind,
        channel_index: row.channel_index,
        name: row.name,
        latest: {
          ts_raw: row.ts_raw ?? null,
          ts: ts ? ts.toISOString() : null,
          ts_madrid: ts ? fmtEsLabel.format(ts) : null,
          age_minutes: ts ? Math.round(Math.max(0, nowMs - ts.getTime()) / 60000) : null,
          value: row.value ?? null,
          state: row.state ?? null
        }
      };
    });

    res.json({
      device_code,
      server_now: serverNow.toISOString(),
      server_now_madrid: fmtEsLabel.format(serverNow),
      channels: out
    });
  } catch (e) {
    if (/column .*deleted_at.* does not exist|column .* does not exist/i.test(String(e.message))) {
      try {
        await initDB();
        const { device_code } = req.params;
        const dev = await requireUserDevice(req, res, device_code);
        if (!dev) return;
        await ensureDefaultChannels(dev.id);

        const serverNow = new Date();
        const nowMs = serverNow.getTime();
        const r = await pool.query(
          `SELECT
             dc.id,
             dc.kind,
             dc.channel_index,
             dc.name,
             s.ts AS ts_raw,
             (s.ts AT TIME ZONE current_setting('TIMEZONE')) AS ts,
             s.value,
             s.state
           FROM device_channels dc
           LEFT JOIN LATERAL (
             SELECT ts, value, state
             FROM channel_samples
             WHERE channel_id = dc.id
             ORDER BY ts DESC
             LIMIT 1
           ) s ON TRUE
           WHERE dc.device_id = $1 AND dc.deleted_at IS NULL
           ORDER BY dc.kind ASC, dc.channel_index ASC`,
          [dev.id]
        );
        const out = r.rows.map((row) => {
          const ts = (() => {
            const raw = row.ts;
            if (!raw) return null;
            const d = raw instanceof Date ? raw : new Date(raw);
            return Number.isNaN(d.getTime()) ? null : d;
          })();
          return {
            id: row.id,
            kind: row.kind,
            channel_index: row.channel_index,
            name: row.name,
            latest: {
              ts_raw: row.ts_raw ?? null,
              ts: ts ? ts.toISOString() : null,
              ts_madrid: ts ? fmtEsLabel.format(ts) : null,
              age_minutes: ts ? Math.round(Math.max(0, nowMs - ts.getTime()) / 60000) : null,
              value: row.value ?? null,
              state: row.state ?? null
            }
          };
        });
        return res.json({
          device_code,
          server_now: serverNow.toISOString(),
          server_now_madrid: fmtEsLabel.format(serverNow),
          channels: out
        });
      } catch (ie) {
        console.warn('initDB retry failed:', ie.message);
      }
    }
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/channels/:device_code', async (req, res) => {
  try {
    const { device_code } = req.params;
    const { kind, name } = req.body || {};

    const dev = await requireUserDevice(req, res, device_code);
    if (!dev) return;

    const ok = await enforceDeviceTokenIfRequired(req, res, device_code);
    if (!ok) return;

    const allowedKinds = new Set([
      'soil_sensor',
      'valve',
      'temperature_air',
      'temperature_soil',
      'humidity_air',
      'ph_soil',
      'ec_soil'
    ]);
    if (!allowedKinds.has(kind)) {
      return res.status(400).json({ error: 'kind inválido' });
    }

    await ensureDefaultChannels(dev.id);
    // Si hay un índice borrado, lo “revivimos” para no ir creciendo (2,3,4...)
    const reuseR = await pool.query(
      `SELECT id, channel_index
       FROM device_channels
       WHERE device_id = $1 AND kind = $2 AND deleted_at IS NOT NULL
       ORDER BY channel_index ASC
       LIMIT 1`,
      [dev.id, kind]
    );

    if (reuseR.rows.length > 0) {
      const id = reuseR.rows[0].id;
      const channel_index = Number(reuseR.rows[0].channel_index);
      const finalName = String(name || (kind === 'valve' ? `Válvula ${channel_index}` : `Sensor ${channel_index}`)).slice(0, 80);
      await pool.query(
        `UPDATE device_channels SET name = $1, deleted_at = NULL WHERE id = $2 AND device_id = $3`,
        [finalName, id, dev.id]
      );
      return res.json({ status: 'OK', device_code, channel: { id, kind, channel_index, name: finalName } });
    }

    const nextIdxR = await pool.query(
      `SELECT COALESCE(MAX(channel_index), 0) + 1 AS next
       FROM device_channels
       WHERE device_id = $1 AND kind = $2 AND deleted_at IS NULL`,
      [dev.id, kind]
    );
    const channel_index = Number(nextIdxR.rows[0]?.next || 1);
    const finalName = String(name || (kind === 'valve' ? `Válvula ${channel_index}` : `Sensor ${channel_index}`)).slice(0, 80);

    const id = uuidv4();
    await pool.query(
      `INSERT INTO device_channels (id, device_id, kind, channel_index, name)
       VALUES ($1, $2, $3, $4, $5)`,
      [id, dev.id, kind, channel_index, finalName]
    );
    res.json({ status: 'OK', device_code, channel: { id, kind, channel_index, name: finalName } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.patch('/api/channels/:device_code/:channel_id', async (req, res) => {
  try {
    const { device_code, channel_id } = req.params;
    const { name } = req.body || {};

    const dev = await requireUserDevice(req, res, device_code);
    if (!dev) return;

    const ok = await enforceDeviceTokenIfRequired(req, res, device_code);
    if (!ok) return;

    const finalName = String(name || '').trim();
    if (!finalName) return res.status(400).json({ error: 'name requerido' });

    const owned = await pool.query(
      `SELECT id FROM device_channels WHERE id = $1 AND device_id = $2 AND deleted_at IS NULL`,
      [channel_id, dev.id]
    );
    if (owned.rows.length === 0) return res.status(404).json({ error: 'Canal no encontrado' });

    await pool.query(
      `UPDATE device_channels SET name = $1 WHERE id = $2`,
      [finalName.slice(0, 80), channel_id]
    );
    res.json({ status: 'OK', device_code, channel_id, name: finalName.slice(0, 80) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/channels/:device_code/:channel_id', async (req, res) => {
  try {
    const { device_code, channel_id } = req.params;

    const dev = await requireUserDevice(req, res, device_code);
    if (!dev) return;

    const ok = await enforceDeviceTokenIfRequired(req, res, device_code);
    if (!ok) return;

    const ch = await pool.query(
      `SELECT id, kind, channel_index
       FROM device_channels
       WHERE id = $1 AND device_id = $2`,
      [channel_id, dev.id]
    );
    if (ch.rows.length === 0) return res.status(404).json({ error: 'Canal no encontrado' });

    const { kind, channel_index } = ch.rows[0];
    // Seguridad UX: no permitir borrar los canales base (1) para no romper el panel/ESP32.
    if ((kind === 'soil_sensor' || kind === 'valve') && Number(channel_index) === 1) {
      return res.status(400).json({ error: 'No se puede eliminar el canal 1 por defecto' });
    }

    await pool.query('DELETE FROM channel_samples WHERE channel_id = $1', [channel_id]);
    await pool.query(
      'UPDATE device_channels SET deleted_at = NOW() WHERE id = $1 AND device_id = $2',
      [channel_id, dev.id]
    );
    res.json({ status: 'OK', device_code, channel_id });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/devices/:device_code', async (req, res) => {
  try {
    const { device_code } = req.params;
    if (!requireUser(req, res)) return;
    const dev = await getDeviceByCode(device_code);
    if (!dev) return res.status(404).json({ error: 'Dispositivo no encontrado' });

    await pool.query(
      'DELETE FROM user_devices WHERE user_id = $1 AND device_id = $2',
      [req.user.id, dev.id]
    );
    res.json({ status: 'OK', device_code });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Histórico por canal
app.get('/api/channel/history/:device_code/:channel_id', async (req, res) => {
  try {
    const { device_code, channel_id } = req.params;
    const step = String(req.query.step || 'raw'); // raw | 1m | 1h | 1d
    const from = parseDateParam(req.query.from) || new Date(Date.now() - 24 * 3600 * 1000);
    const to = parseDateParam(req.query.to) || new Date();
    const limit = Math.min(Number(req.query.limit || 5000), 20000);

    const dev = await requireUserDevice(req, res, device_code);
    if (!dev) return;

    const ch = await pool.query(
      `SELECT id, kind, channel_index, name FROM device_channels WHERE id = $1 AND device_id = $2`,
      [channel_id, dev.id]
    );
    if (ch.rows.length === 0) return res.status(404).json({ error: 'Canal no encontrado' });

    if (step === 'raw') {
      const r = await pool.query(
        `SELECT (ts AT TIME ZONE current_setting('TIMEZONE')) AS ts, value, state
         FROM channel_samples
         WHERE channel_id = $1 AND ts >= $2 AND ts < $3
         ORDER BY ts DESC
         LIMIT $4`,
        [channel_id, from, to, limit]
      );
      return res.json({
        device_code,
        channel: ch.rows[0],
        step,
        range: { from: from.toISOString(), to: to.toISOString() },
        server_now: new Date().toISOString(),
        // Importante: en RAW hay muchos puntos; con LIMIT queremos los más recientes.
        // Devolvemos en orden ascendente para que el frontend pinte correctamente.
        rows: r.rows.reverse().map(enrichRowWithMadridTs)
      });
    }

    // Buckets alineados a Europe/Madrid para que DÍA/MES/AÑO cuadren con el frontend.
    // Nota: (ts AT TIME ZONE 'Europe/Madrid') devuelve timestamp local; luego AT TIME ZONE convierte a timestamptz (UTC).
    let trunc;
    if (step === '1m') trunc = "date_trunc('minute', ts AT TIME ZONE 'Europe/Madrid') AT TIME ZONE 'Europe/Madrid'";
    else if (step === '1h') trunc = "date_trunc('hour', ts AT TIME ZONE 'Europe/Madrid') AT TIME ZONE 'Europe/Madrid'";
    else if (step === '1d') trunc = "date_trunc('day', ts AT TIME ZONE 'Europe/Madrid') AT TIME ZONE 'Europe/Madrid'";
    else return res.status(400).json({ error: 'step inválido (raw|1m|1h|1d)' });

    const r = await pool.query(
      `SELECT
         ${trunc} AS ts,
         AVG(value) AS value,
         MAX(COALESCE(state, 0))::int AS state
       FROM channel_samples
       WHERE channel_id = $1 AND ts >= $2 AND ts < $3
       GROUP BY ts
       ORDER BY ts ASC
       LIMIT $4`,
      [channel_id, from, to, limit]
    );

    res.json({
      device_code,
      channel: ch.rows[0],
      step,
      range: { from: from.toISOString(), to: to.toISOString() },
      server_now: new Date().toISOString(),
      rows: r.rows.map(enrichRowWithMadridTs)
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/devices/:device_code', async (req, res) => {
  try {
    const { device_code } = req.params;
    const { name, location } = req.body || {};

    const dev = await requireUserDevice(req, res, device_code);
    if (!dev) return;

    const ok = await enforceDeviceTokenIfRequired(req, res, device_code);
    if (!ok) return;

    await pool.query(
      `UPDATE devices
       SET name = COALESCE($1, name), location = COALESCE($2, location), updated_at = CURRENT_TIMESTAMP
       WHERE device_code = $3`,
      [name || null, location || null, device_code]
    );
    const updated = await getDeviceByCode(device_code);
    res.json({ status: 'OK', device: { device_code: updated.device_code, name: updated.name, location: updated.location } });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// Recuperar/rotar token SOLO con ADMIN_KEY (seguridad)
app.get('/api/admin/device-token/:device_code', async (req, res) => {
  try {
    const adminKey = process.env.ADMIN_KEY;
    if (!adminKey) return res.status(403).json({ error: 'ADMIN_KEY no configurada' });
    if (req.get('x-admin-key') !== adminKey) return res.status(401).json({ error: 'x-admin-key inválida' });

    const { device_code } = req.params;
    const dev = await getDeviceByCode(device_code);
    if (!dev) return res.status(404).json({ error: 'Dispositivo no encontrado' });

    const rotate = String(req.query.rotate || 'false').toLowerCase() === 'true';
    if (rotate) {
      const newToken = uuidv4();
      await pool.query('UPDATE devices SET api_token = $1, updated_at = CURRENT_TIMESTAMP WHERE device_code = $2', [newToken, device_code]);
      return res.json({ device_code, api_token: newToken, rotated: true });
    }

    res.json({ device_code, api_token: dev.api_token, rotated: false });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// --- SSE: tiempo real (sin polling) ---
app.get('/api/sse/:device_code', async (req, res) => {
  const { device_code } = req.params;
  const dev = await requireUserDevice(req, res, device_code);
  if (!dev) return;
  res.status(200);
  // Nota: en HTTP/2 NO se pueden enviar headers tipo "Connection".
  // Railway puede servir HTTP/2 al navegador; si enviamos ese header, Chrome lanza
  // net::ERR_HTTP2_PROTOCOL_ERROR aunque el status sea 200.
  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  // Evitar buffering en proxies (nginx/CDN) para que los eventos lleguen en streaming.
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders?.();

  const set = sseClientsByDevice.get(device_code) || new Set();
  set.add(res);
  sseClientsByDevice.set(device_code, set);

  // Comentario inicial para abrir el stream inmediatamente
  res.write(`:ok\n\n`);
  res.write(`event: hello\ndata: ${JSON.stringify({ device_code, ts: new Date().toISOString() })}\n\n`);
  const keepAlive = setInterval(() => {
    try {
      res.write(`event: ping\ndata: {}\n\n`);
    } catch {
      // ignore
    }
  }, 25000);

  req.on('close', () => {
    clearInterval(keepAlive);
    const s = sseClientsByDevice.get(device_code);
    if (s) {
      s.delete(res);
      if (s.size === 0) sseClientsByDevice.delete(device_code);
    }
  });
});

async function computeValveOnSeconds(device_id, fromTs, toTs) {
  const r = await pool.query(
    `WITH ordered AS (
       SELECT created_at,
              valve_state,
              LEAD(created_at) OVER (ORDER BY created_at) AS next_at
       FROM sensor_data
       WHERE device_id = $1
         AND created_at >= $2
         AND created_at <= $3
     )
     SELECT COALESCE(SUM(
       EXTRACT(EPOCH FROM (COALESCE(next_at, created_at) - created_at))
       * (CASE WHEN valve_state = 'ON' THEN 1 ELSE 0 END)
     ), 0) AS on_seconds
     FROM ordered`,
    [device_id, fromTs, toTs]
  );
  return Number(r.rows[0]?.on_seconds || 0);
}

async function computeIrrigationCount(device_id, fromTs, toTs) {
  const r = await pool.query(
    `WITH ordered AS (
       SELECT created_at,
              valve_state,
              LAG(valve_state) OVER (ORDER BY created_at) AS prev_state
       FROM sensor_data
       WHERE device_id = $1
         AND created_at >= $2
         AND created_at <= $3
     )
     SELECT COALESCE(SUM(CASE WHEN valve_state = 'ON' AND (prev_state IS DISTINCT FROM 'ON') THEN 1 ELSE 0 END), 0) AS starts
     FROM ordered`,
    [device_id, fromTs, toTs]
  );
  return Number(r.rows[0]?.starts || 0);
}

// Nuevo: estadísticas día/mes/año (serie + overall)
app.get('/api/stats/:device_code', async (req, res) => {
  try {
    const { device_code } = req.params;
    const period = String(req.query.period || 'day');

    const dev = await requireUserDevice(req, res, device_code);
    if (!dev) return;
    const device_id = dev.id;

    let bucket;
    let fromExpr;
    let toExpr = 'NOW()';
    if (period === 'day') {
      bucket = "date_trunc('hour', sd.created_at)";
      fromExpr = "NOW() - INTERVAL '24 hours'";
    } else if (period === 'month') {
      bucket = "date_trunc('day', sd.created_at)";
      fromExpr = "date_trunc('month', NOW())";
    } else if (period === 'year') {
      bucket = "date_trunc('month', sd.created_at)";
      fromExpr = "date_trunc('year', NOW())";
    } else {
      return res.status(400).json({ error: 'period inválido (day|month|year)' });
    }

    const overall = await pool.query(
      `SELECT
         COUNT(*)::int AS total_readings,
         AVG(temperature) AS temp_avg,
         MAX(temperature) AS temp_max,
         MIN(temperature) AS temp_min,
         AVG(humidity) AS hum_avg,
         MAX(humidity) AS hum_max,
         MIN(humidity) AS hum_min
       FROM sensor_data
       WHERE device_id = $1
         AND created_at >= ${fromExpr}
         AND created_at <= ${toExpr}`,
      [device_id]
    );

    const series = await pool.query(
      `SELECT
         ${bucket} AS ts,
         AVG(sd.temperature) AS temperature,
         AVG(sd.humidity) AS humidity,
         AVG(sd.voltage) AS voltage,
         MAX(CASE WHEN sd.valve_state = 'ON' THEN 1 ELSE 0 END)::int AS valve_on
       FROM sensor_data sd
       WHERE sd.device_id = $1
         AND sd.created_at >= ${fromExpr}
         AND sd.created_at <= ${toExpr}
       GROUP BY ts
       ORDER BY ts ASC`,
      [device_id]
    );

    const fromTs = await pool.query(`SELECT ${fromExpr} AS t`);
    const toTsQ = await pool.query(`SELECT ${toExpr} AS t`);
    const fromTsVal = fromTs.rows[0].t;
    const toTsVal = toTsQ.rows[0].t;

    const valve_on_seconds = await computeValveOnSeconds(device_id, fromTsVal, toTsVal);
    const irrigations = await computeIrrigationCount(device_id, fromTsVal, toTsVal);

    res.json({
      device_code,
      period,
      range: { from: new Date(fromTsVal).toISOString(), to: new Date(toTsVal).toISOString() },
      overall: { ...overall.rows[0], valve_on_seconds, irrigations },
      series: series.rows
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// Compatibilidad: stats antiguas 24h
app.get('/api/sensor/stats/:device_code', async (req, res) => {
  try {
    const { device_code } = req.params;

    const dev = await requireUserDevice(req, res, device_code);
    if (!dev) return;
    const result = await pool.query(
      `SELECT 
        COUNT(*) as total_readings,
        AVG(temperature) as temp_avg,
        MAX(temperature) as temp_max,
        MIN(temperature) as temp_min,
        AVG(humidity) as hum_avg
       FROM sensor_data sd
       JOIN devices d ON sd.device_id = d.id
       WHERE d.device_code = $1
       AND sd.created_at >= NOW() - INTERVAL '24 hours'`,
      [device_code]
    );

    if (result.rows.length === 0) {
      return res.json({ total_readings: 0 });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

function parseDateParam(v) {
  if (!v) return null;
  const d = new Date(String(v));
  if (Number.isNaN(d.getTime())) return null;
  return d;
}

// Nuevo histórico real (from/to/step)
app.get('/api/sensor/history/:device_code', async (req, res) => {
  try {
    const { device_code } = req.params;
    const step = String(req.query.step || 'raw'); // raw | 1m | 1h | 1d
    const from = parseDateParam(req.query.from) || new Date(Date.now() - 24 * 3600 * 1000);
    const to = parseDateParam(req.query.to) || new Date();
    const limit = Math.min(Number(req.query.limit || 5000), 20000);

    const dev = await requireUserDevice(req, res, device_code);
    if (!dev) return;
    const device_id = dev.id;

    if (step === 'raw') {
      const result = await pool.query(
        `SELECT
           (created_at AT TIME ZONE current_setting('TIMEZONE')) AS ts,
           temperature, humidity, valve_state, voltage, wifi_rssi, uptime_s,
           reboot_count,
           COALESCE(dc.reboot_count_offset, 0) AS reboot_count_offset,
           GREATEST(0, COALESCE(reboot_count, 0) - COALESCE(dc.reboot_count_offset, 0))::int AS reboot_count_display
         FROM sensor_data sd
         LEFT JOIN device_config dc ON dc.device_id = sd.device_id
         WHERE sd.device_id = $1 AND sd.created_at >= $2 AND sd.created_at < $3
         ORDER BY sd.created_at DESC
         LIMIT $4`,
        [device_id, from, to, limit]
      );
      return res.json({
        device_code,
        step,
        range: { from: from.toISOString(), to: to.toISOString() },
        server_now: new Date().toISOString(),
        // En RAW, el LIMIT debe devolver los puntos más recientes.
        rows: result.rows.reverse().map(enrichRowWithMadridTs)
      });
    }

    // Buckets alineados a Europe/Madrid para que los días/meses cuadren con el frontend.
    let trunc;
    if (step === '1m') trunc = "date_trunc('minute', created_at AT TIME ZONE 'Europe/Madrid') AT TIME ZONE 'Europe/Madrid'";
    else if (step === '1h') trunc = "date_trunc('hour', created_at AT TIME ZONE 'Europe/Madrid') AT TIME ZONE 'Europe/Madrid'";
    else if (step === '1d') trunc = "date_trunc('day', created_at AT TIME ZONE 'Europe/Madrid') AT TIME ZONE 'Europe/Madrid'";
    else return res.status(400).json({ error: 'step inválido (raw|1m|1h|1d)' });

    const result = await pool.query(
      `SELECT
         ${trunc} AS ts,
         COUNT(*)::int AS cnt,
         AVG(temperature) AS temperature,
         AVG(humidity) AS humidity,
         AVG(voltage) AS voltage,
         AVG(wifi_rssi) AS wifi_rssi,
         MAX(CASE WHEN valve_state = 'ON' THEN 1 ELSE 0 END)::int AS valve_on
       FROM sensor_data
       WHERE device_id = $1 AND created_at >= $2 AND created_at < $3
       GROUP BY ts
       ORDER BY ts ASC
       LIMIT $4`,
      [device_id, from, to, limit]
    );

    res.json({
      device_code,
      step,
      range: { from: from.toISOString(), to: to.toISOString() },
      server_now: new Date().toISOString(),
      rows: result.rows.map(enrichRowWithMadridTs)
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// Export CSV/JSON
app.get('/api/sensor/export/:device_code', async (req, res) => {
  try {
    const { device_code } = req.params;
    const format = String(req.query.format || 'csv');
    const from = parseDateParam(req.query.from) || new Date(Date.now() - 24 * 3600 * 1000);
    const to = parseDateParam(req.query.to) || new Date();
    const limit = Math.min(Number(req.query.limit || 20000), 50000);

    const dev = await requireUserDevice(req, res, device_code);
    if (!dev) return;
    const device_id = dev.id;

    const q = await pool.query(
      `SELECT (created_at AT TIME ZONE current_setting('TIMEZONE')) AS ts, temperature, humidity, valve_state, voltage, wifi_rssi, uptime_s, reboot_count
       FROM sensor_data
       WHERE device_id = $1 AND created_at >= $2 AND created_at <= $3
       ORDER BY created_at ASC
       LIMIT $4`,
      [device_id, from, to, limit]
    );

    if (format === 'json') {
      return res.json({ device_code, range: { from: from.toISOString(), to: to.toISOString() }, rows: q.rows });
    }

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${device_code}_${from.toISOString()}_${to.toISOString()}.csv"`);
    res.write('ts,temperature,humidity,valve_state,voltage,wifi_rssi,uptime_s,reboot_count\n');
    for (const r of q.rows) {
      const line = [
        new Date(r.ts).toISOString(),
        r.temperature ?? '',
        r.humidity ?? '',
        r.valve_state ?? '',
        r.voltage ?? '',
        r.wifi_rssi ?? '',
        r.uptime_s ?? '',
        r.reboot_count ?? ''
      ].join(',');
      res.write(line + '\n');
    }
    res.end();
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// --- Alertas (en ingest + job) ---
async function getDeviceConfig(device_id) {
  const r = await pool.query('SELECT * FROM device_config WHERE device_id = $1', [device_id]);
  return r.rows[0] || null;
}

async function triggerAlert({ device_code, device_id, kind, message, cfg }) {
  const cooldown = 30; // min, para evitar spam
  if (await wasAlertRecentlySent(device_id, kind, cooldown)) return;

  await logAlertEvent(device_id, kind, message);
  await markAlertState(device_id, kind);

  const payload = { device_code, kind, message, ts: new Date().toISOString() };
  await sendWebhook(cfg?.notify_webhook_url, payload);
  await sendTelegram(cfg?.notify_telegram_chat_id, `[${device_code}] ${kind}: ${message}`);

  sseBroadcast(device_code, 'alert', payload);
}

async function evaluateAlertsOnIngest({ device_code, device_id, humidity, valve_state, voltage }) {
  const cfg = await getDeviceConfig(device_id);
  if (!cfg) return;

  const threshold = Number(cfg.humidity_low_threshold ?? 50);

  // Humedad baja X minutos (sostenida)
  const lowMin = Number(cfg.alert_humidity_low_minutes || 0);
  if (lowMin > 0 && typeof humidity === 'number') {
    const intervalStr = `${lowMin} minutes`;
    const r = await pool.query(
      `SELECT MIN(humidity) AS min_h, MAX(humidity) AS max_h
       FROM sensor_data
       WHERE device_id = $1 AND created_at >= NOW() - ($2::interval)`,
      [device_id, intervalStr]
    );
    const maxH = r.rows[0]?.max_h == null ? null : Number(r.rows[0].max_h);
    if (maxH != null && maxH < threshold) {
      await triggerAlert({
        device_code,
        device_id,
        kind: 'HUMIDITY_LOW',
        message: `Humedad < ${threshold}% durante ~${lowMin} min`,
        cfg
      });
    }
  }

  // Válvula ON demasiado tiempo
  const valveMax = Number(cfg.alert_valve_on_max_minutes || 0);
  if (valveMax > 0 && String(valve_state || '').toUpperCase() === 'ON') {
    const recent = await pool.query(
      `SELECT created_at, valve_state FROM sensor_data WHERE device_id = $1 ORDER BY created_at DESC LIMIT 5000`,
      [device_id]
    );
    const rows = recent.rows;
    if (rows.length > 0 && String(rows[0].valve_state || '').toUpperCase() === 'ON') {
      let onSince = rows[rows.length - 1].created_at;
      for (const row of rows) {
        if (String(row.valve_state || '').toUpperCase() !== 'ON') {
          onSince = row.created_at;
          break;
        }
      }
      const minutesOn = (Date.now() - new Date(onSince).getTime()) / 60000;
      if (minutesOn >= valveMax) {
        await triggerAlert({
          device_code,
          device_id,
          kind: 'VALVE_ON_TOO_LONG',
          message: `Válvula ON ~${Math.round(minutesOn)} min (límite ${valveMax} min)`,
          cfg
        });
      }
    }
  }

  // Voltaje fuera de rango
  const vmin = cfg.alert_voltage_min == null ? null : Number(cfg.alert_voltage_min);
  const vmax = cfg.alert_voltage_max == null ? null : Number(cfg.alert_voltage_max);
  if (typeof voltage === 'number' && (vmin != null || vmax != null)) {
    if (vmin != null && voltage < vmin) {
      await triggerAlert({ device_code, device_id, kind: 'VOLTAGE_LOW', message: `Voltaje ${voltage}V < ${vmin}V`, cfg });
    }
    if (vmax != null && voltage > vmax) {
      await triggerAlert({ device_code, device_id, kind: 'VOLTAGE_HIGH', message: `Voltaje ${voltage}V > ${vmax}V`, cfg });
    }
  }
}

// Job: sensor muerto (sin datos > N min)
async function checkDeadSensors() {
  try {
    const r = await pool.query(
      `SELECT
         d.id AS device_id,
         d.device_code,
         COALESCE(dc.alert_sensor_dead_minutes, 0) AS dead_min,
         dc.notify_webhook_url,
         dc.notify_telegram_chat_id,
         MAX(sd.created_at) AS last_seen
       FROM devices d
       LEFT JOIN device_config dc ON dc.device_id = d.id
       LEFT JOIN sensor_data sd ON sd.device_id = d.id
       GROUP BY d.id, dc.alert_sensor_dead_minutes, dc.notify_webhook_url, dc.notify_telegram_chat_id`
    );

    for (const row of r.rows) {
      const deadMin = Number(row.dead_min || 0);
      if (deadMin <= 0) continue;
      const last = row.last_seen ? new Date(row.last_seen).getTime() : 0;
      const ageMin = last ? (Date.now() - last) / 60000 : Infinity;
      if (ageMin >= deadMin) {
        await triggerAlert({
          device_code: row.device_code,
          device_id: row.device_id,
          kind: 'SENSOR_DEAD',
          message: `Sin datos desde hace ~${Math.round(ageMin)} min`,
          cfg: row
        });
      }
    }
  } catch (e) {
    console.warn('checkDeadSensors error:', e.message);
  }
}

if (process.env.DATABASE_URL || process.env.AUTO_DB_INIT === 'true') {
  setInterval(checkDeadSensors, 60 * 1000);
}

// Obtener configuración del dispositivo
app.get('/api/config/:device_code', async (req, res) => {
  const { device_code } = req.params;

  // Si no hay DB configurada localmente, devolver configuración por defecto para evitar 500 en dev
  if (!process.env.DATABASE_URL) {
    console.warn('DATABASE_URL not set — returning default config for', device_code);
    return res.json({
      device_id: null,
      humidity_low_threshold: '50.00',
      humidity_low_color: 'Rojo',
      humidity_good_color: 'Verde',
      led_mode: 'auto',
      led_manual_color: 'Off',
      wet_v: null,
      dry_v: null,
      alert_humidity_low_minutes: 0,
      alert_valve_on_max_minutes: 0,
      alert_sensor_dead_minutes: 0,
      alert_voltage_min: null,
      alert_voltage_max: null,
      notify_webhook_url: null,
      notify_telegram_chat_id: null,
      zones: [],
      updated_at: new Date().toISOString()
    });
  }

  if (REQUIRE_USER_LOGIN && !hasValidAdminKey(req)) {
    const dev = await requireDeviceForConfig(req, res, device_code);
    if (!dev) return;
  }

  try {
    const result = await pool.query(
      `SELECT dc.* FROM device_config dc
       JOIN devices d ON dc.device_id = d.id
       WHERE d.device_code = $1`,
      [device_code]
    );

    if (result.rows.length === 0) {
      // Si el dispositivo existe pero no tiene config, devolver defaults en lugar de 404 para UX robusta
      const dev = await pool.query('SELECT id FROM devices WHERE device_code = $1', [device_code]);
      if (dev.rows.length === 0) return res.status(404).json({ error: 'Dispositivo no encontrado' });

      return res.json({
        device_id: dev.rows[0].id,
        humidity_low_threshold: '50.00',
        humidity_low_color: 'Rojo',
        humidity_good_color: 'Verde',
        led_mode: 'auto',
        led_manual_color: 'Off',
        wet_v: null,
        dry_v: null,
        alert_humidity_low_minutes: 0,
        alert_valve_on_max_minutes: 0,
        alert_sensor_dead_minutes: 0,
        alert_voltage_min: null,
        alert_voltage_max: null,
        notify_webhook_url: null,
        notify_telegram_chat_id: null,
        zones: [],
        updated_at: new Date().toISOString()
      });
    }

    {
      const row = { ...result.rows[0] };
      let zones = [];
      if (Array.isArray(row.zones_json)) {
        zones = row.zones_json;
      } else if (typeof row.zones_json === 'string') {
        try {
          const parsed = JSON.parse(row.zones_json);
          if (Array.isArray(parsed)) zones = parsed;
        } catch {
          zones = [];
        }
      }
      row.zones = zones;
      res.json(row);
    }
  } catch (error) {
    console.error('GET /api/config error:', error.message);

    // Si hay un error de esquema (columna faltante), intentar migración y reintentar una vez
    if (/column .* does not exist/i.test(error.message)) {
      try {
        console.warn('Detected missing column — attempting safe migration');
        await pool.query(`ALTER TABLE device_config ADD COLUMN IF NOT EXISTS led_mode VARCHAR(10) DEFAULT 'auto'`);
        await pool.query(`ALTER TABLE device_config ADD COLUMN IF NOT EXISTS led_manual_color VARCHAR(20) DEFAULT 'Off'`);
        const retry = await pool.query(
          `SELECT dc.* FROM device_config dc JOIN devices d ON dc.device_id = d.id WHERE d.device_code = $1`,
          [device_code]
        );
        if (retry.rows.length > 0) return res.json(retry.rows[0]);
      } catch (mErr) {
        console.error('Migration attempt failed:', mErr.message);
      }
    }

    // Fallback seguro: devolver configuración por defecto en vez de 500 para que UI/ESP no rompan
    return res.json({
      device_id: null,
      humidity_low_threshold: '50.00',
      humidity_low_color: 'Rojo',
      humidity_good_color: 'Verde',
      led_mode: 'auto',
      led_manual_color: 'Off',
      wet_v: null,
      dry_v: null,
      alert_humidity_low_minutes: 0,
      alert_valve_on_max_minutes: 0,
      alert_sensor_dead_minutes: 0,
      alert_voltage_min: null,
      alert_voltage_max: null,
      notify_webhook_url: null,
      notify_telegram_chat_id: null,
      zones: [],
      updated_at: new Date().toISOString()
    });
  }
});

// Últimas alertas
app.get('/api/alerts/:device_code', async (req, res) => {
  try {
    const { device_code } = req.params;
    const limit = Math.min(Number(req.query.limit || 20), 200);

    const dev = await requireUserDevice(req, res, device_code);
    if (!dev) return;

    const r = await pool.query(
      `SELECT ae.kind, ae.message,
              (EXTRACT(EPOCH FROM (ae.created_at AT TIME ZONE current_setting('TIMEZONE'))) * 1000) AS created_at_ms
       FROM alert_events ae
       JOIN devices d ON ae.device_id = d.id
       WHERE d.device_code = $1
       ORDER BY ae.created_at DESC
       LIMIT $2`,
      [device_code, limit]
    );

    const rows = r.rows.map((row) => {
      const d = epochMsToDate(row.created_at_ms);
      return {
        kind: row.kind,
        message: row.message,
        created_at: d ? d.toISOString() : null,
        created_at_madrid: d ? fmtEsLabel.format(d) : null
      };
    });

    res.json({ device_code, rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Diagnóstico de hora/último dato (útil para detectar “dato viejo” vs “desfase horario”)
app.get('/api/debug/time/:device_code', async (req, res) => {
  try {
    const { device_code } = req.params;
    const dev = await getDeviceByCode(device_code);
    if (!dev) return res.status(404).json({ error: 'Dispositivo no encontrado' });

    // Auth: admin, usuario dueño, o token del dispositivo
    if (!hasValidAdminKey(req)) {
      if (REQUIRE_USER_LOGIN && req.user?.id) {
        const owned = await pool.query(
          `SELECT 1 FROM user_devices WHERE user_id = $1 AND device_id = $2 LIMIT 1`,
          [req.user.id, dev.id]
        );
        if (owned.rows.length === 0) {
          // permitir fallback por token
          const token = getDeviceTokenFromReq(req);
          if (!token || token !== dev.api_token) return res.status(403).json({ error: 'No tienes acceso a este dispositivo' });
        }
      } else if (!REQUIRE_USER_LOGIN) {
        // modo abierto: permitir
      } else {
        const token = getDeviceTokenFromReq(req);
        if (!token || token !== dev.api_token) return res.status(401).json({ error: 'No autenticado' });
      }
    }

    const dbInfo = await pool.query(
      `SELECT
         current_setting('TIMEZONE') AS timezone,
         NOW() AS now_tz,
         (EXTRACT(EPOCH FROM NOW()) * 1000)::bigint AS now_ms`
    );
    const tz = dbInfo.rows[0]?.timezone || null;
    const dbNowMs = Number(dbInfo.rows[0]?.now_ms || 0);

    const latest = await pool.query(
      `SELECT
         sd.created_at AS created_at_raw,
         (EXTRACT(EPOCH FROM (sd.created_at AT TIME ZONE current_setting('TIMEZONE'))) * 1000)::bigint AS created_at_ms
       FROM sensor_data sd
       WHERE sd.device_id = $1
       ORDER BY sd.created_at DESC
       LIMIT 1`,
      [dev.id]
    );

    const createdAtMs = Number(latest.rows[0]?.created_at_ms || 0);
    const createdAt = epochMsToDate(createdAtMs);
    const ageMs = (dbNowMs && createdAtMs) ? Math.max(0, dbNowMs - createdAtMs) : null;

    const serverNow = new Date();
    res.json({
      device_code,
      server_now: serverNow.toISOString(),
      server_now_madrid: fmtEsLabel.format(serverNow),
      db: {
        timezone: tz,
        now: dbInfo.rows[0]?.now_tz ? new Date(dbInfo.rows[0].now_tz).toISOString() : null,
        now_ms: dbNowMs || null
      },
      latest_sensor: {
        created_at_raw: latest.rows[0]?.created_at_raw ?? null,
        created_at: createdAt ? createdAt.toISOString() : null,
        created_at_madrid: createdAt ? fmtEsLabel.format(createdAt) : null,
        age_minutes: ageMs == null ? null : Math.round(ageMs / 60000)
      }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Diagnóstico de canales (útil cuando las gráficas/tablas no se mueven)
app.get('/api/debug/channels/:device_code', async (req, res) => {
  try {
    const { device_code } = req.params;
    const dev = await getDeviceByCode(device_code);
    if (!dev) return res.status(404).json({ error: 'Dispositivo no encontrado' });

    // Auth: admin, usuario dueño, o token del dispositivo
    if (!hasValidAdminKey(req)) {
      if (REQUIRE_USER_LOGIN && req.user?.id) {
        const owned = await pool.query(
          `SELECT 1 FROM user_devices WHERE user_id = $1 AND device_id = $2 LIMIT 1`,
          [req.user.id, dev.id]
        );
        if (owned.rows.length === 0) {
          const token = getDeviceTokenFromReq(req);
          if (!token || token !== dev.api_token) return res.status(403).json({ error: 'No tienes acceso a este dispositivo' });
        }
      } else if (!REQUIRE_USER_LOGIN) {
        // modo abierto: permitir
      } else {
        const token = getDeviceTokenFromReq(req);
        if (!token || token !== dev.api_token) return res.status(401).json({ error: 'No autenticado' });
      }
    }

    const serverNow = new Date();
    const nowMs = serverNow.getTime();

    // Buscar los canales base (1) que usa el panel por defecto
    const channels = await pool.query(
      `SELECT id, kind, channel_index, name
       FROM device_channels
       WHERE device_id = $1 AND deleted_at IS NULL
         AND ((kind = 'soil_sensor' AND channel_index = 1) OR (kind = 'valve' AND channel_index = 1))`,
      [dev.id]
    );

    const out = [];
    for (const ch of channels.rows) {
      const latest = await pool.query(
        `SELECT
           ts AS ts_raw,
           (EXTRACT(EPOCH FROM (ts AT TIME ZONE current_setting('TIMEZONE'))) * 1000)::bigint AS ts_ms,
           value,
           state
         FROM channel_samples
         WHERE channel_id = $1
         ORDER BY ts DESC
         LIMIT 1`,
        [ch.id]
      );

      const row = latest.rows[0] || null;
      const tsMs = Number(row?.ts_ms || 0);
      const ts = epochMsToDate(tsMs);
      out.push({
        id: ch.id,
        kind: ch.kind,
        channel_index: ch.channel_index,
        name: ch.name,
        latest: {
          ts_raw: row?.ts_raw ?? null,
          ts: ts ? ts.toISOString() : null,
          ts_madrid: ts ? fmtEsLabel.format(ts) : null,
          age_minutes: ts ? Math.round(Math.max(0, nowMs - ts.getTime()) / 60000) : null,
          value: row?.value ?? null,
          state: row?.state ?? null
        }
      });
    }

    res.json({
      device_code,
      server_now: serverNow.toISOString(),
      server_now_madrid: fmtEsLabel.format(serverNow),
      channels: out
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Actualizar configuración del dispositivo
app.post('/api/config/:device_code', async (req, res) => {
  try {
    const { device_code } = req.params;

    const devOwned = await requireUserDevice(req, res, device_code);
    if (!devOwned) return;

    const parsed = DeviceConfigSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ error: 'Payload inválido', details: parsed.error.issues });
    }

    const zonesJsonb = Array.isArray(parsed.data.zones) ? JSON.stringify(parsed.data.zones) : null;

    // Obtener device_id
    const device = await pool.query(
      'SELECT id FROM devices WHERE device_code = $1',
      [device_code]
    );

    if (device.rows.length === 0) {
      return res.status(404).json({ error: 'Dispositivo no encontrado' });
    }

    const device_id = device.rows[0].id;

    // Asegurar que device_config tiene las columnas nuevas (zones_json, notify_*, etc.)
    // para evitar 500 en DBs antiguas.
    await ensureDeviceConfigSchema();

    // Auth (opcional): por defecto NO exige token; activar con REQUIRE_DEVICE_TOKEN=true
    const ok = await enforceDeviceTokenIfRequired(req, res, device_code);
    if (!ok) return;

    async function upsertConfigOnce() {
      // Verificar si existe configuración
      const existing = await pool.query('SELECT id FROM device_config WHERE device_id = $1', [device_id]);

      if (existing.rows.length === 0) {
        // Crear nueva configuración
        const config_id = uuidv4();
        await pool.query(
          `INSERT INTO device_config (
             id, device_id,
             humidity_low_threshold, humidity_low_color, humidity_good_color,
             led_mode, led_manual_color,
             wet_v, dry_v,
             alert_humidity_low_minutes, alert_valve_on_max_minutes, alert_sensor_dead_minutes,
             alert_voltage_min, alert_voltage_max,
             notify_webhook_url, notify_telegram_chat_id,
             zones_json
           )
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17::jsonb)`,
          [
            config_id,
            device_id,
            parsed.data.humidity_low_threshold,
            parsed.data.humidity_low_color,
            parsed.data.humidity_good_color,
            parsed.data.led_mode,
            parsed.data.led_manual_color,
            parsed.data.wet_v,
            parsed.data.dry_v,
            parsed.data.alert_humidity_low_minutes,
            parsed.data.alert_valve_on_max_minutes,
            parsed.data.alert_sensor_dead_minutes,
            parsed.data.alert_voltage_min ?? null,
            parsed.data.alert_voltage_max ?? null,
            parsed.data.notify_webhook_url ?? null,
            parsed.data.notify_telegram_chat_id ?? null,
            zonesJsonb
          ]
        );
      } else {
        // Actualizar configuración existente
        await pool.query(
          `UPDATE device_config 
           SET
             humidity_low_threshold = COALESCE($1, humidity_low_threshold),
             humidity_low_color = COALESCE($2, humidity_low_color),
             humidity_good_color = COALESCE($3, humidity_good_color),
             led_mode = COALESCE($4, led_mode),
             led_manual_color = COALESCE($5, led_manual_color),
             wet_v = COALESCE($6, wet_v),
             dry_v = COALESCE($7, dry_v),
             alert_humidity_low_minutes = COALESCE($8, alert_humidity_low_minutes),
             alert_valve_on_max_minutes = COALESCE($9, alert_valve_on_max_minutes),
             alert_sensor_dead_minutes = COALESCE($10, alert_sensor_dead_minutes),
             alert_voltage_min = COALESCE($11, alert_voltage_min),
             alert_voltage_max = COALESCE($12, alert_voltage_max),
             notify_webhook_url = COALESCE($13, notify_webhook_url),
             notify_telegram_chat_id = COALESCE($14, notify_telegram_chat_id),
             zones_json = COALESCE($15::jsonb, zones_json),
             updated_at = CURRENT_TIMESTAMP
           WHERE device_id = $16`,
          [
            parsed.data.humidity_low_threshold,
            parsed.data.humidity_low_color,
            parsed.data.humidity_good_color,
            parsed.data.led_mode,
            parsed.data.led_manual_color,
            parsed.data.wet_v,
            parsed.data.dry_v,
            parsed.data.alert_humidity_low_minutes,
            parsed.data.alert_valve_on_max_minutes,
            parsed.data.alert_sensor_dead_minutes,
            parsed.data.alert_voltage_min ?? null,
            parsed.data.alert_voltage_max ?? null,
            parsed.data.notify_webhook_url ?? null,
            parsed.data.notify_telegram_chat_id ?? null,
            zonesJsonb,
            device_id
          ]
        );
      }
    }

    try {
      await upsertConfigOnce();
    } catch (e) {
      // Si es un error de esquema/migración incompleta, forzamos initDB y reintentamos una vez.
      if (/column .* does not exist|relation .* does not exist|does not exist/i.test(String(e.message))) {
        console.warn('POST /api/config detected schema issue, running initDB and retrying:', e.message);
        try { await initDB(); } catch (ie) { console.warn('initDB retry failed:', ie.message); }
        try { await ensureDeviceConfigSchema(); } catch {}
        await upsertConfigOnce();
      } else {
        throw e;
      }
    }

    res.json({ status: 'Configuración guardada' });
  } catch (error) {
    console.error(error);
    // Si falla por columnas faltantes, intentar migración y reintentar una vez.
    if (/column .* does not exist|relation .* does not exist/i.test(String(error.message))) {
      try {
        await ensureDeviceConfigSchema();
      } catch {}
    }
    res.status(500).json({ error: error.message });
  }
});

// Redirigir raíz al panel del dispositivo
app.get('/', (req, res) => {
  // Importante: algunos healthchecks no aceptan 3xx.
  // Si no parece navegación HTML, devolvemos 200 OK simple.
  if (!requestWantsHtml(req)) {
    const build =
      process.env.RAILWAY_GIT_COMMIT_SHA ||
      process.env.RAILWAY_GIT_COMMIT ||
      process.env.GIT_COMMIT ||
      process.env.BUILD_ID ||
      null;
    res.set('Cache-Control', 'no-store');
    return res.status(200).json({ ok: true, ts: new Date().toISOString(), build });
  }

  if (REQUIRE_USER_LOGIN && !hasValidAdminKey(req)) {
    if (!req.user?.id) return res.redirect(`/login?next=${encodeURIComponent(req.originalUrl || '/')}`);
    return res.redirect('/app');
  }
  res.redirect('/panel/RIEGO_001');
});

app.get('/app', async (req, res) => {
  if (REQUIRE_USER_LOGIN && !hasValidAdminKey(req)) {
    if (!req.user?.id) return res.redirect(`/login?next=${encodeURIComponent(req.originalUrl || '/app')}`);
    try {
      const r = await pool.query(
        `SELECT d.device_code
         FROM user_devices ud
         JOIN devices d ON d.id = ud.device_id
         WHERE ud.user_id = $1
         ORDER BY d.created_at ASC
         LIMIT 1`,
        [req.user.id]
      );
      const first = r.rows[0]?.device_code;
      if (first) return res.redirect(`/panel/${encodeURIComponent(first)}`);
      res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      res.set('Pragma', 'no-cache');
      res.set('Expires', '0');
      return res.sendFile(__dirname + '/public/no-devices.html');
    } catch {
      res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      res.set('Pragma', 'no-cache');
      res.set('Expires', '0');
      return res.sendFile(__dirname + '/public/no-devices.html');
    }
  }
  res.redirect('/panel/RIEGO_001');
});

app.get('/login', (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.sendFile(__dirname + '/public/login.html');
});

app.get('/email-sent', (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.sendFile(__dirname + '/public/email-sent.html');
});

app.get('/reset-password', (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.sendFile(__dirname + '/public/reset-password.html');
});

// Servir dashboard
app.get('/panel/:device_code', (req, res) => {
  const { device_code } = req.params;
  if (REQUIRE_USER_LOGIN && !hasValidAdminKey(req)) {
    if (!req.user?.id) return res.redirect(`/login?next=${encodeURIComponent(req.originalUrl || `/panel/${device_code}`)}`);
    // validar ownership antes de servir el panel
    pool
      .query(
        `SELECT 1
         FROM user_devices ud
         JOIN devices d ON d.id = ud.device_id
         WHERE ud.user_id = $1 AND d.device_code = $2
         LIMIT 1`,
        [req.user.id, device_code]
      )
      .then((r) => {
        if (!r.rows.length) return res.redirect(`/app?no_access=1&device=${encodeURIComponent(device_code)}`);
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.set('Pragma', 'no-cache');
        res.set('Expires', '0');
        res.sendFile(__dirname + '/public/index.html');
      })
      .catch(() => res.status(500).send('Error de autenticación'));
    return;
  }

  // Evitar caché agresiva (especialmente en despliegues/CDN)
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.sendFile(__dirname + '/public/index.html');
});

// Admin: obtener/rotar claim_token (para provisioning)
app.get('/api/admin/device-claim/:device_code', async (req, res) => {
  try {
    if (!requireAdminKey(req, res)) return;

    const { device_code } = req.params;
    const dev = await getDeviceByCode(device_code);
    if (!dev) return res.status(404).json({ error: 'Dispositivo no encontrado' });

    const rotate = String(req.query.rotate || 'false').toLowerCase() === 'true';
    if (rotate || !dev.claim_token) {
      const newToken = uuidv4();
      await pool.query('UPDATE devices SET claim_token = $1, updated_at = CURRENT_TIMESTAMP WHERE device_code = $2', [newToken, device_code]);
      return res.json({ device_code, claim_token: newToken, rotated: true });
    }
    res.json({ device_code, claim_token: dev.claim_token, rotated: false });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// --- Admin (CRM) ---
app.get('/api/admin/summary', async (req, res) => {
  try {
    if (!requireAdminKey(req, res)) return;
    const [d, u, c] = await Promise.all([
      pool.query('SELECT COUNT(*)::int AS n FROM devices'),
      pool.query('SELECT COUNT(*)::int AS n FROM users'),
      pool.query('SELECT COUNT(*)::int AS n FROM customers')
    ]);
    res.json({
      devices: d.rows[0]?.n ?? 0,
      users: u.rows[0]?.n ?? 0,
      customers: c.rows[0]?.n ?? 0,
      ts: new Date().toISOString()
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/admin/devices', async (req, res) => {
  try {
    if (!requireAdminKey(req, res)) return;
    const r = await pool.query(
      `SELECT
         d.id,
         d.device_code,
         d.name,
         d.location,
         d.created_at,
         d.updated_at,
         ls.last_seen,
         c.id AS customer_id,
         c.name AS customer_name
       FROM devices d
       LEFT JOIN (
         SELECT device_id, MAX(created_at) AS last_seen
         FROM sensor_data
         GROUP BY device_id
       ) ls ON ls.device_id = d.id
       LEFT JOIN customer_devices cd ON cd.device_id = d.id
       LEFT JOIN customers c ON c.id = cd.customer_id
       ORDER BY d.created_at DESC`
    );
    res.json({ devices: r.rows.map(enrichRowWithMadridTs) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/admin/customers', async (req, res) => {
  try {
    if (!requireAdminKey(req, res)) return;
    const r = await pool.query(
      `SELECT
         c.*,
         COALESCE(cd.cnt, 0)::int AS devices_count
       FROM customers c
       LEFT JOIN (
         SELECT customer_id, COUNT(*) AS cnt
         FROM customer_devices
         GROUP BY customer_id
       ) cd ON cd.customer_id = c.id
       ORDER BY c.created_at DESC`
    );
    res.json({ customers: r.rows.map(enrichRowWithMadridTs) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/admin/customers/:id', async (req, res) => {
  try {
    if (!requireAdminKey(req, res)) return;
    const id = String(req.params.id || '').trim();
    const c = await pool.query('SELECT * FROM customers WHERE id = $1', [id]);
    if (!c.rows.length) return res.status(404).json({ error: 'Cliente no encontrado' });

    const devs = await pool.query(
      `SELECT d.id, d.device_code, d.name, d.location, d.created_at, d.updated_at
       FROM customer_devices cd
       JOIN devices d ON d.id = cd.device_id
       WHERE cd.customer_id = $1
       ORDER BY d.created_at DESC`,
      [id]
    );

    res.json({
      customer: enrichRowWithMadridTs(c.rows[0]),
      devices: devs.rows.map(enrichRowWithMadridTs)
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/admin/customers', async (req, res) => {
  try {
    if (!requireAdminKey(req, res)) return;
    const parsed = AdminCustomerCreateSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'Datos inválidos', details: parsed.error.flatten() });

    const id = uuidv4();
    const v = parsed.data;
    const r = await pool.query(
      `INSERT INTO customers (id, name, email, phone, address, notes)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [id, v.name, v.email ?? null, v.phone ?? null, v.address ?? null, v.notes ?? null]
    );
    res.status(201).json({ customer: enrichRowWithMadridTs(r.rows[0]) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/admin/customers/:id', async (req, res) => {
  try {
    if (!requireAdminKey(req, res)) return;
    const id = String(req.params.id || '').trim();
    const parsed = AdminCustomerUpdateSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'Datos inválidos', details: parsed.error.flatten() });

    const existing = await pool.query('SELECT * FROM customers WHERE id = $1', [id]);
    if (!existing.rows.length) return res.status(404).json({ error: 'Cliente no encontrado' });

    const merged = { ...existing.rows[0], ...parsed.data };
    const r = await pool.query(
      `UPDATE customers
       SET name = $1, email = $2, phone = $3, address = $4, notes = $5, updated_at = CURRENT_TIMESTAMP
       WHERE id = $6
       RETURNING *`,
      [
        merged.name,
        merged.email ?? null,
        merged.phone ?? null,
        merged.address ?? null,
        merged.notes ?? null,
        id
      ]
    );
    res.json({ customer: enrichRowWithMadridTs(r.rows[0]) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/admin/customers/:id', async (req, res) => {
  try {
    if (!requireAdminKey(req, res)) return;
    const id = String(req.params.id || '').trim();
    const r = await pool.query('DELETE FROM customers WHERE id = $1 RETURNING id', [id]);
    if (!r.rows.length) return res.status(404).json({ error: 'Cliente no encontrado' });
    res.json({ ok: true, id });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/admin/customers/:id/assign-device', async (req, res) => {
  try {
    if (!requireAdminKey(req, res)) return;
    const customerId = String(req.params.id || '').trim();
    const deviceCode = String(req.body?.device_code || '').trim();
    if (!deviceCode) return res.status(400).json({ error: 'device_code requerido' });

    const c = await pool.query('SELECT 1 FROM customers WHERE id = $1', [customerId]);
    if (!c.rows.length) return res.status(404).json({ error: 'Cliente no encontrado' });
    const d = await pool.query('SELECT id, device_code FROM devices WHERE device_code = $1', [deviceCode]);
    if (!d.rows.length) return res.status(404).json({ error: 'Dispositivo no encontrado' });

    const deviceId = d.rows[0].id;

    // Si ya estaba asignado a otro cliente, lo movemos.
    await pool.query('DELETE FROM customer_devices WHERE device_id = $1', [deviceId]);
    await pool.query('INSERT INTO customer_devices (customer_id, device_id) VALUES ($1, $2)', [customerId, deviceId]);

    res.json({ ok: true, customer_id: customerId, device_code: deviceCode });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/admin/customers/:id/unassign-device', async (req, res) => {
  try {
    if (!requireAdminKey(req, res)) return;
    const customerId = String(req.params.id || '').trim();
    const deviceCode = String(req.body?.device_code || '').trim();
    if (!deviceCode) return res.status(400).json({ error: 'device_code requerido' });

    const d = await pool.query('SELECT id FROM devices WHERE device_code = $1', [deviceCode]);
    if (!d.rows.length) return res.status(404).json({ error: 'Dispositivo no encontrado' });
    const deviceId = d.rows[0].id;

    await pool.query('DELETE FROM customer_devices WHERE customer_id = $1 AND device_id = $2', [customerId, deviceId]);
    res.json({ ok: true, customer_id: customerId, device_code: deviceCode });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// UI Admin (la seguridad real se aplica en /api/admin/* con ADMIN_KEY)
app.get('/admin', (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.sendFile(__dirname + '/public/admin-login.html');
});

app.get('/admin/app', (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.sendFile(__dirname + '/public/admin.html');
});

// Error handler global (debe ir después de las rutas)
app.use((err, req, res, next) => {
  try {
    console.error('EXPRESS_ERROR', err);

    // Este endpoint se consulta en polling desde el panel: nunca debe romper la UI.
    if (req.path === '/api/tickets/unread-count') {
      if (!res.headersSent) return res.status(200).json({ unread_count: 0 });
      return;
    }

    // JSON inválido en config: devolver 400, no 500
    if (req.path && String(req.path).startsWith('/api/config/')) {
      const msg = String(err && (err.message || err.type || '') || '');
      if (err && (err.type === 'entity.parse.failed' || err instanceof SyntaxError || /JSON/i.test(msg))) {
        if (!res.headersSent) return res.status(400).json({ error: 'JSON inválido' });
        return;
      }
    }

    if (res.headersSent) return next(err);
    res.status(500).json({ error: 'Internal Server Error' });
  } catch (e) {
    if (res.headersSent) return next(err);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.use(express.static('public', {
  etag: false,
  lastModified: false,
  maxAge: 0,
  setHeaders: (res, path) => {
    try {
      if (String(path).endsWith('index.html')) {
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.set('Pragma', 'no-cache');
        res.set('Expires', '0');
      } else {
        res.set('Cache-Control', 'no-store');
      }
    } catch {}
  }
}));

const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(`Servidor escuchando en puerto ${PORT}`);
});

function shutdown(signal) {
  console.log(`${signal} recibido: cerrando servidor...`);
  try {
    server.close(() => {
      console.log('HTTP server cerrado');
      pool.end().catch(() => {}).finally(() => process.exit(0));
    });
    // Fallback: si no cierra en 10s, salir.
    setTimeout(() => process.exit(0), 10_000).unref();
  } catch {
    process.exit(0);
  }
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
