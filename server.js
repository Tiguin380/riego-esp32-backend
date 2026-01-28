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

const app = express();
// Railway/Proxies: necesario para que rate-limit y req.ip funcionen bien
app.set('trust proxy', 1);

function envBool(name, defaultValue) {
  const raw = process.env[name];
  if (raw == null || raw === '') return defaultValue;
  return String(raw).toLowerCase() === 'true';
}

const REQUIRE_USER_LOGIN = envBool('REQUIRE_USER_LOGIN', Boolean(process.env.DATABASE_URL));
const JWT_SECRET = process.env.JWT_SECRET || process.env.SESSION_SECRET || 'dev-insecure-jwt-secret';
const JWT_COOKIE_NAME = process.env.JWT_COOKIE_NAME || 'sid';
const COOKIE_SECURE = envBool('COOKIE_SECURE', process.env.NODE_ENV === 'production');
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

function enrichRowWithMadridTs(row) {
  const d = row && row.ts ? new Date(row.ts) : null;
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
  res.cookie(JWT_COOKIE_NAME, token, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: 'lax',
    maxAge: COOKIE_MAX_AGE_MS,
    path: '/'
  });
}

function clearAuthCookie(res) {
  res.clearCookie(JWT_COOKIE_NAME, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: 'lax',
    path: '/'
  });
}

function getJwtFromReq(req) {
  const c = req.cookies?.[JWT_COOKIE_NAME];
  return typeof c === 'string' && c.trim() ? c.trim() : null;
}

function signUserJwt(user) {
  return jwt.sign(
    { sub: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: Math.floor(COOKIE_MAX_AGE_MS / 1000) }
  );
}

function authMiddleware(req, _res, next) {
  const token = getJwtFromReq(req);
  if (!token) {
    req.user = null;
    return next();
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = {
      id: decoded.sub,
      email: decoded.email || null
    };
  } catch {
    req.user = null;
  }
  return next();
}

app.use(authMiddleware);

function requireUser(req, res) {
  if (hasValidAdminKey(req)) return true;
  if (!REQUIRE_USER_LOGIN) return true;
  if (req.user && req.user.id) return true;
  res.status(401).json({ error: 'No autenticado' });
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

  const dev = await getDeviceByCode(device_code);
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

  // Si NO hay usuario, permitimos al ESP32 leer config con X-Device-Token (aunque REQUIRE_DEVICE_TOKEN sea false)
  const token = getDeviceTokenFromReq(req);
  if (dev.api_token && token && token === dev.api_token) return dev;

  res.status(401).json({ error: 'No autenticado' });
  return null;
}

function hasValidAdminKey(req) {
  const adminKey = process.env.ADMIN_KEY;
  if (!adminKey) return false;
  return req.get('x-admin-key') === adminKey;
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
  const missing = await pool.query(`SELECT id FROM devices WHERE claim_token IS NULL OR claim_token = ''`);
  for (const row of missing.rows) {
    await pool.query('UPDATE devices SET claim_token = $1 WHERE id = $2', [uuidv4(), row.id]);
  }
}

async function ensureDefaultChannels(device_id) {
  // Crea canal por defecto para compatibilidad: Sensor 1 (humedad) y Válvula 1
  await pool.query(
    `INSERT INTO device_channels (id, device_id, kind, channel_index, name)
     VALUES ($1, $2, 'soil_sensor', 1, 'Sensor 1')
     ON CONFLICT (device_id, kind, channel_index) DO NOTHING`,
    [uuidv4(), device_id]
  );
  await pool.query(
    `INSERT INTO device_channels (id, device_id, kind, channel_index, name)
     VALUES ($1, $2, 'valve', 1, 'Válvula 1')
     ON CONFLICT (device_id, kind, channel_index) DO NOTHING`,
    [uuidv4(), device_id]
  );
}

async function getChannelId(device_id, kind, channel_index) {
  const r = await pool.query(
    `SELECT id FROM device_channels WHERE device_id = $1 AND kind = $2 AND channel_index = $3`,
    [device_id, kind, channel_index]
  );
  return r.rows[0]?.id || null;
}

async function ensureChannel(device_id, kind, channel_index) {
  if (kind !== 'soil_sensor' && kind !== 'valve') return null;
  const idx = Number(channel_index);
  if (!Number.isInteger(idx) || idx < 1 || idx > 32) return null;

  const existing = await getChannelId(device_id, kind, idx);
  if (existing) return existing;

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
    wifi_rssi: z.coerce.number().int().optional().nullable(),
    uptime_s: z.coerce.number().int().optional().nullable(),
    reboot_count: z.coerce.number().int().optional().nullable(),
    heap_free: z.coerce.number().int().optional().nullable(),
    ip: z.string().optional().nullable(),

    // Nuevo: canales múltiples (sensores/válvulas). Retrocompatible.
    channels: z
      .array(
        z
          .object({
            kind: z.enum(['soil_sensor', 'valve']),
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
    notify_telegram_chat_id: z.string().optional().nullable()
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
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Canales: válvulas y sensores múltiples
    await pool.query(`
      CREATE TABLE IF NOT EXISTS device_channels (
        id UUID PRIMARY KEY,
        device_id UUID REFERENCES devices(id),
        kind VARCHAR(20) NOT NULL, -- 'soil_sensor' | 'valve'
        channel_index INTEGER NOT NULL,
        name VARCHAR(80) NOT NULL,
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

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_sensor_device_time ON sensor_data(device_id, created_at DESC)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_alert_events_device_time ON alert_events(device_id, created_at DESC)`);

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
  password: z.string().min(8).max(200)
});

const LoginSchema = z.object({
  email: z.string().email().max(255),
  password: z.string().min(1).max(200)
});

app.get('/api/auth/me', async (req, res) => {
  if (!req.user?.id) return res.status(401).json({ error: 'No autenticado' });
  res.json({ id: req.user.id, email: req.user.email });
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const parsed = RegisterSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ error: 'Payload inválido', details: parsed.error.issues });
    }
    const email = String(parsed.data.email).trim().toLowerCase();
    const password_hash = await bcrypt.hash(parsed.data.password, 10);
    const id = uuidv4();

    await pool.query(
      `INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)`
      ,
      [id, email, password_hash]
    );

    const token = signUserJwt({ id, email });
    setAuthCookie(res, token);
    res.json({ status: 'OK', user: { id, email } });
  } catch (e) {
    if (/duplicate key value|unique constraint/i.test(String(e.message))) {
      return res.status(409).json({ error: 'Email ya registrado' });
    }
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const parsed = LoginSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ error: 'Payload inválido', details: parsed.error.issues });
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
    if (!dev.claim_token || dev.claim_token !== claim_token) {
      return res.status(401).json({ error: 'claim_token inválido' });
    }

    await pool.query(
      `INSERT INTO user_devices (user_id, device_id, role)
       VALUES ($1, $2, 'owner')
       ON CONFLICT (user_id, device_id) DO NOTHING`,
      [req.user.id, dev.id]
    );

    // Rotar claim_token para que no se pueda reutilizar
    await pool.query('UPDATE devices SET claim_token = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2', [uuidv4(), dev.id]);

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
  initDB();
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
    res.json({ ok: true, db: db.rows[0]?.ok === 1, ts: new Date().toISOString() });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message, ts: new Date().toISOString() });
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
      const claim_token = uuidv4();
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
      channels
    } = parsed.data;
    const device = await pool.query(
      'SELECT id FROM devices WHERE device_code = $1',
      [device_code]
    );

    if (device.rows.length === 0) {
      return res.status(404).json({ error: 'Dispositivo no encontrado' });
    }

    const device_id = device.rows[0].id;

    // Asegurar canales base
    await ensureDefaultChannels(device_id);

    const resolved_valve_state = valve_state || led_status || null;

    await pool.query(
      `INSERT INTO sensor_data (
          device_id, temperature, humidity, rain_level, led_status, valve_state,
          voltage, wifi_rssi, uptime_s, reboot_count, heap_free, ip,
          humidity_low_threshold, humidity_low_color, humidity_good_color
        )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
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
        for (const c of chArr) {
          const kind = c?.kind;
          const idx = Number(c?.index);
          if ((kind !== 'soil_sensor' && kind !== 'valve') || !Number.isInteger(idx)) continue;

          const channelId = await ensureChannel(device_id, kind, idx);
          if (!channelId) continue;

          if (kind === 'soil_sensor') {
            const v = c?.value;
            const num = typeof v === 'number' ? v : Number(v);
            if (!Number.isFinite(num)) continue;
            await pool.query(
              `INSERT INTO channel_samples (channel_id, ts, value) VALUES ($1, $2, $3)`,
              [channelId, now, num]
            );
          } else {
            const s = c?.state;
            const st = typeof s === 'number' ? s : Number(s);
            if (!Number.isFinite(st)) continue;
            await pool.query(
              `INSERT INTO channel_samples (channel_id, ts, state) VALUES ($1, $2, $3)`,
              [channelId, now, st >= 1 ? 1 : 0]
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
        if (resolved_valve_state) {
          const ch = await getChannelId(device_id, 'valve', 1);
          if (ch) {
            const vs = String(resolved_valve_state).toUpperCase();
            const state = vs === 'ON' || vs === '1' || vs === 'TRUE' ? 1 : 0;
            await pool.query(
              `INSERT INTO channel_samples (channel_id, ts, state) VALUES ($1, $2, $3)`,
              [ch, now, state]
            );
          }
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

    res.json(result.rows[0]);
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
           MAX(sd.created_at) AS last_seen
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
          if (r.last_seen) {
            const d = new Date(r.last_seen);
            out.last_seen_madrid = fmtEsLabel.format(d);
          } else {
            out.last_seen_madrid = null;
          }
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
         MAX(sd.created_at) AS last_seen
       FROM devices d
       LEFT JOIN sensor_data sd ON sd.device_id = d.id
       GROUP BY d.id
       ORDER BY d.created_at ASC`
    );
    res.json(
      result.rows.map((r) => {
        const out = { ...r };
        if (r.last_seen) {
          const d = new Date(r.last_seen);
          out.last_seen_madrid = fmtEsLabel.format(d);
        } else {
          out.last_seen_madrid = null;
        }
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
       WHERE device_id = $1
       ORDER BY kind ASC, channel_index ASC`,
      [dev.id]
    );
    res.json({ device_code, channels: r.rows });
  } catch (e) {
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

    if (kind !== 'soil_sensor' && kind !== 'valve') {
      return res.status(400).json({ error: 'kind inválido (soil_sensor|valve)' });
    }

    await ensureDefaultChannels(dev.id);
    const nextIdxR = await pool.query(
      `SELECT COALESCE(MAX(channel_index), 0) + 1 AS next
       FROM device_channels
       WHERE device_id = $1 AND kind = $2`,
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
      `SELECT id FROM device_channels WHERE id = $1 AND device_id = $2`,
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
        `SELECT ts, value, state
         FROM channel_samples
         WHERE channel_id = $1 AND ts >= $2 AND ts <= $3
         ORDER BY ts ASC
         LIMIT $4`,
        [channel_id, from, to, limit]
      );
      return res.json({
        device_code,
        channel: ch.rows[0],
        step,
        range: { from: from.toISOString(), to: to.toISOString() },
        server_now: new Date().toISOString(),
        rows: r.rows.map(enrichRowWithMadridTs)
      });
    }

    let trunc;
    if (step === '1m') trunc = "date_trunc('minute', ts)";
    else if (step === '1h') trunc = "date_trunc('hour', ts)";
    else if (step === '1d') trunc = "date_trunc('day', ts)";
    else return res.status(400).json({ error: 'step inválido (raw|1m|1h|1d)' });

    const r = await pool.query(
      `SELECT
         ${trunc} AS ts,
         AVG(value) AS value,
         MAX(COALESCE(state, 0))::int AS state
       FROM channel_samples
       WHERE channel_id = $1 AND ts >= $2 AND ts <= $3
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
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();

  const set = sseClientsByDevice.get(device_code) || new Set();
  set.add(res);
  sseClientsByDevice.set(device_code, set);

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
           created_at AS ts,
           temperature, humidity, valve_state, voltage, wifi_rssi, uptime_s,
           reboot_count,
           COALESCE(dc.reboot_count_offset, 0) AS reboot_count_offset,
           GREATEST(0, COALESCE(reboot_count, 0) - COALESCE(dc.reboot_count_offset, 0))::int AS reboot_count_display
         FROM sensor_data sd
         LEFT JOIN device_config dc ON dc.device_id = sd.device_id
         WHERE sd.device_id = $1 AND sd.created_at >= $2 AND sd.created_at <= $3
         ORDER BY sd.created_at ASC
         LIMIT $4`,
        [device_id, from, to, limit]
      );
      return res.json({
        device_code,
        step,
        range: { from: from.toISOString(), to: to.toISOString() },
        server_now: new Date().toISOString(),
        rows: result.rows.map(enrichRowWithMadridTs)
      });
    }

    let trunc;
    if (step === '1m') trunc = "date_trunc('minute', created_at)";
    else if (step === '1h') trunc = "date_trunc('hour', created_at)";
    else if (step === '1d') trunc = "date_trunc('day', created_at)";
    else return res.status(400).json({ error: 'step inválido (raw|1m|1h|1d)' });

    const result = await pool.query(
      `SELECT
         ${trunc} AS ts,
         AVG(temperature) AS temperature,
         AVG(humidity) AS humidity,
         AVG(voltage) AS voltage,
         AVG(wifi_rssi) AS wifi_rssi,
         MAX(CASE WHEN valve_state = 'ON' THEN 1 ELSE 0 END)::int AS valve_on
       FROM sensor_data
       WHERE device_id = $1 AND created_at >= $2 AND created_at <= $3
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
      `SELECT created_at AS ts, temperature, humidity, valve_state, voltage, wifi_rssi, uptime_s, reboot_count
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
        updated_at: new Date().toISOString()
      });
    }

    res.json(result.rows[0]);
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
      `SELECT ae.kind, ae.message, ae.created_at
       FROM alert_events ae
       JOIN devices d ON ae.device_id = d.id
       WHERE d.device_code = $1
       ORDER BY ae.created_at DESC
       LIMIT $2`,
      [device_code, limit]
    );

    res.json({ device_code, rows: r.rows });
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

    // Obtener device_id
    const device = await pool.query(
      'SELECT id FROM devices WHERE device_code = $1',
      [device_code]
    );

    if (device.rows.length === 0) {
      return res.status(404).json({ error: 'Dispositivo no encontrado' });
    }

    const device_id = device.rows[0].id;

    // Auth (opcional): por defecto NO exige token; activar con REQUIRE_DEVICE_TOKEN=true
    const ok = await enforceDeviceTokenIfRequired(req, res, device_code);
    if (!ok) return;

    // Verificar si existe configuración
    const existing = await pool.query(
      'SELECT id FROM device_config WHERE device_id = $1',
      [device_id]
    );

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
           notify_webhook_url, notify_telegram_chat_id
         )
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
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
          parsed.data.notify_telegram_chat_id ?? null
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
           updated_at = CURRENT_TIMESTAMP
         WHERE device_id = $15`,
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
          device_id
        ]
      );
    }

    res.json({ status: 'Configuración guardada' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// Redirigir raíz al panel del dispositivo
app.get('/', (req, res) => {
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
      return res.sendFile(__dirname + '/public/no-devices.html');
    } catch {
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
        if (!r.rows.length) return res.status(403).send('No tienes acceso a este dispositivo');
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
    const adminKey = process.env.ADMIN_KEY;
    if (!adminKey) return res.status(403).json({ error: 'ADMIN_KEY no configurada' });
    if (req.get('x-admin-key') !== adminKey) return res.status(401).json({ error: 'x-admin-key inválida' });

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

app.use(express.static('public'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor escuchando en puerto ${PORT}`);
});
