const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
require('dotenv').config();
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(cors());
app.use(express.json());

// Log all incoming requests
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// Conexión a PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

// Inicialización automática de tablas en arranque (útil en despliegues en Railway u otros hosts)
async function initDB() {
  try {
    // Crear tabla de dispositivos
    await pool.query(`
      CREATE TABLE IF NOT EXISTS devices (
        id UUID PRIMARY KEY,
        device_code VARCHAR(20) UNIQUE NOT NULL,
        name VARCHAR(100) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

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
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Migraciones idempotentes (aseguran columnas nuevas en instalaciones existentes)
    await pool.query(`ALTER TABLE device_config ADD COLUMN IF NOT EXISTS led_mode VARCHAR(10) DEFAULT 'auto'`);
    await pool.query(`ALTER TABLE device_config ADD COLUMN IF NOT EXISTS led_manual_color VARCHAR(20) DEFAULT 'Off'`);
    await pool.query(`ALTER TABLE sensor_data ADD COLUMN IF NOT EXISTS valve_state VARCHAR(10)`);

    console.log('Database initialized (auto)');
  } catch (error) {
    console.error('Error initializing DB on startup:', error.message);
  }
}

// Llamar a initDB si hay DATABASE_URL (deployment) o si la variable AUTO_DB_INIT está activa
if (process.env.DATABASE_URL || process.env.AUTO_DB_INIT === 'true') {
  initDB();
} else {
  console.log('DATABASE_URL not set: skipping automatic DB init (use /api/init endpoint to initialize)');
}

// Tabla de dispositivos
app.get('/api/init', async (req, res) => {
  try {
    // Crear tabla de dispositivos
    await pool.query(`
      CREATE TABLE IF NOT EXISTS devices (
        id UUID PRIMARY KEY,
        device_code VARCHAR(20) UNIQUE NOT NULL,
        name VARCHAR(100) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

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
        humidity_low_threshold DECIMAL(5,2),
        humidity_low_color VARCHAR(20),
        humidity_good_color VARCHAR(20),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Crear tabla de configuración
    await pool.query(`
      CREATE TABLE IF NOT EXISTS device_config (
        id UUID PRIMARY KEY,
        device_id UUID UNIQUE REFERENCES devices(id),
        humidity_low_threshold DECIMAL(5,2) DEFAULT 50,
        humidity_low_color VARCHAR(20) DEFAULT 'Rojo',
        humidity_good_color VARCHAR(20) DEFAULT 'Verde',
        led_mode VARCHAR(10) DEFAULT 'auto',
        led_manual_color VARCHAR(20) DEFAULT 'Off',
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    res.json({ status: 'Base de datos inicializada' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// Registrar/obtener dispositivo
app.post('/api/device/register', async (req, res) => {
  try {
    const { device_code, name } = req.body;

    let device = await pool.query(
      'SELECT * FROM devices WHERE device_code = $1',
      [device_code]
    );

    if (device.rows.length === 0) {
      const id = uuidv4();
      await pool.query(
        'INSERT INTO devices (id, device_code, name) VALUES ($1, $2, $3)',
        [id, device_code, name || 'ESP32 Riego']
      );
      device = await pool.query('SELECT * FROM devices WHERE id = $1', [id]);
    }

    res.json(device.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// Enviar datos del sensor (desde ESP32)
app.post('/api/sensor/data', async (req, res) => {
  try {
    const {
      device_code,
      temperature,
      humidity,
      rain_level,
      led_status,
      valve_state,
      humidity_low_threshold,
      humidity_low_color,
      humidity_good_color
    } = req.body;
    const device = await pool.query(
      'SELECT id FROM devices WHERE device_code = $1',
      [device_code]
    );

    if (device.rows.length === 0) {
      return res.status(404).json({ error: 'Dispositivo no encontrado' });
    }

    const device_id = device.rows[0].id;

    const resolved_valve_state = valve_state || led_status || null;

    await pool.query(
      `INSERT INTO sensor_data (device_id, temperature, humidity, rain_level, led_status, valve_state, humidity_low_threshold, humidity_low_color, humidity_good_color)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        device_id,
        temperature,
        humidity,
        rain_level,
        led_status || null,
        resolved_valve_state,
        humidity_low_threshold,
        humidity_low_color,
        humidity_good_color
      ]
    );

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

    const result = await pool.query(
      `SELECT sd.* FROM sensor_data sd
       JOIN devices d ON sd.device_id = d.id
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

// Obtener estadísticas de las últimas 24 horas
app.get('/api/sensor/stats/:device_code', async (req, res) => {
  try {
    const { device_code } = req.params;

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

// Obtener historial de datos
app.get('/api/sensor/history/:device_code', async (req, res) => {
  try {
    const { device_code } = req.params;
    const limit = req.query.limit || 100;

    const result = await pool.query(
      `SELECT sd.* FROM sensor_data sd
       JOIN devices d ON sd.device_id = d.id
       WHERE d.device_code = $1
       ORDER BY sd.created_at DESC
       LIMIT $2`,
      [device_code, limit]
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

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
      updated_at: new Date().toISOString()
    });
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
      updated_at: new Date().toISOString()
    });
  }
});

// Actualizar configuración del dispositivo
app.post('/api/config/:device_code', async (req, res) => {
  try {
    const { device_code } = req.params;
    const { humidity_low_threshold, humidity_low_color, humidity_good_color, led_mode, led_manual_color } = req.body;

    // Obtener device_id
    const device = await pool.query(
      'SELECT id FROM devices WHERE device_code = $1',
      [device_code]
    );

    if (device.rows.length === 0) {
      return res.status(404).json({ error: 'Dispositivo no encontrado' });
    }

    const device_id = device.rows[0].id;

    // Verificar si existe configuración
    const existing = await pool.query(
      'SELECT id FROM device_config WHERE device_id = $1',
      [device_id]
    );

    if (existing.rows.length === 0) {
      // Crear nueva configuración
      const config_id = uuidv4();
      await pool.query(
        `INSERT INTO device_config (id, device_id, humidity_low_threshold, humidity_low_color, humidity_good_color, led_mode, led_manual_color)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [config_id, device_id, humidity_low_threshold, humidity_low_color, humidity_good_color, led_mode, led_manual_color]
      );
    } else {
      // Actualizar configuración existente
      await pool.query(
        `UPDATE device_config 
         SET humidity_low_threshold = $1, humidity_low_color = $2, humidity_good_color = $3, led_mode = $4, led_manual_color = $5, updated_at = CURRENT_TIMESTAMP
         WHERE device_id = $6`,
        [humidity_low_threshold, humidity_low_color, humidity_good_color, led_mode, led_manual_color, device_id]
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
  res.redirect('/panel/RIEGO_001');
});

// Servir dashboard
app.get('/panel/:device_code', (req, res) => {
  // Evitar caché agresiva (especialmente en despliegues/CDN)
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.sendFile(__dirname + '/public/index.html');
});

app.use(express.static('public'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor escuchando en puerto ${PORT}`);
});
