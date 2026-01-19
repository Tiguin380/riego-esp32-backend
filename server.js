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
        humidity_low_threshold DECIMAL(5,2),
        humidity_low_color VARCHAR(20),
        humidity_good_color VARCHAR(20),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
    const { device_code, temperature, humidity, rain_level, led_status, humidity_low_threshold, humidity_low_color, humidity_good_color } = req.body;

    const device = await pool.query(
      'SELECT id FROM devices WHERE device_code = $1',
      [device_code]
    );

    if (device.rows.length === 0) {
      return res.status(404).json({ error: 'Dispositivo no encontrado' });
    }

    const device_id = device.rows[0].id;

    await pool.query(
      `INSERT INTO sensor_data (device_id, temperature, humidity, rain_level, led_status, humidity_low_threshold, humidity_low_color, humidity_good_color) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [device_id, temperature, humidity, rain_level, led_status, humidity_low_threshold, humidity_low_color, humidity_good_color]
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

// Servir dashboard
app.get('/panel/:device_code', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

app.use(express.static('public'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor escuchando en puerto ${PORT}`);
});
