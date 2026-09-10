const express = require('express');
const { Pool } = require('pg');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('render.com')
    ? { rejectUnauthorized: false }
    : false
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS call_centers (
      id SERIAL PRIMARY KEY,
      nombre TEXT NOT NULL UNIQUE,
      creado TIMESTAMPTZ DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS tmks (
      id SERIAL PRIMARY KEY,
      call_center_id INTEGER NOT NULL REFERENCES call_centers(id) ON DELETE CASCADE,
      codigo TEXT NOT NULL,
      creado TIMESTAMPTZ DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS equipo (
      id SERIAL PRIMARY KEY,
      tipo TEXT NOT NULL CHECK (tipo IN ('consultor','closer','gerente')),
      nombre TEXT NOT NULL,
      creado TIMESTAMPTZ DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS clientes (
      id SERIAL PRIMARY KEY,
      fecha DATE,
      usuario TEXT NOT NULL,
      edad TEXT,
      documento TEXT,
      fecha_nacimiento DATE,
      direccion TEXT,
      telefono TEXT,
      enfermedades TEXT,
      medicamentos TEXT,
      alergias TEXT,
      estado_civil TEXT,
      eps TEXT,
      rh TEXT,
      dispositivos BOOLEAN DEFAULT false,
      dispositivos_cual TEXT,
      cirugias TEXT,
      observacion_usuario TEXT,
      firma_autorizacion BOOLEAN DEFAULT false,
      ocupacion TEXT,
      acompanante TEXT,
      edad_acomp TEXT,
      call_center TEXT,
      outsorsing TEXT,
      consultor TEXT,
      closer TEXT,
      gerente TEXT,
      tour BOOLEAN DEFAULT false,
      nt BOOLEAN DEFAULT false,
      vta BOOLEAN DEFAULT false,
      volumen NUMERIC DEFAULT 0,
      cash NUMERIC DEFAULT 0,
      cartera NUMERIC DEFAULT 0,
      contrato TEXT,
      observaciones TEXT,
      creado TIMESTAMPTZ DEFAULT now()
    );
  `);
}

const clienteCols = `
  id, fecha, usuario, edad, documento,
  fecha_nacimiento AS "fechaNacimiento", direccion, telefono, enfermedades,
  medicamentos, alergias, estado_civil AS "estadoCivil", eps, rh,
  dispositivos, dispositivos_cual AS "dispositivosCual", cirugias,
  observacion_usuario AS "observacionUsuario", firma_autorizacion AS "firmaAutorizacion",
  ocupacion, acompanante, edad_acomp AS "edadAcomp",
  call_center AS "callCenter", outsorsing, consultor, closer, gerente,
  tour, nt, vta, volumen, cash, cartera, contrato, observaciones, creado
`;

// ---------- Clientes ----------
app.get('/api/clientes', async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT ${clienteCols} FROM clientes ORDER BY creado DESC`);
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al leer clientes' }); }
});

app.post('/api/clientes', async (req, res) => {
  const c = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO clientes (
        fecha, usuario, edad, documento, fecha_nacimiento, direccion, telefono,
        enfermedades, medicamentos, alergias, estado_civil, eps, rh,
        dispositivos, dispositivos_cual, cirugias, observacion_usuario, firma_autorizacion,
        ocupacion, acompanante, edad_acomp, call_center, outsorsing, consultor, closer, gerente,
        tour, nt, vta, volumen, cash, cartera, contrato, observaciones
      ) VALUES (
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34
      ) RETURNING ${clienteCols}`,
      [
        c.fecha || null, c.usuario, c.edad || null, c.documento || null, c.fechaNacimiento || null,
        c.direccion || null, c.telefono || null, c.enfermedades || null, c.medicamentos || null,
        c.alergias || null, c.estadoCivil || null, c.eps || null, c.rh || null,
        !!c.dispositivos, c.dispositivosCual || null, c.cirugias || null,
        c.observacionUsuario || null, !!c.firmaAutorizacion,
        c.ocupacion || null, c.acompanante || null, c.edadAcomp || null,
        c.callCenter || null, c.outsorsing || null, c.consultor || null, c.closer || null, c.gerente || null,
        !!c.tour, !!c.nt, !!c.vta, c.volumen || 0, c.cash || 0, c.cartera || 0,
        c.contrato || null, c.observaciones || null
      ]
    );
    res.json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al guardar cliente' }); }
});

// ---------- Call Centers + TMK ----------
app.get('/api/callcenters', async (req, res) => {
  try {
    const { rows: centers } = await pool.query('SELECT id, nombre FROM call_centers ORDER BY nombre');
    const { rows: tmks } = await pool.query('SELECT id, call_center_id AS "callCenterId", codigo FROM tmks ORDER BY codigo');
    const result = centers.map(cc => ({
      id: cc.id,
      nombre: cc.nombre,
      tmks: tmks.filter(t => t.callCenterId === cc.id).map(t => ({ id: t.id, codigo: t.codigo }))
    }));
    res.json(result);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al leer call centers' }); }
});

app.post('/api/callcenters', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'INSERT INTO call_centers (nombre) VALUES ($1) ON CONFLICT (nombre) DO NOTHING RETURNING id, nombre',
      [req.body.nombre]
    );
    if (!rows[0]) return res.status(409).json({ error: 'Ya existe' });
    res.json({ ...rows[0], tmks: [] });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al crear call center' }); }
});

app.delete('/api/callcenters/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM call_centers WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al eliminar call center' }); }
});

app.post('/api/callcenters/:id/tmks', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'INSERT INTO tmks (call_center_id, codigo) VALUES ($1, $2) RETURNING id, codigo',
      [req.params.id, req.body.codigo]
    );
    res.json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al agregar TMK' }); }
});

app.delete('/api/tmks/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM tmks WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al eliminar TMK' }); }
});

// ---------- Equipo (consultores, closers, gerentes) ----------
app.get('/api/equipo', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, tipo, nombre FROM equipo ORDER BY nombre');
    const result = { consultor: [], closer: [], gerente: [] };
    rows.forEach(r => { if (result[r.tipo]) result[r.tipo].push({ id: r.id, nombre: r.nombre }); });
    res.json(result);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al leer equipo' }); }
});

app.post('/api/equipo', async (req, res) => {
  try {
    const { tipo, nombre } = req.body;
    if (!['consultor', 'closer', 'gerente'].includes(tipo)) return res.status(400).json({ error: 'Tipo inválido' });
    const { rows } = await pool.query(
      'INSERT INTO equipo (tipo, nombre) VALUES ($1, $2) RETURNING id, tipo, nombre',
      [tipo, nombre]
    );
    res.json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al agregar' }); }
});

app.delete('/api/equipo/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM equipo WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al eliminar' }); }
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
initDb()
  .then(() => {
    app.listen(PORT, () => console.log('Duo Vital CRM escuchando en puerto ' + PORT));
  })
  .catch(err => {
    console.error('Error inicializando la base de datos:', err);
    process.exit(1);
  });
