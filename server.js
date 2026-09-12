const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const path = require('path');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('render.com')
    ? { rejectUnauthorized: false }
    : false
});

const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(session({
  store: new pgSession({ pool, tableName: 'session', createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || 'duovital-crm-secret-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: 'auto', httpOnly: true, maxAge: 1000 * 60 * 60 * 24 * 7 }
}));
app.use(express.static(path.join(__dirname, 'public')));

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'No autenticado' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || !['administrador', 'superadministrador'].includes(req.session.user.rol)) {
    return res.status(403).json({ error: 'No autorizado' });
  }
  next();
}
function requireSuperAdmin(req, res, next) {
  if (!req.session.user || req.session.user.rol !== 'superadministrador') {
    return res.status(403).json({ error: 'Solo el Super Administrador puede hacer esto' });
  }
  next();
}
function hasPerm(user, key) {
  if (!user) return false;
  if (user.rol === 'superadministrador') return true;
  return !!(user.permisos && user.permisos[key]);
}
function requirePerm(key) {
  return (req, res, next) => {
    if (!hasPerm(req.session.user, key)) {
      return res.status(403).json({ error: 'No tienes permiso para esta acción. Pídele al Super Administrador que te lo otorgue.' });
    }
    next();
  };
}
app.use('/api', (req, res, next) => {
  if (req.path === '/login' || req.path === '/health') return next();
  requireAuth(req, res, next);
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
    CREATE TABLE IF NOT EXISTS usuarios (
      id SERIAL PRIMARY KEY,
      nombre TEXT NOT NULL,
      usuario TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      rol TEXT NOT NULL CHECK (rol IN ('administrador','consultor','closer','gerente')),
      creado TIMESTAMPTZ DEFAULT now()
    );
    ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS permisos JSONB DEFAULT '{}'::jsonb;
    ALTER TABLE usuarios DROP CONSTRAINT IF EXISTS usuarios_rol_check;
    ALTER TABLE usuarios ADD CONSTRAINT usuarios_rol_check CHECK (rol IN ('administrador','consultor','closer','gerente','superadministrador'));
    CREATE TABLE IF NOT EXISTS comentarios (
      id SERIAL PRIMARY KEY,
      cliente_id INTEGER NOT NULL REFERENCES clientes(id) ON DELETE CASCADE,
      usuario_nombre TEXT NOT NULL,
      usuario_login TEXT,
      comentario TEXT NOT NULL,
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
    ALTER TABLE clientes ADD COLUMN IF NOT EXISTS ciudad TEXT;
    ALTER TABLE clientes ADD COLUMN IF NOT EXISTS codigo_venta TEXT;
    ALTER TABLE clientes ADD COLUMN IF NOT EXISTS numero_venta TEXT;
    ALTER TABLE clientes ADD COLUMN IF NOT EXISTS emergencia1_nombre TEXT;
    ALTER TABLE clientes ADD COLUMN IF NOT EXISTS emergencia1_celular TEXT;
    ALTER TABLE clientes ADD COLUMN IF NOT EXISTS emergencia2_nombre TEXT;
    ALTER TABLE clientes ADD COLUMN IF NOT EXISTS emergencia2_celular TEXT;
    ALTER TABLE clientes ADD COLUMN IF NOT EXISTS metodo_pago TEXT;
    ALTER TABLE clientes ADD COLUMN IF NOT EXISTS metodo_pago_detalle TEXT;
    ALTER TABLE clientes ADD COLUMN IF NOT EXISTS elaborado_por TEXT;
    ALTER TABLE clientes ADD COLUMN IF NOT EXISTS firma_huella BOOLEAN DEFAULT false;
    ALTER TABLE clientes ADD COLUMN IF NOT EXISTS productos JSONB DEFAULT '[]'::jsonb;
    ALTER TABLE clientes ADD COLUMN IF NOT EXISTS closer2 TEXT;
    ALTER TABLE clientes ADD COLUMN IF NOT EXISTS numero_cuotas INTEGER;
    ALTER TABLE clientes ADD COLUMN IF NOT EXISTS fecha_primera_cuota DATE;
    ALTER TABLE clientes ADD COLUMN IF NOT EXISTS cuotas JSONB DEFAULT '[]'::jsonb;
  `);
}

const clienteCols = `
  id, fecha, usuario, edad, documento,
  fecha_nacimiento AS "fechaNacimiento", direccion, telefono, enfermedades,
  medicamentos, alergias, estado_civil AS "estadoCivil", eps, rh,
  dispositivos, dispositivos_cual AS "dispositivosCual", cirugias,
  observacion_usuario AS "observacionUsuario", firma_autorizacion AS "firmaAutorizacion",
  ocupacion, acompanante, edad_acomp AS "edadAcomp",
  call_center AS "callCenter", outsorsing, consultor, closer AS "closer1", closer2, gerente,
  tour, nt, vta, volumen, cash, cartera, contrato, observaciones,
  ciudad, codigo_venta AS "codigoVenta", numero_venta AS "numeroVenta",
  emergencia1_nombre AS "emergencia1Nombre", emergencia1_celular AS "emergencia1Celular",
  emergencia2_nombre AS "emergencia2Nombre", emergencia2_celular AS "emergencia2Celular",
  metodo_pago AS "metodoPago", metodo_pago_detalle AS "metodoPagoDetalle", elaborado_por AS "elaboradoPor",
  firma_huella AS "firmaHuella", productos,
  numero_cuotas AS "numeroCuotas", fecha_primera_cuota AS "fechaPrimeraCuota", cuotas,
  creado
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
        tour, nt, vta, volumen, cash, cartera, contrato, observaciones,
        ciudad, codigo_venta, numero_venta,
        emergencia1_nombre, emergencia1_celular, emergencia2_nombre, emergencia2_celular,
        metodo_pago, elaborado_por, firma_huella, productos, closer2,
        numero_cuotas, fecha_primera_cuota, cuotas, metodo_pago_detalle
      ) VALUES (
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,
        $35,$36,$37,$38,$39,$40,$41,$42,$43,$44,$45,$46,$47,$48,$49,$50
      ) RETURNING ${clienteCols}`,
      [
        c.fecha || null, c.usuario, c.edad || null, c.documento || null, c.fechaNacimiento || null,
        c.direccion || null, c.telefono || null, c.enfermedades || null, c.medicamentos || null,
        c.alergias || null, c.estadoCivil || null, c.eps || null, c.rh || null,
        !!c.dispositivos, c.dispositivosCual || null, c.cirugias || null,
        c.observacionUsuario || null, !!c.firmaAutorizacion,
        c.ocupacion || null, c.acompanante || null, c.edadAcomp || null,
        c.callCenter || null, c.outsorsing || null, c.consultor || null, c.closer1 || null, c.gerente || null,
        !!c.tour, !!c.nt, !!c.vta, c.volumen || 0, c.cash || 0, c.cartera || 0,
        c.contrato || null, c.observaciones || null,
        c.vta ? (c.ciudad || null) : null,
        c.vta ? (c.codigoVenta || null) : null,
        c.vta ? (c.numeroVenta || null) : null,
        c.vta ? (c.emergencia1Nombre || null) : null,
        c.vta ? (c.emergencia1Celular || null) : null,
        c.vta ? (c.emergencia2Nombre || null) : null,
        c.vta ? (c.emergencia2Celular || null) : null,
        c.vta ? (c.metodoPago || null) : null,
        c.vta ? (c.elaboradoPor || null) : null,
        c.vta ? !!c.firmaHuella : false,
        JSON.stringify(c.vta ? (Array.isArray(c.productos) ? c.productos : []) : []),
        c.closer2 || null,
        c.vta ? (c.numeroCuotas || null) : null,
        c.vta ? (c.fechaPrimeraCuota || null) : null,
        JSON.stringify(c.vta ? (Array.isArray(c.cuotas) ? c.cuotas : []) : []),
        c.vta ? (c.metodoPagoDetalle || null) : null
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

app.post('/api/callcenters', requirePerm('callcenters'), async (req, res) => {
  try {
    const { rows } = await pool.query(
      'INSERT INTO call_centers (nombre) VALUES ($1) ON CONFLICT (nombre) DO NOTHING RETURNING id, nombre',
      [req.body.nombre]
    );
    if (!rows[0]) return res.status(409).json({ error: 'Ya existe' });
    res.json({ ...rows[0], tmks: [] });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al crear call center' }); }
});

app.delete('/api/callcenters/:id', requirePerm('callcenters'), async (req, res) => {
  try {
    await pool.query('DELETE FROM call_centers WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al eliminar call center' }); }
});

app.post('/api/callcenters/:id/tmks', requirePerm('callcenters'), async (req, res) => {
  try {
    const { rows } = await pool.query(
      'INSERT INTO tmks (call_center_id, codigo) VALUES ($1, $2) RETURNING id, codigo',
      [req.params.id, req.body.codigo]
    );
    res.json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al agregar TMK' }); }
});

app.delete('/api/tmks/:id', requirePerm('callcenters'), async (req, res) => {
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

app.post('/api/equipo', requirePerm('equipo'), async (req, res) => {
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

app.delete('/api/equipo/:id', requirePerm('equipo'), async (req, res) => {
  try {
    await pool.query('DELETE FROM equipo WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al eliminar' }); }
});

// ---------- Autenticación ----------
app.post('/api/login', async (req, res) => {
  try {
    const { usuario, password } = req.body;
    const { rows } = await pool.query('SELECT * FROM usuarios WHERE usuario = $1', [usuario]);
    const u = rows[0];
    if (!u) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    const ok = await bcrypt.compare(password || '', u.password_hash);
    if (!ok) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    req.session.user = { id: u.id, nombre: u.nombre, usuario: u.usuario, rol: u.rol, permisos: u.permisos || {} };
    res.json(req.session.user);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al iniciar sesión' }); }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'No autenticado' });
  res.json(req.session.user);
});

// ---------- Usuarios (solo administrador) ----------
app.get('/api/usuarios', requirePerm('usuarios'), async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, nombre, usuario, rol, permisos FROM usuarios ORDER BY nombre');
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al leer usuarios' }); }
});

app.post('/api/usuarios', requirePerm('usuarios'), async (req, res) => {
  try {
    const { nombre, usuario, password, rol, permisos } = req.body;
    if (!nombre || !usuario || !password || !rol) return res.status(400).json({ error: 'Faltan datos' });
    if (!['administrador', 'consultor', 'closer', 'gerente', 'superadministrador'].includes(rol)) return res.status(400).json({ error: 'Rol inválido' });
    if (rol === 'superadministrador' && req.session.user.rol !== 'superadministrador') {
      return res.status(403).json({ error: 'Solo un Super Administrador puede crear otro Super Administrador' });
    }
    const hash = await bcrypt.hash(password, 10);
    const permisosSeguros = (req.session.user.rol === 'superadministrador' && permisos && typeof permisos === 'object') ? permisos : {};
    const { rows } = await pool.query(
      'INSERT INTO usuarios (nombre, usuario, password_hash, rol, permisos) VALUES ($1,$2,$3,$4,$5) RETURNING id, nombre, usuario, rol, permisos',
      [nombre, usuario, hash, rol, JSON.stringify(permisosSeguros)]
    );
    res.json(rows[0]);
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Ese usuario ya existe' });
    console.error(e); res.status(500).json({ error: 'Error al crear usuario' });
  }
});

app.patch('/api/usuarios/:id/permisos', requireSuperAdmin, async (req, res) => {
  try {
    const { permisos } = req.body;
    const { rows } = await pool.query(
      'UPDATE usuarios SET permisos = $1 WHERE id = $2 RETURNING id, nombre, usuario, rol, permisos',
      [JSON.stringify(permisos && typeof permisos === 'object' ? permisos : {}), req.params.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al actualizar permisos' }); }
});

app.delete('/api/usuarios/:id', requirePerm('usuarios'), async (req, res) => {
  try {
    if (String(req.session.user.id) === String(req.params.id)) {
      return res.status(400).json({ error: 'No puedes eliminar tu propio usuario' });
    }
    await pool.query('DELETE FROM usuarios WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al eliminar usuario' }); }
});

app.delete('/api/clientes/:id', requirePerm('borrarClientes'), async (req, res) => {
  try {
    await pool.query('DELETE FROM clientes WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al eliminar el registro' }); }
});

// ---------- Comentarios ----------
app.get('/api/clientes/:id/comentarios', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, usuario_nombre AS "usuarioNombre", usuario_login AS "usuarioLogin", comentario, creado
       FROM comentarios WHERE cliente_id = $1 ORDER BY creado DESC`,
      [req.params.id]
    );
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al leer comentarios' }); }
});

app.post('/api/clientes/:id/comentarios', async (req, res) => {
  try {
    const texto = (req.body.comentario || '').trim();
    if (!texto) return res.status(400).json({ error: 'El comentario no puede estar vacío' });
    const u = req.session.user;
    const { rows } = await pool.query(
      `INSERT INTO comentarios (cliente_id, usuario_nombre, usuario_login, comentario)
       VALUES ($1,$2,$3,$4)
       RETURNING id, usuario_nombre AS "usuarioNombre", usuario_login AS "usuarioLogin", comentario, creado`,
      [req.params.id, u.nombre, u.usuario, texto]
    );
    res.json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al guardar el comentario' }); }
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

async function seedAdmin() {
  const { rows } = await pool.query('SELECT COUNT(*)::int AS n FROM usuarios');
  if (rows[0].n === 0) {
    const hash = await bcrypt.hash('duovital2026', 10);
    await pool.query(
      'INSERT INTO usuarios (nombre, usuario, password_hash, rol) VALUES ($1,$2,$3,$4)',
      ['Super Administrador', 'admin', hash, 'superadministrador']
    );
    console.log('Usuario Super Administrador creado por defecto (admin / duovital2026) - cámbialo cuanto antes.');
  } else {
    const { rows: supers } = await pool.query("SELECT COUNT(*)::int AS n FROM usuarios WHERE rol = 'superadministrador'");
    if (supers[0].n === 0) {
      const { rows: adminRow } = await pool.query("SELECT id FROM usuarios WHERE usuario = 'admin' LIMIT 1");
      const targetId = adminRow[0] ? adminRow[0].id : (await pool.query('SELECT id FROM usuarios ORDER BY id ASC LIMIT 1')).rows[0].id;
      await pool.query("UPDATE usuarios SET rol = 'superadministrador' WHERE id = $1", [targetId]);
      console.log('Usuario existente promovido a Super Administrador (id ' + targetId + ').');
    }
  }
}

const PORT = process.env.PORT || 3000;
initDb()
  .then(seedAdmin)
  .then(() => {
    app.listen(PORT, () => console.log('Duo Vital CRM escuchando en puerto ' + PORT));
  })
  .catch(err => {
    console.error('Error inicializando la base de datos:', err);
    process.exit(1);
  });
