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
app.use(express.json({ limit: '5mb' }));
app.use(session({
  store: new pgSession({ pool, tableName: 'session', createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || 'duovital-crm-secret-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: 'auto', httpOnly: true, maxAge: 1000 * 60 * 60 * 24 * 7 }
}));
app.use(express.static(path.join(__dirname, 'public')));

const ESTADOS_VALIDOS = ['Activo', 'Finalizado', 'Invitado', 'Cancelado', 'Devolución/Retracto'];

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
    ALTER TABLE clientes ADD COLUMN IF NOT EXISTS estado TEXT DEFAULT 'Activo';
    ALTER TABLE clientes ADD COLUMN IF NOT EXISTS fecha_contrato DATE;
    CREATE TABLE IF NOT EXISTS comentarios (
      id SERIAL PRIMARY KEY,
      cliente_id INTEGER NOT NULL REFERENCES clientes(id) ON DELETE CASCADE,
      usuario_nombre TEXT NOT NULL,
      usuario_login TEXT,
      comentario TEXT NOT NULL,
      creado TIMESTAMPTZ DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS recibos (
      id SERIAL PRIMARY KEY,
      cliente_id INTEGER NOT NULL REFERENCES clientes(id) ON DELETE CASCADE,
      numero_recibo TEXT,
      concepto TEXT,
      valor NUMERIC DEFAULT 0,
      fecha DATE,
      usuario_nombre TEXT NOT NULL,
      usuario_login TEXT,
      creado TIMESTAMPTZ DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS reconsultas (
      id SERIAL PRIMARY KEY,
      cliente_id INTEGER NOT NULL REFERENCES clientes(id) ON DELETE CASCADE,
      tipo_tratamiento TEXT,
      fecha DATE,
      producto TEXT,
      usuario_nombre TEXT NOT NULL,
      usuario_login TEXT,
      creado TIMESTAMPTZ DEFAULT now()
    );
    ALTER TABLE reconsultas ADD COLUMN IF NOT EXISTS numero INTEGER;
    ALTER TABLE reconsultas ADD COLUMN IF NOT EXISTS estado TEXT DEFAULT 'Realizada';
    ALTER TABLE clientes ADD COLUMN IF NOT EXISTS llave_import TEXT;
    CREATE INDEX IF NOT EXISTS idx_clientes_llave_import ON clientes(llave_import);
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
  estado, fecha_contrato AS "fechaContrato",
  creado
`;

// ---------- Clientes ----------
app.get('/api/clientes', async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT ${clienteCols} FROM clientes ORDER BY creado DESC`);
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al leer clientes' }); }
});

app.get('/api/clientes/:id', async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT ${clienteCols} FROM clientes WHERE id = $1`, [req.params.id]);
    if (!rows[0]) return res.status(404).json({ error: 'No encontrado' });
    res.json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al leer el cliente' }); }
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
        numero_cuotas, fecha_primera_cuota, cuotas, metodo_pago_detalle, estado, fecha_contrato
      ) VALUES (
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,
        $35,$36,$37,$38,$39,$40,$41,$42,$43,$44,$45,$46,$47,$48,$49,$50,$51,$52
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
        c.vta ? (c.metodoPagoDetalle || null) : null,
        c.vta ? 'Activo' : 'Invitado',
        c.fechaContrato || null
      ]
    );
    res.json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al guardar cliente' }); }
});

app.patch('/api/clientes/:id/estado', async (req, res) => {
  try {
    const { estado } = req.body;
    if (!ESTADOS_VALIDOS.includes(estado)) {
      return res.status(400).json({ error: 'Estado inválido' });
    }
    const { rows } = await pool.query(
      `UPDATE clientes SET estado = $1 WHERE id = $2 RETURNING ${clienteCols}`,
      [estado, req.params.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'No encontrado' });
    res.json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al actualizar el estado' }); }
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

// ---------- Recibos de caja ----------
app.get('/api/clientes/:id/recibos', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, numero_recibo AS "numeroRecibo", concepto, valor, fecha,
              usuario_nombre AS "usuarioNombre", usuario_login AS "usuarioLogin", creado
       FROM recibos WHERE cliente_id = $1 ORDER BY fecha DESC, creado DESC`,
      [req.params.id]
    );
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al leer recibos' }); }
});

app.post('/api/clientes/:id/recibos', async (req, res) => {
  try {
    const { numeroRecibo, concepto, valor, fecha } = req.body;
    if (!fecha || !valor) return res.status(400).json({ error: 'Faltan datos del recibo' });
    const u = req.session.user;
    const { rows } = await pool.query(
      `INSERT INTO recibos (cliente_id, numero_recibo, concepto, valor, fecha, usuario_nombre, usuario_login)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       RETURNING id, numero_recibo AS "numeroRecibo", concepto, valor, fecha, usuario_nombre AS "usuarioNombre", usuario_login AS "usuarioLogin", creado`,
      [req.params.id, numeroRecibo || null, concepto || null, valor || 0, fecha, u.nombre, u.usuario]
    );

    const conceptosQueAbonan = ['Cuota inicial', 'Cuota financiación', 'Abono', 'Otro'];
    let cuotasActualizadas = null;
    let carteraActualizada = null;
    if (conceptosQueAbonan.includes(concepto)) {
      const { rows: clienteRows } = await pool.query('SELECT cuotas, cartera FROM clientes WHERE id = $1', [req.params.id]);
      if (clienteRows[0]) {
        let cuotas = Array.isArray(clienteRows[0].cuotas) ? clienteRows[0].cuotas : [];
        let restante = Number(valor);
        cuotas = cuotas.map(q => ({ ...q, pagado: q.pagado || 0 }));
        cuotas.sort((a, b) => (a.numero || 0) - (b.numero || 0));
        for (const cuota of cuotas) {
          if (restante <= 0) break;
          const pendiente = Number(cuota.monto || 0) - Number(cuota.pagado || 0);
          if (pendiente <= 0) continue;
          const aplicar = Math.min(restante, pendiente);
          cuota.pagado = Number(cuota.pagado || 0) + aplicar;
          restante -= aplicar;
          if (cuota.pagado >= Number(cuota.monto || 0)) {
            cuota.fechaPago = cuota.fechaPago || fecha;
          }
        }
        const nuevaCartera = Math.max(Number(clienteRows[0].cartera || 0) - Number(valor), 0);
        await pool.query('UPDATE clientes SET cuotas = $1, cartera = $2 WHERE id = $3', [JSON.stringify(cuotas), nuevaCartera, req.params.id]);
        cuotasActualizadas = cuotas;
        carteraActualizada = nuevaCartera;
      }
    }

    res.json({ ...rows[0], cuotas: cuotasActualizadas, cartera: carteraActualizada });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al guardar el recibo' }); }
});

app.delete('/api/recibos/:id', requirePerm('borrarRecibos'), async (req, res) => {
  try {
    const { rows: reciboRows } = await pool.query('SELECT cliente_id, valor, concepto FROM recibos WHERE id = $1', [req.params.id]);
    const recibo = reciboRows[0];
    await pool.query('DELETE FROM recibos WHERE id = $1', [req.params.id]);

    const conceptosQueAbonan = ['Cuota inicial', 'Cuota financiación', 'Abono', 'Otro'];
    if (recibo && conceptosQueAbonan.includes(recibo.concepto)) {
      const { rows: clienteRows } = await pool.query('SELECT cuotas, cartera FROM clientes WHERE id = $1', [recibo.cliente_id]);
      if (clienteRows[0]) {
        let cuotas = Array.isArray(clienteRows[0].cuotas) ? clienteRows[0].cuotas : [];
        let restante = Number(recibo.valor);
        cuotas.sort((a, b) => (b.numero || 0) - (a.numero || 0));
        for (const cuota of cuotas) {
          if (restante <= 0) break;
          const pagado = Number(cuota.pagado || 0);
          if (pagado <= 0) continue;
          const revertir = Math.min(restante, pagado);
          cuota.pagado = pagado - revertir;
          restante -= revertir;
          if (cuota.pagado < Number(cuota.monto || 0)) cuota.fechaPago = '';
        }
        cuotas.sort((a, b) => (a.numero || 0) - (b.numero || 0));
        const nuevaCartera = Number(clienteRows[0].cartera || 0) + Number(recibo.valor);
        await pool.query('UPDATE clientes SET cuotas = $1, cartera = $2 WHERE id = $3', [JSON.stringify(cuotas), nuevaCartera, recibo.cliente_id]);
      }
    }
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al eliminar el recibo' }); }
});

// ---------- Reconsultas (Usos) ----------
app.get('/api/clientes/:id/reconsultas', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, tipo_tratamiento AS "tipoTratamiento", fecha, producto, numero, estado,
              usuario_nombre AS "usuarioNombre", usuario_login AS "usuarioLogin", creado
       FROM reconsultas WHERE cliente_id = $1 ORDER BY fecha DESC NULLS LAST, creado DESC`,
      [req.params.id]
    );
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al leer reconsultas' }); }
});

app.post('/api/clientes/:id/reconsultas', async (req, res) => {
  try {
    const { tipoTratamiento, fecha, producto } = req.body;
    if (!fecha) return res.status(400).json({ error: 'Falta la fecha de la reconsulta' });
    const u = req.session.user;
    const { rows } = await pool.query(
      `INSERT INTO reconsultas (cliente_id, tipo_tratamiento, fecha, producto, usuario_nombre, usuario_login)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING id, tipo_tratamiento AS "tipoTratamiento", fecha, producto, usuario_nombre AS "usuarioNombre", usuario_login AS "usuarioLogin", creado`,
      [req.params.id, tipoTratamiento || null, fecha, producto || null, u.nombre, u.usuario]
    );
    res.json(rows[0]);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al guardar la reconsulta' }); }
});

app.delete('/api/reconsultas/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM reconsultas WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Error al eliminar la reconsulta' }); }
});


// ---------- Carga masiva (importación desde Excel) ----------
function normKey(x) {
  return String(x == null ? '' : x).normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toUpperCase().replace(/\s+/g, ' ').trim();
}
function llaveCliente(usuario, contrato) {
  return normKey(usuario) + '|' + normKey(contrato);
}
const esFechaIso = (v) => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v) && !isNaN(Date.parse(v + 'T00:00:00Z'));
const txt = (v) => (v === undefined || v === null || String(v).trim() === '') ? null : String(v).trim();
const num = (v) => (v === undefined || v === null || v === '' || isNaN(Number(v))) ? null : Number(v);

function generarCuotas(cartera, n, fechaIso) {
  if (!cartera || !n || n < 1 || !esFechaIso(fechaIso)) return [];
  const base = Math.floor(cartera / n);
  const resto = cartera - base * n;
  const [y, m, d] = fechaIso.split('-').map(Number);
  const out = [];
  let saldo = cartera;
  for (let i = 0; i < n; i++) {
    const primero = new Date(Date.UTC(y, (m - 1) + i, 1));
    const ultimoDia = new Date(Date.UTC(primero.getUTCFullYear(), primero.getUTCMonth() + 1, 0)).getUTCDate();
    const f = new Date(Date.UTC(primero.getUTCFullYear(), primero.getUTCMonth(), Math.min(d, ultimoDia)));
    const monto = base + (i === n - 1 ? resto : 0);
    out.push({ numero: i + 1, monto, capital: monto, saldo, fecha: f.toISOString().slice(0, 10), fechaPago: '', pagado: 0 });
    saldo -= monto;
  }
  return out;
}

app.post('/api/importar', requirePerm('cargaMasiva'), async (req, res) => {
  const { modo, actualizar } = req.body;
  const clientesIn = Array.isArray(req.body.clientes) ? req.body.clientes : [];
  const sueltasIn = Array.isArray(req.body.reconsultasSueltas) ? req.body.reconsultasSueltas : [];
  const simular = modo === 'validar';
  const u = req.session.user;
  const resumen = { creados: 0, actualizados: 0, omitidos: 0, reconsultasCreadas: 0, reconsultasOmitidas: 0, equipoCreado: 0, callCentersCreados: 0, tmksCreados: 0, equipoNuevo: [], callCentersNuevos: [], tmksNuevos: [], errores: [] };
  const db = await pool.connect();
  try {
    await db.query('BEGIN');
    const equipoVisto = new Set();
    const asegurarEquipo = async (tipo, nombre) => {
      const n = txt(nombre); if (!n) return;
      const k = tipo + '|' + normKey(n);
      if (equipoVisto.has(k)) return;
      equipoVisto.add(k);
      const ex = await db.query('SELECT 1 FROM equipo WHERE tipo = $1 AND upper(trim(nombre)) = upper($2)', [tipo, n]);
      if (!ex.rows.length) { await db.query('INSERT INTO equipo (tipo, nombre) VALUES ($1,$2)', [tipo, n]); resumen.equipoCreado++; resumen.equipoNuevo.push(tipo + ': ' + n); }
    };
    const ccVisto = new Set();
    const asegurarCallCenter = async (callCenter, tmk) => {
      const cc = txt(callCenter); if (!cc) return;
      let id;
      const ex = await db.query('SELECT id FROM call_centers WHERE upper(trim(nombre)) = upper($1)', [cc]);
      if (ex.rows.length) id = ex.rows[0].id;
      else { const ins = await db.query('INSERT INTO call_centers (nombre) VALUES ($1) RETURNING id', [cc]); id = ins.rows[0].id; resumen.callCentersCreados++; resumen.callCentersNuevos.push(cc); }
      const t = txt(tmk); if (!t) return;
      const k = id + '|' + normKey(t);
      if (ccVisto.has(k)) return;
      ccVisto.add(k);
      const ext = await db.query('SELECT 1 FROM tmks WHERE call_center_id = $1 AND upper(trim(codigo)) = upper($2)', [id, t]);
      if (!ext.rows.length) { await db.query('INSERT INTO tmks (call_center_id, codigo) VALUES ($1,$2)', [id, t]); resumen.tmksCreados++; resumen.tmksNuevos.push(cc + ': ' + t); }
    };
    const insertarReconsulta = async (clienteId, r, etiqueta) => {
      const fecha = esFechaIso(r.fecha) ? r.fecha : null;
      const tipo = txt(r.tipoTratamiento);
      const numero = num(r.numero);
      const estado = ['Realizada', 'Pendiente', 'Programada'].includes(r.estado) ? r.estado : 'Realizada';
      const ex = await db.query(
        `SELECT 1 FROM reconsultas WHERE cliente_id = $1 AND COALESCE(tipo_tratamiento,'') = $2
           AND fecha IS NOT DISTINCT FROM $3::date AND numero IS NOT DISTINCT FROM $4::int AND COALESCE(estado,'Realizada') = $5`,
        [clienteId, tipo || '', fecha, numero, estado]);
      if (ex.rows.length) { resumen.reconsultasOmitidas++; return; }
      await db.query(
        `INSERT INTO reconsultas (cliente_id, tipo_tratamiento, fecha, producto, numero, estado, usuario_nombre, usuario_login)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [clienteId, tipo, fecha, txt(r.producto), numero, estado, u.nombre + ' (carga masiva)', u.usuario]);
      resumen.reconsultasCreadas++;
    };

    for (const c of clientesIn) {
      const etiqueta = `${c.usuario || '(sin nombre)'} · contrato ${c.contrato || '—'}`;
      try {
        if (!txt(c.usuario)) throw new Error('Falta el nombre del usuario');
        if (!esFechaIso(c.fecha)) throw new Error('Fecha vacía o inválida');
        const llave = llaveCliente(c.usuario, c.contrato);
        const vta = c.vta === true || c.vta === 'Sí' || c.vta === 'Si';
        const estado = ESTADOS_VALIDOS.includes(c.estado) ? c.estado : (vta ? 'Activo' : 'Invitado');
        const volumen = num(c.volumen), cash = num(c.cash), cartera = num(c.cartera);
        const nCuotas = Number.isInteger(num(c.numeroCuotas)) && num(c.numeroCuotas) > 0 ? num(c.numeroCuotas) : null;
        const fPrimera = esFechaIso(c.fechaPrimeraCuota) ? c.fechaPrimeraCuota : null;

        await asegurarEquipo('consultor', c.consultor);
        await asegurarEquipo('closer', c.closer1);
        await asegurarEquipo('closer', c.closer2);
        await asegurarEquipo('gerente', c.gerente);
        await asegurarCallCenter(c.callCenter, c.outsorsing);

        const ex = await db.query('SELECT id FROM clientes WHERE llave_import = $1 LIMIT 1', [llave]);
        let clienteId;
        if (ex.rows.length) {
          clienteId = ex.rows[0].id;
          if (actualizar) {
            const tieneRecibos = (await db.query('SELECT 1 FROM recibos WHERE cliente_id = $1 LIMIT 1', [clienteId])).rows.length > 0;
            const campos = {
              fecha: c.fecha, fecha_contrato: esFechaIso(c.fechaContrato) ? c.fechaContrato : null,
              documento: txt(c.documento), telefono: txt(c.telefono), edad: txt(c.edad), ocupacion: txt(c.ocupacion),
              estado_civil: txt(c.estadoCivil), acompanante: txt(c.acompanante), call_center: txt(c.callCenter), outsorsing: txt(c.outsorsing),
              consultor: txt(c.consultor), closer: txt(c.closer1), closer2: txt(c.closer2), gerente: txt(c.gerente),
              ciudad: txt(c.ciudad), metodo_pago: txt(c.metodoPago), observaciones: txt(c.observaciones),
              estado: ESTADOS_VALIDOS.includes(c.estado) ? c.estado : null,
              numero_cuotas: nCuotas, fecha_primera_cuota: fPrimera
            };
            if (!tieneRecibos) {
              if (volumen !== null) campos.volumen = volumen;
              if (cash !== null) campos.cash = cash;
              if (cartera !== null) campos.cartera = cartera;
              if (cartera && nCuotas && fPrimera) campos.cuotas = JSON.stringify(generarCuotas(cartera, nCuotas, fPrimera));
            }
            const cols = Object.keys(campos).filter(k => campos[k] !== null && campos[k] !== undefined);
            if (cols.length) {
              const sets = cols.map((k, i) => `${k} = $${i + 1}`).join(', ');
              await db.query(`UPDATE clientes SET ${sets} WHERE id = $${cols.length + 1}`, [...cols.map(k => campos[k]), clienteId]);
            }
            resumen.actualizados++;
          } else {
            resumen.omitidos++;
          }
        } else {
          const cuotas = (cartera && nCuotas && fPrimera) ? generarCuotas(cartera, nCuotas, fPrimera) : [];
          const ins = await db.query(
            `INSERT INTO clientes (fecha, fecha_contrato, usuario, edad, documento, telefono, ocupacion, estado_civil, acompanante,
               call_center, outsorsing, consultor, closer, closer2, gerente, ciudad, metodo_pago, numero_cuotas, fecha_primera_cuota,
               vta, volumen, cash, cartera, contrato, numero_venta, observaciones, estado, cuotas, llave_import)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29)
             RETURNING id`,
            [c.fecha, esFechaIso(c.fechaContrato) ? c.fechaContrato : c.fecha, txt(c.usuario), txt(c.edad), txt(c.documento), txt(c.telefono),
             txt(c.ocupacion), txt(c.estadoCivil), txt(c.acompanante), txt(c.callCenter), txt(c.outsorsing), txt(c.consultor),
             txt(c.closer1), txt(c.closer2), txt(c.gerente), txt(c.ciudad), txt(c.metodoPago), nCuotas, fPrimera,
             vta, volumen || 0, cash || 0, cartera || 0, txt(c.contrato), txt(c.contrato), txt(c.observaciones), estado,
             JSON.stringify(cuotas), llave]);
          clienteId = ins.rows[0].id;
          resumen.creados++;
        }
        for (const r of (Array.isArray(c.reconsultas) ? c.reconsultas : [])) await insertarReconsulta(clienteId, r, etiqueta);
      } catch (e) {
        resumen.errores.push({ usuario: c.usuario || '', contrato: c.contrato || '', error: e.message });
      }
    }

    for (const r of sueltasIn) {
      try {
        const llave = llaveCliente(r.usuario, r.contrato);
        const ex = await db.query('SELECT id FROM clientes WHERE llave_import = $1 LIMIT 1', [llave]);
        if (!ex.rows.length) throw new Error('No existe un cliente con ese usuario y contrato');
        await insertarReconsulta(ex.rows[0].id, r, '');
      } catch (e) {
        resumen.errores.push({ usuario: r.usuario || '', contrato: r.contrato || '', error: 'Reconsulta: ' + e.message });
      }
    }

    await db.query(simular ? 'ROLLBACK' : 'COMMIT');
    res.json(resumen);
  } catch (e) {
    try { await db.query('ROLLBACK'); } catch (_) {}
    console.error(e);
    res.status(500).json({ error: 'Error en la carga: ' + e.message });
  } finally {
    db.release();
  }
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
