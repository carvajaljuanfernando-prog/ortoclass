// Ortoclass — servidor (Express + PostgreSQL)
// Sirve la interfaz (public/) y la API con autenticación, roles y auditoría.
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { pool, init, DEF_CONFIG } = require('./db');

const PORT = process.env.PORT || 3000;
const PROD = process.env.NODE_ENV === 'production';
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 24) {
  console.error('Falta JWT_SECRET (mínimo 24 caracteres). Defínelo en las variables de entorno.');
  process.exit(1);
}
if (!process.env.DATABASE_URL) { console.error('Falta DATABASE_URL.'); process.exit(1); }

const SESION_HORAS = Number(process.env.SESION_HORAS || 12);
const COOKIE = 'ortoclass_sesion';
const ROLES = ['admin', 'doctora', 'secretaria'];
// Campos clínicos del paciente que la secretaria no ve ni puede modificar
const CAMPOS_CLINICOS = ['evoluciones', 'antecedentes', 'alergias', 'medicamentos'];

const app = express();
app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdnjs.cloudflare.com'],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
      imgSrc: ["'self'", 'data:', 'blob:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"]
    }
  }
}));
app.use(compression());
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());

// ---------- utilidades ----------
const ahora = () => new Date().toISOString();
function emitirSesion(res, u) {
  const token = jwt.sign({ id: u.id, rol: u.rol }, JWT_SECRET, { expiresIn: `${SESION_HORAS}h` });
  res.cookie(COOKIE, token, { httpOnly: true, sameSite: 'lax', secure: PROD, maxAge: SESION_HORAS * 3600 * 1000 });
}
async function auditar(req, accion, coleccion, doc_id, detalle) {
  try {
    await pool.query(
      `INSERT INTO auditoria (usuario_id, usuario_nombre, accion, coleccion, doc_id, detalle, ip) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [req.user?.id || null, req.user?.nombre || null, accion, coleccion || null, doc_id || null, detalle ? JSON.stringify(detalle) : null, req.ip]);
  } catch (e) { console.error('auditoria', e.message); }
}
const publico = u => ({ id: u.id, nombre: u.nombre, correo: u.correo, rol: u.rol, profesionalId: u.profesional_id, activo: u.activo, debeCambiarClave: u.debe_cambiar_clave });

// ---------- autenticación ----------
async function auth(req, res, next) {
  try {
    const t = req.cookies[COOKIE];
    if (!t) return res.status(401).json({ error: 'no_autenticado' });
    const p = jwt.verify(t, JWT_SECRET);
    const { rows } = await pool.query('SELECT * FROM usuarios WHERE id=$1 AND activo=TRUE', [p.id]);
    if (!rows[0]) return res.status(401).json({ error: 'no_autenticado' });
    req.user = rows[0];
    next();
  } catch (e) { return res.status(401).json({ error: 'no_autenticado' }); }
}
const soloRoles = (...roles) => (req, res, next) => roles.includes(req.user.rol) ? next() : res.status(403).json({ error: 'sin_permiso' });

const limiteLogin = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false, message: { error: 'demasiados_intentos' } });

app.post('/api/login', limiteLogin, async (req, res) => {
  const correo = String(req.body.correo || '').trim().toLowerCase();
  const clave = String(req.body.clave || '');
  const { rows } = await pool.query('SELECT * FROM usuarios WHERE correo=$1', [correo]);
  const u = rows[0];
  if (!u || !u.activo) { await auditar(req, 'login_fallido', null, null, { correo }); return res.status(401).json({ error: 'credenciales' }); }
  if (u.bloqueado_hasta && new Date(u.bloqueado_hasta) > new Date()) return res.status(423).json({ error: 'bloqueado', hasta: u.bloqueado_hasta });
  const ok = await bcrypt.compare(clave, u.password_hash);
  if (!ok) {
    const n = u.intentos_fallidos + 1;
    const bloqueo = n >= 5 ? new Date(Date.now() + 15 * 60 * 1000) : null;
    await pool.query('UPDATE usuarios SET intentos_fallidos=$1, bloqueado_hasta=$2 WHERE id=$3', [bloqueo ? 0 : n, bloqueo, u.id]);
    await auditar(req, 'login_fallido', null, null, { correo });
    return res.status(401).json({ error: 'credenciales' });
  }
  await pool.query('UPDATE usuarios SET intentos_fallidos=0, bloqueado_hasta=NULL WHERE id=$1', [u.id]);
  emitirSesion(res, u);
  req.user = u; await auditar(req, 'login');
  res.json({ usuario: publico(u) });
});
app.post('/api/logout', auth, async (req, res) => { res.clearCookie(COOKIE); await auditar(req, 'logout'); res.json({ ok: true }); });
app.get('/api/me', auth, (req, res) => res.json({ usuario: publico(req.user) }));

app.post('/api/cambiar-clave', auth, async (req, res) => {
  const { actual, nueva } = req.body;
  if (typeof nueva !== 'string' || nueva.length < 8) return res.status(400).json({ error: 'clave_corta' });
  const ok = await bcrypt.compare(String(actual || ''), req.user.password_hash);
  if (!ok) return res.status(400).json({ error: 'clave_actual' });
  await pool.query('UPDATE usuarios SET password_hash=$1, debe_cambiar_clave=FALSE WHERE id=$2', [await bcrypt.hash(nueva, 12), req.user.id]);
  await auditar(req, 'cambio_clave');
  res.json({ ok: true });
});

// ---------- usuarios (solo admin) ----------
app.get('/api/usuarios', auth, soloRoles('admin'), async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM usuarios ORDER BY id');
  res.json({ usuarios: rows.map(publico) });
});
app.post('/api/usuarios', auth, soloRoles('admin'), async (req, res) => {
  const { nombre, correo, clave, rol, profesionalId } = req.body;
  if (!nombre || !correo || !clave || !ROLES.includes(rol)) return res.status(400).json({ error: 'datos' });
  if (String(clave).length < 8) return res.status(400).json({ error: 'clave_corta' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO usuarios (nombre, correo, password_hash, rol, profesional_id, debe_cambiar_clave) VALUES ($1,$2,$3,$4,$5,TRUE) RETURNING *`,
      [String(nombre).trim(), String(correo).trim().toLowerCase(), await bcrypt.hash(String(clave), 12), rol, profesionalId || null]);
    await auditar(req, 'usuario_creado', 'usuarios', String(rows[0].id), { correo: rows[0].correo, rol });
    res.json({ usuario: publico(rows[0]) });
  } catch (e) { res.status(400).json({ error: e.code === '23505' ? 'correo_existe' : 'datos' }); }
});
app.put('/api/usuarios/:id', auth, soloRoles('admin'), async (req, res) => {
  const id = Number(req.params.id);
  const { nombre, rol, profesionalId, activo, clave } = req.body;
  if (rol && !ROLES.includes(rol)) return res.status(400).json({ error: 'datos' });
  if (id === req.user.id && activo === false) return res.status(400).json({ error: 'no_autodesactivar' });
  const sets = []; const vals = []; let i = 1;
  if (nombre) { sets.push(`nombre=$${i++}`); vals.push(String(nombre).trim()); }
  if (rol) { sets.push(`rol=$${i++}`); vals.push(rol); }
  if (profesionalId !== undefined) { sets.push(`profesional_id=$${i++}`); vals.push(profesionalId || null); }
  if (typeof activo === 'boolean') { sets.push(`activo=$${i++}`); vals.push(activo); }
  if (clave) { if (String(clave).length < 8) return res.status(400).json({ error: 'clave_corta' }); sets.push(`password_hash=$${i++}`); vals.push(await bcrypt.hash(String(clave), 12)); sets.push('debe_cambiar_clave=TRUE'); sets.push('intentos_fallidos=0'); sets.push('bloqueado_hasta=NULL'); }
  if (!sets.length) return res.status(400).json({ error: 'datos' });
  vals.push(id);
  const { rows } = await pool.query(`UPDATE usuarios SET ${sets.join(',')} WHERE id=$${i} RETURNING *`, vals);
  if (!rows[0]) return res.status(404).json({ error: 'no_existe' });
  await auditar(req, 'usuario_actualizado', 'usuarios', String(id), { campos: Object.keys(req.body).filter(k => k !== 'clave'), claveRestablecida: !!clave });
  res.json({ usuario: publico(rows[0]) });
});

// ---------- configuración ----------
app.get('/api/config', auth, async (req, res) => {
  const { rows } = await pool.query('SELECT data FROM config WHERE id=1');
  res.json({ config: { ...DEF_CONFIG, ...rows[0].data } });
});
app.put('/api/config', auth, soloRoles('admin', 'doctora'), async (req, res) => {
  const data = req.body;
  if (!data || typeof data !== 'object') return res.status(400).json({ error: 'datos' });
  await pool.query('UPDATE config SET data=$1, actualizado_en=now() WHERE id=1', [data]);
  await auditar(req, 'config_actualizada');
  res.json({ ok: true });
});

// ---------- documentos: pacientes / citas / movimientos ----------
function filtrarPaciente(doc, rol) {
  if (rol !== 'secretaria') return doc;
  const d = { ...doc };
  CAMPOS_CLINICOS.forEach(k => { delete d[k]; });
  d.planes = (doc.planes || []).map(p => { const { descripcion, ...resto } = p; return resto; });
  d._restringido = true;
  return d;
}
function filtrar(coleccion, doc, rol) { return coleccion === 'pacientes' ? filtrarPaciente(doc, rol) : doc; }

app.get('/api/bootstrap', auth, async (req, res) => {
  const cfg = await pool.query('SELECT data FROM config WHERE id=1');
  const { rows } = await pool.query('SELECT coleccion, id, data, actualizado_en FROM documentos WHERE eliminado=FALSE');
  const out = { pacientes: {}, citas: {}, movimientos: {} };
  rows.forEach(r => { out[r.coleccion][r.id] = filtrar(r.coleccion, r.data, req.user.rol); });
  res.json({ usuario: publico(req.user), config: { ...DEF_CONFIG, ...cfg.rows[0].data }, ...out, desde: ahora() });
});
// Cambios desde una fecha (sondeo cada ~20 s desde el navegador)
app.get('/api/cambios', auth, async (req, res) => {
  const desde = req.query.desde ? new Date(req.query.desde) : new Date(0);
  if (isNaN(desde)) return res.status(400).json({ error: 'fecha' });
  const { rows } = await pool.query('SELECT coleccion, id, data, eliminado FROM documentos WHERE actualizado_en > $1', [desde]);
  const cfg = await pool.query('SELECT data, actualizado_en FROM config WHERE id=1');
  res.json({
    cambios: rows.map(r => ({ coleccion: r.coleccion, id: r.id, eliminado: r.eliminado, data: r.eliminado ? null : filtrar(r.coleccion, r.data, req.user.rol) })),
    config: new Date(cfg.rows[0].actualizado_en) > desde ? { ...DEF_CONFIG, ...cfg.rows[0].data } : null,
    desde: ahora()
  });
});

const COLECCIONES = ['pacientes', 'citas', 'movimientos'];
const idValido = id => /^[A-Za-z0-9_-]{1,64}$/.test(id);

app.put('/api/:coleccion/:id', auth, async (req, res) => {
  const { coleccion, id } = req.params;
  if (!COLECCIONES.includes(coleccion) || !idValido(id)) return res.status(404).json({ error: 'no_existe' });
  let data = req.body;
  if (!data || typeof data !== 'object' || Array.isArray(data)) return res.status(400).json({ error: 'datos' });
  data = { ...data, id };
  const prev = await pool.query('SELECT data FROM documentos WHERE coleccion=$1 AND id=$2 AND eliminado=FALSE', [coleccion, id]);
  const existente = prev.rows[0]?.data;
  const rol = req.user.rol;
  // La secretaria no puede escribir campos clínicos: se conservan los existentes
  if (coleccion === 'pacientes' && rol === 'secretaria') {
    CAMPOS_CLINICOS.forEach(k => { if (existente && existente[k] !== undefined) data[k] = existente[k]; else delete data[k]; });
    const prevPlanes = Object.fromEntries((existente?.planes || []).map(p => [p.id, p]));
    data.planes = (data.planes || []).map(p => ({ ...p, descripcion: prevPlanes[p.id]?.descripcion ?? '' }));
    delete data._restringido;
  }
  // Sello de quién registra (en evoluciones nuevas, citas y movimientos)
  const sello = { por: req.user.nombre, porId: req.user.id, en: ahora() };
  if (coleccion === 'pacientes' && Array.isArray(data.evoluciones)) {
    const prevEv = Object.fromEntries((existente?.evoluciones || []).map(e => [e.id, e]));
    const sinSellos = e => { const { _reg, _mod, ...r } = e; return JSON.stringify(r); };
    data.evoluciones = data.evoluciones.map(e => {
      const p = prevEv[e.id];
      if (!p) return { ...e, _reg: sello };
      const cambio = sinSellos(e) !== sinSellos(p);
      return { ...e, _reg: p._reg || sello, _mod: cambio ? sello : p._mod };
    });
  }
  if (!existente) data._reg = sello; else { data._reg = existente._reg || data._reg; data._mod = sello; }
  await pool.query(
    `INSERT INTO documentos (coleccion, id, data, creado_por, actualizado_por, eliminado) VALUES ($1,$2,$3,$4,$4,FALSE)
     ON CONFLICT (coleccion, id) DO UPDATE SET data=EXCLUDED.data, actualizado_por=EXCLUDED.actualizado_por, actualizado_en=now(), eliminado=FALSE`,
    [coleccion, id, data, req.user.id]);
  await auditar(req, existente ? 'actualizar' : 'crear', coleccion, id, resumenAuditoria(coleccion, data));
  res.json({ ok: true, data: filtrar(coleccion, data, rol) });
});
app.delete('/api/:coleccion/:id', auth, async (req, res) => {
  const { coleccion, id } = req.params;
  if (!COLECCIONES.includes(coleccion) || !idValido(id)) return res.status(404).json({ error: 'no_existe' });
  if (coleccion === 'pacientes' && req.user.rol === 'secretaria') return res.status(403).json({ error: 'sin_permiso' });
  await pool.query('UPDATE documentos SET eliminado=TRUE, actualizado_por=$3, actualizado_en=now() WHERE coleccion=$1 AND id=$2', [coleccion, id, req.user.id]);
  await auditar(req, 'eliminar', coleccion, id);
  res.json({ ok: true });
});
function resumenAuditoria(c, d) {
  if (c === 'pacientes') return { nombre: d.nombre, planes: (d.planes || []).length, evoluciones: (d.evoluciones || []).length };
  if (c === 'citas') return { pacienteId: d.pacienteId, fecha: d.fecha, hora: d.hora, estado: d.estado };
  if (c === 'movimientos') return { tipo: d.tipo, monto: d.monto, fecha: d.fecha, pacienteId: d.pacienteId || null };
  return null;
}

// ---------- auditoría (admin) ----------
app.get('/api/auditoria', auth, soloRoles('admin'), async (req, res) => {
  const { rows } = await pool.query('SELECT id, fecha, usuario_nombre, accion, coleccion, doc_id, detalle FROM auditoria ORDER BY id DESC LIMIT 300');
  res.json({ registros: rows });
});
// Respaldo completo (admin)
app.get('/api/respaldo', auth, soloRoles('admin'), async (req, res) => {
  const cfg = await pool.query('SELECT data FROM config WHERE id=1');
  const { rows } = await pool.query('SELECT coleccion, id, data FROM documentos WHERE eliminado=FALSE');
  const out = { generado: ahora(), config: cfg.rows[0].data, pacientes: {}, citas: {}, movimientos: {} };
  rows.forEach(r => { out[r.coleccion][r.id] = r.data; });
  await auditar(req, 'respaldo_descargado');
  res.setHeader('Content-Disposition', `attachment; filename="respaldo_ortoclass_${ahora().slice(0, 10)}.json"`);
  res.json(out);
});

app.get('/api/salud', (req, res) => res.json({ ok: true }));

// ---------- interfaz ----------
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1h' }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'servidor' }); });

init().then(() => app.listen(PORT, () => console.log(`Ortoclass escuchando en puerto ${PORT}`)))
  .catch(e => { console.error('No se pudo iniciar la base de datos:', e); process.exit(1); });
