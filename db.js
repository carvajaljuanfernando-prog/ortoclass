// Conexión a PostgreSQL y creación del esquema.
// Diseño: cada entidad (paciente, cita, movimiento) se guarda como documento JSON
// con metadatos de auditoría. Es simple, flexible y suficiente para un consultorio.
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const ssl = process.env.DATABASE_SSL === 'false' ? false
  : (process.env.DATABASE_URL && /railway|render|amazonaws|supabase|neon/.test(process.env.DATABASE_URL) ? { rejectUnauthorized: false } : false);

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl });

const SCHEMA = `
CREATE TABLE IF NOT EXISTS usuarios (
  id SERIAL PRIMARY KEY,
  nombre TEXT NOT NULL,
  correo TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  rol TEXT NOT NULL CHECK (rol IN ('admin','doctora','secretaria')),
  profesional_id TEXT,
  activo BOOLEAN NOT NULL DEFAULT TRUE,
  debe_cambiar_clave BOOLEAN NOT NULL DEFAULT TRUE,
  intentos_fallidos INT NOT NULL DEFAULT 0,
  bloqueado_hasta TIMESTAMPTZ,
  creado_en TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS config (
  id INT PRIMARY KEY DEFAULT 1,
  data JSONB NOT NULL,
  actualizado_en TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS documentos (
  coleccion TEXT NOT NULL CHECK (coleccion IN ('pacientes','citas','movimientos')),
  id TEXT NOT NULL,
  data JSONB NOT NULL,
  eliminado BOOLEAN NOT NULL DEFAULT FALSE,
  creado_por INT REFERENCES usuarios(id),
  creado_en TIMESTAMPTZ NOT NULL DEFAULT now(),
  actualizado_por INT REFERENCES usuarios(id),
  actualizado_en TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (coleccion, id)
);
CREATE INDEX IF NOT EXISTS documentos_actualizado_idx ON documentos (actualizado_en);
CREATE TABLE IF NOT EXISTS auditoria (
  id BIGSERIAL PRIMARY KEY,
  fecha TIMESTAMPTZ NOT NULL DEFAULT now(),
  usuario_id INT,
  usuario_nombre TEXT,
  accion TEXT NOT NULL,
  coleccion TEXT,
  doc_id TEXT,
  detalle JSONB,
  ip TEXT
);
CREATE INDEX IF NOT EXISTS auditoria_fecha_idx ON auditoria (fecha DESC);
`;

const DEF_CONFIG = {
  nombre: 'Ortoclass', direccion: '', telefono: '', duracionCita: 30,
  profesionales: [
    { id: 'p1', nombre: 'Dra. Sandra Sofía Sepúlveda Sierra', rol: 'Ortodoncia', color: 2 },
    { id: 'p2', nombre: 'Dra. Leidy Mercedes Sepúlveda Sierra', rol: 'Rehabilitación oral', color: 3 }
  ],
  plantillas: {
    recordatorio: 'Hola {nombre} 👋, te recordamos tu cita en {consultorio} el {fecha} a las {hora} con {profesional}. Motivo: {motivo}. Por favor confirma respondiendo este mensaje. ¡Te esperamos! 🦷',
    confirmacion: 'Hola {nombre}, tu cita en {consultorio} quedó agendada para el {fecha} a las {hora} con {profesional}. Cualquier cambio avísanos con anticipación. ¡Gracias!',
    inasistencia: 'Hola {nombre}, notamos que no pudiste asistir a tu cita del {fecha}. Escríbenos para reprogramarla y continuar tu tratamiento. 🦷'
  },
  recomendaciones: null
};

async function init() {
  await pool.query(SCHEMA);
  await pool.query(`INSERT INTO config (id, data) VALUES (1, $1) ON CONFLICT (id) DO NOTHING`, [DEF_CONFIG]);
  const { rows } = await pool.query('SELECT count(*)::int AS n FROM usuarios');
  if (rows[0].n === 0) {
    const correo = (process.env.ADMIN_EMAIL || 'admin@ortoclass.local').toLowerCase();
    const clave = process.env.ADMIN_PASSWORD || 'Ortoclass2026*';
    const hash = await bcrypt.hash(clave, 12);
    await pool.query(
      `INSERT INTO usuarios (nombre, correo, password_hash, rol, debe_cambiar_clave) VALUES ($1,$2,$3,'admin',TRUE)`,
      ['Administrador', correo, hash]);
    console.log(`[init] Usuario administrador creado: ${correo} (debe cambiar la clave al primer ingreso)`);
  }
}

module.exports = { pool, init, DEF_CONFIG };
