# Ortoclass — Plataforma de gestión del consultorio

Aplicación web para consultorio de odontología, ortodoncia y rehabilitación oral:
agenda, pacientes, planes de tratamiento, evolución clínica, recordatorios por WhatsApp,
recomendaciones de cuidado, cuentas (ingresos, gastos, cartera) y exportación a Excel.

- **Backend:** Node.js 18+ / Express / PostgreSQL
- **Frontend:** HTML + CSS + JavaScript (un solo archivo en `public/index.html`), responsive (celular y computador)
- **Seguridad:** login con correo y contraseña (bcrypt), sesiones firmadas (JWT en cookie httpOnly), roles verificados en el servidor, bloqueo tras 5 intentos fallidos, límite de intentos de login, cabeceras de seguridad (helmet), registro de auditoría de todas las acciones.

## Roles

| Rol | Puede |
|---|---|
| **admin** | Todo. Crea y desactiva usuarios, restablece contraseñas, descarga respaldo y ve el registro de actividad. |
| **doctora** | Agenda, pacientes completos (antecedentes, planes, evolución), recomendaciones, cuentas, ajustes del consultorio. Su agenda se filtra por defecto a su nombre. |
| **secretaria** | Agenda, datos de contacto de pacientes, recordatorios por WhatsApp, pagos y gastos, Excel. **No ve ni puede modificar** antecedentes, alergias, medicamentos, evoluciones ni la descripción clínica de los planes (el servidor lo impide aunque se intente por la API). No puede eliminar pacientes. |

Toda cita, pago y evolución queda sellada con quién la registró y cuándo; las evoluciones editadas conservan quién las modificó.

## Estructura

```
ortoclass/
├── server.js        # API, autenticación, roles, auditoría; sirve public/
├── db.js            # conexión PostgreSQL, esquema y usuario admin inicial
├── public/
│   └── index.html   # la interfaz completa
├── package.json
├── railway.json
├── .env.example
└── README.md
```

## Despliegue en Railway (10 minutos)

1. Sube esta carpeta a un repositorio de GitHub (por ejemplo `ortoclass`).
2. En [railway.app](https://railway.app): **New Project → Deploy from GitHub repo** y elige el repositorio.
3. En el mismo proyecto: **+ New → Database → PostgreSQL**. Railway crea la variable `DATABASE_URL` en el servicio de la base de datos.
4. En el servicio de la aplicación → **Variables**, agrega:
   - `DATABASE_URL` → usa la referencia `${{Postgres.DATABASE_URL}}` (botón *Add Reference*)
   - `JWT_SECRET` → un texto aleatorio largo (genera uno con `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`)
   - `ADMIN_EMAIL` → correo del administrador (tú)
   - `ADMIN_PASSWORD` → contraseña provisional (se pide cambiarla al primer ingreso)
   - `NODE_ENV` → `production`
5. **Settings → Networking → Generate Domain**. Railway entrega una URL `https://ortoclass-xxxx.up.railway.app`.
6. Abre la URL, ingresa con el administrador, cambia la contraseña y en **Ajustes → Usuarios** crea los usuarios de las doctoras (rol *Odontóloga*, asociadas a su profesional) y de la secretaria.

Para un dominio propio (`ortoclass.com.co`): en el proveedor del dominio crea un registro CNAME hacia la URL de Railway y agrégalo en **Settings → Networking → Custom Domain**. HTTPS es automático.

## Correr en el computador (opcional)

```bash
npm install
cp .env.example .env     # edita DATABASE_URL y JWT_SECRET
npm start                # http://localhost:3000
```

Requiere una base PostgreSQL accesible desde `DATABASE_URL`.

## Operación y seguridad recomendadas

- **Respaldos:** Railway hace respaldos de la base de datos; además, descarga semanalmente el **Respaldo completo (JSON)** desde Ajustes (solo admin) y guárdalo en una carpeta segura (p. ej. Google Drive del consultorio). El Excel completo también sirve como copia legible.
- **Contraseñas:** mínimo 8 caracteres; cada persona con su usuario, nunca compartidos. Si alguien se retira, desactívala en Ajustes → Usuarios.
- **Historia clínica:** las evoluciones son historia clínica (Resolución 1995/1999 y 839/2017): no eliminar registros, conservar mínimo 15 años, acceso restringido (por eso la secretaria no las ve).
- **Datos personales:** Ley 1581/2012. Tener la política de tratamiento de datos del consultorio y la autorización firmada de cada paciente.
- **WhatsApp:** los mensajes salen desde la línea WhatsApp (Business) del consultorio con un toque; la plataforma redacta el texto y registra el envío. El envío 100 % automático requiere la API de WhatsApp Business (Meta) y puede integrarse después.

## Costos aproximados

| Concepto | Costo |
|---|---|
| Railway (aplicación + PostgreSQL, plan Hobby) | ~US$5/mes |
| Dominio `.com.co` | ~$60.000–90.000 COP/año |
| WhatsApp Business (app) | gratis |

## API (resumen)

| Método | Ruta | Rol |
|---|---|---|
| POST | `/api/login`, `/api/logout`, `/api/cambiar-clave` | todos |
| GET | `/api/me`, `/api/bootstrap`, `/api/cambios?desde=` | todos |
| PUT/DELETE | `/api/pacientes/:id`, `/api/citas/:id`, `/api/movimientos/:id` | todos (con filtros por rol) |
| GET/PUT | `/api/config` | lectura todos; escritura admin y doctora |
| GET/POST/PUT | `/api/usuarios` | admin |
| GET | `/api/auditoria`, `/api/respaldo` | admin |

## Licencia

Código propiedad del autor. Uso autorizado para el consultorio Ortoclass según acuerdo de entrega.
