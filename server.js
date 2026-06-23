require('dotenv').config();
const express = require('express');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const compression = require('compression');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'clave_secreta';

// Middlewares globales
app.use(cors());
app.use(express.json());
app.use(compression());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// Configuración de Multer (máx 5MB, solo imágenes)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const p = path.join(__dirname, 'uploads');
    if (!fs.existsSync(p)) fs.mkdirSync(p);
    cb(null, p);
  },
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, unique + path.extname(file.originalname));
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) {
      return cb(new Error('Solo se permiten imágenes'));
    }
    cb(null, true);
  }
});

// Transporte de correo (puede fallar silenciosamente)
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: +process.env.EMAIL_PORT,
  secure: false,
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

// ─── ESQUEMAS DE MONGOOSE ──────────────────────────────
const userSchema = new mongoose.Schema({
  dni: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  nombre: { type: String, default: 'Vecino' },
  role: { type: String, enum: ['admin', 'vecino'], default: 'vecino' },
  confianza: { type: Number, default: 0 }
});

const quejaSchema = new mongoose.Schema({
  codigo: { type: String, required: true, unique: true },
  usuario_dni: String,
  titulo: String,
  descripcion: String,
  categoria: String,
  estado: {
    type: String,
    enum: ['En espera', 'En proceso', 'Terminado'],
    default: 'En espera'
  },
  latitud: Number,
  longitud: Number,
  fotos: [String],
  fecha: { type: Date, default: Date.now },
  historial: [{ estado: String, fecha: Date }],
  comentarios: [{ autor: String, texto: String, fecha: Date }],        // internos (admin)
  comentarios_publicos: [{ autor: String, texto: String, fecha: Date }] // públicos
});

const User = mongoose.model('User', userSchema);
const Queja = mongoose.model('Queja', quejaSchema);

function generarCodigo() {
  return Math.random().toString(36).substr(2, 6).toUpperCase();
}

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token requerido' });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(403).json({ error: 'Token inválido' });
  }
}

function adminMiddleware(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Solo administradores' });
  next();
}

function dentroDeAte(lat, lng) {
  const poligono = [
    [-11.992589, -76.782859],[-12.015341, -76.783159],[-12.038093, -76.783460],
    [-12.062546, -76.783760],[-12.084879, -76.877500],[-12.084879, -76.950000],
    [-12.076500, -76.955000],[-12.063479, -76.960704],[-12.053301, -76.965928],
    [-12.045000, -76.972119],[-12.036699, -76.978310],[-12.028398, -76.984501],
    [-12.020097, -76.990692],[-12.011796, -76.996883],[-12.010000, -76.998096],
    [-11.992589, -76.998096]
  ];
  let inside = false;
  for (let i = 0, j = poligono.length - 1; i < poligono.length; j = i++) {
    const xi = poligono[i][0], yi = poligono[i][1];
    const xj = poligono[j][0], yj = poligono[j][1];
    if ((yi > lng) !== (yj > lng) && lat < (xj - xi) * (lng - yi) / (yj - yi) + xi) {
      inside = !inside;
    }
  }
  return inside;
}

// ─── CONEXIÓN A MONGODB + CREACIÓN DE ADMIN POR DEFECTO ─
mongoose.connect(process.env.MONGODB_URI)
  .then(async () => {
    console.log('MongoDB conectado');
    const adminExistente = await User.findOne({ email: 'admin@admin.com' });
    if (!adminExistente) {
      const hash = await bcrypt.hash('admin', 10);
      await User.create({
        dni: '00000001',
        email: 'admin@admin.com',
        password: hash,
        nombre: 'Administrador',
        role: 'admin'
      });
      console.log('✅ Administrador por defecto creado (admin@admin.com / admin)');
    }
  })
  .catch(err => console.error('Error MongoDB:', err));

// ─── AUTENTICACIÓN ──────────────────────────────────────
app.post('/api/register', async (req, res) => {
  try {
    const { dni, email, password, nombre } = req.body;
    if (!dni || !email || !password) return res.status(400).json({ error: 'Faltan campos' });
    const existente = await User.findOne({ $or: [{ dni }, { email }] });
    if (existente) return res.status(409).json({ error: 'Usuario ya existe' });
    const hash = await bcrypt.hash(password, 10);
    const user = new User({ dni, email, password: hash, nombre, role: 'vecino' });
    await user.save();
    res.status(201).json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ error: 'Credenciales inválidas' });
    const token = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      SECRET,
      { expiresIn: '8h' }
    );
    res.json({ token, user: { id: user._id, dni: user.dni, email: user.email, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// ─── QUEJAS ─────────────────────────────────────────────
// Obtener todas las quejas (públicas, sin comentarios internos)
app.get('/api/quejas', async (req, res) => {
  const quejas = await Queja.find()
    .select('-comentarios')            // ocultar comentarios internos
    .select('+comentarios_publicos')   // mostrar comentarios públicos
    .sort({ fecha: -1 }).lean();
  res.json(quejas);
});

// Ruta exclusiva para admin (muestra ambos comentarios)
app.get('/api/admin/quejas', authMiddleware, adminMiddleware, async (req, res) => {
  const quejas = await Queja.find()
    .select('+comentarios +comentarios_publicos')
    .sort({ fecha: -1 }).lean();
  res.json(quejas);
});

// Crear queja (imagen opcional)
app.post('/api/quejas', authMiddleware, upload.array('fotos', 3), async (req, res) => {
  try {
    const { titulo, descripcion, latitud, longitud, categoria, anonimo } = req.body;
    const lat = parseFloat(latitud);
    const lng = parseFloat(longitud);

    if (!titulo || !descripcion || isNaN(lat) || isNaN(lng) || !categoria)
      return res.status(400).json({ error: 'Faltan campos obligatorios' });
    if (!dentroDeAte(lat, lng)) return res.status(400).json({ error: 'Coordenadas fuera de Ate' });

    const fotos = req.files ? req.files.map(f => '/uploads/' + f.filename) : [];

    const ahora = new Date();
    const desdeAyer = new Date(ahora.getTime() - 24 * 60 * 60 * 1000);
    const duplicado = await Queja.findOne({
      categoria,
      fecha: { $gte: desdeAyer },
      latitud: { $exists: true },
      longitud: { $exists: true }
    });
    if (duplicado) {
      const dist = Math.sqrt(
        Math.pow(lat - duplicado.latitud, 2) + Math.pow(lng - duplicado.longitud, 2)
      );
      if (dist < 0.0005) return res.status(409).json({ error: 'Ya existe un reporte similar reciente' });
    }

    const usuario_dni = anonimo === 'true' ? 'Anonimo' : req.user.dni;
    const codigo = generarCodigo();

    const nuevaQueja = new Queja({
      codigo,
      usuario_dni,
      titulo,
      descripcion,
      categoria,
      estado: 'En espera',
      latitud: lat,
      longitud: lng,
      fotos,
      fecha: ahora,
      historial: [{ estado: 'En espera', fecha: ahora }],
      comentarios: [],
      comentarios_publicos: []
    });

    await nuevaQueja.save();
    res.status(201).json({ ok: true, codigo });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error al guardar' });
  }
});

app.get('/api/seguimiento/:codigo', async (req, res) => {
  const queja = await Queja.findOne({ codigo: req.params.codigo }).select('codigo estado titulo fecha historial comentarios_publicos');
  if (!queja) return res.status(404).json({ error: 'Código no encontrado' });
  res.json(queja);
});

app.patch('/api/quejas/:id/estado', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { nuevoEstado } = req.body;
    const permitidos = ['En espera', 'En proceso', 'Terminado'];
    if (!permitidos.includes(nuevoEstado)) return res.status(400).json({ error: 'Estado inválido' });

    const queja = await Queja.findById(req.params.id);
    if (!queja) return res.status(404).json({ error: 'No encontrada' });

    queja.historial.push({ estado: nuevoEstado, fecha: new Date() });
    queja.estado = nuevoEstado;
    await queja.save();

    if (queja.usuario_dni !== 'Anonimo') {
      const user = await User.findOne({ dni: queja.usuario_dni });
      if (user && user.email) {
        await transporter.sendMail({
          from: '"Alerta Distrito" <no-reply@alertadistrito.com>',
          to: user.email,
          subject: `Tu reporte ${queja.codigo} cambió a "${nuevoEstado}"`,
          html: `<p>El estado de tu reporte <strong>${queja.codigo}</strong> ahora es: <strong>${nuevoEstado}</strong>.</p>`
        }).catch(() => {});
      }
    }

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Error al actualizar' });
  }
});

// Comentarios internos (admin)
app.post('/api/quejas/:id/comentarios', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const queja = await Queja.findById(req.params.id);
    if (!queja) return res.status(404).json({ error: 'No encontrada' });
    queja.comentarios.push({ autor: req.user.email, texto: req.body.texto, fecha: new Date() });
    await queja.save();
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Error al comentar' });
  }
});

// Comentarios públicos (cualquier usuario autenticado)
app.post('/api/quejas/:id/comentarios-publicos', authMiddleware, async (req, res) => {
  try {
    const queja = await Queja.findById(req.params.id);
    if (!queja) return res.status(404).json({ error: 'No encontrada' });
    const { texto } = req.body;
    if (!texto || texto.trim() === '') return res.status(400).json({ error: 'Texto vacío' });
    queja.comentarios_publicos.push({
      autor: req.user.email,
      texto: texto.trim(),
      fecha: new Date()
    });
    await queja.save();
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Error al guardar comentario' });
  }
});

// Exportar CSV (admin)
app.get('/api/export/csv', authMiddleware, adminMiddleware, async (req, res) => {
  const quejas = await Queja.find().sort({ fecha: -1 }).lean();
  const header = 'ID,Código,DNI,Título,Categoría,Estado,Fecha,Lat,Long\n';
  const rows = quejas.map(q =>
    `${q._id},${q.codigo},${q.usuario_dni},"${q.titulo}","${q.categoria}",${q.estado},${q.fecha},${q.latitud},${q.longitud}`
  ).join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename=reportes.csv');
  res.send(header + rows);
});

app.get('/api/quejas/etag', async (req, res) => {
  const ultima = await Queja.findOne().sort({ fecha: -1 }).select('fecha').lean();
  const lastModified = ultima ? new Date(ultima.fecha).toUTCString() : new Date().toUTCString();
  res.setHeader('Last-Modified', lastModified);
  res.json({ lastModified });
});

app.get('/', (req, res) => res.redirect('/login.html'));

app.listen(PORT, () => console.log(`Servidor en http://localhost:${PORT}`));