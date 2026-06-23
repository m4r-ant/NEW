require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  dni: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  nombre: { type: String, default: 'Vecino' },
  role: { type: String, enum: ['admin', 'vecino'], default: 'vecino' }
});

const User = mongoose.model('User', userSchema);

mongoose.connect(process.env.MONGODB_URI)
  .then(async () => {
    const exists = await User.findOne({ email: 'admin@ate.gob.pe' });
    if (!exists) {
      await User.create({
        dni: '00000000',
        email: 'admin@ate.gob.pe',
        password: await bcrypt.hash('admin123', 10),
        nombre: 'Administrador',
        role: 'admin'
      });
      console.log('✅ Administrador creado (admin@ate.gob.pe / admin123)');
    } else {
      console.log('⚠️ El administrador ya existe');
    }
    mongoose.disconnect();
  })
  .catch(err => {
    console.error('Error:', err);
    mongoose.disconnect();
  });