const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, maxlength: 100 },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  passwordHash: { type: String, select: false },
  googleId: { type: String, unique: true, sparse: true },
  emailVerified: { type: Boolean, default: false },
  verificationHash: { type: String, select: false },
  verificationExpires: { type: Date, select: false }
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);