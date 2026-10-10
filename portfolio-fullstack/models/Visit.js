const mongoose = require('mongoose');

const visitSchema = new mongoose.Schema({
  sessionId: { type: String, required: true, index: true },
  path: { type: String, required: true, maxlength: 300 },
  referrer: { type: String, default: 'Direct', maxlength: 200 },
  day: { type: String, required: true, index: true },
  visitedAt: { type: Date, default: Date.now }
}, { timestamps: false });

visitSchema.index({ visitedAt: -1 });

module.exports = mongoose.model('Visit', visitSchema);