
require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const path = require('path');

const {
  MONGODB_URI,
  JWT_SECRET,
  ADMIN_PASSWORD,
  PORT = 3000
} = process.env;

// Required environment variables
if (!MONGODB_URI || !JWT_SECRET || !ADMIN_PASSWORD) {
  console.error(
    'Set MONGODB_URI, JWT_SECRET and ADMIN_PASSWORD in your environment.'
  );
  process.exit(1);
}

// Existing message collection.
// Keep the model name "Message" so existing messages remain in
// the same MongoDB collection when models/Message.js uses this name.
const Message = require('./models/Message');

const Project = mongoose.model(
  'Project',
  new mongoose.Schema(
    {
      title: String,
      description: String,
      tags: [String],
      highlights: [String],
      repoUrl: String,
      liveUrl: String,
      badge: {
        type: String,
        default: 'LEARNING BUILD'
      },
      featured: {
        type: Boolean,
        default: false
      },
      order: {
        type: Number,
        default: 0
      }
    },
    { timestamps: true }
  )
);

// New authentication and analytics routes
const authRoutes = require('./routes/auth');
const analyticsRoutes = require('./routes/analytics');
const requireUser = require('./middleware/requireUser');

// App setup
const app = express();

app.set('trust proxy', 1);
app.use('/api/analytics', analyticsRoutes);
app.use(express.json({ limit: '20kb' }));

// Helpers
const s = (value, maxLength) =>
  String(value ?? '').trim().slice(0, maxLength);

const url = value => {
  const clean = s(value, 300);
  return /^https?:\/\/\S+$/i.test(clean) ? clean : '';
};

const list = (value, maxLength) =>
  (Array.isArray(value) ? value : [])
    .map(item => s(item, maxLength))
    .filter(Boolean)
    .slice(0, 20);

const hash = value =>
  crypto.createHash('sha256').update(value).digest();

const wrap = handler => (req, res, next) =>
  Promise.resolve(handler(req, res, next)).catch(error => {
    console.error(error);
    if (!res.headersSent) {
      res.status(500).json({ error: 'server error' });
    }
  });

const projectData = body => ({
  title: s(body.title, 120),
  description: s(body.description, 1000),
  tags: list(body.tags, 40),
  highlights: list(body.highlights, 160),
  repoUrl: url(body.repoUrl),
  liveUrl: url(body.liveUrl),
  badge: s(body.badge, 30) || 'LEARNING BUILD',
  featured: body.featured === true,
  order: Number(body.order) || 0
});

// Admin-only middleware.
// Existing admin login tokens contain { admin: 1 }.
// Ordinary user tokens must never access admin APIs.
const requireAdmin = (req, res, next) => {
  try {
    const authorization = req.headers.authorization || '';
    const match = authorization.match(/^Bearer\s+(\S+)$/i);

    if (!match) {
      return res.status(401).json({ error: 'unauthorized' });
    }

    const claims = jwt.verify(match[1], JWT_SECRET);

    if (claims.admin !== 1) {
      return res.status(403).json({ error: 'forbidden' });
    }

    req.admin = true;
    next();
  } catch {
    return res.status(401).json({ error: 'unauthorized' });
  }
};

// ==========================================
// AUTHENTICATION
// ==========================================

// Email/password registration, email verification, login,
// and Google sign-in are implemented in routes/auth.js.
app.use('/api/auth', authRoutes);

// ==========================================
// PUBLIC PROJECTS
// ==========================================

app.get(
  '/api/projects',
  wrap(async (req, res) => {
    const projects = await Project.find()
      .sort({ featured: -1, order: 1, createdAt: 1 })
      .lean();

    res.json(projects);
  })
);

// ==========================================
// AUTHENTICATED CONTACT MESSAGES
// ==========================================

// Visitors must sign in before sending a message.
// Name and email come from the verified account, not the request body.
app.post(
  '/api/messages',
  rateLimit({
    windowMs: 60 * 60 * 1000,
    limit: 5,
    message: { error: 'Too many messages. Try again later.' }
  }),
  requireUser,
  wrap(async (req, res) => {
    const message = s(req.body?.message, 3000);

    if (!message) {
      return res.status(400).json({
        error: 'A message is required.'
      });
    }

    const savedMessage = await Message.create({
      user: req.user._id,
      name: req.user.name,
      email: req.user.email,
      message
    });

    res.status(201).json({
      ok: true,
      id: savedMessage._id
    });
  })
);

// ==========================================
// VISITOR ANALYTICS
// ==========================================

// The analytics router should provide:
// POST /pageview   - public pageview tracking
// GET  /summary    - admin-only analytics summary
//
// Protect /summary with requireAdmin INSIDE routes/analytics.js.
// Do not expose analytics summaries publicly.
app.use('/api/analytics', analyticsRoutes);

// ==========================================
// ADMIN LOGIN
// ==========================================

app.post(
  '/api/admin/login',
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    message: { error: 'Too many attempts. Try again later.' }
  }),
  (req, res) => {
    const suppliedPassword = s(req.body?.password, 200);

    if (
      !crypto.timingSafeEqual(
        hash(suppliedPassword),
        hash(ADMIN_PASSWORD)
      )
    ) {
      return res.status(401).json({
        error: 'wrong password'
      });
    }

    const token = jwt.sign(
      { admin: 1 },
      JWT_SECRET,
      { expiresIn: '12h' }
    );

    res.json({ token });
  }
);

// ==========================================
// ADMIN API
// ==========================================

const admin = express.Router();

admin.use(requireAdmin);

// Read existing and new messages
admin.get(
  '/messages',
  wrap(async (req, res) => {
    const messages = await Message.find()
      .sort({ createdAt: -1 })
      .limit(200)
      .lean();

    res.json(messages);
  })
);

// Mark a message as read/unread
admin.patch(
  '/messages/:id',
  wrap(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ error: 'invalid message ID' });
    }

    const updated = await Message.findByIdAndUpdate(
      req.params.id,
      { read: req.body?.read === true },
      { new: true, runValidators: true }
    );

    if (!updated) {
      return res.status(404).json({ error: 'message not found' });
    }

    res.json(updated);
  })
);

// Delete a message
admin.delete(
  '/messages/:id',
  wrap(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ error: 'invalid message ID' });
    }

    const deleted = await Message.findByIdAndDelete(req.params.id);

    if (!deleted) {
      return res.status(404).json({ error: 'message not found' });
    }

    res.json({ ok: true });
  })
);

// Create a project
admin.post(
  '/projects',
  wrap(async (req, res) => {
    const project = await Project.create(projectData(req.body || {}));
    res.status(201).json(project);
  })
);

// Update a project
admin.put(
  '/projects/:id',
  wrap(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ error: 'invalid project ID' });
    }

    const updated = await Project.findByIdAndUpdate(
      req.params.id,
      projectData(req.body || {}),
      { new: true, runValidators: true }
    );

    if (!updated) {
      return res.status(404).json({ error: 'project not found' });
    }

    res.json(updated);
  })
);

// Delete a project
admin.delete(
  '/projects/:id',
  wrap(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ error: 'invalid project ID' });
    }

    const deleted = await Project.findByIdAndDelete(req.params.id);

    if (!deleted) {
      return res.status(404).json({ error: 'project not found' });
    }

    res.json({ ok: true });
  })
);

app.use('/api/admin', admin);

// ==========================================
// FRONTEND
// ==========================================

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.use(express.static(path.join(__dirname, 'public')));

// Unknown API routes return JSON instead of the website HTML
app.use('/api', (req, res) => {
  res.status(404).json({ error: 'API endpoint not found' });
});

// ==========================================
// DATABASE + INITIAL PROJECTS
// ==========================================

const seed = [
  {
    title: 'Slotify — Slot Booking REST API',
    description:
      'Users register, log in, browse available slots, book them and cancel their own bookings. Every write operation is JWT-protected, double-bookings are blocked, and same-date overlaps are rejected with a 409. Built with Node.js, Express and MongoDB.',
    tags: [
      'node.js', 'express', 'mongodb',
      'mongoose', 'jwt', 'bcrypt'
    ],
    highlights: [
      'JWT auth + bcrypt password hashing',
      'Slot CRUD, booking and cancellation with ownership rules',
      'Double-booking and overlap conflict prevention (409)',
      '/bookings/me — view your own bookings'
    ],
    featured: true,
    badge: 'FEATURED',
    order: 0
  },
  {
    title: 'Student Records API',
    description:
      'A learning build — REST API for managing student records with CRUD, validation and JWT-based auth in Spring Boot.',
    tags: ['java', 'spring boot', 'rest', 'sql'],
    order: 1
  },
  {
    title: 'Containerized Deploy Lab',
    description:
      'A learning build — packaging a Spring Boot service into lean Docker images and orchestrating it with docker-compose.',
    tags: ['docker', 'docker-compose', 'spring boot'],
    order: 2
  }
];

mongoose.connect(MONGODB_URI)
  .then(async () => {
    if (await Project.countDocuments() === 0) {
      await Project.insertMany(seed);
    }

    app.listen(PORT, () => {
      console.log(`Portfolio server running on port ${PORT}`);
    });
  })
  .catch(error => {
    console.error('MongoDB connection failed:', error.message);
    process.exit(1);
  });
