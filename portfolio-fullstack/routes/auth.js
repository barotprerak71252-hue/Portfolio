const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');
const User = require('../models/User');

const router = express.Router();
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: Number(process.env.SMTP_PORT) === 465,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

const normalizeEmail = value =>
  String(value || '').trim().toLowerCase();

const signUser = user => jwt.sign(
  { sub: user._id.toString(), role: 'user' },
  process.env.JWT_SECRET,
  { expiresIn: '15m', issuer: 'portfolio', audience: 'portfolio-api' }
);

const publicUser = user => ({
  id: user._id,
  name: user.name,
  email: user.email,
  emailVerified: user.emailVerified
});

const digest = value =>
  crypto.createHash('sha256').update(value).digest('hex');

// POST /api/auth/register
router.post('/register', async (req, res) => {
  try {
    const name = String(req.body.name || '').trim().slice(0, 100);
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');

    if (!name || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
        password.length < 12 || password.length > 128) {
      return res.status(400).json({
        error: 'Provide a name, valid email, and password of 12–128 characters'
      });
    }

    let user = await User.findOne({ email });

    if (user?.emailVerified) {
      return res.status(409).json({
        error: 'An account already exists. Please sign in.'
      });
    }

    const code = crypto.randomInt(0, 1000000)
      .toString().padStart(6, '0');

    const passwordHash = await bcrypt.hash(password, 12);

    if (!user) {
      user = new User({ name, email });
    }

    user.name = name;
    user.passwordHash = passwordHash;
    user.verificationHash = digest(code);
    user.verificationExpires = new Date(Date.now() + 10 * 60 * 1000);

    await user.save();

    await mailer.sendMail({
      from: process.env.SMTP_USER,
      to: email,
      subject: 'Verify your portfolio account',
      text: `Your verification code is ${code}. It expires in 10 minutes.`
    });

    res.status(201).json({
      ok: true,
      message: 'Check your email for the verification code.'
    });
  } catch (error) {
    console.error('Registration error:', error.message);
    res.status(500).json({ error: 'Registration could not be completed' });
  }
});

// POST /api/auth/verify-email
router.post('/verify-email', async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const code = String(req.body.code || '');

    if (!/^\d{6}$/.test(code)) {
      return res.status(400).json({ error: 'Invalid or expired code' });
    }

    const user = await User.findOne({ email })
      .select('+verificationHash +verificationExpires');

    if (!user || user.emailVerified ||
        !user.verificationExpires ||
        user.verificationExpires < new Date() ||
        user.verificationHash !== digest(code)) {
      return res.status(400).json({ error: 'Invalid or expired code' });
    }

    user.emailVerified = true;
    user.verificationHash = undefined;
    user.verificationExpires = undefined;
    await user.save();

    res.json({ ok: true, message: 'Email verified. You can now sign in.' });
  } catch (error) {
    console.error('Email verification error:', error.message);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// POST /api/auth/login
router.post('/login', async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');

    const user = await User.findOne({ email }).select('+passwordHash');

    if (!user || !user.passwordHash ||
        !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    if (!user.emailVerified) {
      return res.status(403).json({ error: 'Please verify your email first' });
    }

    res.json({ token: signUser(user), user: publicUser(user) });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

// POST /api/auth/google
router.post('/google', async (req, res) => {
  try {
    const credential = String(req.body.credential || '');

    if (!credential || credential.length > 10000) {
      return res.status(400).json({ error: 'Missing Google credential' });
    }

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();

    if (!payload?.sub || !payload.email ||
        payload.email_verified !== true) {
      return res.status(401).json({
        error: 'Google account email must be verified'
      });
    }

    const email = normalizeEmail(payload.email);
    let user = await User.findOne({
      $or: [{ googleId: payload.sub }, { email }]
    });

    if (user && user.googleId && user.googleId !== payload.sub) {
      return res.status(409).json({
        error: 'Account conflict. Contact the site administrator.'
      });
    }

    if (user && user.passwordHash && !user.googleId) {
      return res.status(409).json({
        error: 'This email already has a password account. Sign in with email first.'
      });
    }

    if (!user) {
      user = new User({
        name: String(payload.name || 'Visitor').slice(0, 100),
        email,
        googleId: payload.sub,
        emailVerified: true
      });
    } else {
      user.googleId = payload.sub;
      user.emailVerified = true;
    }

    await user.save();

    res.json({ token: signUser(user), user: publicUser(user) });
  } catch (error) {
    console.error('Google sign-in error:', error.message);
    res.status(401).json({ error: 'Google sign-in failed' });
  }
});

module.exports = router;