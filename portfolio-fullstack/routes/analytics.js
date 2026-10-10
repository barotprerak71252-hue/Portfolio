
const express = require('express');
const rateLimit = require('express-rate-limit');
const Visit = require('../models/Visit');
const requireAdmin = require('../middleware/requireAdmin');

const router = express.Router();

// Limit public tracking requests to reduce abuse.
const pageviewLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many analytics requests. Try again later.' }
});

// Parse a safe pathname without storing query strings or fragments.
function cleanPath(value) {
  if (typeof value !== 'string') return null;

  const pathname = value.split(/[?#]/)[0];

  if (
    pathname.length > 200 ||
    !pathname.startsWith('/') ||
    pathname.startsWith('//') ||
    pathname.includes('\\')
  ) {
    return null;
  }

  return pathname;
}

// Store only the referral hostname, not its full URL.
function cleanReferrer(value) {
  if (typeof value !== 'string' || !value.trim()) return '';

  try {
    const parsed = new URL(value);

    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return '';
    }

    return parsed.hostname.slice(0, 253);
  } catch {
    return '';
  }
}

// POST /api/analytics/pageview
// Public endpoint called by the portfolio frontend.
router.post('/pageview', pageviewLimiter, async (req, res) => {
  try {
    const { sessionId, path } = req.body || {};

    // Require a UUID-shaped, client-generated session identifier.
    if (
      typeof sessionId !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(sessionId)
    ) {
      return res.status(400).json({ error: 'Invalid session ID' });
    }

    const safePath = cleanPath(path);

    if (!safePath) {
      return res.status(400).json({ error: 'Invalid page path' });
    }

    const now = new Date();
    const day = now.toISOString().slice(0, 10);

    await Visit.create({
      sessionId,
      path: safePath,
      referrer: cleanReferrer(req.body.referrer),
      day,
      visitedAt: now
    });

    return res.status(201).json({ ok: true });
  } catch (error) {
    console.error('Analytics pageview error:', error.message);
    return res.status(500).json({ error: 'Could not record pageview' });
  }
});

// GET /api/analytics/summary?days=7
// Admin-only analytics dashboard endpoint.
router.get('/summary', requireAdmin, async (req, res) => {
  try {
    const requestedDays = Number.parseInt(req.query.days, 10);
    const days = Number.isFinite(requestedDays)
      ? Math.max(1, Math.min(requestedDays, 90))
      : 7;

    const start = new Date();
    start.setUTCHours(0, 0, 0, 0);
    start.setUTCDate(start.getUTCDate() - (days - 1));

    const startDay = start.toISOString().slice(0, 10);

    const match = { day: { $gte: startDay } };

    const [
      totalPageViews,
      uniqueSessions,
      daily,
      topPages,
      referralSources
    ] = await Promise.all([
      Visit.countDocuments(match),

      Visit.distinct('sessionId', match).then(ids => ids.length),

      Visit.aggregate([
        { $match: match },
        {
          $group: {
            _id: '$day',
            pageViews: { $sum: 1 },
            sessions: { $addToSet: '$sessionId' }
          }
        },
        {
          $project: {
            _id: 0,
            day: '$_id',
            pageViews: 1,
            uniqueSessions: { $size: '$sessions' }
          }
        },
        { $sort: { day: 1 } }
      ]),

      Visit.aggregate([
        { $match: match },
        {
          $group: {
            _id: '$path',
            views: { $sum: 1 }
          }
        },
        { $sort: { views: -1, _id: 1 } },
        { $limit: 10 },
        {
          $project: {
            _id: 0,
            path: '$_id',
            views: 1
          }
        }
      ]),

      Visit.aggregate([
        {
          $match: {
            ...match,
            referrer: { $nin: ['', null] }
          }
        },
        {
          $group: {
            _id: '$referrer',
            visits: { $sum: 1 }
          }
        },
        { $sort: { visits: -1, _id: 1 } },
        { $limit: 10 },
        {
          $project: {
            _id: 0,
            source: '$_id',
            visits: 1
          }
        }
      ])
    ]);

    // Fill in days without traffic so charts display continuous dates.
    const dailyByDate = new Map(daily.map(item => [item.day, item]));
    const dailyChart = [];

    for (let i = 0; i < days; i++) {
      const date = new Date(start);
      date.setUTCDate(start.getUTCDate() + i);

      const day = date.toISOString().slice(0, 10);
      const existing = dailyByDate.get(day);

      dailyChart.push({
        day,
        pageViews: existing?.pageViews || 0,
        uniqueSessions: existing?.uniqueSessions || 0
      });
    }

    return res.json({
      periodDays: days,
      totalPageViews,
      uniqueSessions,
      daily: dailyChart,
      topPages,
      referralSources
    });
  } catch (error) {
    console.error('Analytics summary error:', error.message);
    return res.status(500).json({ error: 'Could not load analytics' });
  }
});

module.exports = router;
