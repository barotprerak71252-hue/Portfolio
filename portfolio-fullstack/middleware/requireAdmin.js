const jwt = require('jsonwebtoken');

module.exports = function requireAdmin(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const match = header.match(/^Bearer ([^\s]+)$/);

    if (!match) {
      return res.status(401).json({ error: 'Admin login required' });
    }

    const claims = jwt.verify(match[1], process.env.JWT_SECRET);

    if (claims.admin !== 1) {
      return res.status(403).json({ error: 'Admin access required' });
    }

    next();
  } catch {
    res.status(401).json({ error: 'Invalid admin session' });
  }
};