const jwt = require('jsonwebtoken');
const User = require('../models/User');

module.exports = async function requireUser(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const match = header.match(/^Bearer ([^\s]+)$/);

    if (!match) {
      return res.status(401).json({ error: 'Sign in required' });
    }

    const claims = jwt.verify(match[1], process.env.JWT_SECRET, {
      issuer: 'portfolio',
      audience: 'portfolio-api'
    });

    if (claims.role !== 'user') {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const user = await User.findById(claims.sub);

    if (!user || !user.emailVerified) {
      return res.status(401).json({ error: 'Account is not verified' });
    }

    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired session' });
  }
};