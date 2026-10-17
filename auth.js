const jwt = require('jsonwebtoken');

// A "capability token": a signed token listing exactly what the holder may do (scopes).
function issueCapability(userId, scopes) {
  return jwt.sign({ userId, scopes }, process.env.JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn: '1h',
  });
}

// Middleware: route runs only if the token carries the required scope.
function requireCapability(scope) {
  return (req, res, next) => {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing token' });
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
      if (!Array.isArray(decoded.scopes) || !decoded.scopes.includes(scope)) {
        return res.status(403).json({ error: 'Insufficient capability' });
      }
      req.user = decoded;
      next();
    } catch (e) {
      res.status(401).json({ error: 'Invalid or expired token' });
    }
  };
}

module.exports = { issueCapability, requireCapability };
