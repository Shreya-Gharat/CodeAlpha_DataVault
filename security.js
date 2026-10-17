const pool = require('./db');

// Heuristic SQLi signature detection. This is a DETECTION/LOGGING layer only.
// The real protection is parameterized queries + validation; never rely on a regex alone.
const SQLI_PATTERN =
  /('|"|--|;|\/\*|\*\/|#|\bunion\b|\bselect\b|\bdrop\b|\binsert\b|\bdelete\b|\bupdate\b|\bor\b\s+\S+\s*=\s*\S+|\bsleep\s*\(|\bbenchmark\s*\()/i;

async function detectSuspicious(req, res, next) {
  const body = req.body || {};
  for (const [field, value] of Object.entries(body)) {
    if (field === 'password') continue; // passwords may legitimately contain symbols
    if (typeof value === 'string' && SQLI_PATTERN.test(value)) {
      try {
        await pool.execute(
          'INSERT INTO security_log (ip, route, field_name, payload) VALUES (?, ?, ?, ?)',
          [req.ip, req.path, field, value.slice(0, 500)]
        );
      } catch (e) {
        console.error('Failed to write security log:', e.message);
      }
      return res.status(400).json({ error: 'Suspicious input rejected' });
    }
  }
  next();
}

module.exports = { detectSuspicious };
