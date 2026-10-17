require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');

const pool = require('./db');
const { encrypt, decrypt } = require('./crypto-utils');
const { issueCapability, requireCapability } = require('./auth');
const { detectSuspicious } = require('./security');
const { registerSchema, loginSchema } = require('./validation');

const app = express();
app.set('trust proxy', 1); // correct client IPs when running behind an AWS load balancer
app.use(helmet());
app.use(express.json({ limit: '10kb' }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
});

// Used so a login for a non-existent email takes the same time as a real one.
const DUMMY_HASH = bcrypt.hashSync('dummy-password', 12);

app.get('/health', (req, res) => res.json({ status: 'ok' })); // for load balancer health checks

app.post('/register', authLimiter, detectSuspicious, async (req, res, next) => {
  try {
    const { error, value } = registerSchema.validate(req.body);
    if (error) return res.status(400).json({ error: 'Invalid input' });

    const passwordHash = await bcrypt.hash(value.password, 12);
    const sensitiveEnc = encrypt(value.sensitiveInfo);
    const email = value.email.toLowerCase();
    const role =
      process.env.ADMIN_EMAIL && email === process.env.ADMIN_EMAIL.toLowerCase() ? 'admin' : 'user';

    await pool.execute(
      'INSERT INTO users (email, password_hash, sensitive_enc, role) VALUES (?, ?, ?, ?)',
      [email, passwordHash, sensitiveEnc, role]
    );
    res.status(201).json({ message: 'Registered' });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Email already registered' });
    next(err);
  }
});

app.post('/login', authLimiter, detectSuspicious, async (req, res, next) => {
  try {
    const { error, value } = loginSchema.validate(req.body);
    if (error) return res.status(400).json({ error: 'Invalid input' });

    const [rows] = await pool.execute(
      'SELECT id, password_hash, role FROM users WHERE email = ?',
      [value.email.toLowerCase()]
    );
    const user = rows[0];
    const ok = await bcrypt.compare(value.password, user ? user.password_hash : DUMMY_HASH);
    if (!user || !ok) return res.status(401).json({ error: 'Invalid credentials' });

    const scopes =
      user.role === 'admin' ? ['read:self', 'read:users', 'read:logs'] : ['read:self'];
    res.json({ token: issueCapability(user.id, scopes) });
  } catch (err) {
    next(err);
  }
});

// A user can read their own record; the sensitive field is decrypted only here.
app.get('/me', requireCapability('read:self'), async (req, res, next) => {
  try {
    const [rows] = await pool.execute(
      'SELECT email, sensitive_enc, role FROM users WHERE id = ?',
      [req.user.userId]
    );
    if (!rows[0]) return res.status(404).json({ error: 'Not found' });
    res.json({
      email: rows[0].email,
      role: rows[0].role,
      sensitiveInfo: decrypt(rows[0].sensitive_enc),
    });
  } catch (err) {
    next(err);
  }
});

// Admin-only. Note: even admins never get decrypted sensitive data from this route.
app.get('/admin/users', requireCapability('read:users'), async (req, res, next) => {
  try {
    const [rows] = await pool.execute('SELECT id, email, role, created_at FROM users');
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

app.get('/admin/security-log', requireCapability('read:logs'), async (req, res, next) => {
  try {
    const [rows] = await pool.execute(
      'SELECT id, ip, route, field_name, payload, created_at FROM security_log ORDER BY id DESC LIMIT 100'
    );
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// Generic error handler: never leak SQL errors or stack traces to the client.
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`DataVault listening on port ${PORT}`));
