// Run against your own deployment only:  BASE_URL=http://<your-host>:3000 npm test
const BASE = process.env.BASE_URL || 'http://localhost:3000';
let failed = 0;

async function call(method, path, body, token) {
  const res = await fetch(BASE + path, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch (e) {}
  return { status: res.status, data };
}

function check(name, cond) {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}`);
  if (!cond) failed++;
}

(async () => {
  const email = `test${Date.now()}@example.com`;
  const password = 'StrongPass123';

  const reg = await call('POST', '/register', { email, password, sensitiveInfo: 'ID 12345678' });
  check('Valid registration succeeds (201)', reg.status === 201);

  const login = await call('POST', '/login', { email, password });
  check('Valid login returns a token', login.status === 200 && !!login.data.token);
  const token = login.data && login.data.token;

  const me = await call('GET', '/me', null, token);
  check('/me returns decrypted sensitive field', me.status === 200 && me.data.sensitiveInfo === 'ID 12345678');

  const payloads = [
    "' OR '1'='1",
    "admin'--",
    "' UNION SELECT id, password_hash FROM users --",
    "'; DROP TABLE users; --",
    "x' OR SLEEP(5) --",
  ];
  for (const p of payloads) {
    const r = await call('POST', '/login', { email: p, password: 'anything' });
    check(`Login SQLi payload blocked: ${p}`, r.status === 400);
  }

  const wrong = await call('POST', '/login', { email, password: 'WrongPassword1' });
  check('Wrong password rejected (401)', wrong.status === 401);

  const noToken = await call('GET', '/admin/users');
  check('Admin route without token -> 401', noToken.status === 401);

  const userOnAdmin = await call('GET', '/admin/users', null, token);
  check('Admin route with normal-user token -> 403', userOnAdmin.status === 403);

  console.log(failed === 0 ? '\nAll checks passed.' : `\n${failed} check(s) failed.`);
  process.exit(failed === 0 ? 0 : 1);
})();
