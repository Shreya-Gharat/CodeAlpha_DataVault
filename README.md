# CodeAlpha_DataVault

A small cloud-hosted user data vault built for the CodeAlpha Cloud Computing internship (Task 2).
It stores user credentials and sensitive data securely and defends against SQL injection with layered controls.

## Security design

| Layer | What it does | Where |
|---|---|---|
| Parameterized queries | SQL and user values are sent separately, so input is never interpreted as SQL. This is the primary SQL injection defence. | `server.js`, `security.js` |
| Input validation | Allow-list validation with Joi rejects malformed email, password and sensitive fields. | `validation.js` |
| Injection detection and logging | Regex signatures flag common SQLi payloads, reject the request and record it in `security_log`. Heuristic, secondary layer. | `security.js` |
| Password hashing | bcrypt (cost 12). Passwords are hashed, not encrypted. | `server.js` |
| AES-256-GCM encryption | The sensitive field is encrypted before storage, with a random IV per record and an authentication tag. | `crypto-utils.js` |
| Capability tokens | Signed JWTs carry explicit scopes (`read:self`, `read:users`, `read:logs`). Each route requires a specific scope. | `auth.js` |
| Hardening | helmet headers, request size limit, rate limiting on login and register, generic error responses. | `server.js` |

Note on the brief's "capability code mechanism": it is implemented as scoped capability tokens that control which callers may run which database operations.

## Endpoints

- `POST /register` body: `{ email, password, sensitiveInfo }`
- `POST /login` body: `{ email, password }` returns `{ token }`
- `GET /me` needs `read:self`, returns the decrypted sensitive field
- `GET /admin/users` needs `read:users`
- `GET /admin/security-log` needs `read:logs`
- `GET /health` for load balancer checks

## Run locally

```bash
npm install
cp .env.example .env     # fill in DB details, AES_KEY, JWT_SECRET
mysql -h <host> -u <user> -p < schema.sql
npm start
npm test                 # runs the injection test suite
```

## Deploy on AWS

1. **RDS:** create a MySQL 8 instance (db.t3.micro, free tier eligible). Create a security group `db-sg` that allows inbound 3306 only from the EC2 security group.
2. **EC2:** launch an Amazon Linux 2023 instance (t2.micro or t3.micro) with security group `app-sg` allowing inbound 22 (your IP only) and 3000.
3. SSH in and install tools: `sudo dnf install -y git nodejs npm mariadb105` (check `node -v` is 18 or higher).
4. Clone the repo, run `npm install`, and copy `.env.example` to `.env`. Fill in the RDS endpoint and generate the two secrets with the command shown in the file.
5. Create the schema: `mysql -h <rds-endpoint> -u admin -p < schema.sql`
6. Start the app: `npm start`. For a persistent run, `sudo npm i -g pm2 && pm2 start server.js && pm2 save`.
7. Test: `BASE_URL=http://<ec2-public-ip>:3000 npm test`
8. Optional second network layer: put an Application Load Balancer in front (health check path `/health`) and attach an AWS WAF web ACL with the managed rule group `AWSManagedRulesSQLiRuleSet`.

## Testing with sqlmap

Only against your own deployment:

```bash
sqlmap -u "http://<host>:3000/login" --data='{"email":"a@b.com","password":"x"}' --headers="Content-Type: application/json" --batch
```

Screenshot the result for your video.

## Known limitations

- Traffic is plain HTTP unless you add HTTPS (ALB with an ACM certificate).
- The AES key lives in an environment variable. In production it should come from AWS KMS or Secrets Manager.
- Regex detection can be evaded; parameterized queries and validation are the real defence.
- Single instance, no auto-scaling.
