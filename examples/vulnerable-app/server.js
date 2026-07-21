/**
 * Vulnerable Express App
 *
 * This is a DELIBERATELY INSECURE application for testing GuardGate.
 * DO NOT deploy this to production. Each route demonstrates a specific
 * security vulnerability that GuardGate's E2E plugins detect.
 *
 * Vulnerabilities:
 * 1. No login rate limiting
 * 2. IDOR on /profile/:id
 * 3. Session cookies without HttpOnly/Secure/SameSite
 * 4. Auth bypass on /admin (no auth check)
 * 5. Logout doesn't invalidate session
 * 6. Hardcoded credentials
 */

const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ─── In-memory "database" ─────────────────────────────────────────────
const users = [
  { id: 1, email: 'admin@example.com', password: 'admin123', role: 'admin', name: 'Admin User' },
  { id: 2, email: 'user@example.com', password: 'password123', role: 'user', name: 'Regular User' },
  { id: 3, email: 'jane@example.com', password: 'jane456', role: 'user', name: 'Jane Doe' },
];

const sessions = new Map(); // token -> userId

// ─── Serve HTML pages ─────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Vulnerable App</title></head>
    <body>
      <h1>Welcome to VulnApp</h1>
      <p><a href="/login">Login</a></p>
    </body>
    </html>
  `);
});

app.get('/login', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Login</title></head>
    <body>
      <h1>Login</h1>
      <form method="POST" action="/login">
        <input type="email" id="email" name="email" placeholder="Email" /><br/>
        <input type="password" id="password" name="password" placeholder="Password" /><br/>
        <button type="submit" id="login-btn">Login</button>
      </form>
    </body>
    </html>
  `);
});

// ─── VULN 1: No rate limiting on login ────────────────────────────────
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  const user = users.find((u) => u.email === email && u.password === password);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, user.id);

  // VULN 3: Session cookie WITHOUT HttpOnly, Secure, SameSite
  res.cookie('session_token', token, {
    httpOnly: false,  // VULNERABLE: JavaScript can read this
    secure: false,     // VULNERABLE: Sent over HTTP
    // sameSite not set   // VULNERABLE: No CSRF protection
  });

  res.redirect('/dashboard');
});

// ─── Dashboard (requires auth) ───────────────────────────────────────
app.get('/dashboard', (req, res) => {
  const token = req.cookies.session_token;
  const userId = sessions.get(token);
  const user = users.find((u) => u.id === userId);

  if (!user) {
    return res.redirect('/login');
  }

  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Dashboard</title></head>
    <body>
      <div class="welcome">Welcome, ${user.name}!</div>
      <p><a href="/profile/${user.id}">My Profile</a></p>
      <p><a href="/admin">Admin Panel</a></p>
      <p><a href="/logout">Logout</a></p>
    </body>
    </html>
  `);
});

// ─── VULN 2: IDOR — No authorization check on profile ID ─────────────
app.get('/profile/:id', (req, res) => {
  const profileId = parseInt(req.params.id, 10);
  const user = users.find((u) => u.id === profileId);

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  // BUG: No check that the logged-in user owns this profile!
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Profile</title></head>
    <body>
      <h1>Profile: ${user.name}</h1>
      <p>Email: ${user.email}</p>
      <p>Role: ${user.role}</p>
      <p>ID: ${user.id}</p>
    </body>
    </html>
  `);
});

// ─── VULN 4: Auth bypass — /admin has NO auth check ──────────────────
app.get('/admin', (req, res) => {
  // BUG: No authentication or authorization check!
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Admin Panel</title></head>
    <body>
      <h1>Admin Panel</h1>
      <p>Secret admin data here. User management, system settings, etc.</p>
      <ul>
        ${users.map((u) => `<li>${u.name} (${u.email}) — ${u.role}</li>`).join('')}
      </ul>
    </body>
    </html>
  `);
});

// ─── VULN 5: Logout doesn't invalidate the session ───────────────────
app.get('/logout', (req, res) => {
  // BUG: We clear the cookie but DON'T remove the token from sessions map!
  // The old token can still be replayed.
  res.clearCookie('session_token');
  // sessions.delete(req.cookies.session_token); // <-- This line is missing!
  res.redirect('/login');
});

// ─── API endpoints for JSON-based testing ─────────────────────────────
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  const user = users.find((u) => u.email === email && u.password === password);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, user.id);

  res.cookie('session_token', token, { httpOnly: false, secure: false });
  res.json({ message: 'Login successful', userId: user.id });
});

// ─── Start server ─────────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Vulnerable app running on http://localhost:${PORT}`);
  console.log('⚠️  This app is DELIBERATELY INSECURE — do not deploy to production!');
});
