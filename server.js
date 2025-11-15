// server.js
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 5000;

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// Session (stockée dans SQLite)
app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: __dirname }),
  secret: process.env.SESSION_SECRET || 'change_this_secret_in_prod',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 } // 1 jour
}));

// Database (SQLite file)
const DB_PATH = path.join(__dirname, 'users.sqlite');
const db = new sqlite3.Database(DB_PATH);
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );`);
});

// Helper middleware: protect route
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  return res.status(401).json({ ok: false, message: 'Not authenticated' });
}

// API: register
app.post('/api/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password || password.length < 6) {
      return res.status(400).json({ ok: false, message: 'Email et mot de passe (min 6) requis' });
    }
    const hash = await bcrypt.hash(password, 12);
    const stmt = db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)');
    stmt.run(email.toLowerCase().trim(), hash, function(err) {
      if (err) {
        if (err.message.includes('UNIQUE')) return res.status(409).json({ ok: false, message: 'Email déjà utilisé' });
        return res.status(500).json({ ok: false, message: 'Erreur serveur' });
      }
      // login user
      req.session.userId = this.lastID;
      req.session.email = email.toLowerCase().trim();
      return res.json({ ok: true, message: 'Inscription réussie' });
    });
    stmt.finalize();
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, message: 'Erreur serveur' });
  }
});

// API: login
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ ok: false, message: 'Email et mot de passe requis' });

  db.get('SELECT id, password_hash FROM users WHERE email = ?', [email.toLowerCase().trim()], async (err, row) => {
    if (err) return res.status(500).json({ ok: false, message: 'Erreur serveur' });
    if (!row) return res.status(401).json({ ok: false, message: 'Identifiants incorrects' });

    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) return res.status(401).json({ ok: false, message: 'Identifiants incorrects' });

    req.session.userId = row.id;
    req.session.email = email.toLowerCase().trim();
    return res.json({ ok: true, message: 'Connexion réussie' });
  });
});

// API: logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ ok: false, message: 'Impossible de se déconnecter' });
    res.json({ ok: true, message: 'Déconnecté' });
  });
});

// API: get current user
app.get('/api/me', (req, res) => {
  if (req.session && req.session.userId) {
    return res.json({ loggedIn: true, email: req.session.email });
  }
  return res.json({ loggedIn: false });
});

// Products: read from products.json in public folder
app.get('/api/products', (req, res) => {
  const p = path.join(__dirname, 'public', 'products.json');
  fs.readFile(p, 'utf8', (err, data) => {
    if (err) return res.json({ products: [] });
    try {
      const products = JSON.parse(data);
      return res.json({ products });
    } catch (e) {
      return res.json({ products: [] });
    }
  });
});

// Protected route serving magasin.html via static file is ok; but example protected endpoint:
app.get('/protected', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'magasin.html'));
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Serveur lancé sur http://0.0.0.0:${PORT}`);
});