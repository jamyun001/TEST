const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const bodyParser = require('body-parser');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'your_secret_key';

const db = new sqlite3.Database('./database.sqlite', (err) => {
  if (err) return console.error(err.message);
  console.log('Connected to SQLite database');
});

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    nickname TEXT NOT NULL,
    ip TEXT NOT NULL
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    authorId INTEGER NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(authorId) REFERENCES users(id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    postId INTEGER NOT NULL,
    authorId INTEGER NOT NULL,
    text TEXT NOT NULL,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(postId) REFERENCES posts(id),
    FOREIGN KEY(authorId) REFERENCES users(id)
  )`);
});

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/auth/register',
  body('username').isLength({ min: 3 }),
  body('password').isLength({ min: 6 }),
  body('nickname').notEmpty(),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const { username, password, nickname } = req.body;

    db.get('SELECT id FROM users WHERE ip = ?', [ip], (err, row) => {
      if (err) return res.status(500).json({ error: 'DB error' });
      if (row) return res.status(403).json({ error: '1 account per IP allowed' });

      db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
        if (row) return res.status(409).json({ error: 'Username exists' });

        bcrypt.hash(password, 10, (err, hash) => {
          if (err) return res.status(500).json({ error: 'Hash failed' });
          db.run(
            'INSERT INTO users (username, password, nickname, ip) VALUES (?, ?, ?, ?)',
            [username, hash, nickname, ip],
            function (err) {
              if (err) return res.status(500).json({ error: 'Register failed' });
              res.status(201).json({ message: 'Registered' });
            }
          );
        });
      });
    });
  }
);

app.post('/auth/login', (req, res) => {
  const { id, password } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  db.get('SELECT * FROM users WHERE username = ?', [id], (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Invalid credentials' });

    bcrypt.compare(password, user.password, (err, result) => {
      if (!result) return res.status(401).json({ error: 'Wrong password' });

      const token = jwt.sign(
        { userId: user.id, username: user.username, nickname: user.nickname, ip },
        SECRET_KEY,
        { expiresIn: '30d' }
      );
      res.json({ token, nickname: user.nickname });
    });
  });
});

app.get('/posts', (req, res) => {
  db.all(`
    SELECT posts.id, posts.title, posts.content, posts.createdAt, users.nickname AS authorNickname
    FROM posts JOIN users ON posts.authorId = users.id
    ORDER BY posts.createdAt DESC
  `, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Get posts failed' });
    res.json(rows);
  });
});

app.get('/posts/:id', (req, res) => {
  const postId = req.params.id;
  db.get(`
    SELECT posts.id, posts.title, posts.content, posts.createdAt, users.nickname AS authorNickname
    FROM posts JOIN users ON posts.authorId = users.id WHERE posts.id = ?
  `, [postId], (err, post) => {
    if (err || !post) return res.status(404).json({ error: 'Post not found' });

    db.all(`
      SELECT comments.id, comments.text, comments.createdAt, users.nickname AS authorNickname
      FROM comments JOIN users ON comments.authorId = users.id WHERE comments.postId = ?
    `, [postId], (err, comments) => {
      if (err) return res.status(500).json({ error: 'Get comments failed' });
      post.comments = comments;
      res.json(post);
    });
  });
});

app.post('/posts', authenticateToken, (req, res) => {
  const { title, content } = req.body;
  const authorId = req.user.userId;

  db.run('INSERT INTO posts (authorId, title, content) VALUES (?, ?, ?)',
    [authorId, title, content],
    function (err) {
      if (err) return res.status(500).json({ error: 'Post failed' });
      res.status(201).json({
        id: this.lastID,
        title,
        content,
        createdAt: new Date().toISOString(),
        authorNickname: req.user.nickname
      });
    });
});

app.post('/posts/:postId/comments', authenticateToken, (req, res) => {
  const postId = req.params.postId;
  const authorId = req.user.userId;
  const { text } = req.body;

  db.run('INSERT INTO comments (postId, authorId, text) VALUES (?, ?, ?)',
    [postId, authorId, text],
    function (err) {
      if (err) return res.status(500).json({ error: 'Comment failed' });
      res.status(201).json({
        id: this.lastID,
        postId,
        text,
        createdAt: new Date().toISOString(),
        authorNickname: req.user.nickname
      });
    });
});

app.listen(PORT, () => {
  console.log(`http://localhost:${PORT} 에서 서버 실행 중`);
});
