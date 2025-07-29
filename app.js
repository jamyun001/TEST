const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');

const app = express();
const db = new sqlite3.Database('./database.sqlite');

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      author TEXT NOT NULL,
      content TEXT NOT NULL,
      ip TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      post_id INTEGER NOT NULL,
      author TEXT NOT NULL,
      text TEXT NOT NULL,
      ip TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(post_id) REFERENCES posts(id)
    )
  `);
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/posts', (req, res) => {
  db.all('SELECT * FROM posts ORDER BY created_at DESC', (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/posts/:id', (req, res) => {
  const postId = req.params.id;
  db.get('SELECT * FROM posts WHERE id = ?', [postId], (err, post) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!post) return res.status(404).json({ error: 'Post not found' });

    db.all('SELECT * FROM comments WHERE post_id = ? ORDER BY created_at ASC', [postId], (err, comments) => {
      if (err) return res.status(500).json({ error: err.message });
      post.comments = comments;
      res.json(post);
    });
  });
});

app.post('/posts', (req, res) => {
  const { title, author, content } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  db.run(
    `INSERT INTO posts (title, author, content, ip) VALUES (?, ?, ?, ?)`,
    [title, author, content, ip],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID });
    }
  );
});

app.post('/posts/:id/comments', (req, res) => {
  const postId = req.params.id;
  const { author, text } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  db.run(
    `INSERT INTO comments (post_id, author, text, ip) VALUES (?, ?, ?, ?)`,
    [postId, author, text, ip],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID });
    }
  );
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
