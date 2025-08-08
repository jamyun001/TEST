const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');

const app = express();
const port = 3000;

app.use(cors());
app.use(express.json());

// 🔹 정적 파일 제공: /public 폴더의 HTML, CSS, JS 파일
app.use(express.static(path.join(__dirname, 'public')));

// 🔹 루트 요청 시 index.html 제공
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 🔹 SQLite DB 초기화
const db = new sqlite3.Database('./gallery.db');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    nickname TEXT,
    ip TEXT UNIQUE
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    content TEXT,
    user_id INTEGER,
    created_at INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER,
    user_id INTEGER,
    text TEXT,
    created_at INTEGER,
    FOREIGN KEY(post_id) REFERENCES posts(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});

// 🔹 회원가입 (IP당 1회 제한)
app.post('/api/register', async (req, res) => {
  const { username, password, nickname, ip } = req.body;
  if (!username || !password || !nickname || !ip)
    return res.status(400).json({ error: '모든 필드를 입력하세요.' });

  db.get('SELECT * FROM users WHERE ip = ?', [ip], async (err, existing) => {
    if (existing) return res.status(409).json({ error: '이미 이 IP로 가입됨.' });

    const hash = await bcrypt.hash(password, 10);
    db.run(
      'INSERT INTO users (username, password, nickname, ip) VALUES (?, ?, ?, ?)',
      [username, hash, nickname, ip],
      function (err) {
        if (err) return res.status(409).json({ error: '아이디 중복' });
        res.json({ success: true });
      }
    );
  });
});

// 🔹 로그인
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (!user) return res.status(401).json({ error: '로그인 실패' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: '비밀번호 틀림' });
    res.json({ success: true, user: { id: user.id, nickname: user.nickname } });
  });
});

// 🔹 글 작성
app.post('/api/posts', (req, res) => {
  const { title, content, user_id } = req.body;
  if (!title || !content || !user_id)
    return res.status(400).json({ error: '필수 항목 누락' });

  db.run(
    'INSERT INTO posts (title, content, user_id, created_at) VALUES (?, ?, ?, ?)',
    [title, content, user_id, Date.now()],
    function (err) {
      if (err) return res.status(500).json({ error: '글쓰기 실패' });
      res.json({ success: true, post_id: this.lastID });
    }
  );
});

// 🔹 게시글 목록
app.get('/api/posts', (req, res) => {
  db.all(
    `SELECT posts.id, title, created_at, nickname FROM posts
     JOIN users ON posts.user_id = users.id
     ORDER BY created_at DESC`,
    [],
    (err, rows) => {
      res.json(rows);
    }
  );
});

// 🔹 게시글 상세
app.get('/api/posts/:id', (req, res) => {
  const postId = req.params.id;
  db.get(
    `SELECT posts.id, title, content, created_at, nickname FROM posts
     JOIN users ON posts.user_id = users.id
     WHERE posts.id = ?`,
    [postId],
    (err, row) => {
      if (!row) return res.status(404).json({ error: '게시글 없음' });
      res.json(row);
    }
  );
});

// 🔹 댓글 작성
app.post('/api/comments', (req, res) => {
  const { post_id, user_id, text } = req.body;
  if (!post_id || !user_id || !text)
    return res.status(400).json({ error: '필수 항목 누락' });

  db.run(
    'INSERT INTO comments (post_id, user_id, text, created_at) VALUES (?, ?, ?, ?)',
    [post_id, user_id, text, Date.now()],
    function (err) {
      if (err) return res.status(500).json({ error: '댓글 실패' });
      res.json({ success: true });
    }
  );
});

// 🔹 댓글 조회
app.get('/api/posts/:id/comments', (req, res) => {
  const postId = req.params.id;
  db.all(
    `SELECT text, nickname FROM comments
     JOIN users ON comments.user_id = users.id
     WHERE post_id = ?
     ORDER BY created_at ASC`,
    [postId],
    (err, rows) => {
      res.json(rows);
    }
  );
});

// 🔹 서버 시작
app.listen(port, () => {
  console.log(`✅ 서버 실행 중: http://localhost:${port}`);
});
