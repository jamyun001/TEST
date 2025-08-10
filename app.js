const express = require('express');
const app = express();
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const PORT = 80;
const JWT_SECRET = 'your_jwt_secret'; // 환경변수로 관리 권장

// DB 초기화
const dbFile = path.join(__dirname, 'database.sqlite3');
const db = new sqlite3.Database(dbFile);

db.serialize(() => {
  // users 테이블
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    nickname TEXT NOT NULL
  )`);

  // posts 테이블
  db.run(`CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    category TEXT,
    image_url TEXT,
    views INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  // comments 테이블
  db.run(`CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    parent_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(post_id) REFERENCES posts(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads'),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
  })
});

// JWT 인증 미들웨어
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: 'No token' });
  const token = authHeader.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

// 회원가입
app.post('/api/register', (req, res) => {
  const { username, password, nickname } = req.body;
  if (!username || !password || !nickname) return res.status(400).json({ message: '모든 필드를 입력하세요' });

  db.get('SELECT id FROM users WHERE username = ?', [username], async (err, row) => {
    if (err) return res.status(500).json({ message: '서버 오류' });
    if (row) return res.status(400).json({ message: '아이디가 이미 존재합니다' });

    const hash = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (username, password_hash, nickname) VALUES (?, ?, ?)', [username, hash, nickname], function(err) {
      if (err) return res.status(500).json({ message: '서버 오류' });
      res.json({ message: '회원가입 완료' });
    });
  });
});

// 로그인
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) return res.status(500).json({ message: '서버 오류' });
    if (!user) return res.status(400).json({ message: '아이디 또는 비밀번호가 틀렸습니다' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(400).json({ message: '아이디 또는 비밀번호가 틀렸습니다' });

    const token = jwt.sign({ id: user.id, username: user.username, nickname: user.nickname }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token });
  });
});

// 게시글 목록 조회
app.get('/api/posts', (req, res) => {
  const sql = `
    SELECT p.id, p.title, p.content, p.category, p.image_url, p.views, p.created_at, u.nickname
    FROM posts p JOIN users u ON p.user_id = u.id
    ORDER BY p.created_at DESC
    LIMIT 20
  `;
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ message: '서버 오류' });
    res.json(rows);
  });
});

// 게시글 작성
app.post('/api/posts', authMiddleware, upload.single('image'), (req, res) => {
  const { title, content, category } = req.body;
  const image_url = req.file ? `/uploads/${req.file.filename}` : null;

  if (!title || !content) return res.status(400).json({ message: '제목과 내용을 입력하세요' });

  const sql = `INSERT INTO posts (user_id, title, content, category, image_url) VALUES (?, ?, ?, ?, ?)`;
  db.run(sql, [req.user.id, title, content, category || null, image_url], function(err) {
    if (err) return res.status(500).json({ message: '서버 오류' });
    res.json({ id: this.lastID });
  });
});

// 게시글 상세 + 댓글 조회
app.get('/api/posts/:id', (req, res) => {
  const postId = req.params.id;

  // 조회수 증가
  db.run('UPDATE posts SET views = views + 1 WHERE id = ?', [postId], err => {
    if (err) return res.status(500).json({ message: '서버 오류' });

    // 게시글 조회
    const postSql = `
      SELECT p.*, u.nickname FROM posts p
      JOIN users u ON p.user_id = u.id
      WHERE p.id = ?
    `;
    db.get(postSql, [postId], (err, post) => {
      if (err) return res.status(500).json({ message: '서버 오류' });
      if (!post) return res.status(404).json({ message: '게시글을 찾을 수 없습니다' });

      // 댓글 조회
      const commentSql = `
        SELECT c.*, u.nickname FROM comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.post_id = ?
        ORDER BY c.created_at ASC
      `;
      db.all(commentSql, [postId], (err, comments) => {
        if (err) return res.status(500).json({ message: '서버 오류' });
        res.json({ post, comments });
      });
    });
  });
});

// 댓글 작성
app.post('/api/comments', authMiddleware, (req, res) => {
  const { post_id, content, parent_id } = req.body;
  if (!post_id || !content) return res.status(400).json({ message: '댓글 내용을 입력하세요' });

  const sql = `INSERT INTO comments (post_id, user_id, content, parent_id) VALUES (?, ?, ?, ?)`;
  db.run(sql, [post_id, req.user.id, content, parent_id || null], function(err) {
    if (err) return res.status(500).json({ message: '서버 오류' });
    res.json({ id: this.lastID });
  });
});

// 정적 파일 서빙
app.use(express.static('public'));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
