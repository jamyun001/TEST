const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'your_jwt_secret_key'; // 배포 시 더 안전하게 관리하세요

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'))); // 프론트 파일 경로 맞게 설정

// SQLite DB 초기화
const db = new sqlite3.Database('./db.sqlite3', err => {
  if (err) {
    console.error('DB 연결 실패', err);
  } else {
    console.log('DB 연결 성공');
  }
});

// 테이블 생성 (없으면)
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      nickname TEXT NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      author TEXT NOT NULL,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      postId INTEGER NOT NULL,
      author TEXT NOT NULL,
      content TEXT NOT NULL,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(postId) REFERENCES posts(id) ON DELETE CASCADE
    )
  `);
});

// 미들웨어: JWT 인증 검사
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: '토큰이 필요합니다.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: '토큰이 유효하지 않습니다.' });
    req.user = user;
    next();
  });
}

// --- 회원가입 ---
app.post('/auth/register', (req, res) => {
  const { id, password, nickname } = req.body;
  if (!id || !password || !nickname) {
    return res.status(400).json({ message: '모든 정보를 입력하세요.' });
  }

  // 비밀번호 해싱
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) return res.status(500).json({ message: '서버 오류' });

    // 사용자 등록
    const sql = `INSERT INTO users (username, password, nickname) VALUES (?, ?, ?)`;
    db.run(sql, [id, hashedPassword, nickname], function (err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return res.status(409).json({ message: '이미 존재하는 아이디입니다.' });
        }
        return res.status(500).json({ message: '회원가입 실패' });
      }
      return res.json({ message: '회원가입 성공' });
    });
  });
});

// --- 로그인 ---
app.post('/auth/login', (req, res) => {
  const { id, password } = req.body;
  if (!id || !password) {
    return res.status(400).json({ message: '아이디와 비밀번호를 입력하세요.' });
  }

  const sql = `SELECT * FROM users WHERE username = ?`;
  db.get(sql, [id], (err, user) => {
    if (err) return res.status(500).json({ message: '서버 오류' });
    if (!user) return res.status(400).json({ message: '아이디 또는 비밀번호가 올바르지 않습니다.' });

    bcrypt.compare(password, user.password, (err, result) => {
      if (err) return res.status(500).json({ message: '서버 오류' });
      if (!result) return res.status(400).json({ message: '아이디 또는 비밀번호가 올바르지 않습니다.' });

      // JWT 발급 (payload에 닉네임 포함)
      const token = jwt.sign({ username: user.username, nickname: user.nickname }, JWT_SECRET, { expiresIn: '7d' });
      res.json({ token });
    });
  });
});

// --- 게시글 목록 조회 ---
app.get('/posts', (req, res) => {
  const sql = `SELECT id, author, title, createdAt FROM posts ORDER BY createdAt DESC`;
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ message: '게시글 조회 실패' });
    res.json(rows);
  });
});

// --- 게시글 상세 조회 ---
app.get('/posts/:postId', (req, res) => {
  const postId = req.params.postId;
  const sql = `SELECT * FROM posts WHERE id = ?`;
  db.get(sql, [postId], (err, row) => {
    if (err) return res.status(500).json({ message: '게시글 조회 실패' });
    if (!row) return res.status(404).json({ message: '게시글을 찾을 수 없습니다.' });
    res.json(row);
  });
});

// --- 게시글 작성 ---
app.post('/posts', authenticateToken, (req, res) => {
  const { title, content } = req.body;
  if (!title || !content) {
    return res.status(400).json({ message: '제목과 내용을 입력하세요.' });
  }

  const sql = `INSERT INTO posts (author, title, content) VALUES (?, ?, ?)`;
  db.run(sql, [req.user.nickname, title, content], function (err) {
    if (err) return res.status(500).json({ message: '게시글 작성 실패' });
    res.json({ id: this.lastID });
  });
});

// --- 댓글 목록 조회 ---
app.get('/posts/:postId/comments', (req, res) => {
  const postId = req.params.postId;
  const sql = `SELECT id, author, content, createdAt FROM comments WHERE postId = ? ORDER BY createdAt ASC`;
  db.all(sql, [postId], (err, rows) => {
    if (err) return res.status(500).json({ message: '댓글 조회 실패' });
    res.json(rows);
  });
});

// --- 댓글 작성 ---
app.post('/posts/:postId/comments', authenticateToken, (req, res) => {
  const postId = req.params.postId;
  const { content } = req.body;
  if (!content) {
    return res.status(400).json({ message: '댓글 내용을 입력하세요.' });
  }

  const sqlCheckPost = `SELECT id FROM posts WHERE id = ?`;
  db.get(sqlCheckPost, [postId], (err, post) => {
    if (err) return res.status(500).json({ message: '서버 오류' });
    if (!post) return res.status(404).json({ message: '게시글이 존재하지 않습니다.' });

    const sql = `INSERT INTO comments (postId, author, content) VALUES (?, ?, ?)`;
    db.run(sql, [postId, req.user.nickname, content], function (err) {
      if (err) return res.status(500).json({ message: '댓글 작성 실패' });
      res.json({ id: this.lastID });
    });
  });
});

// --- 서버 시작 ---
app.listen(PORT, () => {
  console.log(`서버가 http://localhost:${PORT} 에서 실행 중입니다.`);
});
