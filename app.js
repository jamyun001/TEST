// app.js
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cors = require('cors');
const app = express();

const SECRET_KEY = 'your-secret-key'; // 실제 배포땐 env로 분리
const PORT = 3000;

// DB 초기화
const db = new sqlite3.Database(':memory:'); // 필요시 파일 DB로 변경

db.serialize(() => {
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    nickname TEXT,
    ip TEXT
  )`);

  db.run(`CREATE TABLE posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    authorId INTEGER,
    title TEXT,
    content TEXT,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(authorId) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    postId INTEGER,
    authorId INTEGER,
    text TEXT,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(postId) REFERENCES posts(id),
    FOREIGN KEY(authorId) REFERENCES users(id)
  )`);
});

app.use(cors());
app.use(bodyParser.json());

// 회원가입 제한: 같은 IP로 가입 제한 (한번만)
function checkIpLimit(ip) {
  return new Promise((resolve, reject) => {
    db.get('SELECT COUNT(*) as count FROM users WHERE ip = ?', [ip], (err, row) => {
      if (err) reject(err);
      else resolve(row.count === 0);
    });
  });
}

// JWT 인증 미들웨어
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ message: '인증 필요' });
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: '토큰 없음' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ message: '유효하지 않은 토큰' });
    req.user = user;
    next();
  });
}

// --- 회원가입 ---
app.post('/auth/register', async (req, res) => {
  const ip = req.ip;
  const { id: username, password, nickname } = req.body;
  if (!username || !password || !nickname) return res.status(400).json({ message: '모든 필드 필요' });

  try {
    const canRegister = await checkIpLimit(ip);
    if (!canRegister) return res.status(429).json({ message: '같은 IP로는 1회만 회원가입 가능' });

    const hashedPw = await bcrypt.hash(password, 10);

    db.run(
      'INSERT INTO users (username, password, nickname, ip) VALUES (?, ?, ?, ?)',
      [username, hashedPw, nickname, ip],
      function (err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint')) {
            return res.status(409).json({ message: '이미 존재하는 아이디입니다.' });
          }
          return res.status(500).json({ message: '서버 오류' });
        }
        return res.status(201).json({ message: '회원가입 성공' });
      }
    );
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: '서버 오류' });
  }
});

// --- 로그인 ---
app.post('/auth/login', (req, res) => {
  const { id: username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: '아이디와 비밀번호 필요' });

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) return res.status(500).json({ message: '서버 오류' });
    if (!user) return res.status(401).json({ message: '아이디 또는 비밀번호 불일치' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: '아이디 또는 비밀번호 불일치' });

    const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '24h' });
    res.json({ token, nickname: user.nickname });
  });
});

// --- 게시물 목록 ---
app.get('/posts', (req, res) => {
  const sql = `
    SELECT p.id, p.title, p.content, p.createdAt, u.nickname as authorNickname
    FROM posts p LEFT JOIN users u ON p.authorId = u.id
    ORDER BY p.createdAt DESC
  `;
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ message: '서버 오류' });
    res.json(rows);
  });
});

// --- 게시글 상세 및 댓글 포함 ---
app.get('/posts/:id', (req, res) => {
  const postId = req.params.id;
  db.get(
    `SELECT p.id, p.title, p.content, p.createdAt, u.nickname as authorNickname
     FROM posts p LEFT JOIN users u ON p.authorId = u.id WHERE p.id = ?`,
    [postId],
    (err, post) => {
      if (err) return res.status(500).json({ message: '서버 오류' });
      if (!post) return res.status(404).json({ message: '게시물 없음' });

      db.all(
        `SELECT c.id, c.text, c.createdAt, u.nickname as authorNickname
         FROM comments c LEFT JOIN users u ON c.authorId = u.id
         WHERE c.postId = ? ORDER BY c.createdAt ASC`,
        [postId],
        (err2, comments) => {
          if (err2) return res.status(500).json({ message: '서버 오류' });
          post.comments = comments;
          res.json(post);
        }
      );
    }
  );
});

// --- 게시글 작성 (인증 필요) ---
app.post('/posts', authenticateToken, (req, res) => {
  const { title, content } = req.body;
  if (!title || !content) return res.status(400).json({ message: '제목과 내용 필요' });

  db.run(
    'INSERT INTO posts (authorId, title, content) VALUES (?, ?, ?)',
    [req.user.id, title, content],
    function (err) {
      if (err) return res.status(500).json({ message: '서버 오류' });
      const postId = this.lastID;
      db.get(
        `SELECT p.id, p.title, p.content, p.createdAt, u.nickname as authorNickname
         FROM posts p LEFT JOIN users u ON p.authorId = u.id WHERE p.id = ?`,
        [postId],
        (err2, post) => {
          if (err2) return res.status(500).json({ message: '서버 오류' });
          res.status(201).json(post);
        }
      );
    }
  );
});

// --- 댓글 작성 (인증 필요) ---
app.post('/posts/:id/comments', authenticateToken, (req, res) => {
  const postId = req.params.id;
  const { text } = req.body;
  if (!text) return res.status(400).json({ message: '댓글 내용 필요' });

  db.get('SELECT id FROM posts WHERE id = ?', [postId], (err, post) => {
    if (err) return res.status(500).json({ message: '서버 오류' });
    if (!post) return res.status(404).json({ message: '게시물 없음' });

    db.run(
      'INSERT INTO comments (postId, authorId, text) VALUES (?, ?, ?)',
      [postId, req.user.id, text],
      function (err2) {
        if (err2) return res.status(500).json({ message: '서버 오류' });
        const commentId = this.lastID;
        db.get(
          `SELECT c.id, c.text, c.createdAt, u.nickname as authorNickname
           FROM comments c LEFT JOIN users u ON c.authorId = u.id WHERE c.id = ?`,
          [commentId],
          (err3, comment) => {
            if (err3) return res.status(500).json({ message: '서버 오류' });
            res.status(201).json(comment);
          }
        );
      }
    );
  });
});

// 서버 시작
app.listen(PORT, () => {
  console.log(`서버가 http://localhost:${PORT} 에서 실행 중입니다.`);
});
