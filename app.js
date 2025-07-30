const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'your_secret_key'; // JWT 비밀키 (안전하게 관리하세요)

// SQLite DB 초기화
const db = new sqlite3.Database('./database.sqlite', (err) => {
  if (err) return console.error('DB 연결 오류:', err);
  console.log('SQLite DB 연결 완료');
});

// 테이블 생성 (없으면)
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    nickname TEXT NOT NULL
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

// JWT 인증 미들웨어
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: '토큰이 없습니다' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: '토큰이 유효하지 않습니다' });
    req.user = user;
    next();
  });
}

// 회원가입
app.post('/auth/register',
  body('username').isLength({ min: 3 }),
  body('password').isLength({ min: 6 }),
  body('nickname').notEmpty(),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { username, password, nickname } = req.body;

    // 중복 확인
    db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
      if (err) return res.status(500).json({ error: 'DB 에러' });
      if (row) return res.status(409).json({ error: '이미 존재하는 아이디입니다.' });

      bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ error: '비밀번호 암호화 실패' });

        db.run(
          'INSERT INTO users (username, password, nickname) VALUES (?, ?, ?)',
          [username, hash, nickname],
          function (err) {
            if (err) return res.status(500).json({ error: '회원가입 실패' });
            res.status(201).json({ message: '회원가입 성공' });
          }
        );
      });
    });
  }
);

// 로그인
app.post('/auth/login', (req, res) => {
  const { id, password } = req.body;

  db.get('SELECT * FROM users WHERE username = ?', [id], (err, user) => {
    if (err) return res.status(500).json({ error: 'DB 에러' });
    if (!user) return res.status(401).json({ error: '아이디 또는 비밀번호가 틀렸습니다.' });

    bcrypt.compare(password, user.password, (err, result) => {
      if (err) return res.status(500).json({ error: '비밀번호 비교 실패' });
      if (!result) return res.status(401).json({ error: '아이디 또는 비밀번호가 틀렸습니다.' });

      const token = jwt.sign({ userId: user.id, username: user.username, nickname: user.nickname }, SECRET_KEY, { expiresIn: '7d' });
      res.json({ token, nickname: user.nickname });
    });
  });
});

// 게시글 목록 조회
app.get('/posts', (req, res) => {
  const sql = `
    SELECT posts.id, posts.title, posts.content, posts.createdAt, users.nickname AS authorNickname
    FROM posts
    JOIN users ON posts.authorId = users.id
    ORDER BY posts.createdAt DESC
  `;
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ error: '게시물 조회 실패' });
    res.json(rows);
  });
});

// 게시글 상세 조회
app.get('/posts/:id', (req, res) => {
  const postId = req.params.id;

  const postSql = `
    SELECT posts.id, posts.title, posts.content, posts.createdAt, users.nickname AS authorNickname
    FROM posts
    JOIN users ON posts.authorId = users.id
    WHERE posts.id = ?
  `;
  db.get(postSql, [postId], (err, post) => {
    if (err) return res.status(500).json({ error: '게시글 조회 실패' });
    if (!post) return res.status(404).json({ error: '게시글이 없습니다.' });

    const commentsSql = `
      SELECT comments.id, comments.text, comments.createdAt, users.nickname AS authorNickname
      FROM comments
      JOIN users ON comments.authorId = users.id
      WHERE comments.postId = ?
      ORDER BY comments.createdAt ASC
    `;
    db.all(commentsSql, [postId], (err, comments) => {
      if (err) return res.status(500).json({ error: '댓글 조회 실패' });
      post.comments = comments;
      res.json(post);
    });
  });
});

// 게시글 작성 (인증 필요)
app.post('/posts', authenticateToken, (req, res) => {
  const { title, content } = req.body;
  const authorId = req.user.userId;

  if (!title || !content) return res.status(400).json({ error: '제목과 내용이 필요합니다.' });

  db.run(
    'INSERT INTO posts (authorId, title, content) VALUES (?, ?, ?)',
    [authorId, title, content],
    function (err) {
      if (err) return res.status(500).json({ error: '게시글 작성 실패' });
      res.status(201).json({
        id: this.lastID,
        authorNickname: req.user.nickname,
        title,
        content,
        createdAt: new Date().toISOString(),
      });
    }
  );
});

// 댓글 작성 (인증 필요)
app.post('/posts/:postId/comments', authenticateToken, (req, res) => {
  const postId = req.params.postId;
  const authorId = req.user.userId;
  const { text } = req.body;

  if (!text) return res.status(400).json({ error: '댓글 내용을 입력하세요.' });

  // 게시글 존재 여부 확인
  db.get('SELECT id FROM posts WHERE id = ?', [postId], (err, post) => {
    if (err) return res.status(500).json({ error: 'DB 에러' });
    if (!post) return res.status(404).json({ error: '게시글이 없습니다.' });

    db.run(
      'INSERT INTO comments (postId, authorId, text) VALUES (?, ?, ?)',
      [postId, authorId, text],
      function (err) {
        if (err) return res.status(500).json({ error: '댓글 작성 실패' });
        res.status(201).json({
          id: this.lastID,
          postId,
          authorNickname: req.user.nickname,
          text,
          createdAt: new Date().toISOString(),
        });
      }
    );
  });
});

// 서버 시작
app.listen(PORT, () => {
  console.log(`서버가 http://localhost:${PORT} 에서 실행 중입니다.`);
});
