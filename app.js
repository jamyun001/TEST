const express = require('express');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'your_secret_here';

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

let db;
(async () => {
  db = await open({
    filename: './database.sqlite',
    driver: sqlite3.Database,
  });

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      nickname TEXT,
      ip TEXT UNIQUE
    );
  `);

  await db.exec(`
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId INTEGER,
      title TEXT,
      content TEXT,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (userId) REFERENCES users(id)
    );
  `);

  await db.exec(`
    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      postId INTEGER,
      userId INTEGER,
      content TEXT,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (postId) REFERENCES posts(id),
      FOREIGN KEY (userId) REFERENCES users(id)
    );
  `);
})();

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ message: '로그인 필요' });

  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: '토큰 없음' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: '유효하지 않은 토큰' });
    req.user = user;
    next();
  });
}

app.post('/signup', async (req, res) => {
  const { username, password, nickname } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!username || !password || !nickname) {
    return res.status(400).json({ message: '모든 항목을 입력하세요' });
  }

  try {
    const existing = await db.get('SELECT * FROM users WHERE ip = ?', ip);
    if (existing) return res.status(400).json({ message: 'IP당 한 개의 계정만 가능' });

    const userCheck = await db.get('SELECT * FROM users WHERE username = ?', username);
    if (userCheck) return res.status(400).json({ message: '이미 존재하는 아이디' });

    const hashed = await bcrypt.hash(password, 10);
    await db.run('INSERT INTO users (username, password, nickname, ip) VALUES (?, ?, ?, ?)', username, hashed, nickname, ip);
    res.json({ message: '회원가입 성공' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: '서버 오류' });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await db.get('SELECT * FROM users WHERE username = ?', username);
    if (!user) return res.status(400).json({ message: '존재하지 않는 아이디' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: '비밀번호 틀림' });

    const token = jwt.sign({ id: user.id, nickname: user.nickname }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, nickname: user.nickname });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: '서버 오류' });
  }
});

app.get('/posts', async (req, res) => {
  try {
    const posts = await db.all(`
      SELECT posts.id, posts.title, posts.content, posts.createdAt, users.nickname
      FROM posts LEFT JOIN users ON posts.userId = users.id
      ORDER BY posts.createdAt DESC
    `);
    res.json(posts);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: '게시물 불러오기 실패' });
  }
});

app.post('/posts', authenticateToken, async (req, res) => {
  const { title, content } = req.body;
  try {
    await db.run('INSERT INTO posts (userId, title, content) VALUES (?, ?, ?)', req.user.id, title, content);
    res.json({ message: '게시물 작성 성공' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: '작성 실패' });
  }
});

app.get('/posts/:id', async (req, res) => {
  try {
    const post = await db.get(`
      SELECT posts.*, users.nickname FROM posts
      LEFT JOIN users ON posts.userId = users.id
      WHERE posts.id = ?
    `, req.params.id);

    const comments = await db.all(`
      SELECT comments.*, users.nickname FROM comments
      LEFT JOIN users ON comments.userId = users.id
      WHERE comments.postId = ?
      ORDER BY comments.createdAt ASC
    `, req.params.id);

    res.json({ ...post, comments });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: '상세 조회 실패' });
  }
});

app.post('/posts/:id/comments', authenticateToken, async (req, res) => {
  const { content } = req.body;
  try {
    await db.run('INSERT INTO comments (postId, userId, content) VALUES (?, ?, ?)', req.params.id, req.user.id, content);
    res.json({ message: '댓글 작성 완료' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: '댓글 실패' });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`서버 실행: http://localhost:${PORT}`);
});
