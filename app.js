const express = require('express');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'your_jwt_secret_key_here'; // 꼭 바꾸세요!

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

let db;

(async () => {
  db = await open({
    filename: './database.sqlite',
    driver: sqlite3.Database,
  });

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      nickname TEXT NOT NULL,
      ip TEXT UNIQUE NOT NULL
    )
  `);

  await db.exec(`
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId INTEGER NOT NULL,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(userId) REFERENCES users(id)
    )
  `);

  await db.exec(`
    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      postId INTEGER NOT NULL,
      userId INTEGER NOT NULL,
      content TEXT NOT NULL,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(postId) REFERENCES posts(id),
      FOREIGN KEY(userId) REFERENCES users(id)
    )
  `);
})();

function getClientIP(req) {
  return (
    (req.headers['x-forwarded-for'] || '').split(',').shift().trim() ||
    req.socket.remoteAddress ||
    ''
  );
}

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

// 회원가입
app.post('/auth/register', async (req, res) => {
  const { id: username, password, nickname } = req.body;
  if (!username || !password || !nickname)
    return res.status(400).json({ message: '모든 필드를 입력하세요.' });

  const ip = getClientIP(req);
  try {
    const ipExists = await db.get('SELECT id FROM users WHERE ip = ?', ip);
    if (ipExists)
      return res.status(400).json({ message: 'IP당 1개 계정만 생성 가능합니다.' });

    const userExists = await db.get('SELECT id FROM users WHERE username = ?', username);
    if (userExists)
      return res.status(400).json({ message: '이미 존재하는 아이디입니다.' });

    const hashedPwd = await bcrypt.hash(password, 10);
    await db.run(
      'INSERT INTO users (username, password, nickname, ip) VALUES (?, ?, ?, ?)',
      username,
      hashedPwd,
      nickname,
      ip
    );

    res.json({ message: '회원가입 성공' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: '서버 오류' });
  }
});

// 로그인
app.post('/auth/login', async (req, res) => {
  const { id: username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: '아이디와 비밀번호를 입력하세요.' });

  try {
    const user = await db.get('SELECT * FROM users WHERE username = ?', username);
    if (!user) return res.status(400).json({ message: '존재하지 않는 아이디입니다.' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: '비밀번호가 틀렸습니다.' });

    const token = jwt.sign(
      { id: user.id, nickname: user.nickname },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.json({ token, nickname: user.nickname });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: '서버 오류' });
  }
});

// 게시글 리스트 조회
app.get('/posts', async (req, res) => {
  try {
    const posts = await db.all(
      `SELECT posts.id, posts.title, posts.content, posts.createdAt, users.nickname AS author
       FROM posts
       JOIN users ON posts.userId = users.id
       ORDER BY posts.createdAt DESC`
    );
    res.json(posts);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: '게시글 조회 실패' });
  }
});

// 게시글 작성
app.post('/posts', authenticateToken, async (req, res) => {
  const { title, content } = req.body;
  if (!title || !content)
    return res.status(400).json({ message: '제목과 내용을 입력하세요.' });

  try {
    await db.run(
      'INSERT INTO posts (userId, title, content) VALUES (?, ?, ?)',
      req.user.id,
      title,
      content
    );
    res.json({ message: '게시글 작성 완료' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: '게시글 작성 실패' });
  }
});

// 게시글 상세 조회 (댓글 포함)
app.get('/posts/:id', async (req, res) => {
  const postId = req.params.id;
  try {
    const post = await db.get(
      `SELECT posts.*, users.nickname AS author
       FROM posts JOIN users ON posts.userId = users.id
       WHERE posts.id = ?`,
      postId
    );

    if (!post) return res.status(404).json({ message: '게시글을 찾을 수 없습니다.' });

    const comments = await db.all(
      `SELECT comments.*, users.nickname AS author
       FROM comments JOIN users ON comments.userId = users.id
       WHERE comments.postId = ?
       ORDER BY comments.createdAt ASC`,
      postId
    );

    res.json({ ...post, comments });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: '상세 조회 실패' });
  }
});

// 댓글 작성
app.post('/posts/:id/comments', authenticateToken, async (req, res) => {
  const postId = req.params.id;
  const { content } = req.body;
  if (!content) return res.status(400).json({ message: '댓글 내용을 입력하세요.' });

  try {
    await db.run(
      'INSERT INTO comments (postId, userId, content) VALUES (?, ?, ?)',
      postId,
      req.user.id,
      content
    );
    res.json({ message: '댓글 작성 완료' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: '댓글 작성 실패' });
  }
});

// index.html 서빙 (정적파일 public 폴더 사용 중)
// 기본적으로 express.static('public')으로 index.html 자동 서빙됩니다.

app.listen(PORT, () => {
  console.log(`서버 실행 중 http://localhost:${PORT}`);
});
