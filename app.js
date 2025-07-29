const express = require('express')
const sqlite3 = require('sqlite3')
const { open } = require('sqlite')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const cors = require('cors')
const path = require('path')

const app = express()
const PORT = 3000
const JWT_SECRET = 'your_jwt_secret_here'

app.use(cors())
app.use(express.json())
app.use(express.static(path.join(__dirname, 'public')))

let db
;(async () => {
  db = await open({
    filename: './database.sqlite',
    driver: sqlite3.Database
  })

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      nickname TEXT,
      ip TEXT UNIQUE
    );
  `)

  await db.exec(`
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId INTEGER,
      title TEXT,
      content TEXT,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (userId) REFERENCES users(id)
    );
  `)

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
  `)
})()

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization']
  if (!authHeader) return res.status(401).json({ message: '로그인 필요' })
  const token = authHeader.split(' ')[1]
  if (!token) return res.status(401).json({ message: '토큰 없음' })

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: '유효하지 않은 토큰' })
    req.user = user
    next()
  })
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'))
})

app.post('/signup', async (req, res) => {
  const { username, password, nickname } = req.body
  const ip = req.ip

  if (!username || !password || !nickname) {
    return res.status(400).json({ message: '모든 필드를 입력하세요.' })
  }

  try {
    const existingIpUser = await db.get('SELECT * FROM users WHERE ip = ?', ip)
    if (existingIpUser) {
      return res.status(400).json({ message: 'IP당 1개의 계정만 가입 가능합니다.' })
    }

    const existingUser = await db.get('SELECT * FROM users WHERE username = ?', username)
    if (existingUser) {
      return res.status(400).json({ message: '이미 존재하는 아이디입니다.' })
    }

    const hashed = await bcrypt.hash(password, 10)
    await db.run(
      'INSERT INTO users (username, password, nickname, ip) VALUES (?, ?, ?, ?)',
      username,
      hashed,
      nickname,
      ip
    )
    res.json({ message: '회원가입 성공' })
  } catch (e) {
    console.error(e)
    res.status(500).json({ message: '서버 오류' })
  }
})

app.post('/login', async (req, res) => {
  const { username, password } = req.body
  if (!username || !password) return res.status(400).json({ message: '아이디와 비밀번호를 입력하세요.' })

  try {
    const user = await db.get('SELECT * FROM users WHERE username = ?', username)
    if (!user) return res.status(400).json({ message: '존재하지 않는 아이디입니다.' })

    const isValid = await bcrypt.compare(password, user.password)
    if (!isValid) return res.status(400).json({ message: '비밀번호가 틀렸습니다.' })

    const token = jwt.sign({ id: user.id, nickname: user.nickname }, JWT_SECRET, { expiresIn: '7d' })
    res.json({ token, nickname: user.nickname })
  } catch (e) {
    console.error(e)
    res.status(500).json({ message: '서버 오류' })
  }
})

app.get('/posts', async (req, res) => {
  try {
    const posts = await db.all(`
      SELECT posts.id, posts.title, posts.content, posts.createdAt, users.nickname
      FROM posts
      LEFT JOIN users ON posts.userId = users.id
      ORDER BY posts.createdAt DESC
    `)
    res.json(posts)
  } catch (e) {
    console.error(e)
    res.status(500).json({ message: '게시물 조회 실패' })
  }
})

app.post('/posts', authenticateToken, async (req, res) => {
  const { title, content } = req.body
  if (!title || !content) return res.status(400).json({ message: '제목과 내용을 입력하세요.' })

  try {
    await db.run('INSERT INTO posts (userId, title, content) VALUES (?, ?, ?)', req.user.id, title, content)
    res.json({ message: '게시물 작성 완료' })
  } catch (e) {
    console.error(e)
    res.status(500).json({ message: '게시물 작성 실패' })
  }
})

app.get('/posts/:id', async (req, res) => {
  const id = req.params.id
  try {
    const post = await db.get(`
      SELECT posts.id, posts.title, posts.content, posts.createdAt, users.nickname
      FROM posts LEFT JOIN users ON posts.userId = users.id WHERE posts.id = ?
    `, id)
    if (!post) return res.status(404).json({ message: '게시물을 찾을 수 없습니다.' })

    const comments = await db.all(`
      SELECT comments.id, comments.content, comments.createdAt, users.nickname
      FROM comments LEFT JOIN users ON comments.userId = users.id
      WHERE comments.postId = ?
      ORDER BY comments.createdAt ASC
    `, id)

    post.comments = comments
    res.json(post)
  } catch (e) {
    console.error(e)
    res.status(500).json({ message: '게시물 상세 조회 실패' })
  }
})

app.post('/posts/:id/comments', authenticateToken, async (req, res) => {
  const postId = req.params.id
  const { content } = req.body
  if (!content) return res.status(400).json({ message: '댓글 내용을 입력하세요.' })

  try {
    const post = await db.get('SELECT * FROM posts WHERE id = ?', postId)
    if (!post) return res.status(404).json({ message: '게시물을 찾을 수 없습니다.' })

    await db.run('INSERT INTO comments (postId, userId, content) VALUES (?, ?, ?)', postId, req.user.id, content)
    res.json({ message: '댓글 작성 완료' })
  } catch (e) {
    console.error(e)
    res.status(500).json({ message: '댓글 작성 실패' })
  }
})

app.listen(PORT, () => {
  console.log(`서버 실행 중: http://localhost:${PORT}`)
})
