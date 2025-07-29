const express = require('express');
const cors = require('cors');
const path = require('path');
const { MongoClient, ObjectId } = require('mongodb');

const app = express();
const PORT = 3000;
const MONGO_URL = 'mongodb://localhost:27017';
const DB_NAME = 'galleryDB';

let db;
let postsCollection;

app.use(cors());
app.use(express.json());

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/posts', async (req, res) => {
  try {
    const posts = await postsCollection
      .find()
      .sort({ createdAt: -1 })
      .toArray();
    res.json(posts);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '서버 오류' });
  }
});

app.post('/posts', async (req, res) => {
  const { title, content, ip } = req.body;
  if (!title || !content) {
    return res.status(400).json({ error: '제목과 내용을 입력하세요.' });
  }
  try {
    const result = await postsCollection.insertOne({
      title,
      content,
      ip,
      createdAt: Date.now(),
      comments: []
    });
    res.status(201).json({ id: result.insertedId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '서버 오류' });
  }
});

app.get('/posts/:id', async (req, res) => {
  try {
    const post = await postsCollection.findOne({ _id: new ObjectId(req.params.id) });
    if (!post) return res.status(404).json({ error: '게시글을 찾을 수 없습니다.' });
    res.json(post);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '서버 오류' });
  }
});

app.post('/posts/:id/comments', async (req, res) => {
  const { author, text, ip } = req.body;
  if (!author || !text) {
    return res.status(400).json({ error: '작성자와 내용을 입력하세요.' });
  }
  try {
    const result = await postsCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $push: { comments: { author, text, ip, createdAt: Date.now() } } }
    );
    if (result.modifiedCount === 0) {
      return res.status(404).json({ error: '게시글을 찾을 수 없습니다.' });
    }
    res.status(201).json({ message: '댓글 작성 완료' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '서버 오류' });
  }
});

app.get('/bannedIPs/:ip', async (req, res) => {
  try {
    const banned = await db.collection('bannedIPs').findOne({ _id: req.params.ip });
    res.json({ banned: !!banned });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: '서버 오류' });
  }
});

MongoClient.connect(MONGO_URL, { useUnifiedTopology: true })
  .then(client => {
    db = client.db(DB_NAME);
    postsCollection = db.collection('posts');
    console.log('✅ MongoDB 연결 성공');
    app.listen(PORT, () => {
      console.log(`✅ 서버 실행: http://localhost:${PORT}`);
    });
  })
  .catch(err => {
    console.error('❌ MongoDB 연결 실패:', err);
  });
