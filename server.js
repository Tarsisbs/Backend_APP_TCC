require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bd = require('./bd');

const app = express();
app.use(cors());
app.use(bodyParser.json());

bd.getConnection((err) => {
  if (err) {
    console.log("ERRO AO CONECTAR NO MYSQL:", err);
  } else {
    console.log("MySQL conectado com sucesso!");
  }
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'tarsisbsaz0911';

app.get('/', (req, res) => res.json({ ok: true, env: process.env.NODE_ENV || 'dev' }));

app.post('/login', async (req, res) => {
  try {
    const { email, senha } = req.body;
    if (!email || !senha) return res.status(400).json({ error: 'email e senha são obrigatórios' });

    const hash = crypto.createHash('sha256').update(String(senha)).digest('hex');

    const [rows] = await bd.query('SELECT id, nome, email, senha_hash FROM usuarios WHERE email = ? LIMIT 1', [email]);

    if (!rows || rows.length === 0) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }
    const user = rows[0];
    if (user.senha_hash !== hash) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    const token = jwt.sign({ id: user.id, nome: user.nome }, JWT_SECRET, { expiresIn: '8h' });

    return res.json({
      success: true,
      token,
      nome: user.nome
    });

  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Erro interno' });
  }
});

app.get('/me', async (req, res) => {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ error: 'Não autorizado' });
  const parts = auth.split(' ');
  if (parts.length !== 2) return res.status(401).json({ error: 'Formato do token inválido' });
  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    return res.json({ user: payload });
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido' });
  }
});

app.post('/register', async (req, res) => {
  try {
    const { nome, email, senha } = req.body;

    if (!nome || !email || !senha) {
      return res.status(400).json({ error: 'Preencha nome, email e senha' });
    }

    const [existe] = await bd.query('SELECT id FROM usuarios WHERE email = ?', [email]);
    if (existe.length > 0) {
      return res.status(400).json({ error: 'Email já cadastrado' });
    }

    const crypto = require('crypto');
    const senha_hash = crypto.createHash('sha256').update(String(senha)).digest('hex');

    await bd.query('INSERT INTO usuarios (nome, email, senha_hash) VALUES (?, ?, ?)', [nome, email, senha_hash]);

    return res.json({ success: true, message: 'Usuário cadastrado com sucesso!' });

  } catch (err) {
    console.error('Erro no registro:', err);
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});

app.get("/api/noticias", async (req, res) => {
  try {
    const [rows] = await bd.query("SELECT * FROM noticias ORDER BY data_publicacao DESC");
    res.json(rows);
  } catch (err) {
    console.error("Erro ao buscar notícias:", err);
    res.status(500).json({ error: "Erro ao buscar notícias" });
  }
});

app.get('/perfil', async (req, res) => {
  try {
    const auth = req.headers['authorization'];
    if (!auth) return res.status(401).json({ error: 'Não autorizado' });

    const token = auth.split(' ')[1];
    const payload = jwt.verify(token, JWT_SECRET);

    const [rows] = await bd.query(
      'SELECT id, nome, email FROM usuarios WHERE id = ? LIMIT 1',
      [payload.id]
    );

    if (!rows || rows.length === 0)
      return res.status(404).json({ error: 'Usuário não encontrado' });

    res.json(rows[0]);

  } catch (err) {
    console.error('Erro /perfil', err);
    res.status(500).json({ error: 'Erro interno' });
  }
});

app.get('/calendario', async (req, res) => {
  try {
    const [rows] = await bd.query('SELECT * FROM calendario ORDER BY data ASC');
    res.json(rows);
  } catch (err) {
    console.error('Erro /calendario', err);
    res.status(500).json({ error: 'Erro ao buscar calendário' });
  }
});

app.get('/fluxo_caixa', async (req, res) => {
  try {
    const [rows] = await bd.query('SELECT * FROM fluxo_caixa ORDER BY data_movimento DESC');
    res.json(rows);
  } catch (err) {
    console.error('Erro /fluxo_caixa', err);
    res.status(500).json({ error: 'Erro ao buscar fluxo de caixa' });
  }
});
