require('dotenv').config(); // Carregar variáveis de ambiente
const express = require('express');
const jwt = require('jsonwebtoken');
const mysql = require('mysql');
const app = express();
const PORT = process.env.PORT || 3000;

// Configuração do banco de dados (MySQL)
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: process.env.DB_PASSWORD,
  database: 'mydb'
});

// Middleware para parsear JSON
app.use(express.json());

// **Microatividade 1: Controle de acesso a recursos com autenticação (JWT)**

// Função para gerar um token JWT com expiração
// Este token terá um campo 'exp' que define o tempo de expiração
function generateToken(username) {
  const payload = {
    username: username,
    exp: Math.floor(Date.now() / 1000) + (60 * 60) // Expira em 1 hora
  };
  return jwt.sign(payload, process.env.JWT_SECRET);
}

// Middleware de autenticação (verificação do token)
// Essa função verifica se o token JWT enviado no cabeçalho da requisição é válido
// Se não for, retorna um erro 401
function authenticateToken(req, res, next) {
  const token = req.header('Authorization')?.replace('Bearer ', '');  // Pega o token enviado no cabeçalho 'Authorization'
  
  if (!token) {
    return res.status(401).json({ message: "Acesso não autorizado" });  // Se não houver token, retorna erro 401
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {  // Verifica o token
    if (err) {
      return res.status(401).json({ message: "Acesso não autorizado" });  // Se o token não for válido, retorna erro 401
    }
    req.user = user;  // Se o token for válido, armazena os dados do usuário na requisição
    next(); // Passa a requisição para a próxima função/rota
  });
}

// **Microatividade 2: Tratamento de dados sensíveis e log de erros com foco em segurança**

app.get('/confidential-data', authenticateToken, (req, res) => {
  // Aqui protegemos a rota /confidential-data com autenticação JWT, ou seja, somente quem tiver um token válido pode acessar
  const jsonData = { userData: 'Dados sensíveis' };  // Simulação de dados sensíveis que seriam retornados
  res.json(jsonData);  // Retorna os dados sensíveis para o usuário autenticado
});

// Endpoint de login para gerar o token JWT
// O endpoint /login cria um token JWT para o usuário, mas somente se as credenciais estiverem corretas
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // **Microatividade 2: Tratamento de dados sensíveis - Validação das credenciais e restrição de tentativas**
  // Neste exemplo, estamos utilizando uma verificação simples de login (não é ideal para produção, mas serve para ilustrar)
  // **Melhoria**: Adicionar limites de tentativas para prevenir ataques de força bruta e mensagens genéricas de erro
  if (username === 'admin' && password === 'admin123') {
    const token = generateToken(username);  // Se as credenciais forem válidas, gera um token JWT
    return res.json({ jwt_token: token });  // Retorna o token para o cliente
  }
  
  res.status(401).json({ message: "Usuário ou senha incorretos." });  // Se as credenciais forem inválidas, retorna uma mensagem genérica
});

// **Microatividade 3: Prevenção de ataques de acesso não autorizado com base em tokens desprotegidos/desatualizados**

function checkTokenExpiration(token) {
  // **Verifica se o token JWT está expirado**
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);  // Verifica a validade do token
    return decoded;  // Se o token for válido, retorna os dados do usuário
  } catch (err) {
    return null;  // Se o token for inválido ou expirado, retorna null
  }
}

app.get('/do-action', authenticateToken, (req, res) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  
  const validToken = checkTokenExpiration(token);  // Verifica a expiração do token
  
  if (!validToken) {
    return res.status(401).json({ message: "Token expirado ou inválido. Faça login novamente." });  // Se o token não for válido, retorna erro
  }

  // Executa a ação somente se o token for válido
  res.json({ message: 'Ação realizada com sucesso!' });
});

// **Microatividade 4: Tratamento de SQL Injection em códigos-fonte**

function doDBAction(id, callback) {
  // Aqui, utilizamos consultas parametrizadas para evitar SQL Injection
  const query = 'SELECT * FROM users WHERE userID = ?';  // A consulta usa o sinal de interrogação (?) como um placeholder para o valor
  connection.query(query, [id], (error, results) => {  // Passamos o valor do 'id' como parâmetro na consulta
    if (error) throw error;
    callback(results);  // Retorna os resultados da consulta
  });
}

app.get('/user', (req, res) => {
  const userId = req.query.id;  // Pega o parâmetro 'id' da requisição

  if (!userId) {
    return res.status(400).json({ message: "ID de usuário é necessário." });  // Se não houver 'id', retorna erro
  }

  // **Microatividade 4: Prevenção de SQL Injection**
  // Utilizando consultas parametrizadas para prevenir injeções
  doDBAction(userId, (results) => {
    res.json(results);  // Retorna os resultados da consulta
  });
});

// **Microatividade 5: Tratamento de CRLF Injection em códigos-fonte**

function sanitizeRedirectUrl(url) {
  // **Microatividade 5: Tratamento de CRLF Injection**
  // A função substitui qualquer caractere de nova linha (CRLF) na URL para evitar CRLF Injection
  return url.replace(/[\r\n]+/g, '');  // Remove qualquer CRLF da URL
}

app.get('/redirect', (req, res) => {
  const redirectUrl = req.query.url;  // Pega a URL de redirecionamento

  if (!redirectUrl) {
    return res.status(400).json({ message: "URL de redirecionamento é necessária." });  // Se não houver URL, retorna erro
  }

  const sanitizedUrl = sanitizeRedirectUrl(redirectUrl);  // Sanitiza a URL para evitar CRLF Injection

  // **Microatividade 5: Impedir redirecionamento para domínios externos**
  // Só permite redirecionamento para o domínio local
  if (sanitizedUrl.startsWith('http://localhost') || sanitizedUrl.startsWith('https://localhost')) {
    return res.redirect(sanitizedUrl);  // Redireciona para a URL sanitizada
  }

  res.status(400).json({ message: "Redirecionamento para URLs externas não permitido." });  // Se a URL não for local, retorna erro
});

// Iniciar o servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
