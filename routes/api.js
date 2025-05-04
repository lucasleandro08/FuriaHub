const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const { TwitterApi } = require('twitter-api-v2');

const router = express.Router();

const oAuthStates = new Map();

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

const twitterClient = new TwitterApi({
  clientId: process.env.TWITTER_CLIENT_ID,
  clientSecret: process.env.TWITTER_CLIENT_SECRET
});

const UsuarioSchema = new mongoose.Schema({
  nome: { 
    type: String, 
    required: [true, 'Nome é obrigatório'],
    trim: true
  },
  email: { 
    type: String, 
    required: function() { return !this.twitterId; },
    unique: true,
    sparse: true,
    lowercase: true,
    trim: true,
    validate: {
      validator: function(v) {
        if (!v && !this.twitterId) return false;
        if (!v) return true;
        return /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/.test(v);
      },
      message: props => `${props.value} não é um email válido!`
    }
  },
  senha: { 
    type: String, 
    required: function() { return !this.twitterId; },
    minlength: [6, 'Senha deve ter no mínimo 6 caracteres']
  },
  authToken: { type: String, index: true },
  authTokenExpira: { type: Date },
  avatar: { type: String, default: '' },
  cpf: {
    type: String,
    unique: true,
    sparse: true,
    trim: true
  },
  endereco: {
    type: String,
    trim: true
  },
  interesses: {
    type: String,
    trim: true
  },
  atividades: {
    type: String,
    trim: true
  },
  participouEventos: {
    type: String,
    enum: ['sim', 'nao', ''],
    default: ''
  },
  realizouCompras: {
    type: String,
    enum: ['sim', 'nao', ''],
    default: ''
  },
  twitterId: {
    type: String,
    unique: true,
    sparse: true
  },
  twitterUsername: {
    type: String,
    trim: true
  },
  twitterAvatar: {
    type: String,
    trim: true
  },
  twitterAccessToken: {
    type: String,
    select: false
  },
  twitterRefreshToken: {
    type: String,
    select: false
  },
  nickname: {
    type: String,
    trim: true,
    unique: true,
    sparse: true
  },
  pontosFuriaGG: {
    type: Number,
    default: 0
  },
  arquivos: [{
    nomeOriginal: String,
    caminho: String,
    nomeSalvo: String,
    tipo: String,
    tamanho: Number,
    dataUpload: Date
  }]
}, { 
  timestamps: true,
  toJSON: {
    transform: (doc, ret) => {
      delete ret.senha;
      delete ret.authToken;
      delete ret.authTokenExpira;
      delete ret.twitterAccessToken;
      delete ret.twitterRefreshToken;
      return ret;
    }
  }
});

UsuarioSchema.methods.gerarToken = function() {
  const token = crypto.randomBytes(32).toString('hex') + this._id.toString();
  this.authToken = token;
  this.authTokenExpira = new Date(Date.now() + 24 * 60 * 60 * 1000);
  return token;
};

UsuarioSchema.methods.invalidarToken = function() {
  this.authToken = undefined;
  this.authTokenExpira = undefined;
};

UsuarioSchema.statics.encontrarPorToken = async function(token) {
  if (!token || token.length < 24) return null;
  
  const userId = token.slice(-24);
  if (!mongoose.Types.ObjectId.isValid(userId)) return null;
  
  return await this.findOne({ 
    _id: userId,
    authToken: token,
    authTokenExpira: { $gt: new Date() }
  }).select('+authToken +authTokenExpira');
};

const Usuario = mongoose.model('Usuario', UsuarioSchema);

const autenticar = async (req, res, next) => {
  try {
    const token = req.cookies?.authToken || req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ error: 'Token não encontrado' });
    }

    const usuario = await Usuario.encontrarPorToken(token);
    if (!usuario) {
      res.clearCookie('authToken');
      return res.status(401).json({ error: 'Token inválido' });
    }

    req.user = usuario;
    next();
  } catch (error) {
    console.error('Erro na autenticação:', error);
    res.status(500).json({ error: 'Erro interno' });
  }
};

const configurarCookiesAutenticacao = (res, token) => {
  const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 24 * 60 * 60 * 1000,
    path: '/'
  };

  if (process.env.NODE_ENV === 'production' && process.env.COOKIE_DOMAIN) {
    cookieOptions.domain = process.env.COOKIE_DOMAIN;
  }

  res.cookie('authToken', token, cookieOptions);
};

const formatarRespostaUsuario = (usuario) => ({
  id: usuario._id,
  nome: usuario.nome,
  email: usuario.email,
  avatar: usuario.avatar,
  twitterUsername: usuario.twitterUsername,
  twitterAvatar: usuario.twitterAvatar,
  nickname: usuario.nickname,
  pontosFuriaGG: usuario.pontosFuriaGG
});

function normalizarTexto(texto) {
  return texto
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9 ]/g, '')
    .trim();
}

async function verifyImagesWithGemini(imagePaths, nomeUsuario) {
  let model;
  try {
    model = genAI.getGenerativeModel({ model: "gemini-1.5-flash-latest" });

    function fileToGenerativePart(path) {
      const mimeType = {
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg'
      }[path.slice(-4).toLowerCase()] || 'application/octet-stream';
      return {
        inlineData: {
          data: Buffer.from(fs.readFileSync(path)).toString("base64"),
          mimeType
        },
      };
    }

    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error('Tempo de resposta do Gemini excedido')), 30000);
    });

    const identifyPrompt = `Analise estas imagens e responda APENAS com o número daquela que parece ser um documento de identificação oficial (RG, CNH, Passaporte).
                        Responda APENAS com "1" ou "2".`;
    const image1Part = fileToGenerativePart(imagePaths[0]);
    const image2Part = fileToGenerativePart(imagePaths[1]);
    const identifyResult = await Promise.race([
      model.generateContent([identifyPrompt, image1Part, image2Part]),
      timeoutPromise
    ]);
    const docIndex = parseInt((await identifyResult.response.text()).trim()) - 1;
    const selfieIndex = docIndex === 0 ? 1 : 0;

    const textMatchPrompt = `Extraia TODO o texto visível desta imagem de documento de identificação.
                         Inclua nomes, números, datas e outras informações.
                         Responda APENAS com o texto bruto, sem formatação.`;
    const docImagePart = fileToGenerativePart(imagePaths[docIndex]);
    const textMatchResult = await Promise.race([
      model.generateContent([textMatchPrompt, docImagePart]),
      timeoutPromise
    ]);
    const extractedText = (await textMatchResult.response.text()).trim();
    const nomeNormalizado = normalizarTexto(nomeUsuario);
    const textoExtraidoNormalizado = normalizarTexto(extractedText);

    if (!textoExtraidoNormalizado || textoExtraidoNormalizado.length < 5) {
      throw new Error(`Não foi possível ler o documento. Por favor:
                  1. Envie uma foto mais nítida do documento
                  2. Certifique-se que todos os dados estão visíveis
                  3. O documento deve estar totalmente dentro da foto`);
    }

    const textMatches = textoExtraidoNormalizado.includes(nomeNormalizado);

    const comparePrompt = `As imagens representam a mesma pessoa? Considere:
                       - Similaridade facial
                       - Características físicas
                       Responda APENAS com "SIM" ou "NÃO".`;
    
    const selfieImagePart = fileToGenerativePart(imagePaths[selfieIndex]);
    const docPhotoPart = fileToGenerativePart(imagePaths[docIndex]);
    
    const compareResult = await Promise.race([
      model.generateContent([comparePrompt, selfieImagePart, docPhotoPart]),
      timeoutPromise
    ]);
    
    const comparison = (await compareResult.response.text()).trim().toUpperCase();
    const imagesMatch = comparison === "SIM";

    if (!textMatches) {
      throw new Error(`Não foi possível verificar seu nome no documento:
                  1. Confira se digitou seu nome exatamente como no documento
                  2. Verifique se o documento está legível
                  3. O nome deve estar claramente visível na foto`);
    }

    if (!imagesMatch) {
      throw new Error(`A selfie não corresponde à foto do documento:
                  1. Envie uma selfie clara segurando o documento
                  2. Seu rosto e o documento devem estar visíveis
                  3. A foto do documento deve estar legível na selfie`);
    }

    return {
      success: textMatches && imagesMatch,
      textMatch: textMatches,
      imagesMatch: imagesMatch,
      extractedText: extractedText
    };

  } catch (error) {
    imagePaths.forEach(path => {
      try { fs.unlinkSync(path); } catch (e) { console.error('Erro ao limpar arquivo:', e); }
    });
    throw new Error(error.message);
  }
}

const storage = multer.diskStorage({
  destination: function(req, file, cb) {
    const userId = req.user ? req.user._id : 'temp';
    const userUploadDir = path.join('uploads', userId.toString());
    if (!fs.existsSync(userUploadDir)) {
      fs.mkdirSync(userUploadDir, { recursive: true });
    }
    cb(null, userUploadDir);
  },
  filename: function(req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, uniqueSuffix + ext);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/jpg'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Tipo de arquivo não suportado. Apenas JPEG, JPG e PNG são permitidos'), false);
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: { 
    fileSize: 10 * 1024 * 1024,
    files: 5 
  }
});

// Rotas estáticas
router.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/home.html'));
});

router.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/login.html'));
});

router.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/signup.html'));
});

router.get('/home', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/home.html'));
});

router.get('/perfil', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/perfil.html'));
});

router.get('/form', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/forms.html'));
});

router.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/dashboard.html'));
});

router.get('/api/me', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1] || 
                 req.cookies?.authToken;
    
    if (!token) return res.status(401).json({ error: 'Token não fornecido' });

    const usuario = await Usuario.encontrarPorToken(token);
    if (!usuario) return res.status(401).json({ error: 'Token inválido' });

    res.json({
      success: true,
      user: {
        ...formatarRespostaUsuario(usuario),
        twitterAvatar: usuario.twitterAvatar,
        pontosFuriaGG: usuario.pontosFuriaGG,
        lastTwitterUpdate: usuario.updatedAt
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

router.get('/api/getDatabaseUser', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1] || req.cookies?.authToken;
    let user = await Usuario.find({ authToken: token });
    if (user) {
      return res.json({
        user
      });
    };
  } catch (e) {
    console.log(e);
    return res.json({ e });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { email, senha } = req.body;
    
    if (!email || !senha) {
      return res.status(400).json({ error: 'Email e senha são obrigatórios' });
    }

    const usuario = await Usuario.findOne({ email }).select('+senha');
    if (!usuario || usuario.senha !== senha) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    const token = usuario.gerarToken();
    await usuario.save();
    
    configurarCookiesAutenticacao(res, token);
    
    res.json({
      success: true,
      user: formatarRespostaUsuario(usuario),
      token: token,
      redirect: '/'
    });

  } catch (error) {
    console.error('Erro no login:', error);
    res.status(500).json({ error: 'Erro no servidor' });
  }
});

router.post('/logout', autenticar, async (req, res) => {
  try {
    req.user.authToken = undefined;
    req.user.authTokenExpira = undefined;
    await req.user.save();
    
    res.clearCookie('authToken', {
      httpOnly: false,
      secure: true,
      sameSite: 'none',
      path: '/'
    });
    
    res.json({
      success: true,
      message: 'Logout realizado com sucesso',
      clearLocalStorage: true
    });
    
  } catch (error) {
    console.error('Erro no logout:', error);
    res.status(500).json({ 
      error: 'Erro no logout',
      details: error.message 
    });
  }
});

router.get('/check-auth', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1] || 
                 req.cookies?.authToken || 
                 req.body?.token;

    if (!token) {
      return res.status(401).json({ 
        error: 'Token não encontrado',
        solution: 'Envie o token via Authorization header, cookie ou body'
      });
    }

    const usuario = await Usuario.encontrarPorToken(token);
    
    if (!usuario) {
      return res.status(401).json({ 
        error: 'Token inválido ou expirado',
        solution: 'Faça login novamente'
      });
    }

    res.json({
      authenticated: true,
      user: formatarRespostaUsuario(usuario)
    });

  } catch (error) {
    console.error('Erro na verificação:', error);
    res.status(500).json({ 
      error: 'Erro interno',
      details: error.message 
    });
  }
});

router.get('/twitter/connect', autenticar, async (req, res) => {
  try {
    const { url, codeVerifier, state } = twitterClient.generateOAuth2AuthLink(
      process.env.TWITTER_CALLBACK_URL,
      { 
        scope: ['tweet.read', 'users.read', 'offline.access'],
        state: crypto.randomBytes(16).toString('hex')
      }
    );
    
    await oAuthStates.set(state, { 
      codeVerifier, 
      state,
      userId: req.user._id.toString()
    });
    
    res.json({ 
      success: true,
      redirectUrl: url
    });
    
  } catch (error) {
    console.error('Erro Twitter OAuth:', error);
    res.status(500).json({ 
      success: false,
      error: 'Erro ao iniciar autenticação' 
    });
  }
});

router.get('/twitter/callback', async (req, res) => {
  const { state, code } = req.query;

  if (!state || !code) {
    return res.redirect('/dashboard?twitterError=missing_params');
  }

  let storedState;
  try {
    storedState = oAuthStates.get(state);
    if (!storedState) {
      return res.redirect('/dashboard?twitterError=invalid_state');
    }
    oAuthStates.delete(state);
  } catch (error) {
    console.error('Erro ao recuperar state:', error);
    return res.redirect('/dashboard?twitterError=server_error');
  }

  let userData;
  try {
    const client = new TwitterApi({
      clientId: process.env.TWITTER_CLIENT_ID,
      clientSecret: process.env.TWITTER_CLIENT_SECRET,
    });

    const { 
      client: loggedClient, 
      accessToken, 
      refreshToken 
    } = await client.loginWithOAuth2({
      code,
      codeVerifier: storedState.codeVerifier,
      redirectUri: process.env.TWITTER_CALLBACK_URL
    });
    
    const userResponse = await loggedClient.v2.me({
      "user.fields": ["profile_image_url", "verified", "name", "username"]
    });
    userData = userResponse.data;

    let usuario;
    let isNewUser = false;

    if (storedState.userId) {
      if (!mongoose.Types.ObjectId.isValid(storedState.userId)) {
        throw new Error('ID de usuário inválido');
      }

      usuario = await Usuario.findById(storedState.userId);
      if (!usuario) {
        throw new Error('Usuário não encontrado');
      }

      const existingUser = await Usuario.findOne({
        twitterId: userData.id,
        _id: { $ne: usuario._id }
      });

      if (existingUser) {
        throw new Error('twitter_already_linked');
      }

      usuario.twitterId = userData.id;
      usuario.twitterUsername = userData.username;
      usuario.twitterAvatar = userData.profile_image_url?.replace('_normal', '') || '';
      usuario.twitterAccessToken = accessToken;
      usuario.twitterRefreshToken = refreshToken;
      
      await usuario.save();
    } else {
      usuario = await Usuario.findOne({ twitterId: userData.id });

      if (!usuario) {
        usuario = new Usuario({
          nome: userData.name || userData.username,
          email: `${userData.id}@twitter.com`,
          twitterId: userData.id,
          twitterUsername: userData.username,
          twitterAvatar: userData.profile_image_url?.replace('_normal', '') || '',
          twitterAccessToken: accessToken,
          twitterRefreshToken: refreshToken,
          nickname: `@${userData.username}`,
          pontosFuriaGG: 0,
          emailVerificado: true
        });
        isNewUser = true;
      }
    }

    const token = usuario.gerarToken();
    await usuario.save();

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 30 * 24 * 60 * 60 * 1000
    });

    return res.redirect(`/dashboard?twitterSuccess=1&isNewUser=${isNewUser ? '1' : '0'}`);

  } catch (error) {
    console.error('Erro no processamento do usuário:', error);

    const errorMessages = {
      'twitter_already_linked': 'Esta conta do Twitter já está vinculada a outro usuário',
      'ID de usuário inválido': 'ID de usuário inválido',
      'Usuário não encontrado': 'Usuário não encontrado'
    };

    const message = errorMessages[error.message] || 'Erro ao processar autenticação';
    return res.redirect(`/dashboard?twitterError=${encodeURIComponent(message)}`);
  }
});

router.post('/twitter/disconnect', autenticar, async (req, res) => {
  try {
    if (!req.user.twitterId) {
      return res.status(400).json({ error: 'Nenhuma conta do Twitter vinculada' });
    }
    
    req.user.twitterId = undefined;
    req.user.twitterUsername = undefined;
    req.user.twitterAvatar = undefined;
    req.user.twitterAccessToken = undefined;
    req.user.twitterRefreshToken = undefined;
    
    await req.user.save();
    
    res.json({ success: true });
  } catch (error) {
    console.error('Erro ao desvincular Twitter:', error);
    res.status(500).json({ error: 'Erro ao desvincular conta do Twitter' });
  }
});

router.get('/api/update-points', autenticar, async (req, res) => {
  try {
    if (!req.user.twitterId || !req.user.twitterUsername) {
      return res.status(400).json({ 
        success: false,
        error: 'Usuário não conectado com Twitter ou username não disponível' 
      });
    }

    let pontos = 0;
    const tweetsComHashtag = [];
    let methodUsed = 'none';

    if (req.user.twitterAccessToken && req.user.twitterRefreshToken) {
      try {
        const client = new TwitterApi({
          clientId: process.env.TWITTER_CLIENT_ID,
          clientSecret: process.env.TWITTER_CLIENT_SECRET,
          accessToken: req.user.twitterAccessToken,
          refreshToken: req.user.twitterRefreshToken
        });

        const { client: refreshedClient } = await client.refreshOAuth2Token(req.user.twitterRefreshToken);
        
        const userTweets = await refreshedClient.v2.userTimeline(req.user.twitterId, {
          'tweet.fields': ['created_at', 'text'],
          max_results: 100,
          expansions: ['author_id']
        });

        for await (const tweet of userTweets) {
          if (tweet.text && tweet.text.toLowerCase().includes('#furiagg')) {
            pontos++;
            tweetsComHashtag.push({
              id: tweet.id,
              text: tweet.text,
              created_at: tweet.created_at
            });
          }
        }

        req.user.twitterAccessToken = refreshedClient.accessToken;
        req.user.twitterRefreshToken = refreshedClient.refreshToken;
        methodUsed = 'user_timeline';
      } catch (error) {
        console.log('Falha ao usar tokens OAuth2, tentando método alternativo...', error);
      }
    }

    if (methodUsed === 'none') {
      try {
        const client = new TwitterApi(process.env.TWITTER_BEARER_TOKEN);
        
        const searchResults = await client.v2.search({
          query: `(#furiagg OR "furiagg") from:${req.user.twitterUsername} -is:retweet`,
          'tweet.fields': ['author_id', 'created_at', 'text'],
          max_results: 100
        });

        console.log(searchResults)

        for await (const tweet of searchResults) {
          if (tweet.author_id === req.user.twitterId) {
            pontos++;
            tweetsComHashtag.push({
              id: tweet.id,
              text: tweet.text,
              created_at: tweet.created_at
            });
          }
        }
        methodUsed = 'public_search';
      } catch (error) {
        console.error('Erro na busca pública:', error);
        return res.status(500).json({ 
          success: false,
          error: error.code == 429 ? 'Você chegou ao limite de requisições! Tente novamente mais tarde.' : 'Algo deu errado! Tente novamente mais tarde.',
          details: error
        });
      }
    }

    req.user.pontosFuriaGG = pontos;
    req.user.lastTwitterUpdate = new Date();
    await req.user.save();

    return res.json({ 
      success: true, 
      pontos,
      tweets: tweetsComHashtag,
      method: methodUsed,
      lastUpdate: req.user.lastTwitterUpdate
    });

  } catch (error) {
    console.error('Erro ao atualizar pontos:', error);
    return res.status(500).json({ 
      success: false,
      error: 'Erro ao atualizar pontos',
      details: error.message
    });
  }
});

router.get('/api/leaderboard', async (req, res) => {
  try {
    const topUsuarios = await Usuario.find({ pontosFuriaGG: { $gt: 0 } })
      .sort({ pontosFuriaGG: -1 })
      .limit(10)
      .select('nome twitterUsername twitterAvatar nickname pontosFuriaGG');

    res.json({ ranking: topUsuarios });
  } catch (error) {
    console.error('Erro ao buscar leaderboard:', error);
    res.status(500).json({ error: 'Erro ao buscar ranking' });
  }
});

router.post('/api/update-nickname', autenticar, async (req, res) => {
  try {
    const { nickname } = req.body;
    
    if (!nickname || nickname.trim().length < 3) {
      return res.status(400).json({ error: 'Nickname deve ter pelo menos 3 caracteres' });
    }

    const existingUser = await Usuario.findOne({ 
      nickname: nickname.trim(),
      _id: { $ne: req.user._id }
    });

    if (existingUser) {
      return res.status(400).json({ error: 'Este nickname já está em uso' });
    }

    req.user.nickname = nickname.trim();
    await req.user.save();

    res.json({ 
      success: true,
      user: formatarRespostaUsuario(req.user)
    });
  } catch (error) {
    console.error('Erro ao atualizar nickname:', error);
    res.status(500).json({ error: 'Erro ao atualizar nickname' });
  }
});

router.post('/cadastro', async (req, res) => {
  try {
    const { nome, email, senha } = req.body;
    
    if (!nome || !email || !senha) {
      return res.status(400).json({ error: 'Todos os campos são obrigatórios' });
    }

    const usuarioExistente = await Usuario.findOne({ email });
    if (usuarioExistente) {
      return res.status(400).json({ error: 'Email já cadastrado' });
    }

    const novoUsuario = await Usuario.create({ nome, email, senha });
    const token = novoUsuario.gerarToken();
    await novoUsuario.save();

    configurarCookiesAutenticacao(res, token);

    res.status(201).json({
      success: true,
      user: formatarRespostaUsuario(novoUsuario),
      redirect: '/'
    });

  } catch (error) {
    console.error('Erro no cadastro:', error);
    
    if (error.name === 'ValidationError') {
      const messages = Object.values(error.errors).map(val => val.message);
      return res.status(400).json({ error: messages.join(', ') });
    }
    
    if (error.code === 11000) {
      return res.status(400).json({ error: 'Email já cadastrado' });
    }
    
    res.status(500).json({ error: 'Erro no servidor' });
  }
});

router.post('/forms', 
  autenticar,
  upload.array('arquivos'),
  async (req, res) => {
    try {
      const { nome, cpf, endereco, interesses, atividades, eventos, compras } = req.body;
      
      if (!nome || !cpf || !endereco) {
        throw new Error('Nome, CPF e Endereço são obrigatórios');
      }

      if (nome.length < 5) {
        throw new Error('Nome deve conter pelo menos 5 caracteres');
      }

      if (req.files?.length > 0) {
        const imageFiles = req.files.filter(f => f.mimetype.startsWith('image/'));
        if (imageFiles.length > 0) {
          const verification = await verifyImagesWithGemini(
            imageFiles.map(f => f.path), 
            nome
          );
          
          if (!verification.success) {
            throw new Error(
              !verification.textMatch ? 'O nome no documento não confere com o digitado. Por favor, verifique se digitou exatamente como no documento.' :
              !verification.imagesMatch ? 'A selfie não corresponde à foto do documento. Por favor, envie uma selfie clara segurando o documento.' :
              'Verificação de imagens falhou'
            );
          }
        }
      }

      const cpfFormatado = cpf.replace(/\D/g, '');
      const usuarioComCPF = await Usuario.findOne({ 
        cpf: cpfFormatado, 
        _id: { $ne: req.user._id } 
      });
      
      if (usuarioComCPF) {
        if (req.files?.length > 0) {
          req.files.forEach(file => fs.unlinkSync(file.path));
        }
        return res.status(400).json({ error: 'CPF já está em uso por outro usuário' });
      }

      const arquivosParaSalvar = req.files?.map(file => ({
        nomeOriginal: file.originalname,
        caminho: file.path,
        nomeSalvo: file.filename,
        tipo: file.mimetype,
        tamanho: file.size,
        dataUpload: new Date()
      })) || [];

      const usuarioAtualizado = await Usuario.findByIdAndUpdate(
        req.user._id,
        {
          $set: {
            nome,
            cpf: cpfFormatado,
            endereco,
            interesses: interesses || null,
            atividades: atividades || null,
            participouEventos: eventos || null,
            realizouCompras: compras || null
          },
          $push: { 
            arquivos: { $each: arquivosParaSalvar } 
          }
        },
        { 
          new: true, 
          runValidators: true 
        }
      ).select('-senha -authToken -authTokenExpira');

      res.status(200).json({
        success: true,
        message: 'Formulário e arquivos salvos com sucesso',
        user: formatarRespostaUsuario(usuarioAtualizado),
        arquivosEnviados: arquivosParaSalvar.map(arq => ({
          nome: arq.nomeOriginal,
          tipo: arq.tipo,
          tamanho: arq.tamanho
        }))
      });

    } catch (error) {
      console.error('Erro no processamento do formulário:', error);
      
      if (req.files?.length > 0) {
        req.files.forEach(file => {
          try {
            if (fs.existsSync(file.path)) {
              fs.unlinkSync(file.path);
            }
          } catch (err) {
            console.error('Erro ao remover arquivo:', err);
          }
        });
      }

      res.status(error.status || 500).json({ 
        success: false,
        error: error.message 
      });
    }
  }
);

module.exports = router;