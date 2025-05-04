require('dotenv').config();
const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const apiRouter = require('./routes/api.js');

const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
const NODE_ENV = process.env.NODE_ENV || 'development';
const DOMAIN = NODE_ENV === 'production' ? 'furiahub.squareweb.app' : 'localhost';

if (!MONGO_URI) {
  console.error('ERRO FATAL: Variável MONGO_URI não configurada no .env');
  process.exit(1);
}

async function startServer() {
  try {
    await connectToDatabase();
    const app = configureExpressApp();
    startExpressServer(app);
  } catch (error) {
    console.error('Falha crítica ao iniciar servidor:', error);
    process.exit(1);
  }
}

async function connectToDatabase() {
  console.log('Conectando ao MongoDB...');
  mongoose.set('strictQuery', false);
  await mongoose.connect(MONGO_URI);
  console.log('✅ MongoDB conectado com sucesso!');
}

function configureExpressApp() {
  const app = express();
  
  // Configuração CORS para produção
  const corsOptions = {
    origin: 'https://furiahub.squareweb.app',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
  };
  app.use(cors(corsOptions));
  app.options('*', cors(corsOptions));

  app.use(cookieParser());
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(express.static(path.join(__dirname, 'public')));

  app.use('/', apiRouter);

  return app;
}

function startExpressServer(app) {
  app.listen(PORT, () => {
    const protocol = NODE_ENV === 'production' ? 'https' : 'http';
    console.log(`🚀 Servidor rodando em ${protocol}://${DOMAIN}:${PORT}`);
    console.log(`Ambiente: ${NODE_ENV}`);
  });
}

startServer();