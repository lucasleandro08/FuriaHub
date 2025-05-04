<h1 align="center">FuriaHub - Plataforma de Engajamento para Fãs</h1>

<div align="center">
  <img src="https://img.shields.io/badge/Node.js-18.x-green" alt="Node.js">
  <img src="https://img.shields.io/badge/Express-4.x-lightgrey" alt="Express">
  <img src="https://img.shields.io/badge/MongoDB-6.x-green" alt="MongoDB">
  <img src="https://img.shields.io/badge/TailwindCSS-3.x-blue" alt="TailwindCSS">
</div>

<h2>📌 Visão Geral</h2>
<p>O FuriaHub é uma plataforma web integrada com Twitter que permite aos fãs da organização de esports FURIA interagir, participar de promoções e acompanhar as modalidades competitivas da equipe.</p>

<h2>🚀 Tecnologias Principais</h2>
<ul>
  <li><strong>Backend:</strong> Node.js, Express.js, MongoDB</li>
  <li><strong>Frontend:</strong> HTML5, Tailwind CSS, JavaScript</li>
  <li><strong>Integrações:</strong> Twitter API v2, Google Gemini AI</li>
  <li><strong>Outras:</strong> Multer (upload de arquivos), CORS, Cookie Parser</li>
</ul>

<h2>📂 Estrutura do Projeto</h2>

<h3>Backend</h3>
<pre>
server.js          # Ponto de entrada do servidor
routes/
  └── api.js       # Todas as rotas da aplicação
uploads/           # Arquivos enviados pelos usuários
public/            # Arquivos estáticos (HTML, CSS, JS)
</pre>

<h3>Frontend</h3>
<pre>
home.html          # Página principal
login.html         # Página de login
signup.html        # Página de cadastro
perfil.html        # Perfil do usuário
forms.html         # Formulários de cadastro
dashboard.html     # Dashboard do usuário
Assets/            # Imagens e recursos visuais
</pre>

<h2>✨ Funcionalidades Principais</h2>

<h3>1. Autenticação e Gerenciamento de Usuários</h3>
<ul>
  <li>Cadastro com e-mail/senha ou via Twitter OAuth</li>
  <li>Login/logout com tokens JWT</li>
  <li>Cookies seguros para autenticação persistente</li>
  <li>Middleware de autenticação para rotas protegidas</li>
</ul>

<h3>2. Integração com Twitter</h3>
<ul>
  <li>Conexão de conta Twitter via OAuth 2.0</li>
  <li>Sistema de pontos baseado em tweets com hashtag #furiagg</li>
  <li>Leaderboard de usuários mais ativos</li>
  <li>Atualização periódica de pontos</li>
</ul>

<h3>3. Verificação de Documentos</h3>
<ul>
  <li>Upload de documentos e selfies</li>
  <li>Verificação via Gemini AI para:
    <ul>
      <li>Identificação do tipo de documento</li>
      <li>Correspondência de texto no documento</li>
      <li>Comparação facial entre documento e selfie</li>
    </ul>
  </li>
</ul>

<h3>4. Frontend Interativo</h3>
<ul>
  <li>Carrossel de produtos FURIA</li>
  <li>Cards das modalidades esportivas</li>
  <li>Interface responsiva com Tailwind CSS</li>
  <li>Integração com API via JavaScript</li>
</ul>

<h2>🔌 Rotas da API</h2>

<h3>Autenticação</h3>
<table>
  <tr>
    <th>Rota</th>
    <th>Método</th>
    <th>Descrição</th>
  </tr>
  <tr>
    <td><code>/login</code></td>
    <td>POST</td>
    <td>Autentica usuário</td>
  </tr>
  <tr>
    <td><code>/logout</code></td>
    <td>POST</td>
    <td>Encerra sessão</td>
  </tr>
  <tr>
    <td><code>/cadastro</code></td>
    <td>POST</td>
    <td>Cria nova conta</td>
  </tr>
  <tr>
    <td><code>/check-auth</code></td>
    <td>GET</td>
    <td>Verifica autenticação</td>
  </tr>
</table>

<h3>Twitter</h3>
<table>
  <tr>
    <th>Rota</th>
    <th>Método</th>
    <th>Descrição</th>
  </tr>
  <tr>
    <td><code>/twitter/connect</code></td>
    <td>GET</td>
    <td>Inicia conexão com Twitter</td>
  </tr>
  <tr>
    <td><code>/twitter/callback</code></td>
    <td>GET</td>
    <td>Callback do OAuth</td>
  </tr>
  <tr>
    <td><code>/twitter/disconnect</code></td>
    <td>POST</td>
    <td>Remove conexão Twitter</td>
  </tr>
  <tr>
    <td><code>/api/update-points</code></td>
    <td>GET</td>
    <td>Atualiza pontos do Twitter</td>
  </tr>
</table>

<h2>⚙️ Configuração do Ambiente</h2>

<h3>Variáveis de Ambiente (<code>.env</code>)</h3>
<pre>
PORT=3000
MONGO_URI=mongodb://localhost:27017/furiahub
NODE_ENV=development
GEMINI_API_KEY=sua-chave-gemini
TWITTER_CLIENT_ID=seu-client-id
TWITTER_CLIENT_SECRET=seu-client-secret
TWITTER_CALLBACK_URL=http://localhost:3000/twitter/callback
TWITTER_BEARER_TOKEN=seu-bearer-token
COOKIE_DOMAIN=.seusite.com
</pre>

<h3>Instalação</h3>
<ol>
  <li>Clone o repositório</li>
  <li>Instale as dependências:
    <pre>npm install</pre>
  </li>
  <li>Configure o arquivo <code>.env</code></li>
  <li>Inicie o servidor:
    <pre>node server.js</pre>
  </li>
</ol>

<h2>🔒 Segurança</h2>
<ul>
  <li>CORS configurado para produção</li>
  <li>Cookies HTTP-only e Secure</li>
  <li>Validação de uploads (tipo e tamanho)</li>
  <li>Proteção contra CSRF com estados OAuth</li>
  <li>Sanitização de inputs</li>
  <li>Tokens JWT com expiração</li>
</ul>

<h2>🎯 Considerações Finais</h2>
<p>O FuriaHub é uma plataforma completa para engajamento de fãs, combinando autenticação segura, integração com redes sociais e verificação de identidade via IA. A arquitetura modular permite fácil expansão com novos recursos e integrações.</p>
