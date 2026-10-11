require('dotenv').config();

/**
 * freela-seguro — ponto de entrada HTTP.
 *
 * Stack de segurança montada aqui, em ordem de aplicação:
 *   1. identificação de requisição + log de acesso      (27)
 *   2. rate limiting global                             (21)
 *   3. Helmet / CSP / HSTS                             (—)
 *   4. HTTPS + redirecionamento TLS                     (26)
 *   5. CORS restrito + parser JSON com limite          (22)
 *   6. proteção CSRF (double submit cookie)             (—)
 *   7. rotas: validação Joi + JWT + auditoria           (22/23/24/25)
 */

const express = require('express');
const mongoose = require('mongoose');
const cron = require('node-cron');
const cors = require('cors');
const helmet = require('helmet');
const crypto = require('crypto');

const config = require('./src/config');
const log = require('./src/log-seguranca');
const mw = require('./src/middleware');
const tls = require('./src/tls');

const Usuario = require('./src/modelos/usuario');
const Vaga = require('./src/modelos/vaga');
const Notificacao = require('./src/modelos/notificacao');
const { Sessao, TokenRevogado } = require('./src/modelos/sessao');
const { TentativaLogin, Auditoria } = require('./src/modelos/seguranca');

const rotasAuth = require('./src/rotas/auth');
const rotasUsuario = require('./src/rotas/usuario');
const rotasVagas = require('./src/rotas/vagas');
const rotasNotificacoes = require('./src/rotas/notificacoes');

const app = express();

// Desativado por padrão porque a API responde com payload varies entre
// ambientes; o proxy reverso é quem deve definir isto em produção.
app.set('x-powered-by', false);
app.set('trust proxy', config.NUM_PROXIES);
app.set('etag', 'strong');

const HABILITADO = process.env.NODE_ENV !== 'production';
const TLS_CONFIGURADO = Boolean(config.TLS_CERT_PATH && config.TLS_KEY_PATH);

// ==========================================
// 1. 🆔 IDENTIFICAÇÃO + LOG DE ACESSO (item 27)
// ==========================================
app.use(mw.idRequisicao);

app.use((req, res, next) => {
    const inicio = process.hrtime.bigint();

    res.on('finish', () => {
        const duracaoMs = Number(process.hrtime.bigint() - inicio) / 1e6;

        // Requisições a assets estáticos não poluem a trilha de segurança.
        if (req.path.startsWith('/css') || req.path.startsWith('/js') || /\.(html|css|js|png|svg|ico|woff2?)$/.test(req.path)) return;

        log.debug('ACESSO_HTTP', {
            status: res.statusCode,
            duracaoMs: Math.round(duracaoMs * 100) / 100,
            usuarioId: req.usuarioLogado?.id,
            tamanhoResposta: res.getHeader('content-length') || undefined
        }, req);
    });

    next();
});

// ==========================================
// 2. 🛡️ RATE LIMITING GLOBAL (item 21)
// ==========================================
app.use(mw.limitadorGlobal);

// ==========================================
// 3. 🛡️ HEADERS DE SEGURANÇA (Helmet + CSP)
// ==========================================
const CSP_SCRIPT = ["'self'", "'unsafe-inline'"];
const CSP_STYLE = ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'];
const CSP_FONT = ["'self'", 'https://fonts.gstatic.com', 'data:'];
const CSP_IMG = ["'self'", 'data:', 'blob:', 'https://via.placeholder.com', 'https://images.unsplash.com'];
const CSP_CONNECT = ["'self'"];

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: CSP_SCRIPT,
            styleSrc: CSP_STYLE,
            fontSrc: CSP_FONT,
            imgSrc: CSP_IMG,
            connectSrc: CSP_CONNECT,
            objectSrc: ["'none'"],
            frameAncestors: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"],
            // Só anunciamos upgrade para HTTPS quando existe TLS real.
            upgradeInsecureRequests: TLS_CONFIGURADO ? [] : null
        }
    },
    crossOriginEmbedderPolicy: false,
    frameguard: { action: 'deny' },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    // HSTS é aplicado pelo módulo TLS (item 26), junto do redirecionamento.
    hsts: false,
    crossOriginResourcePolicy: { policy: 'same-site' }
}));

// ==========================================
// 4. 🔒 HTTPS (item 26)
// ==========================================
// O redirecionamento só é instalado quando existe TLS real ou FORCAR_HTTPS=true;
// caso contrário quebraria o desenvolvimento local em http://localhost.
tls.aplicarHttpsReal(app, { ativo: TLS_CONFIGURADO || config.FORCAR_HTTPS });

// ==========================================
// 5. CORS RESTRITO + PARSER JSON
// ==========================================
app.use(cors({
    origin(origin, callback) {
        // Requisições sem Origin (curl, apps nativos, health checks) são liberadas.
        if (!origin) return callback(null, true);

        if (config.CORS_ORIGIN.includes(origin)) return callback(null, true);

        log.aviso('CORS_BLOQUEADO', { origem: origin });
        return callback(new Error('Origem não permitida pelo CORS.'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
    exposedHeaders: ['X-Request-Id', 'RateLimit', 'RateLimit-Policy'],
    maxAge: 600
}));

// Limite generoso porque o cadastro envia foto em base64, mas nunca ilimitado.
app.use(express.json({ limit: '10mb', strict: true }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

// ==========================================
// 6. 🛡️ PROTEÇÃO CSRF (Double Submit Cookie)
// ==========================================
const CSRF_COOKIE = 'csrfToken';
const CSRF_HEADER = 'x-csrf-token';
const CSRF_ORIGEM_PERMITIDA = new Set(config.CORS_ORIGIN);

function gerarTokenCsrf() {
    return crypto.randomBytes(32).toString('hex');
}

function lerCookie(req, nome) {
    const bruto = req.headers.cookie;
    if (!bruto) return null;
    const parte = bruto.split(';').map(p => p.trim()).find(p => p.startsWith(`${nome}=`));
    return parte ? decodeURIComponent(parte.slice(nome.length + 1)) : null;
}

app.use((req, res, next) => {
    let token = lerCookie(req, CSRF_COOKIE);

    if (!token || !/^[a-f0-9]{64}$/.test(token)) {
        token = gerarTokenCsrf();
        res.cookie(CSRF_COOKIE, token, {
            httpOnly: false,
            sameSite: 'strict',
            secure: TLS_CONFIGURADO || config.EH_PRODUCAO,
            path: '/',
            maxAge: 60 * 60 * 8
        });
    }

    req.csrfToken = token;

    if (mw.METODOS_SEGUROS.has(req.method)) return next();

    // Defence in depth: com Bearer token a proteção CSRF é redundante, mas
    // mantemos a exigência para requisições anônimas (ex.: cadastro/login).
    const tokenEnviado = req.headers[CSRF_HEADER];
    const tamanhoValido = tokenEnviado && tokenEnviado.length === token.length;
    const valido = tamanhoValido && crypto.timingSafeEqual(Buffer.from(tokenEnviado), Buffer.from(token));

    if (!valido) {
        log.aviso('CSRF_REJEITADO', { rota: req.originalUrl?.split('?')[0], metodo: req.method }, req);
        return res.status(403).json({ erro: 'Requisição bloqueada: token CSRF inválido ou ausente.' });
    }

    const origem = req.headers.origin;
    if (origem && !CSRF_ORIGEM_PERMITIDA.has(origem)) {
        log.aviso('CSRF_ORIGEM_NAO_PERMITIDA', { origem, rota: req.originalUrl?.split('?')[0] }, req);
        return res.status(403).json({ erro: 'Origem não permitida.' });
    }

    next();
});

app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
});

// ==========================================
// ESTÁTICOS + LIMITADOR POR MÉTODO
// ==========================================
app.use(express.static('public', { maxAge: HABILITADO ? 0 : '1h', index: 'index.html' }));

// Toda a API herda cota de leitura ou de escrita.
app.use('/auth', mw.limitadorPorMetodo);
app.use('/usuario', mw.limitadorPorMetodo);
app.use('/vaga', mw.limitadorPorMetodo);
app.use('/vagas', mw.limitadorPorMetodo);
app.use('/notificacoes', mw.limitadorPorMetodo);

// ==========================================
// 7. ROTAS DA API
// ==========================================
app.use('/auth', rotasAuth);
app.use('/usuario', rotasUsuario);
app.use('/vaga', rotasVagas);
app.use('/vagas', rotasVagas); // alias plural: lista paginada em /vagas
app.use('/notificacoes', rotasNotificacoes);

// Health check (público, não consome cota de leitura por_usuário)
app.get('/api/saude', (req, res) => {
    res.json({
        status: 'ok',
        ambiente: config.AMBIENTE,
        protocolo: TLS_CONFIGURADO ? 'https' : 'http',
        banco: mongoose.connection.readyState === 1 ? 'conectado' : 'desconectado',
        versao: require('./package.json').version,
        horario: new Date().toISOString()
    });
});

// ==========================================
// 🧹 TRATAMENTO DE ERROS (não vaza stack trace)
// ==========================================
app.use((req, res) => {
    res.status(404).json({ erro: 'Rota não encontrada.' });
});

app.use((erro, req, res, next) => {
    if (res.headersSent) return next(erro);

    // Erros do CORS
    if (/CORS/i.test(erro.message || '')) {
        return res.status(403).json({ erro: 'Origem não permitida pelo CORS.' });
    }

    // Payload grande demais / JSON malformado
    if (erro.type === 'entity.too.large') {
        log.aviso('PAYLOAD_ACIMA_DO_LIMITE', { limite: '10mb' }, req);
        return res.status(413).json({ erro: 'Conteúdo enviado é muito grande.' });
    }
    if (erro instanceof SyntaxError && 'body' in erro) {
        log.aviso('JSON_MALFORMADO', { erro: erro.message }, req);
        return res.status(400).json({ erro: 'Corpo da requisição não é um JSON válido.' });
    }

    const status = erro.status || erro.statusCode || 500;
    if (status >= 500) {
        log.critico('ERRO_NAO_TRATADO', { erro: erro.message, stack: erro.stack }, req);
        return res.status(500).json({ erro: 'Erro interno do servidor.' });
    }

    log.aviso('ERRO_TRATADO', { status, erro: erro.message }, req);
    return res.status(status).json({ erro: erro.message || 'Requisição inválida.' });
});

// ==========================================
// ⏱️ MOTOR DE AUTOMAÇÃO (CRON JOB)
// ==========================================
cron.schedule('* * * * *', async () => {
    try {
        const agora = new Date();

        const vagasComPendencia = await Vaga.find({
            contratados_atuais: { $elemMatch: { confirmado: false, limite_confirmacao: { $lt: agora } } }
        }).select('titulo contratados_atuais fila_de_espera vagasTotais status_vaga');

        if (vagasComPendencia.length === 0) return;

        for (const vaga of vagasComPendencia) {
            let alterou = false;

            const removidos = vaga.contratados_atuais.filter(c => !c.confirmado && c.limite_confirmacao < agora);
            if (removidos.length === 0) continue;

            vaga.contratados_atuais = vaga.contratados_atuais.filter(c => c.confirmado || c.limite_confirmacao >= agora);

            for (const desqualificado of removidos) {
                alterou = true;
                log.info('CONFIRMACAO_EXPIRADA', {
                    vagaId: String(vaga._id),
                    usuarioId: desqualificado.idUsuario,
                    titulo: vaga.titulo
                });

                if (vaga.fila_de_espera.length > 0) {
                    const proximo = vaga.fila_de_espera.shift();

                    vaga.contratados_atuais.push({
                        idUsuario: proximo.idUsuario,
                        nome: proximo.nome,
                        telefoneCriptografado: proximo.telefoneCriptografado,
                        confirmado: false,
                        limite_confirmacao: new Date(Date.now() + 5 * 60 * 1000)
                    });

                    await Notificacao.create({
                        usuarioId: proximo.idUsuario,
                        tipo: 'equipe_selecionada',
                        titulo: 'Você foi promovido na fila',
                        mensagem: `Você subiu para titular na vaga "${vaga.titulo}". Confirme sua presença em até 5 minutos!`,
                        vagaId: vaga._id
                    });
                }
            }

            if (alterou) {
                if (vaga.contratados_atuais.length < vaga.vagasTotais && vaga.status_vaga !== 'cancelada') {
                    vaga.status_vaga = 'aberta';
                }
                await vaga.save();
            }
        }
    } catch (error) {
        log.aviso('ERRO_NO_CRON', { erro: error.message });
    }
});

// ==========================================
// 🚀 BOOT
// ==========================================
async function conectarBanco() {
    try {
        await mongoose.connect(config.MONGODB_URI, { serverSelectionTimeoutMS: 4000 });
        log.info('BANCO_CONECTADO', { uri: config.MONGODB_URI.replace(/\/\/([^:]+):([^@]+)@/, '//***:***@') });
    } catch (erro) {
        // O fallback em memória é exclusivo de desenvolvimento: em produção
        // isso significaria subir com um banco volátil e dados descartáveis.
        if (config.EH_PRODUCAO) {
            log.critico('BANCO_INDISPONIVEL_EM_PRODUCAO', {
                erro: erro.message,
                mensagem: 'MONGODB_URI inacessível. Em produção o app NÃO sobe com banco em memória.'
            });
            throw new Error('Não foi possível conectar ao MongoDB de produção.');
        }

        log.aviso('BANCO_INDISPONIVEL', { mensagem: 'Usando MongoDB Memory Server (dados temporários).' });
        const { MongoMemoryServer } = require('mongodb-memory-server');
        // Porta fixa permite inspecionar o banco por outra ferramenta em dev.
        const mongoServer = await MongoMemoryServer.create({
            instance: { port: Number(process.env.MONGO_MEMORY_PORT) || 27018 }
        });
        await mongoose.connect(mongoServer.getUri());
        log.info('MONGO_MEMORY_SERVER', {
            uri: mongoServer.getUri(),
            mensagem: 'Dados serão perdidos ao reiniciar.'
        });
    }
}

/** 📇 Garante os índices definidos nos schemas (item 30). */
async function garantirIndices() {
    const alvos = [
        ['Usuario', Usuario],
        ['Vaga', Vaga],
        ['Notificacao', Notificacao],
        ['Sessao', Sessao],
        ['TokenRevogado', TokenRevogado],
        ['TentativaLogin', TentativaLogin],
        ['Auditoria', Auditoria]
    ];

    for (const [nome, model] of alvos) {
        try {
            await model.syncIndexes();
            const indices = await model.collection.indexes();
            log.info('INDICES_SINCRONIZADOS', { modelo: nome, indices: indices.map(i => i.name) });
        } catch (erro) {
            log.aviso('FALHA_AO_SINCRONIZAR_INDICES', { modelo: nome, erro: erro.message });
        }
    }
}

async function iniciarSistema() {
    await conectarBanco();
    await garantirIndices();

    const { servidor, protocolo } = tls.criarServidor(app);

    servidor.listen(config.PORT, () => {
        log.info('SERVIDOR_NO_AR', {
            url: `${protocolo}://localhost:${config.PORT}`,
            ambiente: config.AMBIENTE,
            https: protocolo === 'https'
        });
    });

    const encerrar = (sinal) => {
        log.info('ENCERRANDO', { sinal });
        servidor.close(() => mongoose.connection.close(false).then(() => process.exit(0)));
        setTimeout(() => process.exit(1), 10000).unref();
    };

    process.on('SIGTERM', () => encerrar('SIGTERM'));
    process.on('SIGINT', () => encerrar('SIGINT'));

    process.on('unhandledRejection', (motivo) => {
        log.critico('UNHANDLED_REJECTION', { erro: motivo?.message || String(motivo), stack: motivo?.stack });
    });
    process.on('uncaughtException', (erro) => {
        log.critico('UNCAUGHT_EXCEPTION', { erro: erro.message, stack: erro.stack });
        encerrar('uncaughtException');
    });
}

iniciarSistema().catch((erro) => {
    log.critico('FALHA_AO_INICIAR', { erro: erro.message, stack: erro.stack });
    process.exit(1);
});
