'use strict';

/**
 * MIDDLEWARES DE SEGURANÇA
 *  - identificação de requisição e log de acesso (item 27)
 *  - rate limiting global e por rota sensível (item 21)
 *  - validação/sanitização Joi (item 22)
 *  - autenticação JWT com blacklist e versão de senha (item 24)
 */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { rateLimit, ipKeyGenerator } = require('express-rate-limit');

const config = require('./config');
const validadores = require('./validadores');
const log = require('./log-seguranca');
const tokens = require('./tokens');
const { Sessao } = require('./modelos/sessao');

// ==========================================
// 🆔 IDENTIFICAÇÃO DA REQUISIÇÃO (auditoria)
// ==========================================
function idRequisicao(req, res, next) {
    req.idRequisicao = crypto.randomUUID();
    res.setHeader('X-Request-Id', req.idRequisicao);
    next();
}

function ipDe(req) {
    return String(req.ip || req.socket?.remoteAddress || 'desconhecido').replace(/^::ffff:/, '');
}

// ==========================================
// 🛡️ RATE LIMITING (item 21)
// ==========================================

function responderLimite(nome) {
    return (req, res, next, opcoes) => {
        log.aviso('RATE_LIMIT_ATINGIDO', {
            limitador: nome,
            rota: req.originalUrl?.split('?')[0],
            usuarioId: req.usuarioLogado?.id
        }, req);

        res.setHeader('Retry-After', Math.ceil(opcoes.windowMs / 1000));
        res.status(429).json({
            erro: 'Muitas requisições. Aguarde alguns instantes antes de tentar novamente.',
            limitador: nome
        });
    };
}

function criarLimitador(nome, { max, windowMs, chavePorUsuario = false, mensagemPadrao }) {
    const opcoes = {
        windowMs,
        max,
        standardHeaders: 'draft-7',
        legacyHeaders: false,
        handler: responderLimite(nome)
    };

    if (chavePorUsuario) {
        opcoes.keyGenerator = (req) => {
            const ip = ipKeyGenerator(req.ip);
            const usuario = req.usuarioLogado?.id || req.validado?.body?.email || 'anonimo';
            return `${ip}|${String(usuario).toLowerCase()}`;
        };
    }

    const limitador = rateLimit(opcoes);
    limitador.nomeLimite = nome;
    limitador.mensagemPadrao = mensagemPadrao;
    return limitador;
}

/** Cobre TODA a API (não só /auth) — limite generoso para não quebrar UX. */
const limitadorGlobal = criarLimitador('global', {
    max: config.RL_GLOBAL_MAX,
    windowMs: config.RL_GLOBAL_JANELA_MS
});

/** Leituras (GET/HEAD) — mais permissivas, mas com teto para scraping em massa. */
const limitadorLeitura = criarLimitador('leitura', {
    max: config.RL_LEITURA_MAX,
    windowMs: 15 * 60 * 1000
});

/** Escritas — cada escrita autenticada consome cota. */
const limitadorEscrita = criarLimitador('escrita', {
    max: config.RL_ESCRITA_MAX,
    windowMs: 15 * 60 * 1000,
    chavePorUsuario: true
});

/** Login — o mais restritivo, chaveado por IP + e-mail informado. */
const limitadorLogin = criarLimitador('login', {
    max: config.RL_LOGIN_MAX,
    windowMs: 15 * 60 * 1000,
    chavePorUsuario: true
});

/** Cadastro — criações de conta são caras e abusáveis (CPF único em massa). */
const limitadorCadastro = criarLimitador('cadastro', {
    max: config.RL_CADASTRO_MAX,
    windowMs: config.RL_CADASTRO_JANELA_MS
});

/** Renovação de token. */
const limitadorRefresh = criarLimitador('refresh', {
    max: config.RL_LOGIN_MAX * 2,
    windowMs: 15 * 60 * 1000
});

/** Troca de senha / dados de contato. */
const limitadorSenha = criarLimitador('alteracao-senha', {
    max: config.RL_SENHA_MAX,
    windowMs: config.RL_SENHA_JANELA_MS,
    chavePorUsuario: true
});

/** Candidatura a vagas — evita automação de candidatura em massa. */
const limitadorCandidatura = criarLimitador('candidatura', {
    max: config.RL_CANDIDATURA_MAX,
    windowMs: config.RL_CANDIDATURA_JANELA_MS,
    chavePorUsuario: true
});

// ==========================================
// 🧹 VALIDAÇÃO E SANITIZAÇÃO (item 22)
// ==========================================

/**
 * Valida e sanitiza uma fonte da requisição.
 * O resultado fica em `req.validado.<fonte>` — nunca reatribuímos `req.query`,
 * que no Express 5 é um accessor somente-leitura.
 */
function validar(schema, fonte = 'body') {
    return (req, res, next) => {
        if (!req.validado) req.validado = {};

        const bruto = req.validado[fonte] ?? req[fonte] ?? {};

        const { error, value } = schema.validate(bruto, validadores.OPCOES_BASE);

        if (error) {
            const detalhes = error.details.map(d => ({ campo: d.path.join('.') || '(raiz)', mensagem: d.message }));

            log.aviso('VALIDACAO_REJEITADA', {
                fonte,
                rota: req.originalUrl?.split('?')[0],
                campos: detalhes.map(d => d.campo)
            }, req);

            return res.status(422).json({ erro: 'Dados inválidos.', detalhes });
        }

        req.validado[fonte] = value;
        next();
    };
}

const validarCorpo = (schema) => validar(schema, 'body');
const validarQuery = (schema) => validar(schema, 'query');
const validarParams = (schema = validadores.paramsId) => validar(schema, 'params');

/** Compatibilidade: expõe o corpo validado como se fosse req.body. */
function exporCorpoValidado(req, res, next) {
    if (req.validado?.body) req.body = req.validado.body;
    next();
}

// ==========================================
// 🔐 AUTENTICAÇÃO JWT (item 24)
// ==========================================

const SENHA_PADRAO = '$2b$12$C6UzMDM.H6dfI/f/IKcEeO1sJ0J8p8JrTQhCzKqQqFb3nJ7b3m7XKxS';

function autenticarToken(req, res, next) {
    const header = req.headers.authorization;
    const token = header && header.startsWith('Bearer ') ? header.slice(7).trim() : null;

    if (!token) {
        log.acessoNegado('token_ausente', {}, req);
        return res.status(401).json({ erro: 'Acesso negado! Token não fornecido.' });
    }

    let payload;
    try {
        payload = jwt.verify(token, config.JWT_SECRET, {
            algorithms: [tokens.ALGORITMO],
            issuer: tokens.ISSUER
        });
    } catch (err) {
        log.acessoNegado('token_invalido', { motivo: err.name }, req);
        return res.status(401).json({ erro: 'Token inválido ou sessão expirada.' });
    }

    if (payload.typ !== 'access') {
        log.acessoNegado('token_tipo_incorreto', { tipo: payload.typ }, req);
        return res.status(401).json({ erro: 'Token inválido ou sessão expirada.' });
    }

    (async () => {
        // Blacklist: logout, troca de senha ou reuso detectado.
        if (await tokens.tokenEstaRevogado(payload.jti)) {
            log.acessoNegado('token_revogado', { jti: payload.jti }, req);
            return res.status(401).json({ erro: 'Sessão encerrada. Faça login novamente.' });
        }

        const Usuario = require('./modelos/usuario');
        const usuario = await Usuario.findById(payload.sub)
            .select('+versaoSenha +bloqueadoAte +tentativasFalhas')
            .lean();

        if (!usuario) {
            log.acessoNegado('usuario_inexistente', {}, req);
            return res.status(401).json({ erro: 'Token inválido ou sessão expirada.' });
        }

        if (usuario.bloqueadoAte && usuario.bloqueadoAte.getTime() > Date.now()) {
            log.alerta('ACESSO_CONTA_BLOQUEADA', { usuarioId: String(usuario._id) }, req);
            return res.status(403).json({ erro: 'Conta temporariamente bloqueada por excesso de tentativas de login.' });
        }

        // Troca de senha incrementa `versaoSenha` e invalida tokens antigos.
        if ((payload.pv || 1) !== (usuario.versaoSenha || 1)) {
            log.acessoNegado('senha_alterada_desde_emissao', { usuarioId: String(usuario._id) }, req);
            return res.status(401).json({ erro: 'Sua senha foi alterada. Faça login novamente.' });
        }

        req.usuarioLogado = {
            id: String(usuario._id),
            nome: payload.nome,
            tipo: usuario.tipo,
            versaoSenha: usuario.versaoSenha || 1
        };

        next();
    })().catch(next);
}

/** Exige perfil de contratante. */
function apenasContratante(req, res, next) {
    if (req.usuarioLogado?.tipo !== 'contratante') {
        log.acessoNegado('perfil_incorreto', { exigido: 'contratante', tipo: req.usuarioLogado?.tipo }, req);
        return res.status(403).json({ erro: 'Apenas contratantes podem acessar este recurso.' });
    }
    next();
}

/** Exige perfil de contratado (freelancer). */
function apenasContratado(req, res, next) {
    if (req.usuarioLogado?.tipo !== 'contratado') {
        log.acessoNegado('perfil_incorreto', { exigido: 'contratado', tipo: req.usuarioLogado?.tipo }, req);
        return res.status(403).json({ erro: 'Apenas profissionais podem acessar este recurso.' });
    }
    next();
}

// ==========================================
// 🚦 ROTEAMENTO SEGURO DE MÉTODO
// ==========================================
const METODOS_SEGUROS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Rate limiting-aware por método: leituras e escritas recebem cotas distintas.
 * Montado como array para ser aplicado em um único `app.use`.
 */
const limitadorPorMetodo = (req, res, next) => {
    if (METODOS_SEGUROS.has(req.method)) return limitadorLeitura(req, res, next);
    return limitadorEscrita(req, res, next);
};

module.exports = {
    idRequisicao,
    ipDe,
    limitadorGlobal,
    limitadorPorMetodo,
    limitadorLogin,
    limitadorCadastro,
    limitadorRefresh,
    limitadorSenha,
    limitadorCandidatura,
    validar,
    validarCorpo,
    validarQuery,
    validarParams,
    exporCorpoValidado,
    autenticarToken,
    apenasContratante,
    apenasContratado,
    METODOS_SEGUROS,
    criarLimitador,
    responderLimite,
    Sessao,
    SENHA_PADRAO
};
