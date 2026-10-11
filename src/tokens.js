'use strict';

/**
 * 🔑 EMISSÃO E ROTAÇÃO DE TOKENS (item 24)
 *
 * Antes: um único JWT de 24h, sem revogação possível.
 * Agora: access token curto (15m) + refresh token rotativo (7d) com blacklist.
 * O refresh token nunca é gravado em claro: persistimos apenas seu SHA-256.
 */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { Sessao, TokenRevogado, gerarFamilia, gerarJti, expiracaoPadrao, hashToken } = require('./modelos/sessao');
const { JWT_SECRET, REFRESH_TOKEN_SECRET, JWT_ACCESS_TTL, REFRESH_TOKEN_TTL_MS } = require('./config');
const log = require('./log-seguranca');

const ISSUER = 'freela-seguro';
const ALGORITMO = 'HS256';

function segundosParaMs(ttl) {
    const m = /^(\d+)([smhd])$/.exec(String(ttl));
    if (!m) return 15 * 60 * 1000;
    const n = Number(m[1]);
    return n * { s: 1000, m: 60000, h: 3600000, d: 86400000 }[m[2]];
}

function expiracaoAccessToken() {
    return new Date(Date.now() + segundosParaMs(JWT_ACCESS_TTL));
}

function assinarAcessToken(usuario, jti = gerarJti()) {
    const nomeExibicao = (usuario.nomeSocial && usuario.nomeSocial.trim() !== '') ? usuario.nomeSocial : usuario.nome;
    const expiraEm = expiracaoAccessToken();

    // `pv` (password version) amarra o token à senha vigente: ao trocar a senha
    // a versão incrementa e todos os access tokens antigos deixam de valer.
    const token = jwt.sign(
        { nome: nomeExibicao, tipo: usuario.tipo, typ: 'access', pv: usuario.versaoSenha || 1 },
        JWT_SECRET,
        { algorithm: ALGORITMO, expiresIn: JWT_ACCESS_TTL, jwtid: jti, issuer: ISSUER, subject: String(usuario._id) }
    );

    return { token, jti, expiraEm };
}

function assinarRefreshToken(usuario, familia, jti = gerarJti()) {
    const expiraEm = expiracaoPadrao();

    const token = jwt.sign(
        { sub: String(usuario._id), familia, typ: 'refresh' },
        REFRESH_TOKEN_SECRET,
        { algorithm: ALGORITMO, expiresIn: `${Math.floor(REFRESH_TOKEN_TTL_MS / 1000)}s`, jwtid: jti, issuer: ISSUER }
    );

    return { token, jti, expiraEm };
}

/** Cria uma sessão nova (login) e devolve o par access + refresh. */
async function emitirSessao(usuario, req = null) {
    const familia = gerarFamilia();
    const jti = gerarJti();

    const { token, expiraEm } = assinarAcessToken(usuario, jti);
    const refresh = assinarRefreshToken(usuario, familia);

    await Sessao.create({
        usuarioId: usuario._id,
        familia,
        jti: refresh.jti,
        hashToken: hashToken(refresh.token),
        ip: req ? String(req.ip || '').replace(/^::ffff:/, '') : '',
        agente: req ? String(req.get?.('user-agent') || '').slice(0, 400) : '',
        expiraEm: refresh.expiraEm
    });

    return {
        token,
        refreshToken: refresh.token,
        expiraEm,
        refreshExpiraEm: refresh.expiraEm
    };
}

/**
 * Valida o refresh token informado.
 * - Token valido  -> rotaciona: revoga o antigo e emite um novo da mesma familia.
 * - Token valido porem ja revogado -> possivel roubo: revoga a FAMILIA inteira.
 */
async function renovarSessao(refreshToken, req = null) {
    let payload;
    try {
        payload = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, {
            algorithms: [ALGORITMO],
            issuer: ISSUER
        });
    } catch (err) {
        log.aviso('REFRESH_TOKEN_INVALIDO', { motivo: err.name }, req);
        return { erro: 'Sessão inválida. Faça login novamente.', status: 401 };
    }

    if (payload.typ !== 'refresh') {
        log.aviso('REFRESH_TOKEN_TIPO_INVALIDO', {}, req);
        return { erro: 'Sessão inválida. Faça login novamente.', status: 401 };
    }

    const jti = payload.jti;
    const sessao = await Sessao.findOne({ jti });

    if (!sessao) {
        log.alerta('REFRESH_TOKEN_DESCONHECIDO', { jti }, req);
        return { erro: 'Sessão inválida. Faça login novamente.', status: 401 };
    }

    const hashInformado = hashToken(refreshToken);
    if (!crypto.timingSafeEqual(Buffer.from(sessao.hashToken), Buffer.from(hashInformado))) {
        log.critico('REFRESH_TOKEN_HASH_DIVERGENTE', { jti }, req);
        await revogarFamilia(sessao.familia, 'hash_divergente', req);
        return { erro: 'Sessão inválida. Faça login novamente.', status: 401 };
    }

    if (sessao.revogado) {
        // 🔴 Reuso de token já rotacionado/encerrado => compromisso confirmado.
        log.critico('REFRESH_TOKEN_REUTILIZADO', { jti, familia: sessao.familia, usuarioId: sessao.usuarioId }, req);
        await revogarFamilia(sessao.familia, 'reuso_detectado', req);
        return { erro: 'Sessão encerrada por segurança. Faça login novamente.', status: 401 };
    }

    if (sessao.expiraEm.getTime() <= Date.now()) {
        log.aviso('REFRESH_TOKEN_EXPIRADO', { jti }, req);
        return { erro: 'Sessão expirada. Faça login novamente.', status: 401 };
    }

    const Usuario = require('./modelos/usuario');
    const usuario = await Usuario.findById(payload.sub).select('+versaoSenha');
    if (!usuario) {
        log.aviso('REFRESH_TOKEN_USUARIO_AUSENTE', { jti }, req);
        await revogarFamilia(sessao.familia, 'usuario_removido', req);
        return { erro: 'Sessão inválida. Faça login novamente.', status: 401 };
    }

    const familia = sessao.familia;
    const { token, expiraEm } = assinarAcessToken(usuario);
    const novoRefresh = assinarRefreshToken(usuario, familia);

    sessao.revogado = true;
    sessao.revogadoEm = new Date();
    sessao.motivoRevogacao = 'rotacionado';
    sessao.substituidoPor = novoRefresh.jti;
    await sessao.save();

    await Sessao.create({
        usuarioId: usuario._id,
        familia,
        jti: novoRefresh.jti,
        hashToken: hashToken(novoRefresh.token),
        ip: req ? String(req.ip || '').replace(/^::ffff:/, '') : '',
        agente: req ? String(req.get?.('user-agent') || '').slice(0, 400) : '',
        expiraEm: novoRefresh.expiraEm
    });

    log.info('REFRESH_TOKEN_ROTACIONADO', { usuarioId: String(usuario._id), familia }, req);

    return {
        token,
        refreshToken: novoRefresh.token,
        expiraEm,
        refreshExpiraEm: novoRefresh.expiraEm
    };
}

async function revogarFamilia(familia, motivo, req = null) {
    const result = await Sessao.updateMany(
        { familia, revogado: false },
        { revogado: true, revogadoEm: new Date(), motivoRevogacao: motivo }
    );
    log.aviso('FAMILIA_REFRESH_REVOGADA', { familia, motivo, sessoes: result.modifiedCount }, req);
    return result.modifiedCount;
}

/** Logout: revoga a sessão atual e coloca o access token na blacklist até expirar. */
async function encerrarSessao(payload, req = null) {
    if (payload?.typ === 'refresh' && payload?.familia) {
        await revogarFamilia(payload.familia, 'logout', req);
    }
    if (payload?.typ === 'access') {
        await blacklistAccessToken(payload, 'logout', req);
    }
    return true;
}

/**
 * Blacklist de access tokens. O TTL do MongoDB remove o registro assim que o
 * token expiraria de qualquer forma, entao a tabela nunca cresce sozinha.
 */
async function blacklistAccessToken(payload, motivo, req = null) {
    if (!payload?.jti || !payload?.exp) return false;
    try {
        await TokenRevogado.create({
            jti: payload.jti,
            usuarioId: payload.sub,
            motivo,
            expiraEm: new Date(payload.exp * 1000)
        });
        return true;
    } catch (err) {
        if (err?.code !== 11000) log.aviso('FALHA_BLACKLIST_TOKEN', { erro: err.message }, req);
        return false;
    }
}

async function tokenEstaRevogado(jti) {
    if (!jti) return false;
    return Boolean(await TokenRevogado.exists({ jti }));
}

module.exports = {
    ISSUER,
    ALGORITMO,
    emitirSessao,
    renovarSessao,
    encerrarSessao,
    revogarFamilia,
    blacklistAccessToken,
    tokenEstaRevogado,
    expiracaoAccessToken,
    assinarAcessToken
};
