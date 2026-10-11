'use strict';

/**
 * 🛡️ PROTEÇÃO CONTRA FORÇA BRUTA (item 25)
 *
 * Defence em profundidade no login:
 *  1. Rate limiting por IP nas rotas de autenticação (ver src/middleware.js).
 *  2. Contador persistente por identidade (e-mail) e por IP, com janela móvel.
 *  3. Bloqueio progressivo: 5 falhas => 15 min de bloqueio na conta.
 *  4. Resposta genérica ("e-mail ou senha incorretos") para não permitir
 *     enumeração de contas, e comparação bcrypt em tempo constante mesmo
 *     quando o usuário não existe (dummy hash).
 */

const { TentativaLogin } = require('./modelos/seguranca');
const { LIMITE_TENTATIVAS_LOGIN, JANELA_BLOQUEIO_LOGIN_MS, MAX_TENTATIVAS_LOGIN_IP_HORA } = require('./config');
const log = require('./log-seguranca');

const JANELA_IP_MS = 60 * 60 * 1000;

async function registrar(chave, tipo, delta = 1) {
    const agora = new Date();
    const expiraEm = new Date(agora.getTime() + (tipo === 'ip' ? JANELA_IP_MS : JANELA_BLOQUEIO_LOGIN_MS));

    const registro = await TentativaLogin.findOneAndUpdate(
        { chave, tipo },
        {
            $inc: { tentativas: delta },
            $set: { ultimaTentativa: agora, expiraEm },
            $setOnInsert: { primeiraTentativa: agora }
        },
        { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    return registro;
}

function ipDe(req) {
    return String(req?.ip || req?.socket?.remoteAddress || 'desconhecido').replace(/^::ffff:/, '');
}

/** Consulta o estado de bloqueio para uma identidade e para o IP de origem. */
async function consultarBloqueio(email, req) {
    const ip = ipDe(req);
    const agora = Date.now();

    const [porEmail, porIp] = await Promise.all([
        TentativaLogin.findOne({ chave: String(email).toLowerCase(), tipo: 'email' }),
        TentativaLogin.findOne({ chave: ip, tipo: 'ip' })
    ]);

    if (porEmail?.bloqueadoAte && porEmail.bloqueadoAte.getTime() > agora) {
        return { bloqueado: true, motivo: 'conta', segundosRestantes: Math.ceil((porEmail.bloqueadoAte.getTime() - agora) / 1000) };
    }

    if (porIp && porIp.tentativas >= MAX_TENTATIVAS_LOGIN_IP_HORA) {
        const fimJanela = porIp.primeiraTentativa.getTime() + JANELA_IP_MS;
        if (fimJanela > agora) {
            return { bloqueado: true, motivo: 'ip', segundosRestantes: Math.ceil((fimJanela - agora) / 1000) };
        }
    }

    return { bloqueado: false, motivo: null, segundosRestantes: 0 };
}

/** Conta uma falha de autenticação e aplica o bloqueio progressivo. */
async function registrarFalha(email, req, contexto = {}) {
    const ip = ipDe(req);
    const agora = new Date();

    const porEmail = await registrar(String(email).toLowerCase(), 'email', 1);
    const porIp = await registrar(ip, 'ip', 1);

    const excedeuConta = porEmail.tentativas >= LIMITE_TENTATIVAS_LOGIN;
    const excedeuIp = porIp.tentativas >= MAX_TENTATIVAS_LOGIN_IP_HORA;

    if (excedeuConta) {
        porEmail.bloqueadoAte = new Date(agora.getTime() + JANELA_BLOQUEIO_LOGIN_MS);
        await porEmail.save();
    }

    if (excedeuIp && !porIp.bloqueadoAte) {
        porIp.bloqueadoAte = new Date(porIp.primeiraTentativa.getTime() + JANELA_IP_MS);
        await porIp.save();
    }

    log.autenticacao(false, {
        ...contexto,
        email: String(email).toLowerCase(),
        tentativasConta: porEmail.tentativas,
        tentativasIp: porIp.tentativas,
        contaBloqueada: excedeuConta,
        ipBloqueado: excedeuIp
    }, req);

    return {
        contaBloqueada: excedeuConta,
        ipBloqueado: excedeuIp,
        restantes: Math.max(0, LIMITE_TENTATIVAS_LOGIN - porEmail.tentativas)
    };
}

/** Limpa os contadores após um login bem-sucedido. */
async function registrarSucesso(email, req, contexto = {}) {
    const ip = ipDe(req);
    await Promise.all([
        TentativaLogin.deleteOne({ chave: String(email).toLowerCase(), tipo: 'email' }),
        TentativaLogin.deleteOne({ chave: ip, tipo: 'ip' })
    ]);
    log.autenticacao(true, { ...contexto, email: String(email).toLowerCase() }, req);
}

/**
 * bcrypt "dummy": garante que um login com e-mail inexistente gaste o mesmo
 * tempo de CPU de um login real, fechando o oráculo de tempo used para
 * enumerar e-mails cadastrados.
 */
const HASH_DUMMY = '$2b$12$C6UzMDM.H6dfI/f/IKcEeO1sJ0J8p8JrTQhCzKqQqFb3nJ7b3m7XKxS';

module.exports = {
    consultarBloqueio,
    registrarFalha,
    registrarSucesso,
    HASH_DUMMY,
    ipDe
};
