'use strict';

/**
 * 📜 TRILHA DE SEGURANÇA (item 27)
 *
 * Eventos relevantes de segurança sao emitidos em JSON estruturado para o stdout
 * e, opcionalmente, gravados em arquivo (ARQUIVO_LOG_SEGURANCA).
 * NUNCA registramos segredos: senhas, tokens, CPF/celular em texto plano sao
 * mascarados antes de qualquer escrita.
 */

const fs = require('fs');
const path = require('path');
const { AMBIENTE, ARQUIVO_LOG_SEGURANCA, LOG_SEGURANCA_CONSOLE } = require('./config');

const NIVEL = {
    DEBUG: 10,
    INFO: 20,
    AVISO: 30,
    ALERTA: 40,
    CRITICO: 50
};

const NIVEL_MINIMO = process.env.LOG_SEGURANCA_NIVEL && NIVEL[process.env.LOG_SEGURANCA_NIVEL]
    ? NIVEL[process.env.LOG_SEGURANCA_NIVEL]
    : (AMBIENTE === 'production' ? NIVEL.INFO : NIVEL.DEBUG);

const CHAVES_SENSIVEIS = new Set([
    'senha', 'senhaAtual', 'novaSenha', 'senhaCriptografada', 'password',
    'token', 'accessToken', 'refreshToken', 'authorization', 'cookie',
    'cpf', 'cpfCriptografado', 'celular', 'celularCriptografado', 'telefone',
    'cpfOriginal', 'secret', 'jwtSecret'
]);

let streamArquivo = null;

function mascarar(valor, chave) {
    if (valor === null || valor === undefined) return valor;

    if (typeof valor === 'string' && CHAVES_SENSIVEIS.has(chave)) {
        if (valor.length <= 4) return '***';
        return `***${valor.slice(-2)}`;
    }

    if (valor instanceof Date) return valor.toISOString();
    if (typeof valor !== 'object') return valor;

    if (Array.isArray(valor)) return valor.map(v => (v && typeof v === 'object' ? mascarar(v, chave) : mascarar(v, '')));

    const saida = {};
    for (const [k, v] of Object.entries(valor)) {
        saida[k] = mascarar(v, k);
    }
    return saida;
}

function abrirStream() {
    if (streamArquivo || !ARQUIVO_LOG_SEGURANCA) return streamArquivo;
    try {
        const destino = path.resolve(ARQUIVO_LOG_SEGURANCA);
        fs.mkdirSync(path.dirname(destino), { recursive: true });
        streamArquivo = fs.createWriteStream(destino, { flags: 'a', mode: 0o600 });
        streamArquivo.on('error', (err) => console.error('[log-seguranca] falha ao escrever no arquivo:', err.message));
    } catch (err) {
        console.error('[log-seguranca] nao foi possivel abrir o arquivo de log:', err.message);
        streamArquivo = null;
    }
    return streamArquivo;
}

function contextoDaRequisicao(req) {
    if (!req) return {};
    const ip = (req.ip || req.socket?.remoteAddress || 'desconhecido').replace(/^::ffff:/, '');
    return {
        ip,
        metodo: req.method,
        rota: req.originalUrl ? req.originalUrl.split('?')[0] : undefined,
        idRequisicao: req.idRequisicao,
        agente: typeof req.get === 'function' ? req.get('user-agent') : undefined
    };
}

function registrar(nivel, evento, detalhes = {}, req = null) {
    if (NIVEL[nivel] < NIVEL_MINIMO) return;

    const registro = {
        timestamp: new Date().toISOString(),
        nivel,
        ambiente: AMBIENTE,
        evento,
        ...contextoDaRequisicao(req),
        ...mascarar(detalhes, '')
    };

    const linha = JSON.stringify(registro);

    if (LOG_SEGURANCA_CONSOLE) {
        if (nivel === 'CRITICO' || nivel === 'ALERTA') console.error(linha);
        else if (nivel === 'AVISO') console.warn(linha);
        else console.log(linha);
    }

    const stream = abrirStream();
    if (stream) stream.write(`${linha}\n`);
}

const registrarSeguranca = {
    debug: (evento, detalhes, req) => registrar('DEBUG', evento, detalhes, req),
    info: (evento, detalhes, req) => registrar('INFO', evento, detalhes, req),
    aviso: (evento, detalhes, req) => registrar('AVISO', evento, detalhes, req),
    alerta: (evento, detalhes, req) => registrar('ALERTA', evento, detalhes, req),
    critico: (evento, detalhes, req) => registrar('CRITICO', evento, detalhes, req),

    /** Atalho: registra o resultado de uma tentativa de autenticacao. */
    autenticacao: (sucesso, detalhes, req) => registrar(
        sucesso ? 'INFO' : 'AVISO',
        sucesso ? 'LOGIN_CONCLUIDO' : 'LOGIN_NEGADO',
        { sucesso, ...detalhes },
        req
    ),

    /** Atalho: acesso recusado por falta de permissao/token. */
    acessoNegado: (motivo, detalhes, req) => registrar('AVISO', 'ACESSO_NEGADO', { motivo, ...detalhes }, req),

    mascarar
};

module.exports = registrarSeguranca;
