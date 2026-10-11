'use strict';

/**
 * 🔐 PROTEÇÃO DE DADOS SENSÍVEIS EM REPOUSO (item 23)
 *
 * CPF e celular deixam de ser gravados em texto plano no MongoDB. Cada campo e
 * gravado como ciphertext AES-256-GCM (`v1:<iv>:<tag>:<dados>`) e, para permitir
 * consultas de unicidade/lookup sem decifrar, mantemos um "blind index" HMAC-SHA256
 * determinístico do valor normalizado.
 *
 * O índice cego nunca é reversível e só pode ser comparado com outro índice cego
 * derivado da mesma chave — um dump do banco não permite recuperar CPF/celular.
 */

const crypto = require('crypto');
const { chaveCriptografia, chaveIndiceCego } = require('./config');

const PREFIXO = 'v1';
const IV_BYTES = 12;
const TAMANHO_TAG = 16;
const ALGORITMO = 'aes-256-gcm';

/** Remove tudo que não for dígito: "123.456.789-09" -> "12345678909". */
function somenteDigitos(valor) {
    return String(valor ?? '').replace(/\D+/g, '');
}

function cifrar(valor) {
    if (valor === null || valor === undefined || valor === '') return null;
    const texto = String(valor);
    const iv = crypto.randomBytes(IV_BYTES);
    const cifrador = crypto.createCipheriv(ALGORITMO, chaveCriptografia(), iv);
    const dados = Buffer.concat([cifrador.update(texto, 'utf8'), cifrador.final()]);
    const tag = cifrador.getAuthTag();
    return [PREFIXO, iv.toString('base64'), tag.toString('base64'), dados.toString('base64')].join(':');
}

function decifrar(armazenado) {
    if (armazenado === null || armazenado === undefined || armazenado === '') return null;
    if (typeof armazenado !== 'string') return armazenado;

    const partes = armazenado.split(':');
    if (partes.length !== 4 || partes[0] !== PREFIXO) {
        // Dado legado em texto plano: devolvemos como esta para permitir migracao.
        return armazenado;
    }

    try {
        const iv = Buffer.from(partes[1], 'base64');
        const tag = Buffer.from(partes[2], 'base64');
        const dados = Buffer.from(partes[3], 'base64');
        const decifrador = crypto.createDecipheriv(ALGORITMO, chaveCriptografia(), iv);
        decifrador.setAuthTag(tag);
        return Buffer.concat([decifrador.update(dados), decifrador.final()]).toString('utf8');
    } catch {
        return null;
    }
}

function indiceCego(valorNormalizado) {
    const texto = String(valorNormalizado ?? '');
    if (!texto) return null;
    return crypto.createHmac('sha256', chaveIndiceCego()).update(texto).digest('hex');
}

/** Hash determinístico para senha/telefone (não reversível, resistant a rainbow tables). */
function hashSenha(valor) {
    return crypto.createHash('sha256').update(String(valor), 'utf8').digest('hex');
}

function comparacaoSegura(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

function mascararCpf(valor) {
    const d = somenteDigitos(valor);
    if (d.length !== 11) return '***';
    return `***.***.${d.slice(3, 6)}-**`;
}

function mascararCelular(valor) {
    const d = somenteDigitos(valor);
    if (d.length < 4) return '***';
    return `*******${d.slice(-4)}`;
}

module.exports = {
    cifrar,
    decifrar,
    indiceCego,
    hashSenha,
    comparacaoSegura,
    somenteDigitos,
    mascararCpf,
    mascararCelular,
    ehCifrado: (v) => typeof v === 'string' && v.split(':').length === 4 && v.startsWith(`${PREFIXO}:`)
};
