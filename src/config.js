'use strict';

require('dotenv').config();

const crypto = require('crypto');

const AMBIENTE = process.env.NODE_ENV || 'development';
const EH_PRODUCAO = AMBIENTE === 'production';

const SEGREDOS_INSEGUROS = [
    'troque-esta-chave-por-uma-segura-em-producao',
    'secret',
    'changeme',
    'jwt_secret'
];

function falhar(mensagem) {
    console.error(`[config] ${mensagem}`);
    process.exit(1);
}

/**
 * Resolve um segredo obrigatório de no mínimo `minimoBytes` de entropia real.
 * Em desenvolvimento aceitamos um valor derivado do JWT_SECRET para não quebrar
 * o setup local, mas em produção a falha é imediata e explícita.
 */
function resolverSegredo(nome, { minimoBytes = 32, derivarDe = null } = {}) {
    const bruto = (process.env[nome] || '').trim();

    if (!bruto) {
        if (EH_PRODUCAO) falhar(`${nome} nao definido. Configure o arquivo .env antes de iniciar em producao.`);
        if (derivarDe) {
            const derivada = crypto.hkdfSync('sha512', Buffer.from(bruto, 'utf8'), Buffer.alloc(0), Buffer.from(nome, 'utf8'), 32);
            console.warn(`[config] AVISO: ${nome} nao definido. Chave derivada de ${derivarDe} SOMENTE PARA DESENVOLVIMENTO.`);
            return Buffer.from(derivada).toString('hex');
        }
        falhar(`${nome} nao definido. Configure o arquivo .env.`);
    }

    if (SEGREDOS_INSEGUROS.includes(bruto.toLowerCase())) falhar(`${nome} possui um valor placeholder conhecido. Gere um segredo novo.`);

    const hexValido = /^[0-9a-fA-F]+$/.test(bruto) && bruto.length === minimoBytes * 2;
    const base64Valido = (() => {
        try {
            const b = Buffer.from(bruto, 'base64');
            return b.length === minimoBytes && b.toString('base64').replace(/=+$/, '') === bruto.replace(/=+$/, '');
        } catch { return false; }
    })();

    if (!hexValido && !base64Valido) {
        if (EH_PRODUCAO) {
            falhar(`${nome} deve ter ${minimoBytes * 2} caracteres hex ou ${minimoBytes} bytes em base64.`);
        }
        if (bruto.length < minimoBytes * 2) {
            console.warn(`[config] AVISO: ${nome} e curto demais para uso em producao (minimo ${minimoBytes * 2} chars).`);
        }
    }

    return bruto;
}

const JWT_SECRET = resolverSegredo('JWT_SECRET');
const DATA_ENCRYPTION_KEY = resolverSegredo('DATA_ENCRYPTION_KEY', { derivarDe: 'JWT_SECRET' });
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET
    ? resolverSegredo('REFRESH_TOKEN_SECRET', { derivarDe: 'JWT_SECRET' })
    : crypto.hkdfSync('sha512', Buffer.from(JWT_SECRET, 'utf8'), Buffer.alloc(0), Buffer.from('refresh-token'), 32).toString('hex');

function chaveCriptografia() {
    const bruto = DATA_ENCRYPTION_KEY.trim();
    if (/^[0-9a-fA-F]{64}$/.test(bruto)) return Buffer.from(bruto, 'hex');

    const b64 = Buffer.from(bruto, 'base64');
    if (b64.length === 32) return b64;

    // Chave em texto livre: derivamos com scrypt para obter 32 bytes estáveis.
    return crypto.scryptSync(bruto, 'freela-seguro::dados-sensiveis', 32);
}

function chaveIndiceCego() {
    const bruto = DATA_ENCRYPTION_KEY.trim();
    if (/^[0-9a-fA-F]{64}$/.test(bruto)) return Buffer.from(bruto, 'hex');
    return crypto.scryptSync(bruto, 'freela-seguro::indice-cego', 32);
}

module.exports = {
    AMBIENTE,
    EH_PRODUCAO,
    PORT: Number(process.env.PORT) || 3000,
    MONGODB_URI: process.env.MONGODB_URI || 'mongodb://localhost:27017/freela-seguro',
    CORS_ORIGIN: (process.env.CORS_ORIGIN || 'http://localhost:3000').split(',').map(o => o.trim()).filter(Boolean),

    JWT_SECRET,
    JWT_ACCESS_TTL: process.env.JWT_ACCESS_TTL || '15m',
    REFRESH_TOKEN_SECRET,
    REFRESH_TOKEN_TTL_DIAS: Number(process.env.REFRESH_TOKEN_TTL_DIAS) || 7,
    REFRESH_TOKEN_TTL_MS: (Number(process.env.REFRESH_TOKEN_TTL_DIAS) || 7) * 24 * 60 * 60 * 1000,

    chaveCriptografia,
    chaveIndiceCego,

    TLS_CERT_PATH: process.env.TLS_CERT_PATH || '',
    TLS_KEY_PATH: process.env.TLS_KEY_PATH || '',
    TLS_CA_PATH: process.env.TLS_CA_PATH || '',
    FORCAR_HTTPS: process.env.FORCAR_HTTPS === 'true',
    NUM_PROXIES: Number(process.env.NUM_PROXIES) || (EH_PRODUCAO ? 1 : 0),

    ARQUIVO_LOG_SEGURANCA: process.env.ARQUIVO_LOG_SEGURANCA || '',
    LOG_SEGURANCA_CONSOLE: process.env.LOG_SEGURANCA_CONSOLE !== 'false',

    LIMITE_TENTATIVAS_LOGIN: Number(process.env.LIMITE_TENTATIVAS_LOGIN) || 5,
    JANELA_BLOQUEIO_LOGIN_MS: (Number(process.env.JANELA_BLOQUEIO_LOGIN_MINUTOS) || 15) * 60 * 1000,
    MAX_TENTATIVAS_LOGIN_IP_HORA: Number(process.env.MAX_TENTATIVAS_LOGIN_IP_HORA) || 20,

    MAX_PAGINA_VAGAS: Number(process.env.MAX_PAGINA_VAGAS) || 50,
    PAGINA_VAGAS_PADRAO: Number(process.env.PAGINA_VAGAS_PADRAO) || 12,

    SALT_ROUNDS: Number(process.env.SALT_ROUNDS) || 12,
    HASH_PICO_CELULAR: process.env.HASH_PICO_CELULAR || 'bcryptjs',

    // Limites de rate limiting (requisicoes / janela em ms)
    RL_GLOBAL_MAX: Number(process.env.RL_GLOBAL_MAX) || 300,
    RL_GLOBAL_JANELA_MS: (Number(process.env.RL_GLOBAL_JANELA_MINUTOS) || 15) * 60 * 1000,
    RL_LEITURA_MAX: Number(process.env.RL_LEITURA_MAX) || 120,
    RL_ESCRITA_MAX: Number(process.env.RL_ESCRITA_MAX) || 60,
    RL_LOGIN_MAX: Number(process.env.RL_LOGIN_MAX) || 10,
    RL_CADASTRO_MAX: Number(process.env.RL_CADASTRO_MAX) || 5,
    RL_CADASTRO_JANELA_MS: (Number(process.env.RL_CADASTRO_JANELA_HORAS) || 1) * 60 * 60 * 1000,
    RL_SENHA_MAX: Number(process.env.RL_SENHA_MAX) || 5,
    RL_SENHA_JANELA_MS: (Number(process.env.RL_SENHA_JANELA_MINUTOS) || 60) * 60 * 1000,
    RL_CANDIDATURA_MAX: Number(process.env.RL_CANDIDATURA_MAX) || 30,
    RL_CANDIDATURA_JANELA_MS: (Number(process.env.RL_CANDIDATURA_JANELA_MINUTOS) || 10) * 60 * 1000
};
