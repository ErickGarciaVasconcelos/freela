'use strict';

const mongoose = require('mongoose');
const crypto = require('crypto');
const { REFRESH_TOKEN_TTL_MS } = require('../config');

const { Schema } = mongoose;

/**
 * 🔄 SESSÕES / REFRESH TOKENS (item 24)
 *
 * - Cada login cria uma "familia" de refresh tokens.
 * - A cada renovação o token anterior é revogado e substituído (rotação).
 * - Se um token já rotacionado for reutilizado, tratamos como roubo de token:
 *   toda a família é revogada imediatamente.
 */
const SessaoSchema = new Schema({
    usuarioId: { type: Schema.Types.ObjectId, ref: 'Usuario', required: true },
    familia: { type: String, required: true },
    jti: { type: String, required: true, unique: true },

    // Nunca armazenamos o refresh token em claro: guardamos apenas o SHA-256.
    hashToken: { type: String, required: true },

    ip: { type: String, default: '' },
    agente: { type: String, default: '', maxlength: 400 },

    revogado: { type: Boolean, default: false },
    revogadoEm: { type: Date, default: null },
    motivoRevogacao: { type: String, default: '' },
    substituidoPor: { type: String, default: null },

    criadoEm: { type: Date, default: Date.now },
    expiraEm: { type: Date, required: true }
});

SessaoSchema.index({ jti: 1 }, { unique: true, name: 'idx_sessao_jti' });
SessaoSchema.index({ usuarioId: 1, revogado: 1 }, { name: 'idx_sessao_usuario' });
SessaoSchema.index({ familia: 1 }, { name: 'idx_sessao_familia' });
// TTL: limpeza automatica de sessoes expiradas pelo proprio MongoDB
SessaoSchema.index({ expiraEm: 1 }, { name: 'idx_sessao_ttl', expireAfterSeconds: 0 });

/** Blacklist de access tokens (logout, troca de senha, deteccao de reuso). */
const TokenRevogadoSchema = new Schema({
    jti: { type: String, required: true, unique: true },
    usuarioId: { type: Schema.Types.ObjectId, ref: 'Usuario' },
    motivo: { type: String, default: '' },
    expiraEm: { type: Date, required: true },
    criadoEm: { type: Date, default: Date.now }
});

TokenRevogadoSchema.index({ jti: 1 }, { unique: true, name: 'idx_token_revogado_jti' });
TokenRevogadoSchema.index({ expiraEm: 1 }, { name: 'idx_token_revogado_ttl', expireAfterSeconds: 0 });

SessaoSchema.methods.estaValida = function estaValida() {
    return !this.revogado && this.expiraEm.getTime() > Date.now();
};

module.exports = {
    Sessao: mongoose.models.Sessao || mongoose.model('Sessao', SessaoSchema),
    TokenRevogado: mongoose.models.TokenRevogado || mongoose.model('TokenRevogado', TokenRevogadoSchema),

    gerarFamilia: () => crypto.randomBytes(18).toString('hex'),
    gerarJti: () => crypto.randomUUID(),
    expiracaoPadrao: () => new Date(Date.now() + REFRESH_TOKEN_TTL_MS),
    hashToken: (token) => crypto.createHash('sha256').update(String(token), 'utf8').digest('hex')
};
