'use strict';

const mongoose = require('mongoose');

const { Schema } = mongoose;

/**
 * 🛡️ CONTROLE DE FORÇA BRUTA (item 25)
 *
 * Contabiliza falhas por identidade (e-mail normalizado) e por IP. O par
 * (chave, tipo) é único e cada registro expira automaticamente via TTL, o que
 * mantém a janela deslizante sem depender de jobs de limpeza.
 */
const TentativaLoginSchema = new Schema({
    chave: { type: String, required: true },
    tipo: { type: String, enum: ['email', 'ip'], required: true },
    tentativas: { type: Number, default: 0 },
    primeiraTentativa: { type: Date, default: Date.now },
   ultimaTentativa: { type: Date, default: Date.now },
    bloqueadoAte: { type: Date, default: null },
    expiraEm: { type: Date, required: true }
});

TentativaLoginSchema.index({ chave: 1, tipo: 1 }, { unique: true, name: 'idx_tentativa_chave_tipo' });
TentativaLoginSchema.index({ expiraEm: 1 }, { name: 'idx_tentativa_ttl', expireAfterSeconds: 0 });

/**
 * 📜 TRILHA DE AUDITORIA PERSISTENTE (item 27)
 * Complementa o log JSON: guarda quem fez o quê, quando e de onde.
 */
const AuditoriaSchema = new Schema({
    evento: { type: String, required: true, index: true },
    usuarioId: { type: Schema.Types.ObjectId, ref: 'Usuario' },
    resultado: { type: String, enum: ['sucesso', 'falha', 'bloqueado'], default: 'sucesso' },
    ip: { type: String, default: '' },
    rota: { type: String, default: '', maxlength: 300 },
    metodo: { type: String, default: '', maxlength: 10 },
    idRequisicao: { type: String, default: '' },
    detalhes: { type: Schema.Types.Mixed, default: {} },
    criadoEm: { type: Date, default: Date.now }
});

AuditoriaSchema.index({ criadoEm: -1 }, { name: 'idx_auditoria_data' });
AuditoriaSchema.index({ usuarioId: 1, criadoEm: -1 }, { name: 'idx_auditoria_usuario' });
AuditoriaSchema.index({ evento: 1, criadoEm: -1 }, { name: 'idx_auditoria_evento_data' });

module.exports = {
    TentativaLogin: mongoose.models.TentativaLogin || mongoose.model('TentativaLogin', TentativaLoginSchema),
    Auditoria: mongoose.models.Auditoria || mongoose.model('Auditoria', AuditoriaSchema)
};
