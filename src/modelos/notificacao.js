'use strict';

const mongoose = require('mongoose');

const { Schema } = mongoose;

const NotificacaoSchema = new Schema({
    usuarioId: { type: Schema.Types.ObjectId, ref: 'Usuario', required: true },
    tipo: { type: String, enum: ['vaga_disponivel', 'candidato_novo', 'equipe_selecionada', 'vaga_cancelada'], required: true },
    titulo: { type: String, required: true, maxlength: 160 },
    mensagem: { type: String, required: true, maxlength: 1000 },
    vagaId: { type: Schema.Types.ObjectId, ref: 'Vaga' },
    lida: { type: Boolean, default: false },
    dataCriacao: { type: Date, default: Date.now }
}, { timestamps: false });

NotificacaoSchema.index({ usuarioId: 1, lida: 1, dataCriacao: -1 }, { name: 'idx_notificacao_usuario_lida' });
NotificacaoSchema.index({ dataCriacao: -1 }, { name: 'idx_notificacao_data', expireAfterSeconds: 60 * 60 * 24 * 90 });

module.exports = mongoose.models.Notificacao || mongoose.model('Notificacao', NotificacaoSchema);
