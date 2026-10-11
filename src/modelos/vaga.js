'use strict';

const mongoose = require('mongoose');
const { cifrar, decifrar } = require('../criptografia');

const { Schema } = mongoose;

/**
 * Subdocumentos que carregam dados de contato de terceiros.
 * Telefone e e-mail tambem sao cifrados em repouso (item 23) — um dump da
 * colecao `vagas` nao pode expor a agenda de celular dos profissionais.
 */
const CandidatoSchema = new Schema({
    idUsuario: { type: String, required: true },
    nome: { type: String, required: true, maxlength: 120 },
    nomeCompleto: { type: String, maxlength: 120 },
    emailCriptografado: { type: String, default: null },
    telefoneCriptografado: { type: String, default: null },
    idade: Number,
    genero: String,
    experiencias: { type: String, default: '', maxlength: 2000 },
    fotoPerfil: { type: String, default: '' },
    experienciasDetalhadas: [{
        local: { type: String, default: '', maxlength: 120 },
        tempoMeses: { type: Number, default: 0 },
        descricao: { type: String, default: '', maxlength: 600 }
    }],
    criadoEm: { type: Date, default: Date.now }
}, { _id: false });

CandidatoSchema.virtual('email').get(function () { return decifrar(this.emailCriptografado); });
CandidatoSchema.virtual('telefone').get(function () { return decifrar(this.telefoneCriptografado); });

const ContratadoSchema = new Schema({
    idUsuario: { type: String, required: true },
    nome: { type: String, required: true, maxlength: 120 },
    telefoneCriptografado: { type: String, default: null },
    confirmado: { type: Boolean, default: false },
    confirmadoEm: { type: Date, default: null },
    limite_confirmacao: Date
}, { _id: false });

ContratadoSchema.virtual('telefone').get(function () { return decifrar(this.telefoneCriptografado); });

const FilaSchema = new Schema({
    idUsuario: { type: String, required: true },
    nome: { type: String, required: true, maxlength: 120 },
    telefoneCriptografado: { type: String, default: null },
    promovidoEm: { type: Date, default: null }
}, { _id: false });

FilaSchema.virtual('telefone').get(function () { return decifrar(this.telefoneCriptografado); });

const VagaSchema = new Schema({
    titulo: { type: String, required: true, trim: true, minlength: 3, maxlength: 140 },
    descricao: { type: String, default: '', trim: true, maxlength: 3000 },
    valor: { type: Number, min: 0, max: 1_000_000, default: 0 },

    status_vaga: {
        type: String,
        enum: ['aberta', 'preenchida', 'fechada', 'cancelada'],
        default: 'aberta',
        index: true
    },
    vagasTotais: { type: Number, default: 1, min: 1, max: 500 },
    genero: { type: String, enum: ['Todos', 'Masculino', 'Feminino'], default: 'Todos' },
    experienciaRequerida: { type: Boolean, default: false },
    tempoExperiencia: { type: String, default: '', maxlength: 120 },

    dataTrabalho: { type: Date, default: null },
    endereco: { type: String, default: '', trim: true, maxlength: 300 },
    horario: { type: String, default: '', maxlength: 80 },

    horarioInicio: { type: String, default: '', maxlength: 10 },
    horarioFim: { type: String, default: '', maxlength: 10 },

    datasTrabalho: [{
        data: Date,
        horarioInicio: { type: String, default: '', maxlength: 10 },
        horarioFim: { type: String, default: '', maxlength: 10 }
    }],

    criadoPor: { type: Schema.Types.ObjectId, ref: 'Usuario', required: true, index: true },
    motivoCancelamento: { type: String, default: '', maxlength: 500 },
    dataCancelamento: { type: Date, default: null },

    candidatos: { type: [CandidatoSchema], default: [] },
    contratados_atuais: { type: [ContratadoSchema], default: [] },
    fila_de_espera: { type: [FilaSchema], default: [] },

    // Contadores desnormalizados para ordenar/paginar sem carregar arrays grandes.
    totalCandidatos: { type: Number, default: 0 },
    totalContratados: { type: Number, default: 0 }
}, {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
});

// Mantem os contadores coerentes com os arrays
VagaSchema.pre('save', function atualizarContadores(next) {
    this.totalCandidatos = this.candidatos.length;
    this.totalContratados = this.contratados_atuais.length;
    next();
});

// 📇 ÍNDICES (item 30)
VagaSchema.index({ criadoPor: 1 }, { name: 'idx_vaga_criadoPor' });
VagaSchema.index({ status_vaga: 1 }, { name: 'idx_vaga_status' });
VagaSchema.index({ status_vaga: 1, dataTrabalho: -1 }, { name: 'idx_vaga_status_data' });
VagaSchema.index({ criadoPor: 1, status_vaga: 1, criadoAt: -1 }, { name: 'idx_vaga_dono_status' });
VagaSchema.index({ titulo: 'text', descricao: 'text', endereco: 'text' }, {
    name: 'idx_vaga_busca_texto',
    weights: { titulo: 10, descricao: 5, endereco: 2 }
});

module.exports = mongoose.models.Vaga || mongoose.model('Vaga', VagaSchema);
