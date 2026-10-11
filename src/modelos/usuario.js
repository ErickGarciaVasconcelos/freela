'use strict';

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { cifrar, decifrar, indiceCego, somenteDigitos } = require('../criptografia');
const { SALT_ROUNDS } = require('../config');

const { Schema } = mongoose;

const ExperienciaSchema = new Schema({
    local: { type: String, default: '', trim: true, maxlength: 120 },
    tempoMeses: { type: Number, default: 0, min: 0, max: 1200 },
    descricao: { type: String, default: '', trim: true, maxlength: 600 }
}, { _id: false });

const AvaliacaoSchema = new Schema({
    autorId: { type: Schema.Types.ObjectId, ref: 'Usuario', required: true },
    nota: { type: Number, min: 1, max: 5, required: true },
    comentario: { type: String, default: '', trim: true, maxlength: 1000 },
    data: { type: Date, default: Date.now }
});

const UsuarioSchema = new Schema({
    nome: { type: String, required: true, trim: true, minlength: 2, maxlength: 120 },
    nomeSocial: { type: String, default: '', trim: true, maxlength: 120 },

    email: {
        type: String,
        required: true,
        trim: true,
        lowercase: true,
        maxlength: 254
    },
    senha: { type: String, required: true, select: false },

    tipo: { type: String, required: true, enum: ['contratante', 'contratado'], lowercase: true },

    // 🔐 CPF: nunca em texto plano. `cpfCriptografado` guarda AES-256-GCM,
    // `cpfIndice` (HMAC-SHA256) permite unicidade/lookup sem expor o valor.
    cpfCriptografado: { type: String, default: null, select: false },
    cpfIndice: { type: String, default: null },

    // 🔐 Celular: mesma estratégia do CPF.
    celularCriptografado: { type: String, default: null },
    celularIndice: { type: String, default: null },

    idade: { type: Number, min: 16, max: 120 },
    fotoPerfil: { type: String, default: '', maxlength: 8 * 1024 * 1024 },
    genero: { type: String, enum: ['Masculino', 'Feminino', 'Outro'], default: 'Outro' },
    experiencias: { type: String, default: '', maxlength: 2000 },

    experienciasDetalhadas: { type: [ExperienciaSchema], default: [] },

    favoritos: [{ type: Schema.Types.ObjectId, ref: 'Usuario' }],
    avaliacoes: { type: [AvaliacaoSchema], default: [] },

    // 🔐 Estado de segurança da conta (brute force / item 25)
    tentativasFalhas: { type: Number, default: 0, select: false },
    bloqueadoAte: { type: Date, default: null, select: false },
    ultimoLoginEm: { type: Date, default: null },
    senhaAlteradaEm: { type: Date, default: Date.now },
    versaoSenha: { type: Number, default: 1, select: false }
}, {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
});

// ---------------------------------------------------------------------------
// Virtuals `cpf` / `celular`: a API continua devolvendo os valores em claro,
// mas a decifracao acontece em memoria. No banco so existe ciphertext.
// ---------------------------------------------------------------------------
UsuarioSchema.virtual('cpf')
    .set(function (valor) { this._cpfLimpo = somenteDigitos(valor); })
    .get(function () { return decifrar(this.cpfCriptografado); });

UsuarioSchema.virtual('celular')
    .set(function (valor) { this._celularLimpo = somenteDigitos(valor); })
    .get(function () { return decifrar(this.celularCriptografado); });

function aplicarCifragem(doc, campoLimpo, campoCriptografado, campoIndice) {
    const valor = doc[campoLimpo];
    if (valor === undefined) return; // nada a fazer neste ciclo

    const digitos = somenteDigitos(valor || '');
    if (!digitos) {
        doc[campoCriptografado] = null;
        doc[campoIndice] = null;
        return;
    }

    // Só re-cifra se o conteúdo mudou: evita recifrar e trocar o índice a cada save.
    if (doc[campoIndice] && doc[campoCriptografado] && decifrar(doc[campoCriptografado]) === digitos) return;

    doc[campoCriptografado] = cifrar(digitos);
    doc[campoIndice] = indiceCego(digitos);
}

UsuarioSchema.pre('validate', function cifrarCampos(next) {
    // Migração silenciosa de dados legados gravados em texto plano.
    const legadoCpf = this.cpfCriptografado && !String(this.cpfCriptografado).startsWith('v1:')
        ? somenteDigitos(this.cpfCriptografado)
        : null;
    if (legadoCpf && !this.cpfIndice) this._cpfLimpo = legadoCpf;

    const legadoCelular = this.celularCriptografado && !String(this.celularCriptografado).startsWith('v1:')
        ? somenteDigitos(this.celularCriptografado)
        : null;
    if (legadoCelular && !this.celularIndice) this._celularLimpo = legadoCelular;

    aplicarCifragem(this, '_cpfLimpo', 'cpfCriptografado', 'cpfIndice');
    aplicarCifragem(this, '_celularLimpo', 'celularCriptografado', 'celularIndice');

    if (!this.cpfIndice) {
        return next(new Error('CPF e obrigatorio.'));
    }
    if (!this.celularIndice) {
        return next(new Error('Celular e obrigatorio.'));
    }

    next();
});

UsuarioSchema.pre('save', async function hashSenha(next) {
    if (!this.isModified('senha')) return next();
    this.senha = await bcrypt.hash(this.senha, SALT_ROUNDS);
    this.senhaAlteradaEm = new Date();
    this.versaoSenha = (this.versaoSenha || 0) + 1;
    next();
});

UsuarioSchema.methods.compararSenha = function compararSenha(senha) {
    if (!this.senha) return Promise.resolve(false);
    return bcrypt.compare(senha, this.senha);
};

UsuarioSchema.methods.registrarFalhaDeLogin = function registrarFalhaDeLogin(limite, janelaMs) {
    this.tentativasFalhas = (this.tentativasFalhas || 0) + 1;
    if (this.tentativasFalhas >= limite) {
        this.bloqueadoAte = new Date(Date.now() + janelaMs);
    }
    return this.save({ validateBeforeSave: false });
};

UsuarioSchema.methods.resetarFalhasDeLogin = function resetarFalhasDeLogin() {
    this.tentativasFalhas = 0;
    this.bloqueadoAte = null;
    this.ultimoLoginEm = new Date();
    return this.save({ validateBeforeSave: false });
};

// 📇 ÍNDICES (item 30)
UsuarioSchema.index({ email: 1 }, { unique: true, name: 'idx_usuario_email' });
UsuarioSchema.index({ cpfIndice: 1 }, { unique: true, sparse: true, name: 'idx_usuario_cpf' });
UsuarioSchema.index({ celularIndice: 1 }, { sparse: true, name: 'idx_usuario_celular' });
UsuarioSchema.index({ tipo: 1, criadoAt: -1 }, { name: 'idx_usuario_tipo_criacao' });

module.exports = mongoose.models.Usuario || mongoose.model('Usuario', UsuarioSchema);
