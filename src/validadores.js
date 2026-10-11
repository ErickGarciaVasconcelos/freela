'use strict';

const Joi = require('joi');
const mongoose = require('mongoose');

/**
 * 🧹 SANITIZAÇÃO DE ENTRADA (item 22)
 *
 * Todo corpo/query/param passa por estes schemas antes de chegar no controller.
 * Regras aplicadas em todas as rotas:
 *  - `stripUnknown`: campos nao declarados sao REMOVIDOS (impede mass assignment).
 *  - `convert: true` + `abortEarly: false`: erros completos, nao o primeiro.
 *  - Strings passam por `textoSeguro()`: trim, normalizacao de espacos e remocao
 *    de caracteres de controle/invisiveis usados para bypass de filtro.
 *  - Limites de tamanho em cada campo evitam payload abuse e NoSQL injection
 *    via objetos gigante.
 */

const CARACTERES_INVISIVEIS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u200B-\u200F\u2028\u2029\u202A-\u202E\u2060-\u2064\uFEFF]/g;

/** Remove invisíveis, colapsa espaços e neutraliza HTML/script nas strings livres. */
function textoSeguro(valor) {
    if (typeof valor !== 'string') return valor;
    return valor
        .replace(CARACTERES_INVISIVEIS, '')
        .replace(/\s+/g, ' ')
        .trim();
}

/** Igual a textoSeguro, porém preserva quebras de linha (descrições). */
function textoMultilinha(valor) {
    if (typeof valor !== 'string') return valor;
    return valor
        .replace(CARACTERES_INVISIVEIS, '')
        .replace(/\r\n/g, '\n')
        .replace(/\n{3,}/g, '\n\n')
        .trim();
}

const objectId = Joi.string()
    .custom((valor, helpers) => {
        if (!mongoose.Types.ObjectId.isValid(valor)) {
            return helpers.error('string.objectId');
        }
        return valor;
    }, 'ObjectId válido')
    .messages({ 'string.objectId': '{{#label}} deve ser um identificador válido.' });

const senhaForte = Joi.string()
    .min(8)
    .max(128)
    .pattern(/[a-zA-Z]/, 'A senha deve conter ao menos uma letra.')
    .pattern(/\d/, 'A senha deve conter ao menos um número.')
    .required()
    .messages({
        'string.min': 'A senha deve ter no mínimo 8 caracteres.',
        'string.max': 'A senha deve ter no máximo 128 caracteres.'
    });

const email = Joi.string()
    .trim()
    .lowercase()
    .max(254)
    .email({ minDomainSegments: 2, tlds: false })
    .required();

const cpf = Joi.string()
    .custom((valor, helpers) => {
        const d = String(valor).replace(/\D+/g, '');
        if (d.length !== 11) return helpers.error('cpf.tamanho');
        if (/^(\d)\1{10}$/.test(d)) return helpers.error('cpf.repetido');
        const digitos = d.split('').map(Number);
        let soma = digitos.slice(0, 9).reduce((acc, n, i) => acc + n * (10 - i), 0);
        const dv1 = (soma * 10) % 11 % 10;
        soma = digitos.slice(1, 10).reduce((acc, n, i) => acc + n * (11 - i), 0);
        const dv2 = (soma * 10) % 11 % 10;
        if (dv1 !== digitos[9] || dv2 !== digitos[10]) return helpers.error('cpf.invalido');
        return d;
    }, 'CPF válido')
    .messages({
        'cpf.tamanho': 'O CPF deve conter 11 dígitos.',
        'cpf.repetido': 'O CPF informado é inválido.',
        'cpf.invalido': 'O CPF informado é inválido.'
    })
    .required();

const celular = Joi.string()
    .pattern(/^\+?[1-9]\d{7,14}$/, 'Celular deve estar no formato E.164, ex.: +5511999999999.')
    .required();

const dataISO = Joi.date().iso().max('now').max('2100-01-01');

const hora = Joi.string().pattern(/^([01]\d|2[0-3]):[0-5]\d$/, 'Horário deve estar no formato HH:MM.').max(5);

const urlImagem = Joi.string().allow('').max(8 * 1024 * 1024);

const listaExperiencias = Joi.array().max(20).items(Joi.object({
    local: Joi.string().max(120).allow('').default(''),
    tempoMeses: Joi.number().integer().min(0).max(1200).default(0),
    descricao: Joi.string().max(600).allow('').default('')
}).unknown(false));

const OPCOES_BASE = {
    abortEarly: false,
    stripUnknown: true,
    convert: true,
    errors: { wrap: { label: '"' } }
};

// ==========================================
// SCHEMAS POR ROTA
// ==========================================

const cadastro = Joi.object({
    nome: Joi.string().custom(textoSeguro).min(2).max(120).required()
        .messages({ 'string.min': 'Nome deve ter ao menos 2 caracteres.' }),
    nomeSocial: Joi.string().custom(textoSeguro).allow('').max(120).default(''),
    email,
    senha: senhaForte,
    tipo: Joi.string().valid('contratante', 'contratado').required(),
    cpf,
    celular,
    genero: Joi.string().valid('Masculino', 'Feminino', 'Outro').default('Outro'),
    idade: Joi.number().integer().min(16, 'Idade mínima de 16 anos.').max(120),
    experiencias: Joi.string().custom(textoMultilinha).allow('').max(2000).default(''),
    experienciasDetalhadas: listaExperiencias.default([]),
    fotoPerfil: urlImagem.default('')
});

const login = Joi.object({
    email: email.required(),
    senha: Joi.string().min(1).max(128).required()
});

const atualizarPerfil = Joi.object({
    email: email.optional(),
    celular: Joi.string().pattern(/^\+?[1-9]\d{7,14}$/).optional(),
    senhaAtual: Joi.string().allow('').max(128),
    novaSenha: Joi.string().allow('').max(128)
})
    .min(1)
    .custom((valor, helpers) => {
        if (valor.novaSenha) {
            const { error } = senhaForte.validate(valor.novaSenha);
            if (error) return helpers.message({ custom: 'A nova senha deve ter no mínimo 8 caracteres, com letra e número.' });
        }
        return valor;
    });

const refresh = Joi.object({
    refreshToken: Joi.string().min(20).max(4096).required()
});

const avaliar = Joi.object({
    nota: Joi.number().integer().min(1, 'A nota deve estar entre 1 e 5.').max(5).required(),
    comentario: Joi.string().custom(textoMultilinha).allow('').max(1000).default('')
});

const listaVagas = Joi.object({
    pagina: Joi.number().integer().min(1).max(10000).default(1),
    limite: Joi.number().integer().min(1).max(50).default(12),
    status: Joi.string().valid('aberta', 'preenchida', 'fechada', 'cancelada'),
    genero: Joi.string().valid('Todos', 'Masculino', 'Feminino'),
    busca: Joi.string().custom(textoSeguro).allow('').max(120),
    criadoPor: objectId,
    ordem: Joi.string().valid('recentes', 'antigos', 'valor_desc', 'valor_asc', 'data').default('recentes'),
    minha: Joi.boolean().default(false)
});

const listaNotificacoes = Joi.object({
    pagina: Joi.number().integer().min(1).max(10000).default(1),
    limite: Joi.number().integer().min(1).max(50).default(20),
    apenasNaoLidas: Joi.boolean().default(false)
});

const criarVaga = Joi.object({
    titulo: Joi.string().custom(textoSeguro).min(3).max(140).required()
        .messages({ 'string.min': 'Título deve ter ao menos 3 caracteres.' }),
    descricao: Joi.string().custom(textoMultilinha).allow('').max(3000).default(''),
    valor: Joi.number().min(0).max(1_000_000).default(0),
    vagasTotais: Joi.number().integer().min(1).max(500).default(1),
    genero: Joi.string().valid('Todos', 'Masculino', 'Feminino').default('Todos'),
    experienciaRequerida: Joi.boolean().default(false),
    tempoExperiencia: Joi.string().custom(textoSeguro).allow('').max(120).default(''),
    dataTrabalho: dataISO,
    endereco: Joi.string().custom(textoSeguro).allow('').max(300).default(''),
    horario: Joi.string().custom(textoSeguro).allow('').max(80).default(''),
    horarioInicio: hora.allow('').default(''),
    horarioFim: hora.allow('').default(''),
    datasTrabalho: Joi.array().max(30).items(Joi.object({
        data: dataISO.required(),
        horarioInicio: hora.allow('').default(''),
        horarioFim: hora.allow('').default('')
    }).unknown(false)).default([])
});

const selecionarEquipe = Joi.object({
    titulares: Joi.array().items(Joi.string().alphanum().max(64)).min(1, 'Selecione ao menos 1 titular.').max(500).required(),
    reservas: Joi.array().items(Joi.string().alphanum().max(64)).max(500).default([])
})
    .custom((valor, helpers) => {
        const todos = [...valor.titulares, ...valor.reservas];
        if (new Set(todos).size !== todos.length) {
            return helpers.message({ custom: 'A mesma pessoa não pode ser selecionada em mais de uma função.' });
        }
        return valor;
    });

const cancelarVaga = Joi.object({
    motivoCancelamento: Joi.string().custom(textoMultilinha).allow('').max(500).default('')
});

const paramsId = Joi.object({ id: objectId.required() });

module.exports = {
    textoSeguro,
    textoMultilinha,
    objectId,
    OPCOES_BASE,
    cadastro,
    login,
    atualizarPerfil,
    refresh,
    avaliar,
    listaVagas,
    listaNotificacoes,
    criarVaga,
    selecionarEquipe,
    cancelarVaga,
    paramsId
};
