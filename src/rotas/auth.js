'use strict';

/**
 * 🔑 ROTAS DE AUTENTICAÇÃO
 *  - validação Joi de toda entrada (22)
 *  - rate limiting dedicado por IP+e-mail (21)
 *  - bloqueio progressivo contra força bruta (25)
 *  - access token curto + refresh rotativo + blacklist (24)
 *  - CPF/celular cifrados em repouso, busca por índice cego (23)
 *  - trilha de auditoria em toda tentativa (27)
 */

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Joi = require('joi');

const mw = require('../middleware');
const validadores = require('../validadores');
const tokens = require('../tokens');
const forcaBruta = require('../forca-bruta');
const cryptoDados = require('../criptografia');
const log = require('../log-seguranca');
const config = require('../config');
const Usuario = require('../modelos/usuario');
const { Auditoria } = require('../modelos/seguranca');

const router = express.Router();

const EMAIL_NAO_ENCONTRADO = 'E-mail ou senha incorretos.';

async function auditar(evento, resultado, req, usuarioId = null, detalhes = {}) {
    try {
        await Auditoria.create({
            evento,
            resultado,
            usuarioId,
            ip: forcaBruta.ipDe(req),
            rota: req.originalUrl?.split('?')[0],
            metodo: req.method,
            idRequisicao: req.idRequisicao,
            detalhes
        });
    } catch (err) {
        log.aviso('FALHA_AO_GRAVAR_AUDITORIA', { evento, erro: err.message }, req);
    }
}

function nomeExibicao(usuario) {
    return (usuario.nomeSocial && usuario.nomeSocial.trim() !== '') ? usuario.nomeSocial : usuario.nome;
}

// ==========================================
// 📝 CADASTRO
// ==========================================
router.post('/cadastro',
    mw.limitadorCadastro,
    mw.validarCorpo(validadores.cadastro),
    mw.exporCorpoValidado,
    async (req, res) => {
        const { nome, nomeSocial, email, senha, tipo, cpf, celular, genero, experiencias, idade, fotoPerfil, experienciasDetalhadas } = req.validado.body;

        try {
            const emailNormalizado = email.toLowerCase();
            const cpfIndice = cryptoDados.indiceCego(cpf);

            const [emailExistente, cpfExistente] = await Promise.all([
                Usuario.findOne({ email: emailNormalizado }).select('_id').lean(),
                Usuario.findOne({ cpfIndice }).select('_id').lean()
            ]);

            if (emailExistente || cpfExistente) {
                await auditar('CADASTO_DUPLICADO', 'falha', req, null, {
                    campos: [emailExistente ? 'email' : null, cpfExistente ? 'cpf' : null].filter(Boolean)
                });
                log.aviso('CADASTO_DUPLICADO', { campos: [emailExistente ? 'email' : null, cpfExistente ? 'cpf' : null].filter(Boolean) }, req);
                return res.status(409).json({ erro: 'Já existe uma conta com estes dados.' });
            }

            const novoUsuario = new Usuario({
                nome,
                nomeSocial: nomeSocial || '',
                email: emailNormalizado,
                senha,
                tipo,
                cpf,
                celular,
                genero: tipo === 'contratado' ? (genero || 'Outro') : 'Outro',
                experiencias: tipo === 'contratado' ? (experiencias || '') : '',
                experienciasDetalhadas: tipo === 'contratado' ? (experienciasDetalhadas || []) : [],
                idade: tipo === 'contratado' && idade ? Number(idade) : null,
                fotoPerfil: fotoPerfil || ''
            });

            await novoUsuario.save();

            log.info('CADASTO_CONCLUIDO', { usuarioId: String(novoUsuario._id), tipo }, req);
            await auditar('CADASTO_CONCLUIDO', 'sucesso', req, novoUsuario._id, { tipo });

            return res.status(201).json({ mensagem: 'Usuário cadastrado com sucesso! 🎉' });
        } catch (error) {
            log.critico('ERRO_CADASTRO', { erro: error.message }, req);
            return res.status(500).json({ erro: 'Não foi possível concluir o cadastro.' });
        }
    }
);

// ==========================================
// 🔓 LOGIN (com proteção contra força bruta)
// ==========================================
router.post('/login',
    mw.limitadorLogin,
    mw.validarCorpo(validadores.login),
    mw.exporCorpoValidado,
    async (req, res) => {
        const { email, senha } = req.validado.body;
        const emailNormalizado = email.toLowerCase();

        try {
            // 1) Conta bloqueada por excesso de tentativas?
            const bloqueio = await forcaBruta.consultarBloqueio(emailNormalizado, req);
            if (bloqueio.bloqueado) {
                await auditar('LOGIN_BLOQUEADO', 'bloqueado', req, null, { motivo: bloqueio.motivo });
                log.alerta('LOGIN_BLOQUEADO', { email: emailNormalizado, motivo: bloqueio.motivo, segundosRestantes: bloqueio.segundosRestantes }, req);
                const minutos = Math.ceil(bloqueio.segundosRestantes / 60);
                return res.status(423).json({
                    erro: `Muitas tentativas de login. Tente novamente em ${minutos} minuto(s).`
                });
            }

            // 2) Busca pelo e-mail (índice único) — `senha` exige select explícito.
            const usuario = await Usuario.findOne({ email: emailNormalizado }).select('+senha +tentativasFalhas +bloqueadoAte +versaoSenha');

            // 3) E-mail inexistente: comparamos contra um hash fictício para que o
            //    tempo de resposta seja equivalente (evita enumeração de contas).
            if (!usuario) {
                await bcrypt.compare(senha, forcaBruta.HASH_DUMMY);
                await forcaBruta.registrarFalha(emailNormalizado, req, { contaExiste: false });
                await auditar('LOGIN_NEGADO', 'falha', req, null, { contaExiste: false });
                return res.status(401).json({ erro: EMAIL_NAO_ENCONTRADO });
            }

            // 4) Conta bloqueada no próprio documento (defesa redundante).
            if (usuario.bloqueadoAte && usuario.bloqueadoAte.getTime() > Date.now()) {
                const minutos = Math.ceil((usuario.bloqueadoAte.getTime() - Date.now()) / 60000);
                await auditar('LOGIN_BLOQUEADO', 'bloqueado', req, usuario._id, { origem: 'documento' });
                return res.status(423).json({ erro: `Conta bloqueada. Tente novamente em ${minutos} minuto(s).` });
            }

            const senhaValida = await usuario.compararSenha(senha);

            if (!senhaValida) {
                const resultado = await forcaBruta.registrarFalha(emailNormalizado, req, { usuarioId: String(usuario._id), contaExiste: true });
                await usuario.registrarFalhaDeLogin(config.LIMITE_TENTATIVAS_LOGIN, config.JANELA_BLOQUEIO_LOGIN_MS);
                await auditar('LOGIN_NEGADO', 'falha', req, usuario._id, { tentativasRestantes: resultado.restantes });

                if (resultado.contaBloqueada || resultado.ipBloqueado) {
                    return res.status(423).json({ erro: 'Muitas tentativas de login. Tente novamente em 15 minutos.' });
                }
                return res.status(401).json({ erro: EMAIL_NAO_ENCONTRADO });
            }

            // 5) Sucesso: zera contadores e emite o par access + refresh.
            await usuario.resetarFalhasDeLogin();
            await forcaBruta.registrarSucesso(emailNormalizado, req, { usuarioId: String(usuario._id), tipo: usuario.tipo });

            const sessao = await tokens.emitirSessao(usuario, req);
            await auditar('LOGIN_CONCLUIDO', 'sucesso', req, usuario._id, { tipo: usuario.tipo });

            return res.json({
                mensagem: 'Login efetuado com sucesso!',
                token: sessao.token,
                refreshToken: sessao.refreshToken,
                expiraEm: sessao.expiraEm,
                refreshExpiraEm: sessao.refreshExpiraEm,
                usuario: {
                    id: usuario._id,
                    nome: nomeExibicao(usuario),
                    email: usuario.email,
                    tipo: usuario.tipo,
                    celular: usuario.celular
                }
            });
        } catch (error) {
            log.critico('ERRO_LOGIN', { erro: error.message }, req);
            return res.status(500).json({ erro: 'Não foi possível concluir o login.' });
        }
    }
);

// ==========================================
// 🔄 RENOVAÇÃO DE SESSÃO (rotação de refresh token)
// ==========================================
router.post('/refresh',
    mw.limitadorRefresh,
    mw.validarCorpo(validadores.refresh),
    mw.exporCorpoValidado,
    async (req, res) => {
        const { refreshToken } = req.validado.body;

        try {
            const resultado = await tokens.renovarSessao(refreshToken, req);

            if (resultado.erro) {
                await auditar('REFRESH_TOKEN_REJEITADO', 'falha', req);
                return res.status(resultado.status).json({ erro: resultado.erro });
            }

            return res.json({
                mensagem: 'Sessão renovada.',
                token: resultado.token,
                refreshToken: resultado.refreshToken,
                expiraEm: resultado.expiraEm,
                refreshExpiraEm: resultado.refreshExpiraEm
            });
        } catch (error) {
            log.critico('ERRO_REFRESH', { erro: error.message }, req);
            return res.status(500).json({ erro: 'Não foi possível renovar a sessão.' });
        }
    }
);

// ==========================================
// 🚪 LOGOUT (revoga família + blacklist do access token)
// ==========================================
router.post('/logout',
    mw.validarCorpo(Joi.object({ refreshToken: Joi.string().allow('').max(4096).default('') })),
    mw.exporCorpoValidado,
    async (req, res) => {
        try {
            const { refreshToken } = req.validado.body;

            // 1) Revoga a família inteira de refresh tokens (rotacionados e futuros).
            if (refreshToken) {
                try {
                    const payloadRefresh = jwt.verify(refreshToken, config.REFRESH_TOKEN_SECRET, {
                        algorithms: [tokens.ALGORITMO],
                        issuer: tokens.ISSUER
                    });
                    await tokens.revogarFamilia(payloadRefresh.familia, 'logout', req);
                } catch (err) {
                    log.aviso('LOGOUT_REFRESH_INVALIDO', { motivo: err.name }, req);
                }
            }

            // 2) Coloca o access token atual na blacklist até ele expirar.
            const header = req.headers.authorization;
            const token = header && header.startsWith('Bearer ') ? header.slice(7).trim() : null;

            if (token) {
                try {
                    const payload = jwt.verify(token, config.JWT_SECRET, {
                        algorithms: [tokens.ALGORITMO],
                        issuer: tokens.ISSUER
                    });
                    await tokens.blacklistAccessToken(payload, 'logout', req);
                    await auditar('LOGOUT', 'sucesso', req, payload.sub);
                } catch (err) {
                    if (err.name !== 'TokenExpiredError' && err.name !== 'JsonWebTokenError') throw err;
                }
            }

            log.info('LOGOUT', {}, req);
            // 204 mesmo sem token: logout é sempre idempotente.
            return res.status(204).end();
        } catch (error) {
            log.aviso('ERRO_LOGOUT', { erro: error.message }, req);
            return res.status(500).json({ erro: 'Não foi possível encerrar a sessão.' });
        }
    }
);

// ==========================================
// ✏️ ATUALIZAÇÃO DE PERFIL
// ==========================================
router.put('/atualizar',
    mw.autenticarToken,
    mw.limitadorSenha,
    mw.validarCorpo(validadores.atualizarPerfil),
    mw.exporCorpoValidado,
    async (req, res) => {
        const { email, celular, senhaAtual, novaSenha } = req.validado.body;
        const idUsuario = req.usuarioLogado.id;

        try {
            const usuario = await Usuario.findById(idUsuario).select('+senha +versaoSenha');

            if (!usuario) return res.status(404).json({ erro: 'Usuário não encontrado.' });

            if (email && email.toLowerCase() !== usuario.email) {
                const emailDono = await Usuario.findOne({ email: email.toLowerCase(), _id: { $ne: idUsuario } }).select('_id').lean();
                if (emailDono) {
                    log.aviso('ATUALIZACAO_EMAIL_EM_USO', { usuarioId: idUsuario }, req);
                    return res.status(409).json({ erro: 'Este e-mail já está em uso por outra conta.' });
                }
                usuario.email = email.toLowerCase();
            }

            if (celular) usuario.celular = celular;

            let senhaAlterada = false;
            if (novaSenha && novaSenha.trim() !== '') {
                if (!senhaAtual) return res.status(400).json({ erro: 'Você precisa informar sua senha atual para criar uma nova.' });

                const senhaCorreta = await usuario.compararSenha(senhaAtual);
                if (!senhaCorreta) {
                    await forcaBruta.registrarFalha(usuario.email, req, { usuarioId: idUsuario, contexto: 'troca_de_senha' });
                    log.aviso('SENHA_ATUAL_INCORRETA', { usuarioId: idUsuario }, req);
                    await auditar('SENHA_ATUAL_INCORRETA', 'falha', req, idUsuario);
                    return res.status(401).json({ erro: 'Senha atual incorreta.' });
                }

                usuario.senha = novaSenha;
                senhaAlterada = true;
            }

            await usuario.save();

            // Trocar a senha encerra todas as sessões abertas; o cliente recebe
            // um par access + refresh novo para não ser desconectado.
            if (senhaAlterada) {
                const { Sessao } = require('../modelos/sessao');
                await Sessao.updateMany(
                    { usuarioId: idUsuario, revogado: false },
                    { revogado: true, revogadoEm: new Date(), motivoRevogacao: 'senha_alterada' }
                );
                await auditar('SENHA_ALTERADA', 'sucesso', req, idUsuario);
                log.alerta('SENHA_ALTERADA_SESSOES_REVOGADAS', { usuarioId: idUsuario }, req);
            }

            const sessao = await tokens.emitirSessao(usuario, req);

            return res.json({
                mensagem: 'Seu perfil foi atualizado com sucesso! 🔄',
                token: sessao.token,
                refreshToken: sessao.refreshToken,
                expiraEm: sessao.expiraEm,
                refreshExpiraEm: sessao.refreshExpiraEm,
                usuario: {
                    nome: nomeExibicao(usuario),
                    email: usuario.email,
                    tipo: usuario.tipo,
                    celular: usuario.celular
                }
            });
        } catch (error) {
            log.critico('ERRO_ATUALIZAR_PERFIL', { usuarioId: idUsuario, erro: error.message }, req);
            return res.status(500).json({ erro: 'Não foi possível atualizar o perfil.' });
        }
    }
);

// ==========================================
// 📋 SESSÕES ATIVAS DO USUÁRIO
// ==========================================
router.get('/sessoes', mw.autenticarToken, async (req, res) => {
    const { Sessao } = require('../modelos/sessao');
    try {
        const sessoes = await Sessao.find({ usuarioId: req.usuarioLogado.id, revogado: false })
            .select('familia ip agente criadoEm expiraEm')
            .sort({ criadoEm: -1 })
            .limit(20)
            .lean();

        return res.json({ sessoes });
    } catch (error) {
        log.aviso('ERRO_LISTAR_SESSOES', { erro: error.message }, req);
        return res.status(500).json({ erro: 'Não foi possível listar as sessões.' });
    }
});

module.exports = router;
