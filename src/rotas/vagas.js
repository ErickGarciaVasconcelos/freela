'use strict';

/**
 * 💼 ROTAS DE VAGAS
 *  - listagem PAGINADA com filtros ordenados por índice (29/30)
 *  - validação Joi completa de todas as entradas (22)
 *  - dados de contato de candidatos cifrados em repouso (23)
 *  - autorização por dono da vaga em todas as operações sensíveis
 *  - rate limiting dedicado em candidatura e seleção de equipe (21)
 */

const express = require('express');

const mw = require('../middleware');
const validadores = require('../validadores');
const log = require('../log-seguranca');
const cryptoDados = require('../criptografia');
const Usuario = require('../modelos/usuario');
const Vaga = require('../modelos/vaga');
const Notificacao = require('../modelos/notificacao');

const router = express.Router();

const LIMITE_CONFIRMACAO_MS = 5 * 60 * 1000;

const FORMATOS = {
    recentes: { criadoAt: -1 },
    antigos: { criadoAt: 1 },
    valor_desc: { valor: -1, criadoAt: -1 },
    valor_asc: { valor: 1, criadoAt: -1 },
    data: { dataTrabalho: 1, criadoAt: -1 }
};

/** Serialização pública de uma vaga — nunca inclui PII de terceiros. */
function serializarVaga(vaga, meuStatus = null) {
    return {
        _id: vaga._id,
        titulo: vaga.titulo,
        descricao: vaga.descricao,
        valor: vaga.valor,
        status_vaga: vaga.status_vaga,
        vagasTotais: vaga.vagasTotais,
        genero: vaga.genero,
        experienciaRequerida: vaga.experienciaRequerida,
        tempoExperiencia: vaga.tempoExperiencia,
        dataTrabalho: vaga.dataTrabalho,
        endereco: vaga.endereco,
        horario: vaga.horario,
        horarioInicio: vaga.horarioInicio,
        horarioFim: vaga.horarioFim,
        datasTrabalho: vaga.datasTrabalho,
        criadoPor: vaga.criadoPor,
        criadoEm: vaga.criadoEm,
        totalCandidatos: vaga.totalCandidatos,
        totalContratados: vaga.totalContratados,
        meuStatus
    };
}

/** Deriva, no servidor, o papel do usuário solicitante dentro da vaga. */
function derivarMeuStatus(vaga, usuarioId) {
    if (!usuarioId) return null;

    const contratado = vaga.contratados_atuais?.find(c => c.idUsuario === usuarioId) || null;
    const reserva = vaga.fila_de_espera?.find(f => f.idUsuario === usuarioId) || null;
    const candidato = vaga.candidatos?.some(c => c.idUsuario === usuarioId) || false;
    const souDono = String(vaga.criadoPor) === String(usuarioId);

    return {
        souDono,
        candidato,
        contratado: Boolean(contratado),
        confirmado: Boolean(contratado?.confirmado),
        reserva: Boolean(reserva),
        prazoConfirmacao: contratado?.limite_confirmacao || null,
        expirou: Boolean(contratado && !contratado.confirmado && contratado.limite_confirmacao && new Date(contratado.limite_confirmacao) < new Date())
    };
}

// ==========================================
// 📋 LISTAGEM PAGINADA (item 29)
// ==========================================
router.get('/',
    mw.autenticarToken,
    mw.validarQuery(validadores.listaVagas),
    async (req, res) => {
        const { pagina, limite, status, genero, busca, criadoPor, ordem, minha } = req.validado.query;
        const usuarioId = req.usuarioLogado.id;

        try {
            const filtro = {};

            if (minha) filtro.criadoPor = usuarioId;
            else if (criadoPor) filtro.criadoPor = criadoPor;

            if (status) filtro.status_vaga = status;
            if (genero && genero !== 'Todos') filtro.genero = genero;

            let ordenacao = FORMATOS[ordem] || FORMATOS.recentes;

            if (busca) {
                filtro.$text = { $search: busca };
                ordenacao = { score: { $meta: 'textScore' }, ...FORMATOS.recentes };
            }

            const [total, documentos] = await Promise.all([
                Vaga.countDocuments(filtro),
                Vaga.find(filtro)
                    // Projeção enxuta: apenas o necessário para o card + o papel do usuário.
                    .select('titulo descricao valor status_vaga vagasTotais genero experienciaRequerida tempoExperiencia dataTrabalho endereco horario horarioInicio horarioFim datasTrabalho criadoPor criadoEm totalCandidatos totalContratados candidatos.idUsuario contratados_atuais.idUsuario contratados_atuais.confirmado contratados_atuais.limite_confirmacao fila_de_espera.idUsuario')
                    .sort(ordenacao)
                    .skip((pagina - 1) * limite)
                    .limit(limite)
                    .lean()
            ]);

            const dados = documentos.map(v => serializarVaga(v, derivarMeuStatus(v, usuarioId)));
            const totalPaginas = Math.max(1, Math.ceil(total / limite));

            return res.json({
                dados,
                paginacao: {
                    pagina,
                    limite,
                    total,
                    totalPaginas,
                    temProxima: pagina < totalPaginas,
                    temAnterior: pagina > 1
                }
            });
        } catch (error) {
            log.aviso('ERRO_LISTAR_VAGAS', { erro: error.message }, req);
            return res.status(500).json({ erro: 'Não foi possível carregar as vagas.' });
        }
    }
);

// ==========================================
// ➕ CRIAR VAGA
// ==========================================
router.post('/',
    mw.autenticarToken,
    mw.apenasContratante,
    mw.validarCorpo(validadores.criarVaga),
    mw.exporCorpoValidado,
    async (req, res) => {
        const d = req.validado.body;
        const criadoPor = req.usuarioLogado.id;

        try {
            const listaDatas = (d.datasTrabalho || []).map(item => ({
                data: new Date(item.data),
                horarioInicio: item.horarioInicio || '',
                horarioFim: item.horarioFim || ''
            }));

            const inicio = d.horarioInicio || listaDatas[0]?.horarioInicio || '';
            const fim = d.horarioFim || listaDatas[0]?.horarioFim || '';

            const novaVaga = new Vaga({
                titulo: d.titulo,
                descricao: d.descricao || '',
                valor: d.valor,
                vagasTotais: d.vagasTotais,
                genero: d.genero,
                experienciaRequerida: d.experienciaRequerida,
                tempoExperiencia: d.experienciaRequerida ? d.tempoExperiencia : '',
                dataTrabalho: d.dataTrabalho || listaDatas[0]?.data || null,
                endereco: d.endereco,
                horario: d.horario || (inicio && fim ? `${inicio} - ${fim}` : ''),
                horarioInicio: inicio,
                horarioFim: fim,
                datasTrabalho: listaDatas,
                criadoPor,
                status_vaga: 'aberta'
            });

            await novaVaga.save();

            log.info('VAGA_CRIADA', { vagaId: String(novaVaga._id), criadoPor }, req);
            return res.status(201).json({ mensagem: 'Vaga publicada com sucesso!', vaga: serializarVaga(novaVaga) });
        } catch (error) {
            log.aviso('ERRO_CRIAR_VAGA', { criadoPor, erro: error.message }, req);
            return res.status(500).json({ erro: 'Não foi possível publicar a vaga.' });
        }
    }
);

// ==========================================
// 🔍 DETALHES DA VAGA
// ==========================================
router.get('/:id',
    mw.autenticarToken,
    mw.validarParams(),
    async (req, res) => {
        const vagaId = req.validado.params.id;
        try {
            const vaga = await Vaga.findById(vagaId).lean();
            if (!vaga) return res.status(404).json({ erro: 'Vaga não encontrada.' });

            return res.json({ vaga: serializarVaga(vaga, derivarMeuStatus(vaga, req.usuarioLogado.id)) });
        } catch (error) {
            log.aviso('ERRO_OBTER_VAGA', { vagaId, erro: error.message }, req);
            return res.status(500).json({ erro: 'Não foi possível carregar a vaga.' });
        }
    }
);

// ==========================================
// 👥 CANDIDATOS DA VAGA (somente o dono)
// ==========================================
router.get('/:id/candidatos',
    mw.autenticarToken,
    mw.validarParams(),
    async (req, res) => {
        const vagaId = req.validado.params.id;
        const usuarioId = req.usuarioLogado.id;

        try {
            const vaga = await Vaga.findById(vagaId).lean();
            if (!vaga) return res.status(404).json({ erro: 'Vaga não encontrada.' });

            if (String(vaga.criadoPor) !== String(usuarioId)) {
                log.acessoNegado('nao_e_dono_da_vaga', { rota: 'candidatos', vagaId }, req);
                return res.status(403).json({ erro: 'Apenas o criador da vaga pode ver os candidatos.' });
            }

            // Só o dono vê os contatos — e ainda assim decifrados em memoria.
            const candidatos = (vaga.candidatos || []).map(c => ({
                idUsuario: c.idUsuario,
                nome: c.nome,
                nomeCompleto: c.nomeCompleto,
                email: cryptoDados.decifrar(c.emailCriptografado),
                telefone: cryptoDados.decifrar(c.telefoneCriptografado),
                idade: c.idade,
                genero: c.genero,
                experiencias: c.experiencias,
                fotoPerfil: c.fotoPerfil,
                experienciasDetalhadas: c.experienciasDetalhadas || []
            }));

            return res.json({ vagaId: vaga._id, titulo: vaga.titulo, candidatos });
        } catch (error) {
            log.aviso('ERRO_LISTAR_CANDIDATOS', { vagaId, erro: error.message }, req);
            return res.status(500).json({ erro: 'Não foi possível carregar os candidatos.' });
        }
    }
);

// ==========================================
// 🙋 CANDIDATAR-SE
// ==========================================
router.patch('/:id/candidatar',
    mw.autenticarToken,
    mw.apenasContratado,
    mw.limitadorCandidatura,
    mw.validarParams(),
    async (req, res) => {
        const vagaId = req.validado.params.id;
        const idUsuarioLogado = req.usuarioLogado.id;

        try {
            const [usuario, vaga] = await Promise.all([
                Usuario.findById(idUsuarioLogado).select('+cpfCriptografado'),
                Vaga.findById(vagaId)
            ]);

            if (!vaga) return res.status(404).json({ erro: 'Vaga não encontrada.' });
            if (!usuario) return res.status(404).json({ erro: 'Usuário não encontrado.' });

            if (vaga.criadoPor.toString() === idUsuarioLogado) {
                return res.status(403).json({ erro: 'Você não pode se candidatar à própria vaga.' });
            }

            if (vaga.status_vaga !== 'aberta') {
                log.aviso('CANDIDATURA_VAGA_FECHADA', { vagaId, status: vaga.status_vaga }, req);
                return res.status(400).json({ erro: 'Esta vaga não está mais aceitando candidaturas.' });
            }

            if (vaga.genero !== 'Todos' && usuario.genero !== vaga.genero) {
                log.aviso('CANDIDATURA_GENERO_INCOMPATIVEL', { vagaId }, req);
                return res.status(403).json({ erro: 'Esta vaga é restrita a outro perfil.' });
            }

            const jaCandidato = vaga.candidatos.some(c => c.idUsuario === idUsuarioLogado);
            if (jaCandidato) {
                return res.status(409).json({ erro: 'Seu currículo já foi enviado!' });
            }

            vaga.candidatos.push({
                idUsuario: idUsuarioLogado,
                nome: usuario.nomeSocial || usuario.nome,
                nomeCompleto: usuario.nome,
                emailCriptografado: cryptoDados.cifrar(usuario.email),
                telefoneCriptografado: cryptoDados.cifrar(usuario.celular),
                idade: usuario.idade,
                genero: usuario.genero,
                experiencias: usuario.experiencias,
                fotoPerfil: usuario.fotoPerfil,
                experienciasDetalhadas: usuario.experienciasDetalhadas || []
            });

            await vaga.save();

            await Notificacao.create({
                usuarioId: vaga.criadoPor,
                tipo: 'candidato_novo',
                titulo: 'Novo candidato',
                mensagem: `${usuario.nomeSocial || usuario.nome} se candidatou à vaga "${vaga.titulo}".`,
                vagaId: vaga._id
            });

            log.info('CANDIDATURA_REGISTRADA', { vagaId, usuarioId: idUsuarioLogado }, req);
            return res.json({ mensagem: 'Currículo enviado! Aguarde o contratante aprovar seu perfil.' });
        } catch (error) {
            log.aviso('ERRO_CANDIDATAR', { vagaId, erro: error.message }, req);
            return res.status(500).json({ erro: 'Não foi possível enviar seu currículo.' });
        }
    }
);

// ==========================================
// ✅ CONFIRMAR EQUIPE (helper comum)
// ==========================================
async function escalarEquipe(vaga, { titulares, reservas }) {
    const agora = new Date();
    const limite = new Date(agora.getTime() + LIMITE_CONFIRMACAO_MS);

    vaga.contratados_atuais = [];
    vaga.fila_de_espera = [];

    const titularesValidos = [];
    for (const id of titulares) {
        const cand = vaga.candidatos.find(c => c.idUsuario === id);
        if (!cand) continue;
        vaga.contratados_atuais.push({
            idUsuario: cand.idUsuario,
            nome: cand.nome,
            telefoneCriptografado: cand.telefoneCriptografado,
            confirmado: false,
            limite_confirmacao: limite
        });
        titularesValidos.push(cand);
    }

    if (titularesValidos.length === 0) {
        return { erro: 'Nenhum dos titulares selecionados consta na lista de candidatos.', status: 400 };
    }

    const reservasValidos = [];
    for (const id of reservas) {
        const cand = vaga.candidatos.find(c => c.idUsuario === id);
        if (!cand) continue;
        vaga.fila_de_espera.push({
            idUsuario: cand.idUsuario,
            nome: cand.nome,
            telefoneCriptografado: cand.telefoneCriptografado
        });
        reservasValidos.push(cand);
    }

    await vaga.save();

    const avisos = [
        ...titularesValidos.map(c => ({
            usuarioId: c.idUsuario,
            tipo: 'equipe_selecionada',
            titulo: 'Você foi escalado!',
            mensagem: `Você foi escalado para a vaga "${vaga.titulo}". Confirme sua presença em até 5 minutos!`
        })),
        ...reservasValidos.map(c => ({
            usuarioId: c.idUsuario,
            tipo: 'equipe_selecionada',
            titulo: 'Você está na lista de reserva',
            mensagem: `Você entrou na lista de espera da vaga "${vaga.titulo}".`
        }))
    ];

    if (avisos.length) await Notificacao.insertMany(avisos);

    return { titulares: titularesValidos.length, reservas: reservasValidos.length };
}

// ==========================================
// 👔 SELECIONAR EQUIPE
// ==========================================
router.patch('/:id/selecionar-equipe',
    mw.autenticarToken,
    mw.apenasContratante,
    mw.validarParams(),
    mw.validarCorpo(validadores.selecionarEquipe),
    mw.exporCorpoValidado,
    async (req, res, next) => confirmarEquipeHandler(req, res, next, 'preenchida')
);

router.post('/:id/confirmar-equipe',
    mw.autenticarToken,
    mw.apenasContratante,
    mw.validarParams(),
    mw.validarCorpo(validadores.selecionarEquipe),
    mw.exporCorpoValidado,
    async (req, res, next) => confirmarEquipeHandler(req, res, next, 'fechada')
);

async function confirmarEquipeHandler(req, res, next, statusFinal) {
    const vagaId = req.validado.params.id;
    const usuarioLogadoId = req.usuarioLogado.id;
    const { titulares, reservas } = req.validado.body;

    try {
        const vaga = await Vaga.findById(vagaId);
        if (!vaga) return res.status(404).json({ erro: 'Vaga não encontrada.' });

        if (String(vaga.criadoPor) !== String(usuarioLogadoId)) {
            log.acessoNegado('nao_e_dono_da_vaga', { rota: 'confirmar-equipe', vagaId }, req);
            return res.status(403).json({ erro: 'Apenas o criador da vaga pode escalar a equipe.' });
        }

        if (vaga.status_vaga === 'cancelada') {
            return res.status(400).json({ erro: 'Vaga cancelada não permite seleção de equipe.' });
        }

        const resultado = await escalarEquipe(vaga, { titulares, reservas });
        if (resultado.erro) return res.status(resultado.status).json({ erro: resultado.erro });

        vaga.status_vaga = statusFinal;
        await vaga.save();

        log.info('EQUIPE_ESCALADA', {
            vagaId,
            criadoPor: usuarioLogadoId,
            titulares: resultado.titulares,
            reservas: resultado.reservas,
            status: statusFinal
        }, req);

        return res.status(200).json({
            mensagem: '✅ Equipe confirmada com sucesso! Os profissionais foram notificados.',
            vaga: {
                id: vaga._id,
                titulo: vaga.titulo,
                status: vaga.status_vaga,
                contratadosCount: vaga.contratados_atuais.length,
                filaCount: vaga.fila_de_espera.length
            }
        });
    } catch (error) {
        log.aviso('ERRO_CONFIRMAR_EQUIPE', { vagaId, erro: error.message }, req);
        next(error);
    }
}

// ==========================================
// ❌ DESISTIR DA VAGA
// ==========================================
router.patch('/:id/cancelar',
    mw.autenticarToken,
    mw.validarParams(),
    async (req, res) => {
        const vagaId = req.validado.params.id;
        const idUsuarioLogado = req.usuarioLogado.id;

        try {
            const vaga = await Vaga.findById(vagaId);
            if (!vaga) return res.status(404).json({ erro: 'Vaga não encontrada.' });

            const naVaga = vaga.contratados_atuais.some(c => c.idUsuario === idUsuarioLogado);
            if (!naVaga) {
                log.acessoNegado('nao_escalado', { rota: 'cancelar-inscricao', vagaId }, req);
                return res.status(403).json({ erro: 'Você não está nesta vaga.' });
            }

            vaga.contratados_atuais = vaga.contratados_atuais.filter(c => c.idUsuario !== idUsuarioLogado);

            let promovido = null;
            if (vaga.fila_de_espera.length > 0) {
                promovido = vaga.fila_de_espera.shift();
                vaga.contratados_atuais.push({
                    idUsuario: promovido.idUsuario,
                    nome: promovido.nome,
                    telefoneCriptografado: promovido.telefoneCriptografado,
                    confirmado: false,
                    limite_confirmacao: new Date(Date.now() + LIMITE_CONFIRMACAO_MS)
                });
            } else if (vaga.status_vaga !== 'cancelada') {
                vaga.status_vaga = 'aberta';
            }

            await vaga.save();

            if (promovido) {
                await Notificacao.create({
                    usuarioId: promovido.idUsuario,
                    tipo: 'equipe_selecionada',
                    titulo: 'Você subiu para titular!',
                    mensagem: `Uma vaga abriu em "${vaga.titulo}". Confirme sua presença em até 5 minutos!`,
                    vagaId: vaga._id
                });
            }

            log.info('INSCRICAO_CANCELADA', { vagaId, usuarioId: idUsuarioLogado, promovido: Boolean(promovido) }, req);

            return res.json({
                mensagem: promovido
                    ? 'Você cancelou sua inscrição. A vaga foi repassada ao próximo da fila.'
                    : 'Você cancelou sua inscrição.'
            });
        } catch (error) {
            log.aviso('ERRO_CANCELAR_INSCRICAO', { vagaId, erro: error.message }, req);
            return res.status(500).json({ erro: 'Não foi possível cancelar sua inscrição.' });
        }
    }
);

// ==========================================
// ✅ CONFIRMAR PRESENÇA
// ==========================================
router.patch('/:id/confirmar',
    mw.autenticarToken,
    mw.validarParams(),
    async (req, res) => {
        const vagaId = req.validado.params.id;
        const idUsuarioLogado = req.usuarioLogado.id;

        try {
            const vaga = await Vaga.findById(vagaId);
            if (!vaga) return res.status(404).json({ erro: 'Vaga não encontrada.' });

            if (String(vaga.criadoPor) === idUsuarioLogado) {
                return res.status(403).json({ erro: 'O criador da vaga não confirma presença.' });
            }

            const inscricao = vaga.contratados_atuais.find(c => c.idUsuario === idUsuarioLogado);
            if (!inscricao) {
                log.acessoNegado('nao_escalado', { rota: 'confirmar-presenca', vagaId }, req);
                return res.status(403).json({ erro: 'Acesso negado: você não está escalado nesta vaga.' });
            }
            if (inscricao.confirmado) return res.status(409).json({ erro: 'Presença já confirmada anteriormente.' });
            if (inscricao.limite_confirmacao && new Date() > new Date(inscricao.limite_confirmacao)) {
                return res.status(400).json({ erro: 'Tempo esgotado!' });
            }

            inscricao.confirmado = true;
            inscricao.confirmadoEm = new Date();
            await vaga.save();

            log.info('PRESENCA_CONFIRMADA', { vagaId, usuarioId: idUsuarioLogado }, req);
            return res.json({ mensagem: 'Presença confirmada e travada! 🎯' });
        } catch (error) {
            log.aviso('ERRO_CONFIRMAR_PRESENCA', { vagaId, erro: error.message }, req);
            return res.status(500).json({ erro: 'Não foi possível confirmar sua presença.' });
        }
    }
);

// ==========================================
// 🛑 CANCELAR A VAGA (somente o dono)
// ==========================================
router.patch('/:id/cancelar-vaga',
    mw.autenticarToken,
    mw.apenasContratante,
    mw.validarParams(),
    mw.validarCorpo(validadores.cancelarVaga),
    mw.exporCorpoValidado,
    async (req, res) => {
        const vagaId = req.validado.params.id;
        const usuarioLogadoId = req.usuarioLogado.id;
        const { motivoCancelamento } = req.validado.body;

        try {
            const vaga = await Vaga.findById(vagaId);
            if (!vaga) return res.status(404).json({ erro: 'Vaga não encontrada.' });

            if (String(vaga.criadoPor) !== String(usuarioLogadoId)) {
                log.acessoNegado('nao_e_dono_da_vaga', { rota: 'cancelar-vaga', vagaId }, req);
                return res.status(403).json({ erro: 'Apenas o criador da vaga pode cancelá-la.' });
            }

            if (!['aberta', 'preenchida', 'fechada'].includes(vaga.status_vaga)) {
                return res.status(400).json({ erro: `Vaga com status "${vaga.status_vaga}" não pode ser cancelada.` });
            }

            const afetados = [
                ...vaga.contratados_atuais.map(c => ({ idUsuario: c.idUsuario, nome: c.nome })),
                ...vaga.fila_de_espera.map(f => ({ idUsuario: f.idUsuario, nome: f.nome }))
            ];

            vaga.status_vaga = 'cancelada';
            vaga.motivoCancelamento = motivoCancelamento || '';
            vaga.dataCancelamento = new Date();
            vaga.contratados_atuais = [];
            vaga.fila_de_espera = [];
            await vaga.save();

            if (afetados.length) {
                await Notificacao.insertMany(afetados.map(a => ({
                    usuarioId: a.idUsuario,
                    tipo: 'vaga_cancelada',
                    titulo: 'Vaga cancelada',
                    mensagem: `A vaga "${vaga.titulo}" foi cancelada. Motivo: ${motivoCancelamento || 'não informado'}.`,
                    vagaId: vaga._id
                })));
            }

            log.info('VAGA_CANCELADA', { vagaId, criadoPor: usuarioLogadoId, afetados: afetados.length }, req);

            return res.json({
                mensagem: 'Vaga cancelada com sucesso! Notificações enviadas aos profissionais.',
                profissionaisNotificados: afetados.length
            });
        } catch (error) {
            log.aviso('ERRO_CANCELAR_VAGA', { vagaId, erro: error.message }, req);
            return res.status(500).json({ erro: 'Não foi possível cancelar a vaga.' });
        }
    }
);

module.exports = router;
