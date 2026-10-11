'use strict';

/**
 * 📢 ROTAS DE NOTIFICAÇÕES
 * Leitura sempre restrita ao titular; listagem paginada para não despejar
 * hundreds de documentos no navegador.
 */

const express = require('express');

const mw = require('../middleware');
const validadores = require('../validadores');
const log = require('../log-seguranca');
const Notificacao = require('../modelos/notificacao');

const router = express.Router();

router.get('/',
    mw.autenticarToken,
    mw.validarQuery(validadores.listaNotificacoes),
    async (req, res) => {
        const { pagina, limite, apenasNaoLidas } = req.validado.query;
        const usuarioId = req.usuarioLogado.id;

        try {
            const filtro = { usuarioId };
            if (apenasNaoLidas) filtro.lida = false;

            const [total, documentos] = await Promise.all([
                Notificacao.countDocuments(filtro),
                Notificacao.find(filtro)
                    .sort({ dataCriacao: -1 })
                    .skip((pagina - 1) * limite)
                    .limit(limite)
                    .lean()
            ]);

            return res.json({
                dados: documentos,
                paginacao: {
                    pagina,
                    limite,
                    total,
                    totalPaginas: Math.max(1, Math.ceil(total / limite)),
                    temProxima: pagina < Math.ceil(total / limite),
                    temAnterior: pagina > 1
                }
            });
        } catch (error) {
            log.aviso('ERRO_LISTAR_NOTIFICACOES', { usuarioId, erro: error.message }, req);
            return res.status(500).json({ erro: 'Não foi possível carregar as notificações.' });
        }
    }
);

router.patch('/marcar-todas-lidas', mw.autenticarToken, async (req, res) => {
    const usuarioId = req.usuarioLogado.id;
    try {
        const resultado = await Notificacao.updateMany({ usuarioId, lida: false }, { $set: { lida: true } });
        return res.json({
            mensagem: 'Todas as notificações foram marcadas como lidas.',
            marcadas: resultado.modifiedCount
        });
    } catch (error) {
        log.aviso('ERRO_MARCAR_TODAS_LIDAS', { usuarioId, erro: error.message }, req);
        return res.status(500).json({ erro: 'Não foi possível marcar as notificações.' });
    }
});

router.patch('/:id/ler', mw.autenticarToken, mw.validarParams(), async (req, res) => {
    const usuarioId = req.usuarioLogado.id;
    const notificacaoId = req.validado.params.id;

    try {
        // Filtro pelo dono no proprio update: uma notificação de outra conta
        // simplesmente não é encontrada (não vazamos existência).
        const notificacao = await Notificacao.findOneAndUpdate(
            { _id: notificacaoId, usuarioId },
            { $set: { lida: true } },
            { new: true }
        ).lean();

        if (!notificacao) {
            log.acessoNegado('notificacao_inexistente_ou_alheia', { notificacaoId }, req);
            return res.status(404).json({ erro: 'Notificação não encontrada.' });
        }

        return res.json({ mensagem: 'Notificação marcada como lida.', notificacao });
    } catch (error) {
        log.aviso('ERRO_MARCAR_LIDA', { usuarioId, notificacaoId, erro: error.message }, req);
        return res.status(500).json({ erro: 'Não foi possível marcar a notificação.' });
    }
});

module.exports = router;
