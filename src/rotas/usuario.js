'use strict';

/**
 * 👤 ROTAS DE USUÁRIO (favoritos, avaliações, perfil público)
 * Autorização objeto-a-objeto: cada recurso é conferido contra o dono do dado.
 */

const express = require('express');

const mw = require('../middleware');
const validadores = require('../validadores');
const log = require('../log-seguranca');
const Usuario = require('../modelos/usuario');
const Vaga = require('../modelos/vaga');

const router = express.Router();

// ==========================================
// 💙 FAVORITAR / DESFAVORITAR
// ==========================================
router.patch('/favoritar/:id',
    mw.autenticarToken,
    mw.validarParams(),
    async (req, res) => {
        const usuarioLogadoId = req.usuarioLogado.id;
        const alvoId = req.validado.params.id;

        try {
            if (usuarioLogadoId === alvoId) {
                return res.status(400).json({ erro: 'Você não pode favoritizar a si mesmo.' });
            }

            const usuario = await Usuario.findById(usuarioLogadoId);
            if (!usuario) return res.status(404).json({ erro: 'Usuário não encontrado.' });

            if (usuario.tipo !== 'contratante') {
                log.acessoNegado('perfil_incorreto', { rota: 'favoritar', tipo: usuario.tipo }, req);
                return res.status(403).json({ erro: 'Apenas contratantes podem favoritar profissionais.' });
            }

            const alvo = await Usuario.findOne({ _id: alvoId, tipo: 'contratado' }).select('_id').lean();
            if (!alvo) return res.status(404).json({ erro: 'Profissional não encontrado.' });

            const indice = usuario.favoritos.findIndex(id => id.toString() === alvoId);
            const favoritado = indice === -1;

            if (favoritado) usuario.favoritos.push(alvoId);
            else usuario.favoritos.splice(indice, 1);

            await usuario.save();

            log.info('FAVORITO_ALTERADO', { usuarioId: usuarioLogadoId, alvoId, favoritado }, req);
            return res.json({
                mensagem: favoritado ? 'Adicionado aos favoritos!' : 'Removido dos favoritos.',
                favoritado
            });
        } catch (error) {
            log.aviso('ERRO_FAVORITAR', { usuarioId: usuarioLogadoId, erro: error.message }, req);
            return res.status(500).json({ erro: 'Não foi possível atualizar os favoritos.' });
        }
    }
);

// ==========================================
// ⭐ AVALIAR
// ==========================================
router.post('/:id/avaliar',
    mw.autenticarToken,
    mw.validarParams(),
    mw.validarCorpo(validadores.avaliar),
    mw.exporCorpoValidado,
    async (req, res) => {
        const { nota, comentario } = req.validado.body;
        const autorId = req.usuarioLogado.id;
        const avaliadoId = req.validado.params.id;

        try {
            if (autorId === avaliadoId) {
                return res.status(400).json({ erro: 'Você não pode avaliar a si mesmo.' });
            }

            const [avaliado, autor] = await Promise.all([
                Usuario.findById(avaliadoId),
                Usuario.findById(autorId).select('tipo').lean()
            ]);

            if (!avaliado) return res.status(404).json({ erro: 'Usuário não encontrado.' });
            if (!autor) return res.status(404).json({ erro: 'Autor não encontrado.' });

            if (autor.tipo !== 'contratante') {
                log.acessoNegado('perfil_incorreto', { rota: 'avaliar', tipo: autor.tipo }, req);
                return res.status(403).json({ erro: 'Apenas contratantes podem avaliar profissionais.' });
            }

            // Só é possível avaliar quem realmente trabalhou com o avaliador:
            // precisa ter criado uma vaga com o candidato escalado ou com a
            // candidatura registrada.
            const possuiRelacao = await Vaga.exists({
                criadoPor: autorId,
                $or: [
                    { 'candidatos.idUsuario': avaliadoId },
                    { 'contratados_atuais.idUsuario': avaliadoId },
                    { 'fila_de_espera.idUsuario': avaliadoId }
                ]
            });

            if (!possuiRelacao) {
                log.acessoNegado('sem_relacao_comercial', { rota: 'avaliar', avaliadoId }, req);
                return res.status(403).json({ erro: 'Você só pode avaliar usuários com quem você já contratou ou candidato.' });
            }

            const jaAvaliou = avaliado.avaliacoes.some(av => av.autorId && av.autorId.toString() === autorId);
            if (jaAvaliou) {
                log.aviso('AVALIACAO_DUPLICADA', { autorId, avaliadoId }, req);
                return res.status(409).json({ erro: 'Você já avaliou este usuário.' });
            }

            const avaliacao = {
                autorId,
                nota,
                comentario: comentario || '',
                data: new Date()
            };
            avaliado.avaliacoes.push(avaliacao);
            await avaliado.save();

            log.info('AVALIACAO_REGISTRADA', { autorId, avaliadoId, nota }, req);
            return res.status(201).json({
                mensagem: 'Avaliação salva com sucesso!',
                avaliacao
            });
        } catch (error) {
            log.aviso('ERRO_AVALIAR', { autorId, erro: error.message }, req);
            return res.status(500).json({ erro: 'Não foi possível salvar a avaliação.' });
        }
    }
);

// ==========================================
// 👤 PERFIL (público ou próprio)
// ==========================================
router.get('/:id',
    mw.autenticarToken,
    mw.validarParams(),
    async (req, res) => {
        const alvoId = req.validado.params.id;
        const solicitanteId = req.usuarioLogado.id;
        const ehDono = solicitanteId === alvoId;

        try {
            const usuario = await Usuario.findById(alvoId)
                .select('+cpfCriptografado')
                .populate('avaliacoes.autorId', 'nome nomeSocial');

            if (!usuario) return res.status(404).json({ erro: 'Usuário não encontrado.' });

            const mediaNotas = usuario.avaliacoes.length > 0
                ? (usuario.avaliacoes.reduce((soma, av) => soma + av.nota, 0) / usuario.avaliacoes.length).toFixed(1)
                : 0;

            const resposta = {
                id: usuario._id,
                nome: usuario.nome,
                nomeSocial: usuario.nomeSocial,
                tipo: usuario.tipo,
                fotoPerfil: usuario.fotoPerfil,
                genero: usuario.genero,
                avaliacoes: usuario.avaliacoes,
                mediaNotas
            };

            // Contato e documentos ficam restritos ao próprio titular.
            if (ehDono) {
                resposta.email = usuario.email;
                resposta.celular = usuario.celular;
                resposta.cpf = usuario.cpf;
                resposta.idade = usuario.idade;
                resposta.experiencias = usuario.experiencias;
                resposta.experienciasDetalhadas = usuario.experienciasDetalhadas;
            } else {
                // Só quem já tem relação comercial vê o celular do profissional.
                const possuiRelacao = await Vaga.exists({
                    criadoPor: solicitanteId,
                    $or: [
                        { 'candidatos.idUsuario': alvoId },
                        { 'contratados_atuais.idUsuario': alvoId },
                        { 'fila_de_espera.idUsuario': alvoId }
                    ]
                });
                if (possuiRelacao) resposta.celular = usuario.celular;
            }

            return res.json(resposta);
        } catch (error) {
            log.aviso('ERRO_OBTER_USUARIO', { alvoId, erro: error.message }, req);
            return res.status(500).json({ erro: 'Não foi possível carregar o usuário.' });
        }
    }
);

module.exports = router;
