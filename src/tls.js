'use strict';

/**
 * 🔒 TRANSPORTE SEGURO — HTTPS/TLS (item 26)
 *
 * Se `TLS_CERT_PATH` e `TLS_KEY_PATH` estiverem definidos, o servidor sobe com
 * HTTPS. Sem eles, rodamos HTTP e deixamos isso explícito no log (e, se
 * `FORCAR_HTTPS=true`, bloqueamos o tráfego em claro em vez de servi-lo).
 *
 * Para gerar certificados locais de desenvolvimento:
 *   mkdir -p certs && openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
 *     -keyout certs/server.key -out certs/server.crt -subj "/CN=localhost" \
 *     -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
 */

const fs = require('fs');
const https = require('https');
const http = require('http');
const path = require('path');

const config = require('./config');
const log = require('./log-seguranca');

function credenciaisTLS() {
    if (!config.TLS_CERT_PATH || !config.TLS_KEY_PATH) return null;

    const certPath = path.resolve(config.TLS_CERT_PATH);
    const keyPath = path.resolve(config.TLS_KEY_PATH);

    if (!fs.existsSync(certPath)) throw new Error(`Certificado não encontrado em ${certPath}`);
    if (!fs.existsSync(keyPath)) throw new Error(`Chave privada não encontrada em ${keyPath}`);

    const opcoes = {
        cert: fs.readFileSync(certPath),
        key: fs.readFileSync(keyPath),
        minVersion: 'TLSv1.2',
        ciphers: [
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'TLS_AES_128_GCM_SHA256',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-CHACHA20-POLY1305',
            'ECDHE-RSA-CHACHA20-POLY1305',
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES128-GCM-SHA256'
        ].join(':'),
        honorCipherOrder: true
    };

    if (config.TLS_CA_PATH && fs.existsSync(path.resolve(config.TLS_CA_PATH))) {
        opcoes.ca = fs.readFileSync(path.resolve(config.TLS_CA_PATH));
    }

    return opcoes;
}

const HSTS_ATIVO = 'max-age=63072000; includeSubDomains; preload';

function aplicarHttpsReal(app, { ativo } = {}) {
    if (!ativo) return app;

    // 1) Redireciona HTTP -> HTTPS sem alterar o caminho nem a query.
    app.use((req, res, next) => {
        const xForwardedProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
        const protocolo = xForwardedProto || req.protocol;

        if (protocolo === 'https' || req.secure) return next();

        const host = String(req.headers.host || '').replace(/:\d+$/, '');
        if (!host || /[^\w.-]/.test(host)) return res.status(400).json({ erro: 'Host inválido.' });

        return res.redirect(308, `https://${host}${req.originalUrl}`);
    });

    // 2) HSTS só faz sentido sob HTTPS: envia o header aqui porque o helmet roda
    //    antes deste middleware e não deve anunciá-lo em respostas de redirecionamento.
    app.use((req, res, next) => {
        res.setHeader('Strict-Transport-Security', HSTS_ATIVO);
        next();
    });

    return app;
}

/**
 * Plataforma que já termina TLS na borda (Vercel, Railway, Render, Fly.io,
 * Cloud Run, Heroku...). Nesses ambientes a aplicação fala HTTP com o proxy e
 * recebe `X-Forwarded-Proto: https` — exigir certificado local derrubaria o
 * boot sem qualquer ganho de segurança.
 */
function tlsGerenciadoPelaPlataforma() {
    if (process.env.TLS_GERENCIADO_PELA_PLATAFORMA === 'true') return true;
    if (process.env.VERCEL) return true;
    if (process.env.RAILWAY_ENVIRONMENT) return true;
    if (process.env.RENDER) return true;
    if (process.env.FLY_APP_NAME) return true;
    if (process.env.K_SERVICE) return true;
    return false;
}

function criarServidor(app) {
    try {
        const credenciais = credenciaisTLS();

        if (credenciais) {
            const servidor = https.createServer(credenciais, app);
            log.info('HTTPS_ATIVADO', { protocolo: 'TLSv1.2+', porta: config.PORT });
            return { servidor, protocolo: 'https' };
        }

        if (tlsGerenciadoPelaPlataforma()) {
            log.info('TLS_DELEGADO_AO_PROXY', {
                mensagem: 'HTTPS é terminado pela plataforma/proxy. Confie em X-Forwarded-Proto.',
                exigeProxyConfiavel: config.NUM_PROXIES > 0
            });
            return { servidor: http.createServer(app), protocolo: 'http+proxy-tls' };
        }

        if (config.FORCAR_HTTPS || config.EH_PRODUCAO) {
            log.critico('HTTPS_OBRIGATORIO_SEM_CERTIFICADOS', {
                mensagem: 'Defina TLS_CERT_PATH e TLS_KEY_PATH, ou TLS_GERENCIADO_PELA_PLATAFORMA=true se houver proxy TLS.'
            });
            throw new Error('HTTPS é obrigatório, mas nenhum certificado foi configurado.');
        }

        log.aviso('HTTPS_DESATIVADO', {
            mensagem: 'O servidor está em HTTP puro (apenas desenvolvimento). Configure TLS_CERT_PATH/TLS_KEY_PATH para produção.',
            dica: 'Nunca envie senha, CPF ou token de acesso por HTTP sem TLS.'
        });

        return { servidor: http.createServer(app), protocolo: 'http' };
    } catch (error) {
        log.critico('FALHA_AO_CONFIGURAR_TLS', { erro: error.message });
        throw error;
    }
}

module.exports = { criarServidor, aplicarHttpsReal, credenciaisTLS, tlsGerenciadoPelaPlataforma };
