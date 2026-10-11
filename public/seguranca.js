'use strict';

/**
 * 🛡️ CAMADA DE SEGURANÇA DO FRONTEND (itens 24 e 28)
 *
 * XSS: todo dado vindo da API ou digitado pelo usuário passa por `escaparHtml`
 * antes de entrar em innerHTML. Atributos usam `escaparAtributo` e URLs passam
 * por `urlSegura`, que bloqueia `javascript:`, `data:text/html` e afins.
 * Nenhum valor de dados é interpolado dentro de handlers `onclick` — eles viajam
 * em `data-*` e são lidos via delegação de eventos.
 *
 * Sessão: o access token fica apenas em memória (não em localStorage, legível por
 * qualquer XSS). O refresh token persiste e é rotacionado automaticamente.
 */

(function () {
    // ==================================================================
    // ESCAPE / SANITIZAÇÃO
    // ==================================================================

    const ENTIDADES = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '`': '&#x60;',
        '=': '&#x3D;'
    };

    const ESCAPE = /[&<>"'`=]/g;

    /** Escapa texto destined a innerHTML. `null`/`undefined` viram string vazia. */
    function escHtml(valor) {
        if (valor === null || valor === undefined) return '';
        return String(valor).replace(ESCAPE, c => ENTIDADES[c]);
    }

    /** Alias semântico para o contexto de atributo (mesmo conjunto de escapes). */
    function escAttr(valor) {
        return escHtml(valor);
    }

    /**
     * Só deixa passar esquemas http, https, mailto e imagens data:image.
     * Qualquer outra coisa (javascript:, vbscript:, data:text/html) vira ''.
     */
    function urlSegura(valor, { permitirDataImage = true } = {}) {
        if (!valor) return '';
        const bruto = String(valor).trim();

        // URLs relativas do próprio site são aceitáveis.
        if (bruto.startsWith('/') && !bruto.startsWith('//')) return escAttr(bruto);

        if (/^data:image\/(png|jpe?g|gif|webp|svg\+xml);base64,[a-z0-9+/=\s]+$/i.test(bruto)) {
            return permitirDataImage ? escAttr(bruto) : '';
        }

        try {
            const url = new URL(bruto, window.location.origin);
            if (['http:', 'https:', 'mailto:'].includes(url.protocol)) return escAttr(url.href);
        } catch { /* URL inválida */ }

        return '';
    }

    /** Só aceita ObjectId do MongoDB antes de interpolá-lo em atributos/handlers. */
    function idValido(valor) {
        return /^[a-f0-9]{24}$/i.test(String(valor || '')) ? String(valor) : '';
    }

    /** Inteiro seguro para usar em índice de array dentro de handlers inline. */
    function indiceSeguro(valor, maximo) {
        const n = Number(valor);
        return Number.isInteger(n) && n >= 0 && n < maximo ? n : 0;
    }

    /** Formata um valor vindo do servidor como número finito. */
    function numeroSeguro(valor, padrao = 0) {
        const n = Number(valor);
        return Number.isFinite(n) ? n : padrao;
    }

    // ==================================================================
    // SESSÃO / TOKENS
    // ==================================================================

    let accessToken = null;
    let refreshToken = localStorage.getItem('refreshFreela') || null;
    let renovando = null;

    function guardarSessao({ token, refreshToken: novoRefresh }) {
        if (token) accessToken = token;
        if (novoRefresh) {
            refreshToken = novoRefresh;
            localStorage.setItem('refreshFreela', novoRefresh);
        }
    }

    function limparSessao() {
        accessToken = null;
        refreshToken = null;
        localStorage.removeItem('refreshFreela');
        localStorage.removeItem('tokenFreela');
    }

    function usuarioLogado() {
        return Boolean(accessToken || localStorage.getItem('nomeUsuario'));
    }

    function aoExpirarSessao() {
        limparSessao();
        if (typeof window.atualizarSessao === 'function') window.atualizarSessao();
    }

    async function renovarToken() {
        if (!refreshToken) return null;
        if (renovando) return renovando;

        renovando = (async () => {
            try {
                const res = await fetch('/auth/refresh', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ refreshToken })
                });

                if (!res.ok) {
                    aoExpirarSessao();
                    return null;
                }

                const dados = await res.json();
                guardarSessao(dados);
                return dados.token;
            } catch {
                aoExpirarSessao();
                return null;
            } finally {
                renovando = null;
            }
        })();

        return renovando;
    }

    /**
     * Wrapper de fetch para a API: injeta o Bearer token e, em 401, tenta
     * renovar a sessão uma única vez antes de desistir.
     */
    async function api(caminho, opcoes = {}) {
        const config = Object.assign({}, opcoes);
        config.headers = Object.assign({}, opcoes.headers);

        if (accessToken) config.headers['Authorization'] = `Bearer ${accessToken}`;

        let res = await fetch(caminho, config);

        if (res.status === 401 && refreshToken) {
            const novoToken = await renovarToken();
            if (novoToken) {
                config.headers['Authorization'] = `Bearer ${novoToken}`;
                res = await fetch(caminho, config);
            } else {
                aoExpirarSessao();
            }
        }

        return res;
    }

    /** Lê o corpo JSON tolerando respostas 204/vazias. */
    async function lerJson(res) {
        try { return await res.json(); } catch { return {}; }
    }

    // ==================================================================
    // RENDERIZAÇÃO SEGURA
    // ==================================================================

    /**
     * `innerHTML` só é usado com HTML já escapado por escHtml/escAttr/urlSegura.
     * Este helper existe para tornar essa regra explícita na revisão de código.
     */
    function definirHTML(elemento, html) {
        if (elemento) elemento.innerHTML = html;
    }

    window.Seguranca = {
        escHtml,
        escAttr,
        urlSegura,
        idValido,
        indiceSeguro,
        numeroSeguro,
        api,
        lerJson,
        guardarSessao,
        limparSessao,
        usuarioLogado,
        definirHTML
    };
})();
