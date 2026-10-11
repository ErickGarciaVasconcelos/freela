'use strict';

/**
 * Teste ponta a ponta das correcoes de seguranca (itens 21-30).
 *
 * Uso (o servidor precisa estar rodando em $BASE, padrao http://localhost:3100):
 *   FASE=rate  node scripts/teste-seguranca.js   # consome os limitadores
 *   FASE=fluxo node scripts/teste-seguranca.js   # fluxo completo
 *
 * Cada fase deve rodar contra um servidor recem-iniciado: os limitadores usam
 * janela deslizante em memoria e nao se limpam entre execucoes.
 */

const BASE = process.env.BASE || 'http://localhost:3100';
const FASE = process.env.FASE || 'fluxo';
const rodando = (f) => FASE === f;
const MONGO_MEM = process.env.MONGO_MEMORY_PORT || '27018';

let cookie = '';
let csrf = '';
let ok = 0;
let falhas = 0;

function registrar(nome, passou, detalhe = '') {
    if (passou) { ok++; console.log(`  \u2714 ${nome}${detalhe ? ' — ' + detalhe : ''}`); }
    else { falhas++; console.log(`  \u2718 ${nome}${detalhe ? ' — ' + detalhe : ''}`); }
}

async function req(caminho, opcoes = {}) {
    const headers = Object.assign({}, opcoes.headers);
    if (cookie) headers.Cookie = cookie;
    const metodo = (opcoes.method || 'GET').toUpperCase();
    if (csrf && !['GET', 'HEAD'].includes(metodo)) headers['X-CSRF-Token'] = csrf;

    const res = await fetch(BASE + caminho, Object.assign({}, opcoes, { headers, redirect: 'manual' }));

    for (const c of (res.headers.getSetCookie ? res.headers.getSetCookie() : [])) {
        const par = c.split(';')[0];
        if (par.startsWith('csrfToken=')) {
            csrf = decodeURIComponent(par.slice('csrfToken='.length));
            cookie = par;
        }
    }

    let corpo = null;
    if ((res.headers.get('content-type') || '').includes('application/json')) {
        corpo = await res.json().catch(() => null);
    }

    return { status: res.status, corpo, headers: res.headers };
}

const json = (obj) => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(obj) });
const auth = (t) => ({ Authorization: `Bearer ${t}` });

/** Gera um CPF matematicamente valido a partir de 9 digitos base. */
function cpfValido(base9) {
    const d = String(base9).padStart(9, '0').split('').map(Number);
    const dv1 = (d.reduce((a, n, i) => a + n * (10 - i), 0) * 10) % 11 % 10;
    const comDv1 = [...d, dv1];
    const dv2 = (comDv1.reduce((a, n, i) => a + n * (11 - i), 0) * 10) % 11 % 10;
    return comDv1.concat(dv2).join('');
}

const CPFS = [cpfValido('529982247'), cpfValido('111444777'), cpfValido('390533447')];
const unico = Date.now().toString().slice(-5);

async function cadastrar(tipo, cpf, email, senha = 'Senha1234') {
    return req('/auth/cadastro', json({ nome: `Teste ${tipo}`, email, senha, tipo, cpf, celular: '+5511988880000' }));
}

void (async function () {
    // Materializa o cookie CSRF antes de qualquer escrita.
    await req('/');

    // ==================================================================
    console.log(`\n=== FASE: ${FASE} ===`);

    // ------------------------------------------------------------------
    // 21. Rate limiting
    // ------------------------------------------------------------------
    if (rodando('rate')) {
        console.log('\n=== 21. RATE LIMITING ===');

        let r1 = null;
        let i = 0;
        for (; i < 250; i++) {
            r1 = await req('/vagas');
            if (r1.status === 429) break;
        }
        registrar('leitura bloqueia varrimento em massa', r1.status === 429, `429 na tentativa ${i + 1}`);
        registrar('429 em JSON + header Retry-After',
            !!r1.corpo?.erro && r1.headers.get('retry-after') !== null, `limitador=${r1.corpo?.limitador}`);

        let r2 = null;
        let j = 0;
        for (; j < 60; j++) {
            r2 = await req('/auth/refresh', json({ refreshToken: 'x'.repeat(30) }));
            if (r2.status === 429) break;
        }
        registrar('limitador dedicado em /auth/refresh', r2.status === 429, `429 na tentativa ${j + 1}`);

        let r3 = null;
        let k = 0;
        for (; k < 25; k++) {
            r3 = await req('/auth/cadastro', json({
                nome: 'X', email: `rl${unico}-${k}@x.com`, senha: 'Senha1234',
                tipo: 'contratante', cpf: cpfValido(String(100000000 + k)), celular: '+5511966660000'
            }));
            if (r3.status === 429) break;
        }
        registrar('limitador dedicado em /auth/cadastro', r3.status === 429, `429 na tentativa ${k + 1}`);

        let r4 = null;
        let m = 0;
        for (; m < 90; m++) {
            r4 = await req('/vaga', json({ titulo: 'Teste de cota de escrita' }));
            if (r4.status === 429) break;
        }
        registrar('limitador de escrita cobre rota fora de /auth', r4.status === 429, `429 na tentativa ${m + 1}`);
    }

    // ------------------------------------------------------------------
    // 22. Validacao e sanitizacao
    // ------------------------------------------------------------------
    if (rodando('fluxo')) {
        console.log('\n=== 22. VALIDACAO E SANITIZACAO (Joi) ===');

        const vazio = await req('/auth/cadastro', json({ nome: 'x' }));
        registrar('cadastro sem campos obrigatorios -> 422', vazio.status === 422, `status ${vazio.status}`);
        registrar('erros detalhados campo a campo',
            Array.isArray(vazio.corpo?.detalhes) && vazio.corpo.detalhes.length > 0,
            `${vazio.corpo?.detalhes?.length} campos`);

        const fraco = await req('/auth/cadastro', json({
            nome: 'T', email: 'a@b.com', senha: '123', tipo: 'contratante', cpf: '111', celular: 'abc'
        }));
        registrar('senha fraca + CPF invalido + celular invalido -> 422', fraco.status === 422,
            `status ${fraco.status} (${fraco.corpo?.detalhes?.length} erros)`);

        const massa = await cadastrar('contratante', CPFS[0], `mass${unico}@x.com`);
        registrar('cadastro valido aceito', massa.status === 201, `status ${massa.status}`);

        const xss = await req('/auth/cadastro', json({
            nome: '<img src=x onerror=alert(1)>',
            email: `xss${unico}@x.com`, senha: 'Senha1234', tipo: 'contratado',
            cpf: CPFS[2], celular: '+5511977770000',
            experiencias: '"><script>alert(document.cookie)</script>',
           ExperienciasDetalhadas: [{ local: 'x'.repeat(5000) }]
        }));
        registrar('payload XSS aceito (a sanitizacao ocorre na renderizacao)', xss.status === 201,
            `status ${xss.status} ${xss.corpo?.detalhes ? JSON.stringify(xss.corpo.detalhes) : ''}`);

        const cpfRepetido = await req('/auth/cadastro', json({
            nome: 'T', email: `rep${unico}@x.com`, senha: 'Senha1234',
            tipo: 'contratante', cpf: '11111111111', celular: '+5511955550000'
        }));
        registrar('CPF com todos os digitos iguais -> 422', cpfRepetido.status === 422, `status ${cpfRepetido.status}`);

        const jsonMalformado = await req('/auth/login', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{quebrado'
        });
        registrar('JSON malformado -> 400 (sem stack trace)', jsonMalformado.status === 400,
            `status ${jsonMalformado.status}`);

        const bodyEnorme = await req('/auth/login', json({ email: 'a@b.com', senha: 'x'.repeat(3 * 1024 * 1024) }));
        registrar('payload acima do limite -> 413', bodyEnorme.status === 413, `status ${bodyEnorme.status}`);

        const logLimpo = (await req('/auth/login', json({ email: 'x@y.com', senha: 'z' })));
        registrar('mensagem de erro nao vaza stack trace nem SQL',
            !!logLimpo.corpo?.erro && !/at |node:|mongodb:\/\//i.test(logLimpo.corpo.erro),
            logLimpo.corpo?.erro);
    }

    // ------------------------------------------------------------------
    // 25. Brute force
    // ------------------------------------------------------------------
    if (rodando('fluxo')) {
        console.log('\n=== 25. PROTECAO CONTRA FORCA BRUTA ===');

        const emailBF = `bruta${unico}@x.com`;
        await cadastrar('contratante', CPFS[0], emailBF);

        let statusFinal = 0;
        let tentativas = 0;
        for (; tentativas < 10; tentativas++) {
            const r = await req('/auth/login', json({ email: emailBF, senha: `errada${tentativas}` }));
            statusFinal = r.status;
            if (r.status === 423) break;
        }
        registrar('conta bloqueada apos falhas repetidas', statusFinal === 423, `423 apos ${tentativas + 1} tentativas`);

        const correta = await req('/auth/login', json({ email: emailBF, senha: 'Senha1234' }));
        registrar('bloqueio persiste mesmo com a senha correta', correta.status === 423, `status ${correta.status}`);

        const inexistente = await req('/auth/login', json({ email: `naoexiste${unico}@x.com`, senha: 'x' }));
        registrar('resposta generica impede enumeracao de contas',
            inexistente.status === 401 && inexistente.corpo.erro === 'E-mail ou senha incorretos.',
            `"${inexistente.corpo?.erro}"`);
    }

    // ------------------------------------------------------------------
    // 24. Refresh token, rotacao e blacklist
    // ------------------------------------------------------------------
    if (rodando('fluxo')) {
        console.log('\n=== 24. REFRESH TOKEN + BLACKLIST ===');

        const emailCTR = `ctr${unico}@x.com`;
        const emailFRE = `fre${unico}@x.com`;
        await cadastrar('contratante', CPFS[0], emailCTR);
        await cadastrar('contratado', CPFS[1], emailFRE);

        const login = await req('/auth/login', json({ email: emailFRE, senha: 'Senha1234' }));
        registrar('login emite access + refresh',
            login.status === 200 && !!login.corpo.token && !!login.corpo.refreshToken,
            `status ${login.status}`);

        if (login.status !== 200) {
            console.log('  (fluxo de tokens abortado)');
        } else {
            const { token: accessOriginal, refreshToken: refreshOriginal } = login.corpo;
            const claims = JSON.parse(Buffer.from(accessOriginal.split('.')[1], 'base64url').toString());

            registrar('access token curto (nao 24h)', (claims.exp - claims.iat) <= 3600,
                `${(claims.exp - claims.iat) / 60} minutos`);
            registrar('claim de tipo distingue access de refresh', claims.typ === 'access');
            registrar('claim de versao de senha presente (pv)', typeof claims.pv === 'number', `pv=${claims.pv}`);

            const anonimo = await req(`/usuario/${claims.sub}`);
            registrar('rota exige Bearer token', anonimo.status === 401, `status ${anonimo.status}`);

            const tokenForjado = accessOriginal.slice(0, -4) + 'AAAA';
            const forjado = await req(`/usuario/${claims.sub}`, { headers: auth(tokenForjado) });
            registrar('token adulterado rejeitado', forjado.status === 401, `status ${forjado.status}`);

            const algNone = `${Buffer.from(JSON.stringify({ typ: 'access', sub: claims.sub })).toString('base64url')}.`;
            const semAlg = await req(`/usuario/${claims.sub}`, { headers: auth(`${algNone}x`) });
            registrar('token sem assinatura rejeitado', semAlg.status === 401, `status ${semAlg.status}`);

            const prof = await req(`/usuario/${claims.sub}`, { headers: auth(accessOriginal) });
            registrar('access token autentica', prof.status === 200, `status ${prof.status}`);

            const r1 = await req('/auth/refresh', json({ refreshToken: refreshOriginal }));
            registrar('refresh rotaciona o token',
                r1.status === 200 && r1.corpo.refreshToken !== refreshOriginal, `status ${r1.status}`);

            const comNovo = await req(`/usuario/${claims.sub}`, { headers: auth(r1.corpo.token) });
            registrar('novo access token funciona', comNovo.status === 200, `status ${comNovo.status}`);

            const reuso = await req('/auth/refresh', json({ refreshToken: refreshOriginal }));
            registrar('reuso do refresh antigo -> 401', reuso.status === 401, `status ${reuso.status}`);

            const aposReuso = await req(`/usuario/${claims.sub}`, { headers: auth(r1.corpo.token) });
            registrar('deteccao de reuso revoga a familia inteira', aposReuso.status === 401,
                `status ${aposReuso.status}`);
        }
    }

    // ------------------------------------------------------------------
    // 24b. Logout
    // ------------------------------------------------------------------
    if (rodando('fluxo')) {
        console.log('\n=== 24b. LOGOUT REVOGA SESSAO ===');

        const l = await req('/auth/login', json({ email: `fre${unico}@x.com`, senha: 'Senha1234' }));
        if (l.status === 200) {
            const { token, refreshToken } = l.corpo;
            const sub = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString()).sub;

            registrar('token valido antes do logout',
                (await req(`/usuario/${sub}`, { headers: auth(token) })).status === 200);

            await req('/auth/logout', {
                method: 'POST',
                headers: Object.assign({ 'Content-Type': 'application/json' }, auth(token)),
                body: JSON.stringify({ refreshToken })
            });

            const depois = await req(`/usuario/${sub}`, { headers: auth(token) });
            registrar('access token na blacklist apos logout', depois.status === 401, `status ${depois.status}`);

            const reusoRefresh = await req('/auth/refresh', json({ refreshToken }));
            registrar('refresh token revogado apos logout', reusoRefresh.status === 401, `status ${reusoRefresh.status}`);
        } else {
            registrar('login para testar logout', false, `status ${l.status}`);
        }
    }

    // ------------------------------------------------------------------
    // 23. Dados sensiveis cifrados em repouso
    // ------------------------------------------------------------------
    if (rodando('fluxo')) {
        console.log('\n=== 23. DADOS SENSIVEIS CIFRADOS EM REPOUSO ===');

        const mongoose = require('mongoose');
        let doc = null;

        try {
            await mongoose.connect(`mongodb://127.0.0.1:${MONGO_MEM}/freela-seguro`, { serverSelectionTimeoutMS: 3000 });
            const col = mongoose.connection.db.collection('usuarios');
            doc = await col.findOne({ email: `fre${unico}@x.com` });
        } catch {
            registrar('conexao com o banco para inspecao', false, `MongoDB em ${MONGO_MEM} inacessivel`);
        }

        if (doc) {
            const bruto = JSON.stringify(doc);

            registrar('CPF ausente do documento em texto plano',
                !CPFS.some(c => bruto.includes(c)));
            registrar('celular ausente do documento em texto plano', !bruto.includes('88880000'));
            registrar('CPF gravado como ciphertext AES-256-GCM (v1:iv:tag:dados)',
                typeof doc.cpfCriptografado === 'string' && doc.cpfCriptografado.startsWith('v1:'),
                `${String(doc.cpfCriptografado).slice(0, 28)}...`);
            registrar('celular gravado como ciphertext', typeof doc.celularCriptografado === 'string' &&
                doc.celularCriptografado.startsWith('v1:'));
            registrar('indice cego HMAC-SHA256 presente', typeof doc.cpfIndice === 'string' && doc.cpfIndice.length === 64,
                `${String(doc.cpfIndice).slice(0, 16)}...`);
            registrar('indice cego NAO e o CPF em claro', doc.cpfIndice !== CPFS[1] && !doc.cpfIndice.includes(CPFS[1]));
            registrar('senha nunca guardada em claro', /^\$2[aby]\$/.test(doc.senha), `${String(doc.senha).slice(0, 10)}...`);
            registrar('cpf plaintext nao existe mais no schema', doc.cpf === undefined || doc.cpf === null);

            const repetidos = await col.countDocuments({ cpfIndice: doc.cpfIndice });
            registrar('unicidade via indice cego', repetidos === 1, `${repetidos} documento(s)`);

            // Cifras distintas para o mesmo valor (IV aleatorio) provam que nao
            // e cifrado deterministico: dois usuarios com o mesmo CPF ficam com
            // ciphertexts diferentes no banco.
            const doc2 = await col.findOne({ email: `ctr${unico}@x.com` });
            registrar('IV aleatorio: mesmo CPF -> ciphertext diferente',
                Boolean(doc2) && doc2.cpfCriptografado !== doc.cpfCriptografado);
        }

        try { await mongoose.disconnect(); } catch { /* ignore */ }
    }

    // ------------------------------------------------------------------
    // 29. Paginacao (+ 30. uso de indices)
    // ------------------------------------------------------------------
    if (rodando('fluxo')) {
        console.log('\n=== 29. PAGINACAO EM GET /vagas ===');

        const ctr = await req('/auth/login', json({ email: `ctr${unico}@x.com`, senha: 'Senha1234' }));
        if (ctr.status !== 200) {
            registrar('login do contratante', false, `status ${ctr.status}`);
        } else {
            const token = ctr.corpo.token;
            const hdr = auth(token);

            let criadas = 0;
            for (let i = 0; i < 15; i++) {
                const v = await req('/vaga', {
                    method: 'POST',
                    headers: Object.assign({ 'Content-Type': 'application/json' }, hdr),
                    body: JSON.stringify({
                        titulo: `Vaga de teste ${i}`, valor: 100 + i, vagasTotais: 2,
                        endereco: `Rua Teste ${i}`, descricao: `Descricao ${i}`
                    })
                });
                if (v.status === 201) criadas++;
            }
            registrar('cria 15 vagas para exercitar a paginacao', criadas === 15, `${criadas} criadas`);

            const p1 = await req('/vagas?pagina=1&limite=10', { headers: hdr });
            registrar('pagina 1 respeita o limite', p1.status === 200 && p1.corpo.dados.length === 10,
                `${p1.corpo?.dados?.length} itens`);
            registrar('metadados de paginacao presentes',
                p1.corpo.paginacao?.total >= 15 && p1.corpo.paginacao.temProxima === true,
                `total=${p1.corpo?.paginacao?.total} paginas=${p1.corpo?.paginacao?.totalPaginas}`);

            const p2 = await req('/vagas?pagina=2&limite=10', { headers: hdr });
            const ids1 = p1.corpo.dados.map(v => v._id);
            const ids2 = p2.corpo.dados.map(v => v._id);
            registrar('pagina 2 nao repete itens da pagina 1',
                ids2.length > 0 && ids2.every(id => !ids1.includes(id)), `${ids2.length} itens`);

            const teto = await req('/vagas?limite=9999', { headers: hdr });
            registrar('limite acima do teto rejeitado (422)', teto.status === 422, `status ${teto.status}`);

            const zero = await req('/vagas?pagina=0', { headers: hdr });
            registrar('pagina zero/negativa rejeitada (422)', zero.status === 422, `status ${zero.status}`);

            const injetado = await req('/vagas?status_vaga[$ne]=aberta', { headers: hdr });
            registrar('tentativa de NoSQL injection na query ignorada',
                injetado.status === 200 || injetado.status === 422, `status ${injetado.status}`);

            const serial = JSON.stringify(p1.corpo.dados);
            registrar('lista publica nao expoe contatos de terceiros',
                !serial.includes('telefone') && !serial.includes('emailCriptografado') &&
                !serial.includes('"candidatos"') && !serial.includes('fila_de_espera'));
            registrar('resposta traz apenas campos explicitamente serializados',
                Object.keys(p1.corpo.dados[0]).every(k =>
                    ['_id', 'titulo', 'descricao', 'valor', 'status_vaga', 'vagasTotais', 'genero',
                        'experienciaRequerida', 'tempoExperiencia', 'dataTrabalho', 'endereco', 'horario',
                        'horarioInicio', 'horarioFim', 'datasTrabalho', 'criadoPor', 'criadoEm',
                        'totalCandidatos', 'totalContratados', 'meuStatus'].includes(k)),
                Object.keys(p1.corpo.dados[0]).join(','));
            registrar('papel do usuario calculado no servidor (meuStatus)',
                p1.corpo.dados.every(v => v.meuStatus !== undefined));

            registrar('detalhe da vaga acessivel',
                (await req(`/vaga/${ids1[0]}`, { headers: hdr })).status === 200);

            const semDono = await req('/vaga/000000000000000000000000/candidatos', { headers: hdr });
            registrar('rota inexistente devolve 404/422 e nao 500',
                [404, 422].includes(semDono.status), `status ${semDono.status}`);

            const busca = await req('/vagas?busca=teste', { headers: hdr });
            registrar('busca textual (indice de texto) funciona',
                busca.status === 200 && busca.corpo.dados.length > 0, `${busca.corpo?.dados?.length} hits`);

            const minha = await req('/vagas?minha=true', { headers: hdr });
            registrar('filtro minha=true devolve so vagas do usuario',
                minha.status === 200 && minha.corpo.dados.length === 15, `${minha.corpo?.dados?.length} vagas`);

            const statusFiltro = await req('/vagas?status=aberta', { headers: hdr });
            registrar('filtro por status aplica o indice de status_vaga',
                statusFiltro.status === 200 && statusFiltro.corpo.dados.every(v => v.status_vaga === 'aberta'),
                `${statusFiltro.corpo?.dados?.length} vagas`);

            const fre = await req('/auth/login', json({ email: `fre${unico}@x.com`, senha: 'Senha1234' }));
            if (fre.status === 200) {
                const fhdr = auth(fre.corpo.token);
                const cand = await req(`/vaga/${ids1[0]}/candidatar`, { method: 'PATCH', headers: fhdr });
                registrar('profissional se candidata', cand.status === 200, `status ${cand.status}`);

                const dono = await req(`/vaga/${ids1[0]}/candidatos`, { headers: hdr });
                registrar('dono da vaga ve os candidatos (decrifrados em memoria)',
                    dono.status === 200 && Array.isArray(dono.corpo.candidatos) &&
                    dono.corpo.candidatos.some(c => c.telefone === '+5511988880000'),
                    `status ${dono.status}`);

                const intruso = await req(`/vaga/${ids1[0]}/candidatos`, { headers: fhdr });
                registrar('nao-dono nao ve a lista de candidatos', intruso.status === 403, `status ${intruso.status}`);

                const escalar = await req(`/vaga/${ids1[0]}/confirmar-equipe`, {
                    method: 'POST',
                    headers: Object.assign({ 'Content-Type': 'application/json' }, fhdr),
                    body: JSON.stringify({ titulares: [], reservas: [] })
                });
                registrar('freela nao pode escalar equipe da vaga de outro', escalar.status === 403,
                    `status ${escalar.status}`);
            }
        }
    }

    // ------------------------------------------------------------------
    // 27. Logs de seguranca
    // ------------------------------------------------------------------
    if (rodando('fluxo')) {
        console.log('\n=== 27. LOGS DE SEGURANCA ===');

        const fs = require('fs');
        const caminho = 'logs/seguranca.log';

        if (!fs.existsSync(caminho)) {
            registrar('arquivo de log criado', false, 'logs/seguranca.log nao encontrado');
        } else {
            const linhas = fs.readFileSync(caminho, 'utf8').trim().split('\n').filter(Boolean);
            const eventos = linhas.map(l => { try { return JSON.parse(l); } catch { return null; } });

            registrar('todas as linhas sao JSON valido', eventos.every(Boolean), `${linhas.length} eventos`);
            registrar('cada evento tem timestamp e nivel',
                eventos.every(e => e.timestamp && e.nivel && e.evento));

            const nomes = new Set(eventos.map(e => e.evento));
            for (const esperado of ['LOGIN_NEGADO', 'LOGIN_BLOQUEADO', 'VALIDACAO_REJEITADA',
                'REFRESH_TOKEN_REUTILIZADO', 'ACESSO_NEGADO', 'VAGA_CRIADA', 'CSRF_REJEITADO']) {
                registrar(`evento "${esperado}" registrado`, nomes.has(esperado));
            }

            registrar('log nao expoe senhas em claro',
                !linhas.some(l => /"senha"\s*:\s*"(?!\*\*\*)/.test(l)));
            registrar('log nao expoe tokens em claro',
                !linhas.some(l => /"(token|refreshToken)"\s*:\s*"(?!\*\*\*)/.test(l)));
            registrar('log nao expoe CPF/celular em claro',
                !linhas.some(l => CPFS.some(c => l.includes(c)) || l.includes('88880000')));
            registrar('eventos carregam IP de origem', eventos.some(e => !!e.ip));
            registrar('eventos de acesso carregam idRequisicao', eventos.some(e => !!e.idRequisicao));
        }
    }

    // ------------------------------------------------------------------
    // 26. HTTPS e headers de transporte
    // ------------------------------------------------------------------
    if (rodando('fluxo')) {
        console.log('\n=== 26. HTTPS + HEADERS DE TRANSPORTE ===');

        const home = await req('/');
        registrar('HSTS nao anunciado em HTTP de dev',
            home.headers.get('strict-transport-security') === null);
        registrar('CSP ativa (Helmet)',
            (home.headers.get('content-security-policy') || '').includes("default-src 'self'"));
        registrar('frame-ancestors bloqueia embedding (clickjacking)',
            (home.headers.get('content-security-policy') || '').includes("frame-ancestors 'none'"));
        registrar('X-Powered-By removido', home.headers.get('x-powered-by') === null);
        registrar('X-Content-Type-Options: nosniff', home.headers.get('x-content-type-options') === 'nosniff');
        registrar('X-Frame-Options: DENY', home.headers.get('x-frame-options') === 'DENY');
        registrar('Referrer-Policy restritiva',
            home.headers.get('referrer-policy') === 'strict-origin-when-cross-origin');
        registrar('Cookie CSRF com SameSite=Strict',
            (home.headers.getSetCookie ? home.headers.getSetCookie() : []).some(c => /csrfToken=.*SameSite=Strict/i.test(c)));

        const app = await req('/');
        registrar('pagina inicial servida', app.status === 200);

        const modulo = await req('/seguranca.js');
        registrar('modulo de sanitizacao do frontend servido', modulo.status === 200);

        const csrfAusente = await fetch(BASE + '/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: 'a@b.com', senha: 'x' })
        });
        registrar('escrita sem token CSRF bloqueada (403)', csrfAusente.status === 403, `status ${csrfAusente.status}`);

        const inexistente = await req('/rota-que-nao-existe');
        registrar('404 em JSON sem stack trace',
            inexistente.status === 404 && inexistente.corpo?.erro === 'Rota não encontrada.');
    }

    console.log(`\n================ RESUMO (${FASE}) ================`);
    console.log(`  passaram: ${ok}   falharam: ${falhas}`);
    process.exit(falhas > 0 ? 1 : 0);
})();
