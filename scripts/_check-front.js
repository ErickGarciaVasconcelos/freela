/**
 * Validação estática do front: checa sintaxe do JS inline, tag de script,
 * proxies de onclick e ausência de interpolações dangerously em handlers.
 */
const fs = require('fs');
const vm = require('vm');

const html = fs.readFileSync('public/index.html', 'utf8');

const linhas = html.split('\n');
console.log('linhas:', linhas.length);

// 1) Tags <script>
const scripts = [...html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)];
console.log('blocos <script>:', scripts.length);
scripts.forEach((s, i) => console.log(`  [${i}] src=${/src="([^"]+)"/.exec(s[1])?.[1] || '(inline)'} | ${s[2].split('\n').length} linhas`));

// 2) Sintaxe do script inline
const inline = scripts.filter(s => !/src=/.test(s[1])).map(s => s[2]);
inline.forEach((codigo, i) => {
    try {
        new vm.Script(codigo, { filename: `inline-${i}.js` });
        console.log(`  sintaxe inline[${i}]: OK`);
    } catch (e) {
        console.log(`  sintaxe inline[${i}]: FALHOU -> ${e.message}`);
        const m = /inline-\d+\.js:(\d+)/.exec(e.stack || '');
        if (m) {
            const n = Number(m[1]);
            console.log('    contexto:', (codigo.split('\n')[n - 1] || '').trim());
        }
    }
});

// 3) Sintaxe de seguranca.js
try {
    new vm.Script(fs.readFileSync('public/seguranca.js', 'utf8'), { filename: 'seguranca.js' });
    console.log('  sintaxe seguranca.js: OK');
} catch (e) {
    console.log('  sintaxe seguranca.js: FALHOU ->', e.message);
}

// 4) onclick com interpolação de dado dinâmico dentro do JS (risco de XSS)
const linhasInHtml = html.split('\n').slice(0, 290);
let suspeitas = 0;
for (const [i, l] of linhasInHtml.entries()) {
    for (const m of l.matchAll(/on(?:click|change)="([^"]*)"/g)) {
        if (/\$\{/.test(m[1])) {
            console.log(`  linha ${i + 1}: onclick com interpolacao -> ${m[1]}`);
            suspeitas++;
        }
    }
}
console.log('  onclick com interpolacao (estatico):', suspeitas);

// 5) innerHTML no script inline sem esc()
const semEscape = [...inline.join('\n').matchAll(/innerHTML\s*[+]?=\s*`[^`]*\$\{(?!esc\(|escAttr\(|urlSegura\(|indiceSeguro\(|numeroSeguro\(|linkMaps\(|estrelas\.repeat\(|'⭐'\.repeat\(|corDoStatus\(|status\.)/g)];
console.log('  innerHTML com ${...} nao escapado:', semEscape.length);
semEscape.slice(0, 10).forEach(m => console.log('    ' + m[0].slice(0, 120).replace(/\n/g, ' ')));
