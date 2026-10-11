const fs = require('fs');
const ARQUIVO = 'public/index.html';
let linhas = fs.readFileSync(ARQUIVO, 'utf8').split('\n');

while (linhas.length && linhas[linhas.length - 1].trim() === '') linhas.pop();

if (!linhas[linhas.length - 1].includes('</html>')) {
    linhas.push('');
    linhas.push('  <div id="container-notificacoes" style="position: fixed; top: 80px; right: 20px; z-index: 9999; max-width: 400px; max-height: 600px; overflow-y: auto;"></div>');
    linhas.push(' </body>');
    linhas.push('</html>');
}

fs.writeFileSync(ARQUIVO, linhas.join('\n') + '\n', 'utf8');
console.log('total de linhas:', linhas.length);
console.log('ultimas 6:');
linhas.slice(-6).forEach(l => console.log('  ' + l));
