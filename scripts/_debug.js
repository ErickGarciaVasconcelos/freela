const fs = require('fs');
const l = fs.readFileSync('public/index.html', 'utf8').split('\n').slice(0, 290);
const set = new Set();
for (const linha of l) {
    for (const m of linha.matchAll(/on(?:click|change|mouseover|mouseout)="([^"]*)"/g)) {
        for (const c of m[1].matchAll(/([A-Za-z_$][\w$]*)\s*\(/g)) set.add(c[1]);
    }
}
console.log([...set].sort().join(', '));
