'use strict';

/**
 * Segunda etapa do reparo: restaura os emojis que a degradação de codificação
 * transformou em "?" literal. Cada substituição é ancorada por número de linha
 * e por texto circundante, para não tocar em "?" legítimo (ternários JS,
 * optional chaining e pontos de interrogação em português).
 */

const fs = require('fs');

const ARQUIVO = 'public/index.html';
const linhas = fs.readFileSync(ARQUIVO, 'utf8').split('\n');

/** Substitui a 1ª ocorrência de `de` por `para` na linha `n`. */
const trocar = (n, de, para) => {
    const i = linhas[n - 1].indexOf(de);
    if (i === -1) {
        console.warn(`AVISO linha ${n}: trecho nao encontrado -> ${de}`);
        return;
    }
    linhas[n - 1] = linhas[n - 1].slice(0, i) + para + linhas[n - 1].slice(i + de.length);
};

/** Converte N "?" iniciais em `emoji` repetido. */
const estrelas = (n, quantidade, emoji = '⭐') => {
    const re = new RegExp(`^(\\s*<option value="${n}">)\\?+`);
    if (!re.test(linhas[n - 1])) {
        console.warn(`AVISO linha ${n}: estrelas nao encontradas`);
        return;
    }
    linhas[n - 1] = linhas[n - 1].replace(re, `$1${emoji.repeat(quantidade)}`);
};

trocar(14, '??', '\u{1F514}');
trocar(16, 'Conta ??</button>', 'Conta \u{1F510}</button>');
trocar(19, '<h1>??? FreelaSeguro</h1>', '<h1>\u{1F37D}\uFE0F FreelaSeguro</h1>');
trocar(36, '>Entrar ??</button>', '>Entrar →</button>');
trocar(79, '<label>?? Minhas Experiências', '<label>\u{1F4BC} Minhas Experiências');
trocar(83, 'Registrar Conta Segura ??</button>', 'Registrar Conta Segura →</button>');
trocar(96, 'Nota (1-5 ?):', 'Nota (1-5 ⭐):');
estrelas(99, 1);
estrelas(100, 2);
estrelas(101, 3);
estrelas(102, 4);
estrelas(103, 5);
trocar(110, 'Avaliação ?</button>', 'Avaliação →</button>');
trocar(119, '<h2>? Cancelar Vaga</h2>', '<h2>⚠️ Cancelar Vaga</h2>');
trocar(128, 'Confirmar Cancelamento ?</button>', 'Confirmar Cancelamento →</button>');
trocar(145, 'Confirmar Equipe ?</button>', 'Confirmar Equipe →</button>');
trocar(158, '>?? Postar Nova Vaga</h2>', '>\u{1F4BC} Postar Nova Vaga</h2>');
trocar(165, '>?? Informações Básicas</h3>', '>\u{1F4CB} Informações Básicas</h3>');
trocar(184, '>? Data e Horários</h3>', '>\u{1F4C5} Data e Horários</h3>');
trocar(203, '>?? LOCALIZAÇÃO</h3>', '>\u{1F4CD} LOCALIZAÇÃO</h3>');
trocar(214, '<span>?? Esta vaga', '<span>\u{1F4C5} Esta vaga');
trocar(220, '>?? Adicionar Mais Dias</h4>', '>➕ Adicionar Mais Dias</h4>');
trocar(254, '?? Lançar Vaga', '\u{1F680} Lançar Vaga');
trocar(263, 'Meus Jobs ???</button>', 'Meus Jobs \u{1F4CB}</button>');
trocar(264, 'Mural de Vagas ??</button>', 'Mural de Vagas \u{1F310}</button>');
trocar(268, 'Meus Trabalhos (Jobs) ???</h2>', 'Meus Trabalhos (Jobs) \u{1F4BC}</h2>');
trocar(274, '<span style="font-size:2rem;">??</span>', '<span style="font-size:2rem;">\u{1F4CB}</span>');
trocar(292, '// ??? PROTEÇÃO CSRF', '// \u{1F6E1}\uFE0F PROTEÇÃO CSRF');
trocar(323, '// ??? Helpers de sanitização', '// \u{1F6E1}\uFE0F Helpers de sanitização');
trocar(334, '>??? Como Chegar</a>', '>\u{1F5FA}\uFE0F Como Chegar</a>');
trocar(356, '// ?? Gerenciar experiências', '// \u{1F4CB} Gerenciar experiências');
trocar(612, '// ?? carregarVagasTemp', '// ⚠️ carregarVagasTemp');
trocar(1067, '// ?? FUNÇÃO PARA CARREGAR', '// \u{1F4E2} FUNÇÃO PARA CARREGAR');
trocar(1096, '// ?? FUNÇÃO CORRIGIDA', '// \u{1F3A8} FUNÇÃO CORRIGIDA');

fs.writeFileSync(ARQUIVO, linhas.join('\n'), 'utf8');
console.log('Emojis restaurados.');
