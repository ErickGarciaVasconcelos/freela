'use strict';

/**
 * Reparo pontual do public/index.html.
 * Substitui apenas os caracteres não-ASCII perdidos (marcados com U+FFFD)
 * pelos grafemas corretos do português. Nenhum outro byte é tocado.
 */

const fs = require('fs');

const ARQUIVO = 'public/index.html';
const R = '\uFFFD';

const MAPA = [
    ['AVALIA??ES', 'AVALIAÇÕES'],
    ['INFORMA??ES', 'INFORMAÇÕES'],
    ['NOTIFICA??O', 'NOTIFICAÇÃO'],
    ['VISUALIZA??O', 'VISUALIZAÇÃO'],
    ['PROTE??O', 'PROTEÇÃO'],
    ['RENDERIZA??O', 'RENDERIZAÇÃO'],
    ['Identifica??o', 'Identificação'],
    ['Pagina??o', 'Paginação'],
    ['Localiza??o', 'LOCALIZAÇÃO'],
    ['notifica??es', 'notificações'],
    ['notificar?', 'notificará'],
    ['Confirma??o', 'Confirmação'],
    ['a??o', 'ação'],
    ['Aten??o', 'Atenção'],
    ['Avalia??o', 'Avaliação'],
    ['Descri??o', 'Descrição'],
    ['duplica??o', 'duplicação'],
    ['edi??o', 'edição'],
    ['escala??o', 'escalação'],
    ['interpola??o', 'interpolação'],
    ['navega??o', 'navegação'],
    ['sanitiza??o', 'sanitização'],
    ['requisi??o', 'requisição'],
    ['Sele??es', 'Seleções'],
    ['Sele??o', 'Seleção'],
    ['Valida??o', 'Validação'],
    ['Verifica??o', 'Verificação'],
    ['fun??o.', 'função.'],
    ['FUN??O', 'FUNÇÃO'],
    ['conclus?o', 'conclusão'],
    ['conex?o', 'conexão'],
    ['exclus?o', 'exclusão'],
    ['coment?rio', 'comentário'],
    ['Endere?o', 'Endereço'],
    ['Formul?rio', 'Formulário'],
    ['Experi?ncia', 'Experiência'],
    ['experi?ncia', 'experiência'],
    ['Experi?ncias', 'Experiências'],
    ['experi?ncias', 'experiências'],
    ['Hor?rio', 'Horário'],
    ['HOR?RIOS', 'HORÁRIOS'],
    ['In?cio', 'Início'],
    ['Lan?ar', 'Lançar'],
    ['M?dia', 'Média'],
    ['m?ltiplos', 'múltiplos'],
    ['m?s', 'mês'],
    ['or?amento', 'orçamento'],
    ['padr?o', 'padrão'],
    ['s?bado', 'sábado'],
    ['Seguran?a', 'Segurança'],
    ['T?tulo', 'Título'],
    ['USU?RIO', 'USUÁRIO'],
    ['VIS?O', 'VISÃO'],
    ['Cach?', 'Cachê'],
    ['Curr?culos', 'Currículos'],
    ['Curr?culo', 'Currículo'],
    ['algu?m', 'alguém'],
    ['An?lise', 'Análise'],
    ['bot?es', 'botões'],
    ['bot?o', 'botão'],
    ['BOT?O', 'BOTÃO'],
    ['B?SICAS', 'Básicas'],
    ['Cr?tica', 'Crítica'],
    ['din?mico', 'dinâmico'],
    ['Fa?a', 'Faça'],
    ['gar?om', 'garçom'],
    ['G?nero', 'Gênero'],
    ['S?o', 'São'],
    ['SE??O', 'SEÇÃO'],
    ['Voc?', 'Você'],
    ['n?o', 'não'],
    ['?nico', 'único'],
    ['N?o', 'Não'],
    ['?s ', 'é '],
    ['?s.', 'és.'],
    // Lowercases e variações que faltavam na primeira passada
    ['Coment?rio', 'Comentário'],
    ['Informa??es', 'Informações'],
    ['LOCALIZA??O', 'LOCALIZAÇÃO'],
    ['M?LTIPLOS', 'MÚLTIPLOS'],
    ['usu?rio', 'usuário'],
    ['Usu?rio', 'Usuário'],
    ['sele??es', 'seleções'],
    ['sele??o', 'seleção'],
    ['avalia??es', 'avaliações'],
    ['Notifica??es', 'Notificações'],
    ['fun??o', 'função'],
    ['Fun??o', 'Função'],
    ['t?tulo', 'título'],
    // Emojis usados como separadores
    ['?? Informa??es', '📋 Informações'],
    ['?carregarVagasTemp ? declarado', '⚠️ carregarVagasTemp é declarado'],
    ['?? Dica:', '💡 Dica:'],
    ['? Reserva ou fechar', 'à Reserva ou fechar'],
    ['?? FUNÇÃO PARA CARREGAR', '📢 FUNÇÃO PARA CARREGAR'],
    ['?? Notifica??es carregadas', '📢 Notificações carregadas'],
    ['?? FUNÇÃO CORRIGIDA', '🎨 FUNÇÃO CORRIGIDA'],
    ["? ' + exp.descricao", "• ' + exp.descricao"],
    ["? Local:</strong> N?o informado", "📍 Local:</strong> Não informado"],
    // Atlhos que sobraram (símbolos usados como separador)
    ['Inteligente ? Sele', 'Inteligente • Sele'],
    ['Avalia??o ?</button>', 'Avaliação →</button>'],
    ['s? ? enviada ao servidor', 'só é enviada ao servidor'],
    ['? RENDERIZAR', '⭐ RENDERIZAR'],
    ['?? FUN??O', '📢 FUNÇÃO'],
    ['??? PROTE??O', '🛡️ PROTEÇÃO'],
    ['?? MODAL', '👥 MODAL'],
    ['Minhas Experi?ncias', 'Minhas Experiências']
];

let texto = fs.readFileSync(ARQUIVO, 'utf8');
let total = 0;

for (const [de, para] of MAPA) {
    const alvo = de.split('?').join(R);
    const ocorrencias = texto.split(alvo).length - 1;
    if (ocorrencias === 0) continue;
    texto = texto.split(alvo).join(para);
    total += ocorrencias;
    process.stdout.write(`${ocorrencias}x  ${de} -> ${para}\n`);
}

// "s?" isolado = "só"
texto = texto.replace(new RegExp(`\\bs${R}\\b`, 'g'), 'só');
// "s<FFFD> " no comentário de delegação já tratado acima.

fs.writeFileSync(ARQUIVO, texto, 'utf8');

const restantes = (texto.match(new RegExp(R, 'g')) || []).length;
console.log(`\nSubstituicoes: ${total} | U+FFFD restantes: ${restantes}`);

if (restantes > 0) {
    const linhas = texto.split('\n');
    linhas.forEach((linha, i) => {
        if (linha.includes(R)) console.log(`${i + 1}: ${linha.trim()}`);
    });
}
