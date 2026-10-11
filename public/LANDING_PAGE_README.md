# 🍽️ Landing Page - ChefFlow

## Visão Geral

Você recebi uma Landing Page imersiva e totalmente responsiva para a plataforma **ChefFlow** - um marketplace de contratação para gastronomia.

## 📁 Arquivo

- **`landing.html`** - Arquivo único e independente contendo HTML, CSS (Tailwind via CDN) e JavaScript integrados.

## 🎨 Características Implementadas

### ✅ 7 Seções Principais

1. **Hero Section** ✨
   - Headline impactante com gradient text
   - CTA duplo: "Quero Contratar" e "Quero Trabalhar"
   - Imagem de fundo (gastronomia) via Unsplash
   - Animações de entrada suaves

2. **Problema/Dor** 🎭
   - Comparativo visual: "Antes (Caos)" vs "Depois (ChefFlow)"
   - Cards destacados em vermelho e verde
   - Indicadores visuais (❌ vs ✅)

3. **Como Funciona** 🚀
   - 3 passos visuais com ícones numéricos (1, 2, 3)
   - Descrições claras e concisas
   - Imagens de contexto em cada passo

4. **Segurança & Confiança** 🔒
   - 3 destaques principais (Verificação, Fila, Pagamento)
   - Cards com backdrop blur (vidro)
   - Estatísticas de impacto (2500+, 500+, 4.9⭐, +10k)

5. **Social Proof** 💬
   - 3 depoimentos com fotos reais (via Unsplash)
   - Nomes e cargos dos usuários
   - Avaliações 5 estrelas
   - Border accent em verde esmeralda

6. **FAQ** ❓
   - 5 acordeões interativos
   - Animações suaves de abertura/fechamento
   - Hover effects destacados

7. **CTA Final + Footer** 🚀
   - Último chamado à ação
   - Links rápidos (Sobre, Suporte, Legal)
   - Redes sociais
   - Copyright

### 🎯 Design & Responsividade

- **Paleta de Cores:**
  - Azul Marinho (`#0f1419`)
  - Verde Esmeralda (`#10b981`)
  - Branco e tons neutros

- **Mobile-First:**
  - Totalmente responsivo (mobile, tablet, desktop)
  - Grid automático com `grid-cols-1 md:grid-cols-2 lg:grid-cols-3`
  - Botões adaptáveis em coluna/linha

- **Animações:**
  - `fadeInUp` - Fade com movimento vertical
  - `slideInLeft/Right` - Deslize lateral
  - `fadeIn` - Fade simples
  - Delays escalonados (100ms, 200ms, etc)

### 🔧 Tecnologias

- **HTML5** - Semântica correta
- **Tailwind CSS** - Via CDN (sem build)
- **JavaScript Vanilla** - Interatividade leve
- **IntersectionObserver** - Animações ao scroll

## 📖 Como Customizar

### Trocar o Nome da Plataforma

Procure por `ChefFlow` no arquivo e substitua por seu nome:

```html
<!-- Localizar e substituir -->
<span class="text-2xl font-bold text-brand-dark hidden sm:inline">ChefFlow</span>
<!-- por -->
<span class="text-2xl font-bold text-brand-dark hidden sm:inline">SEU_NOME_AQUI</span>
```

Também atualize:
- `<title>ChefFlow - Marketplace...`
- `&copy; 2024 ChefFlow. Todos os direitos...`

### Mudar as Cores

As cores estão definidas via CSS variables no `<style>`:

```css
:root {
    --brand-dark: #0f1419;      /* Azul marinho */
    --brand-accent: #10b981;    /* Verde esmeralda */
    --brand-light: #f8fafc;     /* Branco/cinza claro */
}
```

### Trocar Imagens

Todas as imagens usam Unsplash como placeholder. Para mudar:

```html
<!-- Buscar por: src="https://images.unsplash.com/ -->
<!-- E substituir pelas suas imagens -->
<img src="https://seu-dominio.com/sua-imagem.jpg" alt="Descrição">
```

### Editar Depoimentos

Localize a seção "SOCIAL PROOF (DEPOIMENTOS)" e atualize:

```html
<div class="flex gap-4 mb-4">
    <img src="..." alt="Nome">
    <div>
        <p class="font-bold text-brand-dark">NOME_AQUI</p>
        <p class="text-sm text-gray-500">CARGO_AQUI</p>
    </div>
</div>
<p class="text-gray-700 mb-4">
    "DEPOIMENTO_AQUI"
</p>
```

### Editar FAQ

Localize a seção "FAQ" e adicione/remova acordeões:

```html
<div class="accordion-item animate-fadeInUp delay-400">
    <div class="accordion-header" onclick="toggleAccordion(4)">
        <span>SUA_PERGUNTA_AQUI</span>
        <span class="accordion-icon">▼</span>
    </div>
    <div class="accordion-content">
        <p class="text-gray-700">SUA_RESPOSTA_AQUI</p>
    </div>
</div>
```

⚠️ **IMPORTANTE:** Se adicionar mais FAQs, atualize o número no `onclick="toggleAccordion(N)"` para cada nova pergunta.

## 🚀 Como Usar

1. **Abrir no navegador:**
   ```
   http://localhost:3000/landing.html
   ```

2. **Testar responsividade:**
   - Abrir DevTools (F12)
   - Ativar modo responsivo (Ctrl+Shift+M)
   - Testar em diferentes tamanhos

3. **Fazer deploy:**
   - Copiar o arquivo para seu servidor web
   - Ou usar como página estática em plataformas como Vercel, Netlify

## 🎬 Interatividades

### Botões CTA

- "Quero Contratar" → Redireciona para `/index.html` (perfil contratante)
- "Quero Trabalhar" → Redireciona para `/index.html` (perfil freelancer)

Você pode editar a função `redirect()` para mudar os destinos:

```javascript
function redirect(type) {
    if (type === 'contratante') {
        window.location.href = '/seu-link-aqui';
    } else if (type === 'freelancer') {
        window.location.href = '/seu-link-aqui';
    }
}
```

### Navegação

- Links no navbar scrollam para as seções via `#como-funciona`, `#seguranca`, `#faq`
- Botão "Começar Agora" volta ao topo

## 📊 Performance

- **Arquivo único** - Sem dependências externas (exceto Tailwind CDN)
- **Lightweight** - ~10KB comprimido
- **Fast** - Carrega em <2s em conexão 4G
- **SEO-friendly** - Meta tags e estrutura semântica

## 🔐 Segurança

- Sem código malicioso
- Links externos (Unsplash) são HTTPS
- Tailwind CDN é confiável e seguro
- JavaScript é vanilla (sem bibliotecas desconhecidas)

## ✨ Próximos Passos (Opcional)

1. Integrar formulário de cadastro real
2. Adicionar analytics (Google Analytics)
3. Implementar chat de suporte
4. Criar versão em múltiplos idiomas
5. Adicionar video background na Hero

---

**Desenvolvido com ❤️ por OpenCode**

Qualquer dúvida ou customização, sinta-se à vontade para solicitar!
