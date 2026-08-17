# secret-scanner

Ferramenta de linha de comando em Python que varre um diretório (ou repositório) procurando senhas, chaves de API e tokens expostos no código, e gera um relatório do que encontrou e onde.

## Por que esse projeto

É o terceiro de três projetos que estou construindo para reforçar meu portfólio para vagas de estágio em backend. Os dois primeiros ([task-manager-api](https://github.com/pedropz7/task-manager-api) e [bank-api](https://github.com/pedropz7/bank-api)) são APIs REST genéricas/fintech; esse aqui é deliberadamente diferente — uma ferramenta de segurança, área que quero seguir no futuro e que a maioria dos candidatos a estágio não costuma explorar em portfólio. A ideia não foi só "escanear texto com regex", mas reproduzir a técnica real usada por ferramentas como TruffleHog, Gitleaks e detect-secrets: combinar regras de assinatura conhecidas com detecção por entropia para pegar segredos genéricos.

## O que a ferramenta faz

- Varre recursivamente um diretório (ou um único arquivo), pulando automaticamente pastas como `.git`, `node_modules`, `venv`, `dist`, arquivos binários etc.
- Detecta **segredos conhecidos** por assinatura: chaves AWS, tokens do GitHub e Slack, chaves do Google e da Stripe, blocos de chave privada, JWTs, strings de conexão de banco com credenciais embutidas, e atribuições genéricas de API key/senha.
- Detecta **segredos genéricos** (sem formato conhecido) por **entropia de Shannon**: strings entre aspas, longas e "aleatórias demais para serem texto normal" também são sinalizadas.
- Gera relatório em **texto** (colorido no terminal) ou **JSON** (pra integrar com outra ferramenta/CI).
- **Nunca imprime o segredo completo por padrão** — o relatório vem redigido (`AKIA...MNOP`); é preciso pedir `--reveal` explicitamente.
- Suporta uma allowlist (`.secretscanignore`) para caminhos inteiros e um marcador inline (`# secret-scanner:ignore`) pra silenciar um falso positivo específico numa linha.
- Sai com código de erro configurável (`--fail-on`), pensado pra rodar como *gate* em CI ou hook de pre-commit.

## Como funciona (a técnica por trás)

1. **Regras de assinatura** (`patterns.py`): cada regra é um regex amarrado ao formato real de um provedor — prefixo, tamanho, charset (ex.: uma AWS Access Key sempre começa com `AKIA` e tem 20 caracteres). Isso mantém a taxa de falso positivo baixa, mas só cobre formatos conhecidos.
2. **Entropia de Shannon** (`entropy.py`): para o resto — um segredo genérico não tem prefixo reconhecível. A ferramenta calcula a entropia (aleatoriedade, em bits por caractere) de toda string longa entre aspas; acima de um limiar, ela é sinalizada como "possível segredo". O limiar é sensível ao charset: uma string hexadecimal satura a entropia perto de 4 bits/caractere (alfabeto de 16 símbolos), então usa um limiar mais baixo (3.0) do que uma string base64/mista (4.5).
3. **Deduplicação**: quando as duas técnicas batem na mesma string (ex.: uma chave da Stripe também é "aleatória o bastante"), só a regra de assinatura é reportada — evita contar o mesmo segredo duas vezes.

## Como rodar localmente

Pré-requisitos: Python 3.10+.

```bash
# 1. Clone o repositório
git clone <url-do-repositorio>
cd secret-scanner

# 2. Crie e ative o ambiente virtual
python -m venv venv
source venv/Scripts/activate   # Windows (Git Bash)
# venv\Scripts\activate.bat    # Windows (cmd)
# source venv/bin/activate     # Linux/Mac

# 3. Instale o pacote em modo editável (com as dependências de desenvolvimento)
pip install -e ".[dev]"

# 4. Rode a ferramenta
secret-scanner /caminho/para/o/repositorio/a/escanear
```

### Rodando os testes e o linter

```bash
pytest
ruff check .
```

## Uso

```bash
secret-scanner <caminho> [opções]

  --format {text,json}       Formato do relatório (padrão: text)
  --output ARQUIVO           Salva o relatório num arquivo em vez de imprimir
  --fail-on {critical,high,medium,low,none}
                              Severidade mínima que faz sair com código != 0 (padrão: high)
  --reveal                    Mostra o valor completo do segredo (por padrão, é redigido)
  --no-entropy                 Desativa a detecção por entropia, usa só as regras conhecidas
  --min-entropy-length N       Tamanho mínimo de string considerado na checagem de entropia
  --ignore-file ARQUIVO         Arquivo de ignore (padrão: .secretscanignore na raiz escaneada)
  --no-color                    Desativa cores no relatório em texto
```

### Exemplos

```bash
# Escanear o diretório atual, relatório em texto no terminal
secret-scanner .

# Gerar um relatório JSON pra consumir em outra ferramenta
secret-scanner . --format json --output relatorio.json

# Rodar como gate de CI: só falha se achar algo CRITICAL
secret-scanner . --fail-on critical

# Modo "auditoria": nunca falha, só reporta (útil pra primeira varredura de um repo antigo)
secret-scanner . --fail-on none
```

### Ignorando falsos positivos

Arquivo inteiro ou pasta — crie um `.secretscanignore` na raiz do que está sendo escaneado:

```
# .secretscanignore — um padrão glob por linha
tests/fixtures/*
*.lock
```

Linha específica — comente com o marcador na própria linha:

```python
DEBUG_TOKEN = "ghp_exemplo_nao_e_real_1234567890"  # secret-scanner:ignore
```

### Testando contra o próprio repositório

Os testes usam fixtures com segredos **propositalmente falsos** (`tests/fixtures/`) — rodar a ferramenta contra o próprio projeto é uma boa demonstração de que ela funciona:

```bash
secret-scanner . --fail-on none
```

## Estrutura do projeto

```
secret-scanner/
├── src/secret_scanner/
│   ├── models.py       # Finding, Severity
│   ├── patterns.py     # regras de assinatura (regex por provedor)
│   ├── entropy.py       # detecção por entropia de Shannon
│   ├── ignore.py         # .secretscanignore, marcador inline, filtros de binário/diretório
│   ├── scanner.py         # orquestra: percorre arquivos, aplica regras, deduplica
│   ├── report.py           # formatação texto/JSON + redação do segredo
│   └── cli.py                # argparse: entrada de linha de comando
├── tests/
│   ├── fixtures/               # segredos FALSOS usados nos testes
│   └── test_*.py
├── pyproject.toml
└── .gitignore
```

## Decisões técnicas

- **Zero dependências de runtime**: só biblioteca padrão do Python. Numa ferramenta de segurança, cada dependência de terceiros é superfície de ataque (supply-chain) a mais pra confiar — não faz sentido puxar um framework pesado só pra rodar regex e andar em diretórios.
- **Redação por padrão, `--reveal` como opt-in**: um relatório é exatamente o tipo de arquivo que acaba sendo commitado, colado num ticket ou compartilhado em tela. Nunca imprimir o segredo completo por padrão é a escolha mais segura, mesmo custando um pouco de conveniência.
- **Entropia sensível ao charset**: usar o mesmo limiar de entropia pra qualquer string seria ingênuo — uma string hexadecimal aleatória nunca passa de ~4 bits/caractere (só 16 símbolos possíveis), então o limiar pra hex é mais baixo que o genérico. Essa é a mesma lógica usada pelas ferramentas reais da categoria (ex.: os plugins Hex/Base64 do `detect-secrets`).
- **Deduplicação assinatura vs. entropia**: sem isso, qualquer segredo que já bate com uma regra conhecida (ex.: uma chave da Stripe) apareceria *de novo* como "string de alta entropia", inflando o relatório com o mesmo achado sob dois nomes.
- **`.secretscanignore` é um subconjunto simplificado do `.gitignore`**, não a especificação completa (sem negação, sem âncoras de diretório). Implementar o gitignore de verdade é surpreendentemente complexo; um subconjunto com `fnmatch` cobre o caso comum sem precisar de uma dependência extra.
- **`--fail-on` com saída não-zero**: pensado desde o início pra rodar em CI/pre-commit, não só interativamente — é assim que uma ferramenta desse tipo é usada de verdade (bloqueando um PR com uma chave exposta, por exemplo).
- **Fixar UTF-8 no stdout/stderr**: no Windows, o console usa por padrão o codepage do sistema (aqui, `cp1252`), o que corrompia os acentos do português nas mensagens da CLI. `sys.stdout.reconfigure(encoding="utf-8")` resolve isso de forma portátil (é um no-op onde o stdout já é UTF-8).
