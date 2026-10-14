# Envelope Digital Assinado

Programa para criar e abrir **envelopes digitais assinados** com criptografia híbrida:
o texto é cifrado com **AES-256-CBC**, a chave de sessão é protegida com **RSA-OAEP**
e o criptograma é assinado com **RSA (PKCS#1 v1.5) + SHA-2**, na abordagem
**Encrypt-then-Sign**. O resultado é um único arquivo **JSON**, interoperável com
programas de outros grupos, com o [CyberChef](https://gchq.github.io/CyberChef/) e com o OpenSSL.

> Trabalho da disciplina
> **Segurança em Sistemas Computacionais**; Professor: Carlos André Batista de Carvalho.
>
> **Integrantes:** Hederson Franco Benvindo Lima · João Guilherme Oliveira Pereira · David Soares Pereira Junior

---

## Sumário

1. [Funcionalidades](#funcionalidades)
2. [Requisitos](#requisitos)
3. [Instalação](#instalação)
4. [Uso rápido](#uso-rápido)
5. [Referência dos comandos](#referência-dos-comandos)
6. [Formato do envelope](#formato-do-envelope)
7. [Estrutura do projeto](#estrutura-do-projeto)
8. [Arquivos de teste](#arquivos-de-teste)
9. [Testes automatizados](#testes-automatizados)
10. [Interoperabilidade](#interoperabilidade)
11. [Tratamento de erros](#tratamento-de-erros)
12. [Considerações de segurança](#considerações-de-segurança)
13. [Licença](#licença)

---

## Funcionalidades

- **Criar envelope:** gera uma chave AES-256 e um IV aleatórios, cifra o texto (AES-256-CBC
  com PKCS#7), cifra a chave de sessão com a chave pública do destinatário (RSA-OAEP com
  SHA-256 ou SHA-512, MGF1 com o mesmo hash) e assina o criptograma com a chave privada do
  remetente (RSASSA-PKCS1-v1_5 com SHA-256 ou SHA-512).
- **Abrir envelope:** valida o JSON, **verifica a assinatura antes de qualquer decifragem**,
  recupera a chave de sessão e decifra o texto.
- **Verificar** apenas a assinatura de um envelope.
- **Gerar pares de chaves** RSA em PEM (com senha opcional), compatíveis com o OpenSSL.
- Codificação **Base64** ou **Hex**, à escolha do usuário.
- Duas interfaces: **linha de comando** (subcomandos) e **menu interativo**.
- Tratamento de erros completo: feito com um glorioso *stack trace*.

## Requisitos

- **Python 3.14.5 ou superior** (testado no Python 3.14.5)
- Biblioteca [`cryptography`](https://cryptography.io/) ≥ 41
- Windows, Linux ou macOS
- Opcional: `pytest` para rodar os testes e OpenSSL 3.x para os testes de interoperabilidade

## Instalação

```bash
# 1. Entre na pasta do projeto
cd envelope-digital-assinado

# 2. (Recomendado) Crie e ative um ambiente virtual
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
.venv\Scripts\activate           # Windows

# 3. Instale a dependência
pip install -r requirements.txt
```

Depois disso, o programa pode ser executado de duas formas:

| Forma | Comando |
|---|---|
| Sem instalar o pacote | `python envelope.py` |
| Instalando o pacote (cria o comando `envelope`) | `pip install -e .` e depois `envelope` |

> Nos exemplos abaixo, use `python envelope.py` no lugar de `envelope` se não instalou o pacote.
> No Linux/macOS, pode ser necessário usar `python3`.

## Uso rápido

### Menu interativo

Execute sem argumentos e siga as perguntas. O valor entre `[colchetes]` é o padrão (basta pressionar Enter):

```bash
python envelope.py
```

```
==============================================================
   ENVELOPE DIGITAL ASSINADO  v1.0.0
   AES-256-CBC  +  RSA-OAEP  +  Assinatura RSA (Encrypt-then-Sign)
==============================================================

  1) Gerar par de chaves RSA
  2) Criar envelope   (cifrar e assinar)
  3) Abrir envelope   (verificar assinatura e decifrar)
  4) Apenas verificar a assinatura de um envelope
  5) Ajuda
  0) Sair
```

### Linha de comando: fluxo completo

```bash
# 1. Gerar os pares de chaves (pasta ./chaves)
envelope gerar-chaves --nome remetente
envelope gerar-chaves --nome destinatario

# 2. REMETENTE cria o envelope: pública do destinatário + privada do remetente
envelope cifrar -e exemplos/mensagem.txt \
    --pub-destinatario chaves/destinatario_publica.pem \
    --priv-remetente   chaves/remetente_privada.pem \
    --hash-oaep SHA-256 --hash-assinatura SHA-256 --codificacao Base64 \
    -o envelope.json

# 3. DESTINATÁRIO abre o envelope: privada do destinatário + pública do remetente
envelope decifrar -e envelope.json \
    --priv-destinatario chaves/destinatario_privada.pem \
    --pub-remetente     chaves/remetente_publica.pem \
    -o mensagem_decifrada.txt --mostrar
```

No Windows (cmd), troque a barra invertida `\` de continuação de linha por `^`, ou escreva o comando em uma única linha.

As chaves também podem ser geradas com o OpenSSL:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out remetente_privada.pem
openssl pkey -in remetente_privada.pem -pubout -out remetente_publica.pem
```

## Referência dos comandos

Use `envelope COMANDO --help` para ver todas as opções.

### `gerar-chaves`

| Opção | Descrição | Padrão |
|---|---|---|
| `--nome NOME` | prefixo dos arquivos: `NOME_privada.pem` e `NOME_publica.pem` | *(obrigatório)* |
| `--pasta PASTA` | pasta de destino | `chaves` |
| `--bits BITS` | tamanho da chave (mínimo 2048) | `2048` |
| `--com-senha` | protege a chave privada com senha (pergunta no terminal) | não |
| `--sobrescrever` | substitui um par existente | não |

### `cifrar` (criação do envelope)

| Opção | Descrição | Padrão |
|---|---|---|
| `-e, --entrada ARQUIVO` | arquivo de texto UTF-8 a cifrar | — |
| `-t, --texto TEXTO` | alternativa a `-e`: texto digitado na linha de comando | — |
| `--pub-destinatario PEM` | chave pública do destinatário | *(obrigatório)* |
| `--priv-remetente PEM` | chave privada do remetente | *(obrigatório)* |
| `-o, --saida JSON` | arquivo do envelope | `envelope.json` |
| `--hash-oaep HASH` | `SHA-256` ou `SHA-512` | `SHA-256` |
| `--hash-assinatura HASH` | `SHA-256` ou `SHA-512` | `SHA-256` |
| `--codificacao COD` | `Base64` ou `Hex` | `Base64` |
| `--pedir-senha` | pergunta a senha da chave privada | não |

### `decifrar` (abertura do envelope)

| Opção | Descrição | Padrão |
|---|---|---|
| `-e, --envelope JSON` | arquivo do envelope | *(obrigatório)* |
| `--priv-destinatario PEM` | chave privada do destinatário | *(obrigatório)* |
| `--pub-remetente PEM` | chave pública do remetente | *(obrigatório)* |
| `-o, --saida ARQUIVO` | arquivo do texto decifrado | `mensagem_decifrada.txt` |
| `--mostrar` | também exibe o texto no terminal | não |
| `--pedir-senha` | pergunta a senha da chave privada | não |

Os parâmetros (hashes e codificação) são lidos do próprio JSON.

### `verificar`

Confere só a assinatura (não precisa da chave privada do destinatário):
`envelope verificar -e envelope.json --pub-remetente chaves/remetente_publica.pem`

## Formato do envelope

O arquivo segue exatamente a estrutura definida no enunciado:

```json
{
    "parametros": {
        "algoritmo_simetrico": "AES-256-CBC",
        "padding_simetrico": "PKCS7",
        "algoritmo_chave": "RSA-OAEP",
        "hash_oaep": "SHA-256",
        "algoritmo_assinatura": "RSA",
        "hash_assinatura": "SHA-256",
        "codificacao": "Base64"
    },
    "envelope": {
        "iv": "<IV de 16 bytes, codificado>",
        "chave_sessao": "<RSA-OAEP(pública do destinatário, chave AES CODIFICADA), codificado>",
        "mensagem_cifrada": "<AES-256-CBC(texto), codificado>",
        "assinatura": "<RSA-PKCS1v15(privada do remetente, TEXTO de mensagem_cifrada), codificado>"
    }
}
```

O passo a passo byte a byte, com todas as convenções, está em [docs/PROTOCOLO.md](PROTOCOLO.md).

## Estrutura do projeto

```
envelope-digital-assinado/
├── envelope.py                  # atalho: executa o programa sem instalar
├── src/envelope_digital/
│   ├── cli.py                   # linha de comando (argparse) e códigos de saída
│   ├── menu.py                  # menu interativo
│   ├── operacoes.py             # operações de alto nível (arquivos → protocolo)
│   ├── envelope.py              # protocolo: criar, validar, verificar e abrir o envelope
│   ├── cripto.py                # primitivas: AES-CBC, RSA-OAEP, assinatura PKCS#1 v1.5
│   ├── codificacao.py           # Base64 / Hex
│   ├── chaves.py                # leitura, validação e geração de chaves PEM
│   ├── erros.py                 # exceções com mensagem e dica de correção
│   └── saida.py                 # mensagens padronizadas no terminal
├── tests/                       # testes automatizados (pytest)
├── exemplos/
│   ├── mensagem.txt             # texto de exemplo (UTF-8, com acentos e emoji)
│   └── gerados/                 # chaves e envelopes de teste (ver abaixo)
├── scripts/
│   ├── gerar_exemplos.py        # (re)gera exemplos/gerados/
│   └── empacotar_entrega.py     # gera o .zip de entrega no SIGAA
├── docs/
│   ├── PROTOCOLO.md             # especificação detalhada e convenções
│   └── CYBERCHEF.md             # como abrir e criar envelopes no CyberChef
├── pyproject.toml / requirements.txt
└── LICENSE
```

O código é organizado em camadas: só `cli.py` e `menu.py` conversam com o usuário. As demais
camadas lançam exceções da hierarquia `EnvelopeErro`, que a interface captura e exibe.

## Arquivos de teste

A pasta `exemplos/gerados/` (já incluída no pacote de entrega; pode ser recriada com
`python scripts/gerar_exemplos.py`) contém:

```
exemplos/gerados/
├── chaves/
│   ├── remetente_privada.pem      remetente_publica.pem
│   ├── destinatario_privada.pem   destinatario_publica.pem
│   └── intruso_privada.pem        intruso_publica.pem      # para simular chave errada
├── envelopes/                      # 8 envelopes válidos, um por combinação de parâmetros
│   ├── envelope_oaep-sha-256_assin-sha-256_base64.json
│   ├── envelope_oaep-sha-256_assin-sha-256_hex.json
│   ├── ...
│   └── envelope_oaep-sha-512_assin-sha-512_hex.json
└── adulterados/                    # defeitos propositais → erro tratado
    ├── 01_criptograma_alterado.json         # → INTEGRIDADE VIOLADA (código 3)
    ├── 02_assinatura_alterada.json          # → INTEGRIDADE VIOLADA (código 3)
    ├── 03_chave_sessao_alterada.json        # → falha ao decifrar a chave de sessão
    ├── 04_hash_assinatura_divergente.json   # → INTEGRIDADE VIOLADA (código 3)
    ├── 05_parametro_invalido.json           # → codificação não suportada
    ├── 06_campo_ausente.json                # → campo obrigatório ausente
    └── 07_json_truncado.json                # → JSON inválido
```

Todos os envelopes foram criados a partir de `exemplos/mensagem.txt`, com a pública do
destinatário e a privada do remetente. Para abrir qualquer um deles:

```bash
envelope decifrar -e exemplos/gerados/envelopes/envelope_oaep-sha-512_assin-sha-256_hex.json \
    --priv-destinatario exemplos/gerados/chaves/destinatario_privada.pem \
    --pub-remetente     exemplos/gerados/chaves/remetente_publica.pem --mostrar
```

Para simular chaves erradas, use as chaves `intruso_*` no lugar de uma delas.

> As chaves de `exemplos/gerados/` existem **apenas para teste** e não devem proteger nada real.

## Testes automatizados

```bash
pip install pytest      # ou: pip install -e ".[dev]"
python -m pytest
```

A bateria (122 testes) cobre:

- **ida e volta nas 8 combinações** (2 hashes OAEP × 2 hashes de assinatura × 2 codificações);
- **conformidade com o enunciado**, verificando cada passo de forma independente (o RSA cifra
  a chave *codificada*; a assinatura é sobre o *texto* do criptograma; o IV tem 16 bytes);
- **verificação antes da decifragem** (nenhuma decifragem ocorre se a assinatura falhar);
- **adulteração** de cada campo, chaves trocadas ou erradas, parâmetros divergentes, JSON malformado;
- **chaves**: arquivo inexistente, PEM corrompido, chave não RSA, chave com senha, formatos PKCS#1 e PKCS#8;
- **interface**: códigos de saída, menu interativo e ausência de *stack trace* em todos os casos de erro;
- **interoperabilidade com o OpenSSL** nos dois sentidos, nas 8 combinações (pulados se o OpenSSL 3 não estiver instalado).

## Interoperabilidade

| Ferramenta | Resultado |
|---|---|
| **CyberChef** v11.5 | envelopes do programa abertos pelo CyberChef e envelopes montados só com operações do CyberChef abertos pelo programa, nas 8 combinações |
| **OpenSSL** 3.x | `dgst -verify`/`-sign`, `pkeyutl` com OAEP e `enc -aes-256-cbc`, nos dois sentidos, nas 8 combinações (testes automatizados) |

O passo a passo para abrir e criar um envelope manualmente no CyberChef está em
[docs/CYBERCHEF.md](CYBERCHEF.md).

**Convenções adotadas** (detalhes em [docs/PROTOCOLO.md](PROTOCOLO.md)):

- **Na escrita**, o programa segue o formato canônico: Base64 padrão (RFC 4648, com `+/` e `=`)
  em uma única linha, Hex em minúsculas e JSON em UTF-8.
- **Na leitura**, ele é tolerante: ignora espaços e quebras de linha nos campos, aceita Hex em
  maiúsculas e aceita variações de escrita nos parâmetros (`sha256`, `HEX`, `PKCS5`...).
- **Modo de compatibilidade:** se outro programa cifrar a chave de sessão em bytes brutos (em vez
  do texto codificado) ou assinar os bytes brutos do criptograma (em vez do texto codificado),
  o envelope ainda é aberto, mas com um **aviso** explicando a divergência do protocolo.

## Tratamento de erros

Toda falha previsível vira uma mensagem com o que aconteceu e uma **dica de correção**. Exemplo:

```
[ERRO] INTEGRIDADE VIOLADA: a assinatura digital do criptograma não confere.
       Dica: O envelope foi alterado, a chave pública não é a do REMETENTE, ou
       'hash_assinatura' não corresponde ao usado na assinatura. Nada foi decifrado.
```

| Código de saída | Significado |
|---|---|
| `0` | sucesso |
| `1` | erro tratado (arquivo, chave, JSON, parâmetro, decifragem...) |
| `2` | uso incorreto da linha de comando |
| `3` | **assinatura inválida** (integridade violada) |
| `130` | operação interrompida pelo usuário (Ctrl+C) |

No menu interativo, um erro nunca fecha o programa: a mensagem é exibida e o menu volta.

## Considerações de segurança

- Chave de sessão e IV vêm do gerador criptográfico do sistema operacional (`os.urandom`), e um novo par é gerado para cada envelope.
- Ao abrir o envelope, a assinatura é verificada antes de qualquer decifragem. Isso impede que dados adulterados cheguem ao RSA ou ao AES e mitiga ataques do tipo *padding oracle*.
- O programa recusa gerar chaves com menos de 2048 bits e avisa quando a chave do destinatário é pequena demais para o OAEP escolhido.
- O protocolo do enunciado tem limitações conhecidas:
  - **O IV e os parâmetros não são cobertos pela assinatura.** Quem alterar o IV muda o
    primeiro bloco de 16 bytes do texto decifrado sem que a assinatura acuse. Um teste
    automatizado demonstra isso (`test_iv_nao_e_coberto_pela_assinatura`). Para corrigir,
    a assinatura deveria cobrir também o IV, a chave cifrada e os parâmetros.
  - **No Encrypt-then-Sign, a assinatura fica exposta.** Qualquer pessoa que intercepte o
    envelope pode verificar quem o enviou, mesmo sem conseguir lê-lo.
  - **O AES-CBC não autentica sozinho.** Neste protocolo, a integridade depende da
    assinatura. Em sistemas reais, um modo autenticado como o AES-GCM seria preferível.

## Licença

Distribuído sob a licença MIT. Veja [LICENSE](../LICENSE).
