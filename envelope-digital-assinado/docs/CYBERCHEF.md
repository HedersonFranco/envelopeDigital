# Envelopes no CyberChef

Este guia mostra como **abrir** um envelope gerado pelo programa e como **criar** um envelope
manualmente no [CyberChef](https://gchq.github.io/CyberChef/), usando apenas as operações dele.
As receitas abaixo foram validadas com o CyberChef v11.5 nas 8 combinações de parâmetros, nos
dois sentidos.

> **Atenção ao colar valores:** copie o conteúdo entre aspas do JSON, **sem as aspas** e sem
> espaços ou quebras de linha no fim.

Nas receitas, `From Base64` / `To Base64` valem para envelopes em Base64. Para envelopes em Hex,
use `From Hex` / `To Hex` (Delimiter: `None`) e selecione **Hex** nos campos *Key* e *IV* do AES.

---

## Abrir um envelope

### 1. Verificar a assinatura

| | |
|---|---|
| **Input** | valor de `assinatura` |
| **Receita** | `From Base64` → `RSA Verify` |
| RSA Public Key (PEM) | conteúdo de `remetente_publica.pem` |
| Message | valor de `mensagem_cifrada` (o texto codificado, como está no JSON) |
| Message format | `Raw` |
| Message Digest Algorithm | valor de `hash_assinatura` (`SHA-256` ou `SHA-512`) |
| **Saída esperada** | `Verified OK` |

Se a saída for `Verification Failure`, o envelope foi alterado ou a chave não é a do remetente.
Pelo protocolo, não se deve continuar nesse caso.

### 2. Recuperar a chave de sessão

| | |
|---|---|
| **Input** | valor de `chave_sessao` |
| **Receita** | `From Base64` → `RSA Decrypt` |
| RSA Private Key (PEM) | conteúdo de `destinatario_privada.pem` (aceita `BEGIN PRIVATE KEY`) |
| Key Password | em branco (ou a senha, se a chave tiver uma) |
| Encryption Scheme | `RSA-OAEP` |
| Message Digest Algorithm | valor de `hash_oaep` |
| **Saída** | a chave de sessão **codificada**: 44 caracteres Base64 ou 64 caracteres Hex |

### 3. Decifrar a mensagem

| | |
|---|---|
| **Input** | valor de `mensagem_cifrada` |
| **Receita** | `From Base64` → `AES Decrypt` |
| Key | saída do passo 2, com a opção **Base64** (ou **Hex**) |
| IV | valor de `iv`, com a opção **Base64** (ou **Hex**) |
| Mode | `CBC` |
| Input / Output | `Raw` / `Raw` |
| **Saída** | o texto original |

Se acentos aparecerem trocados, acrescente `Decode text` (UTF-8) ao fim da receita.

---

## Criar um envelope (para o programa abrir)

### 1. Gerar a chave de sessão e o IV

- Chave: `Pseudo-Random Number Generator` (Number of bytes: `32`, Output as: `Raw`) → `To Base64`.
  Anote o resultado: é a **chave codificada** (`Ktxt`).
- IV: `Pseudo-Random Number Generator` (Number of bytes: `16`, Output as: `Raw`) → `To Base64`.
  Esse é o valor do campo `iv`.

Para Hex, use `Output as: Hex` diretamente.

### 2. `chave_sessao`

| | |
|---|---|
| **Input** | `Ktxt` (o texto Base64/Hex da chave, e não os bytes brutos) |
| **Receita** | `RSA Encrypt` → `To Base64` |
| RSA Public Key (PEM) | conteúdo de `destinatario_publica.pem` |
| Encryption Scheme | `RSA-OAEP` |
| Message Digest Algorithm | `SHA-256` ou `SHA-512` (será o `hash_oaep`) |

### 3. `mensagem_cifrada`

| | |
|---|---|
| **Input** | o texto em claro |
| **Receita** | `AES Encrypt` → `To Base64` |
| Key | `Ktxt`, com a opção **Base64** (ou **Hex**) |
| IV | o IV do passo 1, com a mesma opção |
| Mode | `CBC` |
| Input / Output | `Raw` / `Raw` |

### 4. `assinatura`

| | |
|---|---|
| **Input** | a saída do passo 3 (o **texto** Base64/Hex de `mensagem_cifrada`) |
| **Receita** | `RSA Sign` → `To Base64` |
| RSA Private Key (PEM) | conteúdo de `remetente_privada.pem` |
| Message Digest Algorithm | `SHA-256` ou `SHA-512` (será o `hash_assinatura`) |

### 5. Montar o JSON

Preencha o modelo com os valores obtidos e com os hashes e a codificação escolhidos:

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
        "iv": "<passo 1>",
        "chave_sessao": "<passo 2>",
        "mensagem_cifrada": "<passo 3>",
        "assinatura": "<passo 4>"
    }
}
```

Depois, abra com:
`envelope decifrar -e envelope.json --priv-destinatario destinatario_privada.pem --pub-remetente remetente_publica.pem --mostrar`
