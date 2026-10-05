# Protocolo do envelope digital assinado

Este documento descreve, byte a byte, como o programa cria e abre o envelope. O objetivo é
permitir que qualquer implementação (em qualquer linguagem) produza e leia envelopes idênticos.

## Notação

| Símbolo | Significado |
|---|---|
| `COD(x)` | codificação textual de `x` em Base64 ou Hex, conforme `parametros.codificacao` |
| `DEC(s)` | operação inversa: texto Base64/Hex para bytes |
| `ascii(s)` | bytes ASCII do texto `s` (o texto Base64/Hex só contém caracteres ASCII) |
| `utf8(t)` | bytes UTF-8 do texto em claro |

## Algoritmos

| Função | Especificação |
|---|---|
| Cifra simétrica | AES-256 (chave de 32 bytes), modo CBC, IV de 16 bytes |
| Padding simétrico | PKCS#7 com bloco de 16 bytes (equivalente ao "PKCS#5" de muitas bibliotecas) |
| Cifra da chave de sessão | RSAES-OAEP (PKCS#1 v2.2), hash `hash_oaep`, **MGF1 com o mesmo hash**, rótulo (label) vazio |
| Assinatura | RSASSA-PKCS1-v1_5, hash `hash_assinatura` |
| Hashes aceitos | `SHA-256`, `SHA-512` |
| Codificações aceitas | `Base64` (RFC 4648, alfabeto padrão com `=`), `Hex` |
| Chaves | RSA em PEM: pública em SubjectPublicKeyInfo (`BEGIN PUBLIC KEY`) ou PKCS#1 (`BEGIN RSA PUBLIC KEY`); privada em PKCS#8 (`BEGIN PRIVATE KEY`, opcionalmente cifrada) ou PKCS#1 (`BEGIN RSA PRIVATE KEY`) |

## Criação (remetente)

Entradas: texto em claro (UTF-8), pública do destinatário (`PubD`) e privada do remetente (`PrivR`).

```
1. K  ← 32 bytes aleatórios                          (chave de sessão AES-256)
   IV ← 16 bytes aleatórios
2. Ktxt ← COD(K)                                     (44 caracteres em Base64, 64 em Hex)
3. chave_sessao     ← COD( RSA-OAEP-Encrypt(PubD, ascii(Ktxt)) )
4. C                ← AES-256-CBC-Encrypt(K, IV, PKCS7(utf8(texto)))
   mensagem_cifrada ← COD(C)
5. assinatura       ← COD( RSA-PKCS1v15-Sign(PrivR, ascii(mensagem_cifrada)) )
6. iv               ← COD(IV)
```

Pontos que mais causam incompatibilidade:

- **Passo 3:** o RSA cifra o **texto** codificado da chave (`Ktxt`), e não os 32 bytes brutos.
  É o que o enunciado define ("cifrar a chave de sessão codificada") e o que o CyberChef faz
  naturalmente, já que o campo *Key* do AES aceita a chave em Base64 ou Hex.
- **Passo 5:** a assinatura é calculada sobre o **texto** do campo `mensagem_cifrada`, exatamente
  como ele aparece no JSON, e não sobre os bytes brutos do criptograma.
- Uma única codificação vale para **todos** os campos do envelope.

## Abertura (destinatário)

Entradas: envelope, privada do destinatário (`PrivD`) e pública do remetente (`PubR`).

```
1. Ler e validar o JSON (seções, campos obrigatórios, valores permitidos).
2. RSA-PKCS1v15-Verify(PubR, ascii(mensagem_cifrada), DEC(assinatura))
      → se falhar: PARAR com "integridade violada" (nada é decifrado)
3. Ktxt ← RSA-OAEP-Decrypt(PrivD, DEC(chave_sessao));   K ← DEC(Ktxt);   exigir |K| = 32
4. texto ← unPKCS7( AES-256-CBC-Decrypt(K, DEC(iv), DEC(mensagem_cifrada)) );   exigir |IV| = 16
```

## Validação do JSON

| Campo | Regra |
|---|---|
| `parametros.algoritmo_simetrico` | deve ser `AES-256-CBC` (se ausente: aviso e assume o valor fixo) |
| `parametros.padding_simetrico` | deve ser `PKCS7` (aceita também `PKCS5`/`PKCS#7`; se ausente: aviso) |
| `parametros.algoritmo_chave` | deve ser `RSA-OAEP` (se ausente: aviso) |
| `parametros.algoritmo_assinatura` | deve ser `RSA` (se ausente: aviso) |
| `parametros.hash_oaep` | **obrigatório**: `SHA-256` ou `SHA-512` |
| `parametros.hash_assinatura` | **obrigatório**: `SHA-256` ou `SHA-512` |
| `parametros.codificacao` | **obrigatório**: `Base64` ou `Hex` |
| `envelope.iv`, `chave_sessao`, `mensagem_cifrada`, `assinatura` | **obrigatórios**, textos não vazios na codificação declarada |

Campos extras são ignorados. Os nomes dos parâmetros são comparados sem diferenciar
maiúsculas e minúsculas, hífens ou sublinhados (`sha256`, `SHA_256` e `SHA-256` são equivalentes).

## Formato canônico de escrita

- Base64 padrão em **uma única linha**, com `=` de preenchimento.
- Hex em **minúsculas**, sem separadores.
- JSON em UTF-8, indentado com 4 espaços. A formatação do arquivo não afeta a assinatura,
  porque ela cobre o *valor* do campo `mensagem_cifrada`, e não o arquivo.

## Tolerância na leitura

- Espaços e quebras de linha dentro dos campos codificados são ignorados na decodificação.
  A assinatura, porém, é verificada sobre o texto exato do campo.
- Hex é aceito em maiúsculas ou minúsculas.
- **Modo de compatibilidade** (sempre com aviso ao usuário):
  - se a chave de sessão decifrada tiver 32 bytes e não for um texto Base64/Hex válido,
    ela é usada como chave bruta;
  - se a chave de sessão estiver na outra codificação (por exemplo, Hex num envelope Base64),
    ela é aceita;
  - se a assinatura não conferir sobre o texto, ela é verificada sobre os bytes brutos do
    criptograma. A integridade continua garantida, porque é o mesmo criptograma assinado pela
    mesma chave; só a convenção é diferente.

## Limites

- O RSA-OAEP cifra no máximo `k − 2·hLen − 2` bytes, em que `k` é o tamanho da chave em bytes.
  Com RSA-2048: 190 bytes com SHA-256 e 126 bytes com SHA-512, o suficiente para os 44 ou 64
  caracteres de `Ktxt`. Com RSA-1024 e SHA-512, não há espaço, e o programa informa o erro.
- O texto em claro pode ter qualquer tamanho, inclusive zero (vira um bloco de padding).

## Vetor de verificação

Para conferir uma implementação, abra qualquer envelope de `exemplos/gerados/envelopes/` com as
chaves de `exemplos/gerados/chaves/`. O resultado deve ser idêntico, byte a byte, a
`exemplos/mensagem.txt`.
