# Passo a passo: primeiro uso pelo menu

Este guia mostra, com um exemplo, como usar o programa do começo ao fim pelo menu interativo.

**O exemplo:** a Alice quer mandar uma mensagem secreta para o Bruno. O programa garante duas coisas:
só o Bruno consegue ler, e o Bruno tem certeza de que foi a Alice quem enviou, sem nenhuma alteração.

No programa, a Alice é o `remetente` e o Bruno é o `destinatario`.

## 1. Instalar e abrir o menu

Você precisa do Python 3.14.5 ou superior. Abra o terminal **na pasta do projeto** e rode:

```bash
python -m pip install -r requirements.txt
python envelope.py
```

> No Linux ou no macOS, troque `python` por `python3`.

O menu abre assim:

```
  1) Gerar par de chaves RSA
  2) Criar envelope   (cifrar e assinar)
  3) Abrir envelope   (verificar assinatura e decifrar)
  4) Apenas verificar a assinatura de um envelope
  5) Ajuda
  0) Sair

Escolha uma opção:
```

Para escolher, digite o número e aperte Enter.

**Dica:** o valor que aparece entre `[colchetes]` é a resposta padrão, e basta apertar Enter para aceitá-lo.
Neste exemplo, quase todos os padrões já estão certos.

## 2. Criar as chaves da Alice e do Bruno (opção 1)

Escolha `1` e responda:

| Pergunta | Resposta |
|---|---|
| Nome do par | digite `remetente` |
| Pasta de destino [chaves] | Enter |
| Tamanho da chave em bits [2048] | Enter |
| Proteger a chave privada com senha? [n] | Enter |

Deve aparecer `[OK] Par de chaves RSA-2048 gerado.` Aperte Enter para voltar ao menu.

Escolha `1` de novo e repita tudo, agora com o nome `destinatario`.

A pasta `chaves/` passa a ter quatro arquivos:

| Arquivo | De quem | Pode compartilhar? |
|---|---|---|
| `remetente_privada.pem` | Alice | Não |
| `remetente_publica.pem` | Alice | Sim |
| `destinatario_privada.pem` | Bruno | Não |
| `destinatario_publica.pem` | Bruno | Sim |

Na vida real, cada pessoa gera as próprias chaves no seu computador e só entrega a pública para a outra.
Aqui tudo fica na mesma pasta para facilitar o teste.

## 3. A Alice cria o envelope (opção 2)

Escolha `2` e responda:

| Pergunta | Resposta |
|---|---|
| Origem da mensagem [arquivo] | digite `2` (digitar) |
| Digite a mensagem | `Oi, Bruno! O contrato foi aprovado.` |
| Chave PÚBLICA do destinatário | Enter |
| Chave PRIVADA do remetente | Enter |
| Hash do RSA-OAEP, Hash da assinatura e Codificação | Enter em cada uma |
| Arquivo de saída do envelope [envelope.json] | Enter |

O menu já sugere as chaves certas: a **pública do Bruno**, para que só ele consiga abrir, e a
**privada da Alice**, para assinar.

Deve aparecer:

```
[OK] Envelope criado: envelope.json (35 bytes de texto cifrados)
```

O `envelope.json` é o arquivo que a Alice enviaria ao Bruno, por e-mail por exemplo. Quem abrir esse
arquivo só vai ver texto embaralhado.

## 4. O Bruno abre o envelope (opção 3)

Escolha `3` e aperte Enter em todas as perguntas. O menu já sugere a **privada do Bruno**, para
decifrar, e a **pública da Alice**, para conferir a assinatura.

Deve aparecer:

```
[OK] Assinatura válida.
[OK] Mensagem decifrada gravada em: mensagem_decifrada.txt
  Exibir a mensagem aqui? (s/n) [s]:

----- início da mensagem -----
Oi, Bruno! O contrato foi aprovado.
------ fim da mensagem -------
```

Pronto: o Bruno leu a mensagem e sabe que ela veio da Alice sem alterações.

## 5. (Opcional) Ver a proteção funcionando (opção 4)

1. Abra o `envelope.json` num editor de texto. O menu pode continuar aberto.
2. Em `"mensagem_cifrada"`, troque uma letra do meio do texto por outra letra e salve.
3. No menu, escolha `4` e aperte Enter nas duas perguntas.

O programa recusa o envelope:

```
[ERRO] INTEGRIDADE VIOLADA: a assinatura digital do criptograma não confere.
```

Para voltar ao normal, repita o passo 3.

## Se der erro

- **`No module named 'cryptography'`**: faltou a instalação do passo 1.
- **"já existe. Sobrescrever?"**: aparece quando você repete um passo. Responda `s` para substituir o arquivo.

Para sair do menu, escolha `0`.
