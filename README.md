# Envelope Digital Assinado

Programa que cria e abre **envelopes digitais assinados**. A mensagem é cifrada
com uma chave de sessão AES-256, essa chave é protegida com a chave pública RSA do
destinatário e o criptograma é assinado com a chave privada do remetente
(*Encrypt-then-Sign*). O envelope é um arquivo JSON que também pode ser aberto no
[CyberChef](https://gchq.github.io/CyberChef/) e no OpenSSL.

Trabalho 01 da disciplina Segurança em Sistemas Computacionais (Ciência da Computação, UFPI),
prof. Carlos André Batista de Carvalho.

## Como funciona

|            Etapa           |               Algoritmo              | Chave usada |
|---|---|---|
| Cifrar a mensagem| AES-256-CBC + PKCS#7                 | chave de sessão aleatória, nova a cada envelope |
| Proteger a chave de sessão | RSA-OAEP (SHA-256 ou SHA-512)        | pública do destinatário |
| Assinar o criptograma| RSA PKCS#1 v1.5 (SHA-256 ou SHA-512) | privada do remetente |

Ao abrir o envelope, o programa verifica a assinatura **antes** de decifrar qualquer coisa.

## Como usar

Requer Python 3.14.5 ou superior.

```bash
pip install -r requirements.txt

# 1. Gerar os pares de chaves (pasta ./chaves)
python envelope.py gerar-chaves --nome remetente
python envelope.py gerar-chaves --nome destinatario

# 2. Remetente: cifrar e assinar
python envelope.py cifrar -e exemplos/mensagem.txt --pub-destinatario chaves/destinatario_publica.pem --priv-remetente chaves/remetente_privada.pem -o envelope.json

# 3. Destinatário: verificar a assinatura e decifrar
python envelope.py decifrar -e envelope.json --priv-destinatario chaves/destinatario_privada.pem --pub-remetente chaves/remetente_publica.pem --mostrar
```

Sem argumentos, `python envelope.py` abre um menu interativo.

## Testes

```bash
pip install pytest
python -m pytest
```
## Arquivos de teste

A pasta `exemplos/gerados/` traz chaves e envelopes prontos para teste. Ela vem no pacote de
entrega e pode ser recriada com `python scripts/gerar_exemplos.py`.

```
exemplos/gerados/
├── chaves/        # pares remetente_*, destinatario_* e intruso_* (o intruso simula chave errada)
├── envelopes/     # 8 envelopes válidos, um para cada combinação de hash e codificação
└── adulterados/   # 7 envelopes com defeitos propositais, que devem gerar erro tratado
```

Todos foram criados a partir de `exemplos/mensagem.txt`. Para abrir um deles:

```bash
python envelope.py decifrar -e exemplos/gerados/envelopes/envelope_oaep-sha-256_assin-sha-256_base64.json --priv-destinatario exemplos/gerados/chaves/destinatario_privada.pem --pub-remetente exemplos/gerados/chaves/remetente_publica.pem --mostrar
```

Para ver o tratamento de erros, troque o envelope por um de `adulterados/`. Para simular chave errada, use uma chave `intruso_*`.

## Documentação

- [Guia completo](docs/GUIA.md): comandos, formato do JSON, tratamento de erros e limitações de segurança
- [Protocolo](docs/PROTOCOLO.md): especificação byte a byte
- [CyberChef](docs/CYBERCHEF.md): como abrir e criar envelopes manualmente

## Autores

Hederson Franco Benvindo Lima, João Guilherme Oliveira Pereira e David Soares Pereira Junior.

## Licença

[MIT](LICENSE)
