"""Linha de comando e menu: códigos de saída e ausência de stack traces."""

import builtins
import json

import pytest

from envelope_digital.cli import main

from .conftest import TEXTO_EXEMPLO


@pytest.fixture
def arquivos(tmp_path, remetente, destinatario):
    msg = tmp_path / "mensagem.txt"
    msg.write_text(TEXTO_EXEMPLO, encoding="utf-8")
    return {
        "msg": str(msg),
        "env": str(tmp_path / "envelope.json"),
        "saida": str(tmp_path / "saida.txt"),
        "rem_priv": str(remetente.privada_pem),
        "rem_pub": str(remetente.publica_pem),
        "dest_priv": str(destinatario.privada_pem),
        "dest_pub": str(destinatario.publica_pem),
        "tmp": tmp_path,
    }


def _cifrar(a, *extra):
    return main(["cifrar", "-e", a["msg"], "--pub-destinatario", a["dest_pub"],
                 "--priv-remetente", a["rem_priv"], "-o", a["env"], *extra])


def _decifrar(a, *extra):
    return main(["decifrar", "-e", a["env"], "--priv-destinatario", a["dest_priv"],
                 "--pub-remetente", a["rem_pub"], "-o", a["saida"], *extra])


def _sem_traceback(capsys):
    saida = capsys.readouterr()
    assert "Traceback" not in saida.out + saida.err
    return saida


@pytest.mark.parametrize("opcoes", [[], ["--hash-oaep", "SHA-512", "--hash-assinatura", "sha512", "--codificacao", "hex"]])
def test_fluxo_completo(arquivos, capsys, opcoes):
    assert _cifrar(arquivos, *opcoes) == 0
    assert _decifrar(arquivos, "--mostrar") == 0
    with open(arquivos["saida"], encoding="utf-8") as f:
        assert f.read() == TEXTO_EXEMPLO
    assert main(["verificar", "-e", arquivos["env"], "--pub-remetente", arquivos["rem_pub"]]) == 0
    assert TEXTO_EXEMPLO.splitlines()[0] in _sem_traceback(capsys).out


def test_cifrar_texto_direto(arquivos, capsys):
    assert main(["cifrar", "-t", "direto", "--pub-destinatario", arquivos["dest_pub"],
                 "--priv-remetente", arquivos["rem_priv"], "-o", arquivos["env"]]) == 0
    assert _decifrar(arquivos) == 0
    _sem_traceback(capsys)


def test_assinatura_invalida_retorna_3(arquivos, capsys):
    _cifrar(arquivos)
    with open(arquivos["env"], encoding="utf-8") as f:
        env = json.load(f)
    c = env["envelope"]["mensagem_cifrada"]
    env["envelope"]["mensagem_cifrada"] = ("A" if c[0] != "A" else "B") + c[1:]
    with open(arquivos["env"], "w", encoding="utf-8") as f:
        json.dump(env, f)
    assert _decifrar(arquivos) == 3
    saida = _sem_traceback(capsys)
    assert "INTEGRIDADE VIOLADA" in saida.err


@pytest.mark.parametrize("conteudo", ["", "{", "[]", '{"parametros": {}, "envelope": {}}', "\x00\xff"])
def test_envelope_corrompido(arquivos, capsys, conteudo):
    with open(arquivos["env"], "w", encoding="latin-1") as f:
        f.write(conteudo)
    assert _decifrar(arquivos) == 1
    assert "[ERRO]" in _sem_traceback(capsys).err


def test_arquivos_inexistentes(arquivos, capsys):
    assert main(["cifrar", "-e", "nao_existe.txt", "--pub-destinatario", arquivos["dest_pub"],
                 "--priv-remetente", arquivos["rem_priv"]]) == 1
    assert main(["decifrar", "-e", "nao_existe.json", "--priv-destinatario", arquivos["dest_priv"],
                 "--pub-remetente", arquivos["rem_pub"]]) == 1
    _sem_traceback(capsys)


def test_entrada_que_nao_e_utf8(arquivos, capsys):
    with open(arquivos["msg"], "wb") as f:
        f.write(b"\xff\xfe\x00 latin-1 \xe9")
    assert _cifrar(arquivos) == 1
    assert "UTF-8" in _sem_traceback(capsys).err


def test_chaves_trocadas(arquivos, capsys):
    assert main(["cifrar", "-e", arquivos["msg"], "--pub-destinatario", arquivos["dest_priv"],
                 "--priv-remetente", arquivos["rem_priv"], "-o", arquivos["env"]]) == 1
    _cifrar(arquivos)
    # destinatário usa a própria pública no lugar da privada do remetente etc.
    assert main(["decifrar", "-e", arquivos["env"], "--priv-destinatario", arquivos["rem_priv"],
                 "--pub-remetente", arquivos["rem_pub"], "-o", arquivos["saida"]]) == 1
    assert main(["decifrar", "-e", arquivos["env"], "--priv-destinatario", arquivos["dest_priv"],
                 "--pub-remetente", arquivos["dest_pub"], "-o", arquivos["saida"]]) == 3
    _sem_traceback(capsys)


@pytest.mark.parametrize("args", [["cifrar"], ["cifrar", "-t", "x", "--hash-oaep", "MD5"], ["comando-inexistente"],
                                  ["gerar-chaves", "--nome", "x", "--bits", "1024"]])
def test_uso_incorreto_retorna_2(args, capsys):
    assert main(args) == 2
    assert "[ERRO] Uso incorreto" in _sem_traceback(capsys).err


def test_ajuda_e_versao(capsys):
    assert main(["--help"]) == 0
    assert main(["--versao"]) == 0
    _sem_traceback(capsys)


def test_gerar_chaves_cli(tmp_path, capsys):
    pasta = str(tmp_path / "k")
    assert main(["gerar-chaves", "--nome", "teste", "--pasta", pasta]) == 0
    assert main(["gerar-chaves", "--nome", "teste", "--pasta", pasta]) == 1  # já existe
    assert main(["gerar-chaves", "--nome", "teste", "--pasta", pasta, "--sobrescrever"]) == 0
    _sem_traceback(capsys)


def test_erro_inesperado_nao_mostra_traceback(arquivos, capsys, monkeypatch):
    from envelope_digital import operacoes

    def explode(**_):
        raise RuntimeError("falha simulada")

    monkeypatch.setattr(operacoes, "cifrar", explode)
    assert _cifrar(arquivos) == 1
    assert "falha simulada" in _sem_traceback(capsys).err


# ------------------------------------------------------------------ menu
def _alimentar(monkeypatch, respostas):
    fila = iter(respostas)

    def falso_input(prompt=""):
        try:
            return next(fila)
        except StopIteration:
            raise EOFError from None

    monkeypatch.setattr(builtins, "input", falso_input)


def test_menu_fluxo_completo(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "mensagem.txt").write_text("via menu", encoding="utf-8")
    _alimentar(monkeypatch, [
        "1", "remetente", "", "", "n", "",            # gerar chaves do remetente
        "1", "destinatario", "", "", "n", "",         # gerar chaves do destinatário
        "2", "", "", "", "", "2", "2", "2", "", "",   # cifrar (SHA-512, SHA-512, Hex)
        "3", "", "", "", "", "s", "",                 # decifrar e exibir
        "4", "", "", "",                              # verificar
        "3", "inexistente.json", "", "", "outra.txt", "",  # erro tratado, menu continua
        "7", "0",
    ])
    assert main([]) == 0
    saida = _sem_traceback(capsys)
    assert (tmp_path / "mensagem_decifrada.txt").read_text(encoding="utf-8") == "via menu"
    assert "via menu" in saida.out
    assert "não encontrado" in saida.err
    assert "Opção inválida" in saida.out


def test_menu_encerra_com_eof(monkeypatch, capsys):
    _alimentar(monkeypatch, [])
    assert main([]) == 0
    _sem_traceback(capsys)
