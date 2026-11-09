"""Funções extras (Caio): upload de log, tela Ao vivo, chat, boletim, diagnóstico e Telegram."""

import io
import json
import os
import re

from ia import chat, diagnostico, resumo
from notificacoes import telegram
from tests.conftest import RAIZ


def _csrf(html):
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def _entrar(cliente, email="admin@cybershield.com", senha="Admin12345"):
    token = _csrf(cliente.get("/login").get_data(as_text=True))
    cliente.post("/login", data={"email": email, "senha": senha, "csrf": token})
    return _csrf(cliente.get("/ao-vivo").get_data(as_text=True))


def _limpar_caches():
    resumo._cache.update(quando=0.0, resultado=None, versao=None)
    diagnostico._cache.clear()


# ── upload de log ────────────────────────────────────────────────────────────
def test_upload_de_log_real_gera_alertas(cliente, app):
    csrf = _entrar(cliente)
    with open(os.path.join(RAIZ, "logs", "ataque_teste.log"), "rb") as f:
        conteudo = f.read()
    r = cliente.post("/analisar/upload", data={"csrf": csrf, "fonte": "auto",
                                               "arquivo": (io.BytesIO(conteudo), "ataque.log")})
    assert r.status_code == 302
    repo = app.extensions["securapy"].repo
    assert repo.totais()["alertas"] > 0
    assert repo.alertas_do_ip("203.0.113.66")


def test_upload_sem_linhas_validas_nao_quebra(cliente, app):
    csrf = _entrar(cliente)
    r = cliente.post("/analisar/upload", data={"csrf": csrf, "fonte": "auto",
                                               "arquivo": (io.BytesIO(b"lixo\nmais lixo\n"), "x.log")})
    assert r.status_code == 302
    assert app.extensions["securapy"].repo.totais()["eventos"] == 0


def test_upload_exige_analista(cliente):
    csrf = _entrar(cliente, "leitor@cybershield.com", "Leitor12345")
    r = cliente.post("/analisar/upload", data={"csrf": csrf, "fonte": "auto",
                                               "arquivo": (io.BytesIO(b"x"), "x.log")})
    assert r.status_code == 403


# ── tela Ao vivo ─────────────────────────────────────────────────────────────
def test_api_ao_vivo_banco_vazio_e_com_dados(cliente_com_dados):
    d = cliente_com_dados.get("/api/ao-vivo").get_json()
    assert d["totais"]["eventos"] == 58
    assert d["ultimos"] and {"severidade", "ip", "descricao"} <= d["ultimos"][0].keys()
    assert 0 <= d["saude"]["nota"] <= 100


def test_zerar_so_admin(cliente_com_dados, app):
    csrf = _entrar(cliente_com_dados, "leitor@cybershield.com", "Leitor12345")
    assert cliente_com_dados.post("/ao-vivo/zerar", data={"csrf": csrf}).status_code == 403
    csrf = _entrar(cliente_com_dados)
    assert cliente_com_dados.post("/ao-vivo/zerar", data={"csrf": csrf}).status_code == 302
    assert app.extensions["securapy"].repo.totais()["eventos"] == 0


def test_rotas_post_exigem_csrf(cliente):
    _entrar(cliente)
    for rota in ("/ao-vivo/ia", "/assistente/perguntar", "/ip/diagnostico", "/ao-vivo/zerar"):
        assert cliente.post(rota, data={"pergunta": "oi", "ip": "1.2.3.4"}).status_code == 400, rota


# ── boletim da IA ────────────────────────────────────────────────────────────
def test_boletim_nunca_fica_desatualizado(cliente, h_admin):
    """Regressão: o cache não pode mostrar 'tudo tranquilo' depois que um ataque chegou."""
    _limpar_caches()
    csrf = _entrar(cliente)
    vazio = cliente.post("/ao-vivo/ia", data={"csrf": csrf}).get_json()
    assert "nenhum ataque" in vazio["texto"]
    cliente.post("/api/analisar", headers=h_admin, json={})
    depois = cliente.post("/ao-vivo/ia", data={"csrf": csrf}).get_json()  # dentro dos 8 s do cache
    assert "nenhum ataque" not in depois["texto"]
    assert "alertas" in depois["texto"]


def test_boletim_com_llm_falhando_usa_regras(repo_mongo, analise):
    _limpar_caches()
    repo_mongo.salvar_alertas(analise["alertas"])

    def fora_do_ar(texto):
        raise ValueError("sem rede")
    r = resumo.gerar_boletim(repo_mongo, chamar_llm=fora_do_ar)
    assert r["origem"] == "fallback" and r["texto"]


# ── chat ─────────────────────────────────────────────────────────────────────
def test_chat_por_regras(cliente_com_dados):
    csrf = _entrar(cliente_com_dados)
    r = cliente_com_dados.post("/assistente/perguntar", data={"csrf": csrf, "pergunta": "Quem é o mais perigoso?"})
    assert r.status_code == 200 and "risco" in r.get_json()["resposta"]


def test_chat_nao_envia_dados_sensiveis_ao_gemini(monkeypatch):
    """O corpo que sai para o Gemini não pode conter senha, email nem IP interno — nem no histórico."""
    enviado = {}

    class RespostaFalsa:
        def raise_for_status(self):
            pass

        def json(self):
            return {"candidates": [{"content": {"parts": [{"text": "ok"}]}}]}

    def post_falso(url, json=None, **kwargs):
        enviado["corpo"] = json
        return RespostaFalsa()
    monkeypatch.setattr(chat.requests, "post", post_falso)
    historico = [{"de": "usuario", "texto": "minha senha=Segredo123 e email ana@empresa.com, ip 192.168.1.10"}]
    assert chat._chamar_gemini("contexto", "e agora?", historico, "chave-falsa") == "ok"
    corpo = str(enviado["corpo"])
    assert "Segredo123" not in corpo and "ana@empresa.com" not in corpo and "192.168.1.10" not in corpo


def test_chat_pergunta_vazia_e_historico_invalido(cliente):
    csrf = _entrar(cliente)
    r = cliente.post("/assistente/perguntar", data={"csrf": csrf, "pergunta": "", "historico": "não é json"})
    assert r.status_code == 200 and r.get_json()["resposta"]


# ── diagnóstico ──────────────────────────────────────────────────────────────
def test_diagnostico_ip_atacante_e_ip_invalido(cliente_com_dados):
    _limpar_caches()
    csrf = _entrar(cliente_com_dados)
    r = cliente_com_dados.post("/ip/diagnostico", data={"csrf": csrf, "ip": "185.220.101.1"}).get_json()
    assert r["itens"] and all({"problema", "onde", "correcao"} <= i.keys() for i in r["itens"])
    assert cliente_com_dados.post("/ip/diagnostico", data={"csrf": csrf, "ip": "999.1.1.1"}).status_code == 400


def test_diagnostico_ip_sem_dados(repo_mongo):
    _limpar_caches()
    assert diagnostico.diagnosticar(repo_mongo, "203.0.113.200")["origem"] == "sem_dados"


def test_diagnostico_llm_com_resposta_invalida_usa_manual(repo_mongo, analise):
    _limpar_caches()
    repo_mongo.salvar_eventos(analise["eventos"])
    repo_mongo.salvar_alertas(analise["alertas"])
    r = diagnostico.diagnosticar(repo_mongo, "185.220.101.1", chamar_llm=lambda t: json.dumps({"x": 1}))
    assert r["origem"] == "fallback" and r["itens"]


# ── Telegram ─────────────────────────────────────────────────────────────────
def test_telegram_desligado_nao_envia_nem_quebra(monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
    assert telegram.notificar_criticos([{"severidade": "CRITICA", "ip": "1.2.3.4", "regra_id": "R003"}]) == 0
    ok, detalhe = telegram.enviar("teste")
    assert ok is False and "não configurado" in detalhe


def test_telegram_anti_spam_por_ip(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "token-falso")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "123")
    monkeypatch.setattr(telegram, "_enviar_e_registrar", lambda texto: None)
    telegram._ultimo_por_ip.clear()
    telegram._envios_recentes.clear()
    alerta = [{"severidade": "CRITICA", "ip": "198.51.100.7", "regra_id": "R003"}]
    assert telegram.notificar_criticos(alerta) == 1
    assert telegram.notificar_criticos(alerta) == 0  # mesmo IP dentro de 2 minutos → não repete
    assert telegram.notificar_criticos([{"severidade": "ALTA", "ip": "198.51.100.8"}]) == 0  # só CRITICA


def test_mensagem_telegram_em_linguagem_simples():
    texto = telegram.montar_mensagem("198.51.100.7", [{"regra_id": "R003"}, {"regra_id": "R003"}])
    assert "arquivos secretos" in texto and texto.count("arquivos secretos") == 1
    assert "198.51.100.7" in texto
