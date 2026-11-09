"""Módulo D — API REST (cenários D1–D5) + autenticação JWT e tratamento de erros."""

from datetime import datetime, timedelta, timezone

import jwt


def test_saude_200(cliente):
    r = cliente.get("/api/saude")
    assert r.status_code == 200 and r.json["status"] == "ok"


def test_analisar_persiste_e_retorna_resumo(cliente, h_admin):
    r = cliente.post("/api/analisar", headers=h_admin, json={})
    assert r.status_code == 200
    assert r.json["eventos_processados"] == 58
    assert r.json["persistencia"]["eventos"]["inseridos"] == 58
    assert r.json["ameacas"][0]["ip"] == "185.220.101.1"
    assert r.json["ameacas"][0]["score_ml"] > 50


def test_d1_alertas_criticos_paginados(cliente_com_dados):
    r = cliente_com_dados.get("/api/alertas?severidade=critica&pagina=1&tamanho=5")
    assert r.status_code == 200
    assert r.json["total"] >= 2 and len(r.json["itens"]) <= 5
    assert all(a["severidade"] == "CRITICA" for a in r.json["itens"])


def test_d2_detalhes_do_ip(cliente_com_dados):
    r = cliente_com_dados.get("/api/ip/185.220.101.1")
    assert r.status_code == 200
    d = r.json
    assert d["total_eventos"] == 25 and d["total_alertas"] > 0
    assert "geo" in d and d["score_ml"]["rotulo"] == "ataque"
    assert d["explicacao_llm"]["classificacao"] == "CRÍTICO"


def test_d3_post_sem_token_401(cliente):
    assert cliente.post("/api/alertas", json={"ip": "1.2.3.4"}).status_code == 401
    assert cliente.post("/api/analisar").status_code == 401


def test_d4_corpo_invalido_400(cliente, h_admin):
    assert cliente.post("/api/alertas", headers=h_admin, data="nao-e-json",
                        content_type="application/json").status_code == 400
    assert cliente.post("/api/alertas", headers=h_admin, json={"ip": "1.2.3.4"}).status_code == 400
    assert cliente.post("/api/alertas", headers=h_admin, json=[1, 2]).status_code == 400
    r = cliente.post("/api/alertas", headers=h_admin, json={"ip": "1.2.3.4", "severidade": "urgente",
                                                             "regra_nome": "x", "descricao": "y"})
    assert r.status_code == 400 and "Severidade" in r.json["erro"]


def test_d5_ip_e_id_malformados_400(cliente):
    r = cliente.get("/api/ip/999.1.1.1")
    assert r.status_code == 400 and r.json == {"erro": "IP inválido"}
    assert cliente.get("/api/ip/abc'or'1'='1").status_code == 400
    assert cliente.get("/api/alertas/nao-e-um-id").status_code == 400
    assert cliente.get("/api/alertas/" + "a" * 64).status_code == 404
    assert cliente.get("/api/alertas?pagina=0").status_code == 400
    assert cliente.get("/api/eventos?tamanho=1000").status_code == 400


def test_post_alerta_valido_201_e_ignora_campos_extras(cliente, h_admin):
    r = cliente.post("/api/alertas", headers=h_admin, json={
        "ip": "203.0.113.7", "severidade": "Alta", "regra_nome": "Manual", "descricao": "teste", "_id": "x",
        "pontuacao": 999})
    assert r.status_code == 201
    salvo = cliente.get(f"/api/alertas/{r.json['id']}").json
    assert salvo["severidade"] == "ALTA" and salvo["pontuacao"] == 7 and salvo["criado_por"] == "admin@cybershield.com"


def test_nivel_insuficiente_403(cliente, h_leitor):
    assert cliente.post("/api/analisar", headers=h_leitor, json={}).status_code == 403
    assert cliente.get("/api/relatorio", headers=h_leitor).status_code == 200


def test_jwt_expirado_ou_alg_none_rejeitado(cliente, app):
    agora = datetime.now(timezone.utc)
    base = {"sub": "1", "email": "a@b.com", "nome": "A", "nivel": 5, "iss": "securapy-platform", "aud": "securapy-api"}
    expirado = jwt.encode({**base, "iat": agora - timedelta(hours=2), "exp": agora - timedelta(hours=1)},
                          app.config["JWT_SECRET"], algorithm="HS256")
    sem_assinatura = jwt.encode({**base, "iat": agora, "exp": agora + timedelta(hours=1)}, None, algorithm="none")
    outro_segredo = jwt.encode({**base, "iat": agora, "exp": agora + timedelta(hours=1)}, "x" * 40, algorithm="HS256")
    for token in (expirado, sem_assinatura, outro_segredo, "lixo"):
        assert cliente.post("/api/analisar", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_login_generico_e_limite_de_tentativas(cliente):
    errada = cliente.post("/api/login", json={"email": "admin@cybershield.com", "senha": "errada"})
    inexistente = cliente.post("/api/login", json={"email": "ninguem@x.com", "senha": "errada"})
    assert errada.status_code == inexistente.status_code == 401
    assert errada.json == inexistente.json == {"erro": "Credenciais inválidas"}
    for _ in range(5):
        cliente.post("/api/login", json={"email": "alvo@x.com", "senha": "x"})
    assert cliente.post("/api/login", json={"email": "alvo@x.com", "senha": "x"}).status_code == 429


def test_analisar_bloqueia_path_traversal_e_valida_lote(cliente, h_admin):
    r = cliente.post("/api/analisar", headers=h_admin, json={"caminho": "../../etc/passwd", "fonte": "auth"})
    assert r.status_code == 400
    assert cliente.post("/api/analisar", headers=h_admin, json={"eventos": "x"}).status_code == 400
    lote = {"eventos": [{"fonte": "web", "linha": "2025-02-20 09:00:00 GET url=/../../etc/passwd ip=203.0.113.5 status=404"},
                        {"fonte": "web", "linha": "linha quebrada"}]}
    r = cliente.post("/api/analisar", headers=h_admin, json=lote)
    assert r.status_code == 200 and r.json["eventos_processados"] == 1 and r.json["linhas_ignoradas"] == 1


def test_erro_500_nao_vaza_detalhes(cliente, app, monkeypatch):
    def explode(*a, **k):
        raise RuntimeError("SELECT * FROM usuarios WHERE senha='segredo' /home/app/db.py")
    monkeypatch.setattr(app.extensions["securapy"], "resumo_dashboard", explode)
    r = cliente.get("/api/resumo")
    assert r.status_code == 500 and r.json == {"erro": "Erro interno"}
    assert b"SELECT" not in r.data and b"Traceback" not in r.data


def test_banco_fora_do_ar_vira_503(cliente, app, monkeypatch):
    from db import RepositorioIndisponivel

    def fora(*a, **k):
        raise RepositorioIndisponivel("mongo caiu em 10.0.0.3:27017")
    monkeypatch.setattr(app.extensions["securapy"].repo, "buscar_alertas", fora)
    r = cliente.get("/api/alertas")
    assert r.status_code == 503 and "10.0.0.3" not in r.get_data(as_text=True)


def test_gestao_de_usuarios_admin(cliente, h_admin, h_leitor):
    novo = {"nome": "Carla", "email": "carla@cybershield.com", "senha": "Carla12345", "nivel_acesso": 3}
    assert cliente.post("/api/usuarios", headers=h_leitor, json=novo).status_code == 403
    assert cliente.post("/api/usuarios", headers=h_admin, json=novo).status_code == 201
    assert cliente.post("/api/usuarios", headers=h_admin, json=novo).status_code == 409  # B3 via API


def test_json_declara_utf8(cliente):
    """Clientes antigos (PowerShell 5.1) só acentuam certo se o charset vier no header."""
    r = cliente.get("/api/ip/999.1.1.1")
    assert r.headers["Content-Type"] == "application/json; charset=utf-8"
    assert r.get_json() == {"erro": "IP inválido"}
