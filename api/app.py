"""
SecuraPy Platform — aplicação Flask (API REST + dashboard web).

2º sem: Aulas 6 (Flask, status codes), 7 (integração com banco, paginação,
filtros), 8 (OWASP: XSS, headers, logging), 10 (token, boas práticas REST).

Rotas da API (prefixo /api):
  GET  /saude                     → 200 + status dos componentes
  POST /login                     → JWT (mensagem genérica em falha)
  GET  /eventos                   → filtros fonte/tipo/ip/inicio/fim + paginação
  GET  /alertas                   → filtros severidade/ip/regra_id + paginação
  GET  /alertas/<id>              → 400 (id malformado) / 404 / 200
  POST /alertas            [token nível 3]
  POST /analisar           [token nível 3]  → núcleo + regras + detector + ML + Mongo + TCP
  GET  /ip/<ip>                   → eventos + alertas + geo + score ML + explicação LLM
  GET  /resumo                    → dados do dashboard
  GET  /relatorio          [token]          → exportação JSON completa
  POST /assistente/classificar [token nível 2]
  GET  /ml/status                 → integridade do modelo + métricas
  GET/POST /usuarios       [token nível 5]  → gestão de operadores (MySQL)

Uso local:  python -m api.app      (ou gunicorn "api.app:create_app()")
"""

import json
import logging
import os
import time
from logging.handlers import RotatingFileHandler

from flask import Blueprint, Flask, g, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from api import auth
from api import validacao as v
from api.servico import ErroEntrada, ServicoSecuraPy
from db import RegistroDuplicado, RepositorioIndisponivel
from ia.assistente import classificar_evento
from ia.saude import calcular as calcular_saude
from ml.treinar import CAMINHO_METRICAS

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")

api_bp = Blueprint("api", __name__, url_prefix="/api")


def servico() -> ServicoSecuraPy:
    from flask import current_app
    return current_app.extensions["securapy"]


def _json_do_corpo():
    """Lê o corpo JSON; corpo ausente/malformado → 400 (nunca 500)."""
    dados = request.get_json(silent=True)
    if dados is None:
        raise v.ErroValidacao("Corpo da requisição deve ser JSON válido (Content-Type: application/json)")
    return dados


# ── rotas públicas ───────────────────────────────────────────────────────────
@api_bp.get("/saude")
def saude():
    return jsonify(status="ok", componentes=servico().status())


@api_bp.post("/login")
def login():
    dados = request.get_json(silent=True) or {}
    email, senha = dados.get("email"), dados.get("senha")
    chave = f"{request.remote_addr}|{str(email)[:254].lower()}"
    limitador = g.limitador
    if limitador.bloqueado(chave):
        return jsonify(erro="Muitas tentativas. Aguarde alguns minutos."), 429
    usuario = servico().usuarios.autenticar(email, senha)
    if not usuario:
        limitador.registrar_falha(chave)
        return jsonify(erro="Credenciais inválidas"), 401  # mesma mensagem p/ usuário inexistente
    limitador.limpar(chave)
    token, expira = auth.gerar_token(usuario)
    return jsonify(token=token, tipo="Bearer", expira_em=expira, nivel=usuario["nivel_acesso"])


@api_bp.get("/eventos")
def listar_eventos():
    pagina, tamanho = v.paginacao(request.args)
    return jsonify(servico().repo.buscar_eventos(v.filtros_eventos(request.args), pagina, tamanho))


@api_bp.get("/alertas")
def listar_alertas():
    pagina, tamanho = v.paginacao(request.args)
    return jsonify(servico().repo.buscar_alertas(v.filtros_alertas(request.args), pagina, tamanho))


@api_bp.get("/alertas/<id_alerta>")
def obter_alerta(id_alerta):
    alerta = servico().repo.obter_alerta(v.validar_id_alerta(id_alerta))
    if alerta is None:
        return jsonify(erro="Alerta não encontrado"), 404
    return jsonify(alerta)


@api_bp.get("/ip/<path:ip>")
def detalhes_ip(ip):
    ip = v.validar_ip(ip)
    detalhes = servico().detalhes_ip(ip, com_llm=request.args.get("llm", "1") != "0")
    if detalhes is None:
        return jsonify(erro="Nenhum evento ou alerta para este IP", ip=ip), 404
    return jsonify(detalhes)


@api_bp.get("/resumo")
def resumo():
    return jsonify(servico().resumo_dashboard())


@api_bp.get("/ao-vivo")
def ao_vivo():
    """Dados da tela Ao vivo (consultada a cada 2 s pelo navegador)."""
    s = servico()
    campos = ("id", "severidade", "regra_id", "regra_nome", "ip", "descricao", "score_risco", "fonte")
    return jsonify(
        totais=s.repo.totais(),
        alertas_por_severidade=s.repo.contagem_por_severidade(),
        eventos_por_fonte=s.repo.contagem_por_fonte(),
        ultimos=[{c: a.get(c) for c in campos} for a in s.repo.ultimos_alertas(12)],
        top_risco=[{c: x.get(c) for c in ("ip", "score", "nivel", "rotulo", "anomalo")} for x in s.repo.listar_scores(6)],
        saude=calcular_saude(s.repo),
    )


@api_bp.get("/ml/status")
def ml_status():
    metricas = None
    try:
        with open(CAMINHO_METRICAS, encoding="utf-8") as f:
            metricas = json.load(f)
    except (OSError, ValueError):
        pass
    return jsonify(modelo_integro=servico().status()["modelo_integro"], metricas=metricas)


# ── rotas protegidas ─────────────────────────────────────────────────────────
@api_bp.post("/alertas")
@auth.requer_token(nivel_minimo=3)
def criar_alerta():
    alerta = v.corpo_alerta(_json_do_corpo())
    salvo = servico().criar_alerta_manual(alerta, autor=g.usuario["email"])
    return jsonify(salvo), 201


@api_bp.post("/analisar")
@auth.requer_token(nivel_minimo=3)
def analisar():
    corpo = request.get_json(silent=True) if request.data else {}
    if corpo is None:
        raise v.ErroValidacao("Corpo da requisição deve ser JSON válido")
    return jsonify(servico().analisar(corpo))


@api_bp.get("/relatorio")
@auth.requer_token(nivel_minimo=1)
def relatorio():
    return jsonify(servico().relatorio_completo())


@api_bp.post("/assistente/classificar")
@auth.requer_token(nivel_minimo=2)
def assistente():
    dados = _json_do_corpo()
    alvo = dados.get("evento") if isinstance(dados, dict) else None
    if alvo is None and isinstance(dados, dict):
        alvo = v.validar_texto(dados.get("texto"), "texto", 4000)
    if not isinstance(alvo, (dict, str)):
        raise v.ErroValidacao("Envie 'evento' (objeto) ou 'texto' (string)")
    return jsonify(classificar_evento(alvo))


@api_bp.get("/usuarios")
@auth.requer_token(nivel_minimo=5)
def listar_usuarios():
    return jsonify(itens=servico().usuarios.listar_usuarios())


@api_bp.post("/usuarios")
@auth.requer_token(nivel_minimo=5)
def criar_usuario():
    dados = _json_do_corpo()
    if not isinstance(dados, dict):
        raise v.ErroValidacao("Corpo deve ser um objeto JSON")
    nivel = v.validar_inteiro(dados.get("nivel_acesso"), "nivel_acesso", 1, 5, 1)
    try:
        novo_id = servico().usuarios.criar_usuario(dados.get("nome"), dados.get("email"), dados.get("senha"), nivel)
    except ValueError as e:
        raise v.ErroValidacao(str(e)) from None
    except RegistroDuplicado:
        return jsonify(erro="Email já cadastrado"), 409
    return jsonify(id=novo_id), 201


# ── fábrica da aplicação ─────────────────────────────────────────────────────
def _configurar_log_acesso(app):
    """OWASP A09 — registrar cada requisição (sem corpo, sem headers de autenticação)."""
    logger = logging.getLogger("securapy.acesso")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        caminho = app.config["LOG_ACESSO"]
        os.makedirs(os.path.dirname(caminho), exist_ok=True)
        arquivo = RotatingFileHandler(caminho, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
        arquivo.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        logger.addHandler(arquivo)
        console = logging.StreamHandler()
        console.setFormatter(logging.Formatter("%(asctime)s [ACESSO] %(message)s"))
        logger.addHandler(console)
    return logger


def create_app(repo_eventos=None, repo_usuarios=None, config=None, classificador=None):
    app = Flask(__name__, template_folder=os.path.join(RAIZ, "web", "templates"),
                static_folder=os.path.join(RAIZ, "web", "static"))
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    app.config.update(
        JWT_SECRET=auth.segredo_ou_aleatorio("JWT_SECRET", app.logger),
        SECRET_KEY=auth.segredo_ou_aleatorio("FLASK_SECRET_KEY", app.logger),
        JWT_EXPIRA_MINUTOS=int(os.getenv("JWT_EXPIRA_MINUTOS", "60")),
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("COOKIE_SEGURO", "0") == "1",
        JSON_SORT_KEYS=False,
        LOG_ACESSO=os.getenv("LOG_ACESSO", os.path.join(RAIZ, "var", "acesso.log")),
        ALERTAS_TCP=os.getenv("ALERTAS_TCP", "1") == "1",
    )
    app.json.ensure_ascii = False
    if config:
        app.config.update(config)

    if repo_eventos is None:
        from db.mongo_repo import conectar
        repo_eventos = conectar()
    if repo_usuarios is None:
        from db.mysql_repo import RepositorioUsuarios
        repo_usuarios = RepositorioUsuarios()

    try:
        repo_eventos.criar_indices()
    except RepositorioIndisponivel:
        app.logger.error("MongoDB indisponível na inicialização — a API sobe e responde 503 até ele voltar")
    try:
        repo_usuarios.criar_tabelas()
        repo_usuarios.garantir_admin(os.getenv("ADMIN_EMAIL"), os.getenv("ADMIN_SENHA"))
    except RepositorioIndisponivel:
        app.logger.error("MySQL indisponível na inicialização")
    except ValueError as e:
        app.logger.error("Admin inicial inválido: %s", e)

    app.extensions["securapy"] = ServicoSecuraPy(repo_eventos, repo_usuarios, classificador=classificador,
                                                 broadcast=app.config["ALERTAS_TCP"])
    limitador = auth.LimitadorTentativas()
    log_acesso = _configurar_log_acesso(app)

    if app.config["ALERTAS_TCP"]:
        from alertas.servidor_alertas import iniciar_em_background
        iniciar_em_background()

    from web.rotas import web_bp
    app.register_blueprint(api_bp)
    app.register_blueprint(web_bp)

    @app.before_request
    def _antes():
        g.inicio = time.perf_counter()
        g.limitador = limitador

    @app.after_request
    def _depois(resposta):
        resposta.headers["X-Content-Type-Options"] = "nosniff"
        resposta.headers["X-Frame-Options"] = "DENY"
        resposta.headers["Content-Security-Policy"] = CSP
        resposta.headers["Referrer-Policy"] = "no-referrer"
        resposta.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        if resposta.mimetype == "application/json":
            # Declara o UTF-8: sem isso o PowerShell 5.1 (Invoke-RestMethod) mostra "CRÃTICO"
            resposta.headers["Content-Type"] = "application/json; charset=utf-8"
        if request.path.startswith("/api") or request.path in ("/login",):
            resposta.headers["Cache-Control"] = "no-store"
        usuario = getattr(g, "usuario", None) or {}
        duracao = (time.perf_counter() - g.get("inicio", time.perf_counter())) * 1000
        log_acesso.info("ip=%s metodo=%s rota=%s status=%s usuario=%s duracao_ms=%.1f ua=%r",
                        request.remote_addr, request.method, request.path, resposta.status_code,
                        usuario.get("email", "-"), duracao, request.user_agent.string[:120])
        return resposta

    def _e_api():
        return request.path.startswith("/api")

    def _resposta_erro(codigo, mensagem):
        if _e_api():
            return jsonify(erro=mensagem), codigo
        return render_template("erro.html", codigo=codigo, mensagem=mensagem), codigo

    @app.errorhandler(v.ErroValidacao)
    @app.errorhandler(ErroEntrada)
    def _erro_validacao(e):
        return _resposta_erro(400, str(e))

    @app.errorhandler(RepositorioIndisponivel)
    def _erro_banco(e):
        app.logger.error("Banco indisponível: %s", e)
        return _resposta_erro(503, "Serviço temporariamente indisponível")

    @app.errorhandler(HTTPException)
    def _erro_http(e):
        mensagens = {400: "Requisição inválida", 404: "Recurso não encontrado", 405: "Método não permitido",
                     413: "Requisição muito grande", 415: "Tipo de conteúdo não suportado"}
        return _resposta_erro(e.code, mensagens.get(e.code, e.name))

    @app.errorhandler(Exception)
    def _erro_interno(e):
        # Traceback só no log do servidor — o cliente recebe mensagem genérica (sem query/segredo)
        app.logger.exception("Erro interno não tratado")
        return _resposta_erro(500, "Erro interno")

    return app


if __name__ == "__main__":
    create_app().run(host=os.getenv("API_HOST", "127.0.0.1"), port=int(os.getenv("API_PORTA", "5000")))
