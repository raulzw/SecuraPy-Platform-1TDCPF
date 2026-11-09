"""
Módulo 2 — Motor de Regras (regras.py)
Responsável por carregar regras de um arquivo JSON e aplicá-las
a eventos, gerando alertas quando as condições são violadas.

[2º semestre] Reaproveitado do SecuraPy CLI. Ajustes:
  - nova condição "sqli" (regra R006 em config/regras.json);
  - URL lida do campo "url" do evento (antes era cortada no 1º espaço,
    o que escondia payloads como "1' OR '1'='1");
  - comparação de padrões case-insensitive;
  - alerta carrega "timestamp_iso" e "origem": "regra".
"""

import logging
from urllib.parse import unquote_plus

log = logging.getLogger("securapy.core.regras")

import json
from datetime import datetime


# Regras padrão usadas se o arquivo JSON falhar
REGRAS_PADRAO = [
    {
        "id": "R001",
        "nome": "Login com Usuário Privilegiado",
        "descricao": "Tentativa de login com usuário root, admin, sa ou oracle",
        "fonte": "auth",
        "condicao": "usuario_privilegiado",
        "usuarios_alvo": ["root", "admin", "sa", "oracle", "administrator"],
        "severidade_base": 6,
        "ativa": True
    },
    {
        "id": "R003",
        "nome": "Tentativa de Path Traversal",
        "descricao": "URL contém padrões de path traversal (../)",
        "fonte": "web",
        "condicao": "path_traversal",
        "padroes": ["../", "..\\", "/etc/passwd", "/etc/shadow"],
        "severidade_base": 9,
        "ativa": True
    }
]


def carregar_regras(caminho_config):
    """
    Lê o arquivo regras.json e retorna lista de dicionários de regras.

    Parâmetros:
        caminho_config (str): caminho para o arquivo regras.json

    Retorna:
        list[dict]: lista de regras carregadas
    """
    try:
        with open(caminho_config, "r", encoding="utf-8") as f:
            dados = json.load(f)

        regras = dados.get("regras", [])
        log.info(f"[OK] {len(regras)} regras carregadas de {caminho_config}")
        return regras

    except FileNotFoundError:
        log.error(f"[ERRO] Arquivo de regras não encontrado: {caminho_config}")
        log.info("[INFO] Usando regras padrão embutidas.")
        return REGRAS_PADRAO

    except json.JSONDecodeError as e:
        log.error(f"[ERRO] JSON inválido em {caminho_config}: {e}")
        log.info("[INFO] Usando regras padrão embutidas.")
        return REGRAS_PADRAO

    except Exception as e:
        log.error(f"[ERRO] Falha ao carregar regras: {e}")
        return REGRAS_PADRAO


def classificar_severidade(pontuacao):
    """
    Recebe pontuação numérica e retorna string de severidade.

    Parâmetros:
        pontuacao (int/float): pontuação da regra

    Retorna:
        str: CRITICA | ALTA | MEDIA | BAIXA | INFO
    """
    # Limites definidos como tupla imutável
    limites = (
        (9, "CRITICA"),
        (7, "ALTA"),
        (5, "MEDIA"),
        (3, "BAIXA"),
        (0, "INFO")
    )

    for limite, nivel in limites:
        if pontuacao >= limite:
            return nivel

    return "INFO"


def avaliar_regra(regra, evento):
    """
    Avalia se um evento viola uma regra específica.

    Parâmetros:
        regra (dict): dicionário com os dados da regra
        evento (dict): dicionário com os dados do evento normalizado

    Retorna:
        dict: alerta gerado, ou None se a regra não foi violada
    """
    # Ignora regras desativadas
    if not regra.get("ativa", False):
        return None

    # Verifica se a fonte do evento bate com a fonte da regra
    if regra.get("fonte") and regra["fonte"] != evento.get("fonte"):
        return None

    condicao = regra.get("condicao", "")
    url = _url_do_evento(evento)
    detalhes = evento.get("detalhes", "")
    violou = False

    # ── R001: Login com usuário privilegiado ──────────────────────────────────
    if condicao == "usuario_privilegiado":
        if evento.get("tipo") == "FAIL" and "usuario=" in detalhes:
            usuario = detalhes.split("usuario=")[1].split()[0]
            if usuario in regra.get("usuarios_alvo", []):
                violou = True

    # ── R002: Acesso a porta crítica bloqueado ────────────────────────────────
    elif condicao == "porta_critica":
        if evento.get("tipo") == "BLOCK" and "dport=" in detalhes:
            try:
                porta_str = detalhes.split("dport=")[1].split()[0]
                porta = int(porta_str)
                if porta in regra.get("portas_criticas", []):
                    violou = True
            except (ValueError, IndexError):
                pass

    # ── R003: Path traversal ──────────────────────────────────────────────────
    elif condicao == "path_traversal":
        if _contem_padrao(url, regra.get("padroes", [])):
            violou = True

    # ── R004: XSS ─────────────────────────────────────────────────────────────
    elif condicao == "xss":
        if _contem_padrao(url, regra.get("padroes", [])):
            violou = True

    # ── R006: SQL Injection ──────────────────────────────────────────────────
    elif condicao == "sqli":
        if _contem_padrao(url, regra.get("padroes", [])):
            violou = True

    # ── R005: Reconhecimento web ──────────────────────────────────────────────
    elif condicao == "reconhecimento":
        user_agent = evento.get("user_agent", "").lower()
        if user_agent:
            if any(scanner in user_agent for scanner in regra.get("urls_suspeitas", [])):
                violou = True

    if not violou:
        return None

    severidade = classificar_severidade(regra.get("severidade_base", 0))

    return {
        "timestamp": evento.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "regra_id": regra.get("id", "???"),
        "regra_nome": regra.get("nome", "Regra sem nome"),
        "severidade": severidade,
        "pontuacao": regra.get("severidade_base", 0),
        "ip": evento.get("ip", "desconhecido"),
        "fonte": evento.get("fonte", "desconhecido"),
        "descricao": regra.get("descricao", ""),
        "evento_original": evento.get("linha_original", ""),
        "timestamp_iso": evento.get("timestamp_iso"),
        "origem": "regra",
    }


def _url_do_evento(evento):
    """URL completa do evento web (campo "url" ou extraída de "detalhes")."""
    if evento.get("url"):
        return str(evento["url"])
    detalhes = evento.get("detalhes", "")
    if "url=" in detalhes:
        return detalhes.split("url=")[1].rsplit(" status=", 1)[0]
    return ""


def _decodificar_url(texto, rodadas=3):
    """
    Desfaz o URL-encoding (%20, %27, + ...) — inclusive duplo (%2527), truque comum
    para esconder o ataque. Sem isso, "1'%20OR%20'1'='1" escapava da regra de SQLi.
    """
    for _ in range(rodadas):
        decodificado = unquote_plus(texto)
        if decodificado == texto:
            break
        texto = decodificado
    return texto


def _contem_padrao(texto, padroes):
    """True se algum padrão aparece no texto, cru ou decodificado (case-insensitive)."""
    cru = (texto or "").lower()
    decodificado = _decodificar_url(cru)
    return any(str(p).lower() in cru or str(p).lower() in decodificado for p in padroes)


def aplicar_regras(eventos, regras):
    """
    Aplica todas as regras ativas a todos os eventos.

    Parâmetros:
        eventos (list[dict]): lista de eventos normalizados
        regras (list[dict]): lista de regras carregadas

    Retorna:
        list[dict]: lista de alertas gerados
    """
    alertas = []

    # Filtra apenas regras ativas
    regras_ativas = [r for r in regras if r.get("ativa", False)]

    for evento in eventos:
        for regra in regras_ativas:
            alerta = avaliar_regra(regra, evento)
            if alerta:
                alertas.append(alerta)

    log.info(f"[OK] {len(alertas)} alertas gerados a partir de {len(eventos)} eventos")
    return alertas


# ─── Testes isolados do módulo ───────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    from core.coletor import carregar_todos_os_logs  # rode da raiz: python -m core.regras

    print("=== Teste do Módulo 2 — Motor de Regras ===\n")

    regras = carregar_regras("config/regras.json")
    eventos = carregar_todos_os_logs("logs")
    alertas = aplicar_regras(eventos, regras)

    print("\n--- Primeiros 5 alertas ---")
    for alerta in alertas[:5]:
        print(f"[{alerta['severidade']}] {alerta['regra_nome']} — IP: {alerta['ip']}")

    print(f"\n--- Teste classificar_severidade ---")
    for pts in [9, 7, 5, 3, 1]:
        print(f"  {pts} pontos → {classificar_severidade(pts)}")
