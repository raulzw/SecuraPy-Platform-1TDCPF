"""
SecuraPy Platform — ponto de entrada (integração, seção 4 do enunciado).

    python main.py api          # sobe API + dashboard + servidor TCP de alertas (dev)
    python main.py ingerir      # núcleo → regras → detector → ML → MongoDB
    python main.py treinar      # treina o modelo e grava hash + métricas
    python main.py relatorio    # exporta saida/relatorio_exemplo.json
    python main.py console      # abre um console de alertas em tempo real (cliente TCP)
    python main.py demo         # fluxo ponta a ponta no terminal (sem banco), como no 1º semestre

Em produção/compose, a API roda com gunicorn (ver Dockerfile).
"""

import logging
import os
import sys


def demo():
    """Orquestração conceitual do enunciado, rodando só o núcleo + ML + LLM."""
    from core.detector import carregar_blacklist
    from core.pipeline import CAMINHO_BLACKLIST, analisar_pasta
    from ia.assistente import classificar_evento
    from ml.classificar import ClassificadorRisco, priorizar_alertas

    blacklist = carregar_blacklist(CAMINHO_BLACKLIST)
    r = analisar_pasta(blacklist=blacklist)                                 # 1-3: núcleo do 1º sem
    scores = ClassificadorRisco().pontuar(r["eventos"], r["alertas"], blacklist)  # 5: ML
    alertas = priorizar_alertas(r["alertas"], scores)
    print(f"\n{len(r['eventos'])} eventos | {len(alertas)} alertas | {len(r['ameacas'])} IPs suspeitos\n")
    print("Ameaças priorizadas:")
    for a in r["ameacas"]:
        s = scores.get(a["ip"], {})
        print(f"  [{a['severidade']:7s}] {a['ip']:16s} risco ML {s.get('score', '-'):>5} — {'; '.join(a['motivos'])}")
    peso = {"CRITICA": 4, "ALTA": 3, "MEDIA": 2, "BAIXA": 1}
    mais_grave = max(alertas, key=lambda a: (peso.get(a["severidade"], 0), a.get("score_risco") or 0))
    print(f"\nAssistente (LLM/fallback) no alerta mais grave — {mais_grave['regra_nome']} ({mais_grave['ip']}):")
    print(" ", classificar_evento(mais_grave))


def main():
    comando = sys.argv[1] if len(sys.argv) > 1 else "demo"
    logging.basicConfig(level=logging.WARNING)
    if comando == "api":
        from api.app import create_app
        create_app().run(host=os.getenv("API_HOST", "127.0.0.1"), port=int(os.getenv("API_PORTA", "5000")))
    elif comando == "ingerir":
        from scripts.ingerir import main as ingerir
        return ingerir(sys.argv[2] if len(sys.argv) > 2 else None)
    elif comando == "treinar":
        from ml.treinar import treinar
        treinar()
    elif comando == "relatorio":
        from scripts.exportar_relatorio import main as exportar
        exportar()
    elif comando == "console":
        from alertas.cliente_alertas import conectar_servidor
        conectar_servidor(os.getenv("ALERTAS_HOST_CLIENTE", "127.0.0.1"), int(os.getenv("ALERTAS_PORTA", "9999")))
    elif comando == "demo":
        demo()
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
