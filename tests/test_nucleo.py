"""Módulo A — núcleo reaproveitado do 1º semestre (cenários A1–A4 + bônus)."""

from collections import Counter

from core.coletor import carregar_log, normalizar_timestamp, parsear_linha_auth, parsear_linha_firewall, parsear_linha_web
from core.detector import (detectar_brute_force, detectar_brute_force_janela, detectar_port_scan,
                           gerar_resumo_ameacas, verificar_blacklist)
from core.pipeline import analisar_pasta
from tests.conftest import BLACKLIST, RAIZ


def test_a1_carrega_os_3_logs_com_fonte_correta(eventos):
    assert len(eventos) == 58
    assert Counter(e["fonte"] for e in eventos) == {"auth": 23, "firewall": 17, "web": 18}
    for e in eventos:
        assert {"timestamp", "fonte", "tipo", "ip", "detalhes", "timestamp_iso"} <= e.keys()


def test_a2_brute_force_185_alta(eventos):
    bf = detectar_brute_force(eventos)
    # O enunciado cita 10 FAILs; o auth.log oficial tem 11 linhas FAIL desse IP. Severidade = ALTA.
    assert bf["185.220.101.1"]["tentativas"] >= 10
    assert bf["185.220.101.1"]["severidade"] == "ALTA"
    assert bf["91.240.118.172"] == {"tentativas": 5, "usuarios": ["admin", "guest", "root"], "severidade": "MEDIA"}
    assert bf["45.33.32.156"]["severidade"] == "BAIXA"


def test_a3_port_scan_185_com_7_portas(eventos):
    ps = detectar_port_scan(eventos)
    assert ps["185.220.101.1"]["quantidade"] == 7
    assert isinstance(ps["185.220.101.1"]["portas"], set)
    assert ps["185.220.101.1"]["severidade"] == "ALTA"
    assert ps["91.240.118.172"]["quantidade"] == 3


def test_a4_intersecao_com_blacklist(eventos):
    ips, contagem = verificar_blacklist(eventos, BLACKLIST)
    assert ips == {"185.220.101.1", "45.33.32.156", "91.240.118.172"}
    assert "23.94.5.100" not in ips


def test_resumo_consolidado_185_critica(eventos):
    resumo = gerar_resumo_ameacas(detectar_brute_force(eventos), detectar_port_scan(eventos),
                                  verificar_blacklist(eventos, BLACKLIST)[0])
    assert resumo[0]["ip"] == "185.220.101.1" and resumo[0]["severidade"] == "CRITICA"


def test_linha_malformada_nao_trava(tmp_path):
    arquivo = tmp_path / "auth.log"
    arquivo.write_text("2025-02-20 08:15:01 FAIL usuario=admin ip=1.2.3.4\nlinha sem formato\n\n"
                       "2025-02-20 08:15:02 OK usuario=ana ip=10.0.0.1\n", encoding="utf-8")
    assert len(carregar_log(str(arquivo), "auth")) == 2
    assert carregar_log(str(tmp_path / "nao_existe.log"), "auth") == []


def test_formatos_reais_do_1o_semestre_continuam_funcionando():
    assert parsear_linha_auth("Jun  1 02:10:01 server sshd[1]: Failed password for root from 185.220.101.1 port 1 ssh2")["tipo"] == "FAIL"
    fw = parsear_linha_firewall("Jun  1 02:10:00 fw kernel: [UFW BLOCK] IN=eth0 OUT= SRC=45.33.32.156 DST=10.0.0.1 PROTO=TCP DPT=22 SPT=6")
    assert fw["porta"] == 22
    web = parsear_linha_web('23.94.5.100 - - [01/Jun/2025:02:12:00 +0000] "GET /login?id=1\' OR \'1\'=\'1 HTTP/1.1" 200 1 "-" "sqlmap/1.7.8"')
    assert web["url"] == "/login?id=1' OR '1'='1"
    resultado = analisar_pasta(f"{RAIZ}/logs/exemplos_reais", blacklist=set(BLACKLIST))
    assert len(resultado["eventos"]) == 58
    assert any(a["regra_id"] == "R006" for a in resultado["alertas"])  # SQLi detectado


def test_normalizar_timestamp():
    assert normalizar_timestamp("2025-02-20 08:15:01") == "2025-02-20T08:15:01"
    assert normalizar_timestamp("01/Jun/2025:02:10:00 +0000") == "2025-06-01T02:10:00"
    assert normalizar_timestamp("Jun  1 02:10:01") == "2025-06-01T02:10:01"
    assert normalizar_timestamp("lixo") is None


def test_bonus_brute_force_em_janela(eventos):
    janela = detectar_brute_force_janela(eventos, janela_segundos=60, threshold=5)
    assert janela["185.220.101.1"]["max_na_janela"] >= 10
    assert "45.33.32.156" not in janela  # só 3 falhas
    curta = detectar_brute_force_janela(eventos, janela_segundos=5, threshold=3)
    assert "91.240.118.172" not in curta  # falhas espaçadas (low-and-slow) não disparam janela curta


def test_regras_detectam_ataque_com_url_codificada():
    """Ferramentas como o sqlmap mandam a URL codificada (%20, %27); a regra precisa ver através disso."""
    from core.coletor import parsear_linha_web
    from core.regras import aplicar_regras, carregar_regras
    regras = carregar_regras(f"{RAIZ}/config/regras.json")
    casos = {
        "R006": '203.0.113.45 - - [08/Nov/2026:14:10:00 -0300] "GET /p?id=1\'%20OR%20\'1\'=\'1 HTTP/1.1" 500 1 "-" "sqlmap"',
        "R003": '203.0.113.45 - - [08/Nov/2026:14:10:01 -0300] "GET /d?f=%252e%252e%252fetc%252fpasswd HTTP/1.1" 400 1 "-" "curl"',
        "R004": '203.0.113.45 - - [08/Nov/2026:14:10:02 -0300] "GET /b?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 1 "-" "x"',
    }
    for regra_id, linha in casos.items():
        evento = parsear_linha_web(linha.replace("\\'", "'"))
        assert evento, linha
        assert regra_id in {a["regra_id"] for a in aplicar_regras([evento], regras)}, regra_id
