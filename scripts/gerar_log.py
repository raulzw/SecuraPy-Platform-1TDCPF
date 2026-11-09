"""
Gerador de logs de teste para o SecuraPy.

Cria um arquivo de log realista (SSH, firewall UFW e site Apache/Nginx) com
tráfego normal misturado aos ataques que você escolher. Serve para testar o
"Analisar um arquivo de log seu" do dashboard ou o POST /api/analisar.

Só usa a biblioteca padrão do Python — não precisa instalar nada.

Exemplos:
    py scripts/gerar_log.py                                # todos os ataques → ataque_gerado.log
    py scripts/gerar_log.py --saida loja.log --normais 80  # mais tráfego normal
    py scripts/gerar_log.py --ataques forca_bruta sqli     # só esses ataques
    py scripts/gerar_log.py --sucesso                      # a força bruta termina com login aceito
    py scripts/gerar_log.py --semente 7                    # mesma semente = mesmo arquivo

Ataques disponíveis: forca_bruta, port_scan, sqli, xss, path_traversal, scanner, blacklist
Os IPs de ataque são de faixas reservadas para documentação (RFC 5737) — não são de ninguém.
"""

import argparse
import random
from datetime import datetime, timedelta

ATAQUES = ("forca_bruta", "port_scan", "sqli", "xss", "path_traversal", "scanner", "blacklist")
USUARIOS_INTERNOS = ("ana", "bruno", "carla", "diego", "elisa")
USUARIOS_ATACADOS = ("root", "admin", "ubuntu", "test", "oracle", "deploy", "postgres", "sa")
PAGINAS = ("/", "/produtos", "/produtos/42", "/carrinho", "/checkout", "/contato", "/sobre", "/blog")
NAVEGADORES = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 14) Mobile Chrome/130.0",
)
IP_BLACKLIST = "23.94.5.100"  # está em config/blacklist.json


class Log:
    """Acumula as linhas com o relógio andando para frente."""

    def __init__(self, inicio, rng, host="loja-web"):
        self.t, self.rng, self.host, self.linhas = inicio, rng, host, []

    def passa(self, minimo=1, maximo=None):
        self.t += timedelta(seconds=self.rng.randint(minimo, maximo or minimo))

    def _syslog(self):
        return f"{self.t:%b} {self.t.day:2d} {self.t:%H:%M:%S} {self.host}"

    def ssh(self, ok, usuario, ip):
        acao = "Accepted password" if ok else "Failed password"
        pid, porta = self.rng.randint(1000, 9999), self.rng.randint(30000, 65000)
        self.linhas.append(f"{self._syslog()} sshd[{pid}]: {acao} for {usuario} from {ip} port {porta} ssh2")

    def firewall(self, acao, ip, porta):
        self.linhas.append(
            f"{self._syslog()} kernel: [UFW {acao}] IN=eth0 OUT= MAC= SRC={ip} DST=10.0.0.10 LEN=60 TOS=0x00 "
            f"PROTO=TCP SPT={self.rng.randint(30000, 65000)} DPT={porta} WINDOW=1024 RES=0x00 SYN URGP=0")

    def web(self, ip, url, status, agente=None, metodo="GET"):
        agente = agente or self.rng.choice(NAVEGADORES)
        self.linhas.append(f'{ip} - - [{self.t:%d/%b/%Y:%H:%M:%S} -0300] "{metodo} {url} HTTP/1.1" '
                           f'{status} {self.rng.randint(300, 9000)} "-" "{agente}"')


def ip_interno(rng):
    return f"192.168.0.{rng.randint(10, 60)}"


def ip_cliente(rng):
    return f"{rng.choice((177, 179, 187, 189, 200, 201))}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"


def ip_atacante(rng):
    return f"{rng.choice(('198.51.100', '203.0.113'))}.{rng.randint(2, 250)}"


# ── tráfego normal ───────────────────────────────────────────────────────────
def trafego_normal(log, quantidade):
    rng = log.rng
    for _ in range(quantidade):
        tipo = rng.random()
        if tipo < 0.15:
            usuario, ip = rng.choice(USUARIOS_INTERNOS), ip_interno(rng)
            if rng.random() < 0.2:  # errou a senha uma vez (não é ataque)
                log.ssh(False, usuario, ip)
                log.passa(3, 8)
            log.ssh(True, usuario, ip)
        elif tipo < 0.3:
            log.firewall("ALLOW", rng.choice((ip_interno(rng), ip_cliente(rng))), rng.choice((80, 443)))
        else:
            ip = ip_cliente(rng) if rng.random() < 0.7 else ip_interno(rng)
            log.web(ip, rng.choice(PAGINAS), rng.choice((200, 200, 200, 200, 304, 404)))
        log.passa(5, 60)


# ── ataques ──────────────────────────────────────────────────────────────────
def forca_bruta(log, ip, sucesso):
    for _ in range(log.rng.randint(10, 18)):
        log.ssh(False, log.rng.choice(USUARIOS_ATACADOS), ip)
        log.passa(1, 3)
    if sucesso:  # o pior cenário: depois de muitas tentativas, uma senha funcionou
        log.ssh(True, "deploy", ip)


def port_scan(log, ip):
    for porta in sorted(log.rng.sample((21, 22, 23, 25, 110, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080), 9)):
        log.firewall("BLOCK", ip, porta)
        log.passa(1)


def sqli(log, ip):
    for url in ("/produtos?id=1'%20OR%20'1'='1",
                "/produtos?id=1%20UNION%20SELECT%20usuario,senha%20FROM%20clientes--",
                "/login?usuario=admin'--&senha=x"):
        log.web(ip, url, log.rng.choice((500, 200)), "sqlmap/1.8.4#stable")
        log.passa(2, 4)


def xss(log, ip):
    for url in ("/busca?q=<script>alert(document.cookie)</script>",
                "/contato?nome=%3Cimg%20src=x%20onerror=alert(1)%3E"):
        log.web(ip, url, 200, "Mozilla/5.0")
        log.passa(2, 5)


def path_traversal(log, ip):
    for url in ("/download?arquivo=../../../../etc/passwd",
                "/download?arquivo=%252e%252e%252f%252e%252e%252fetc%252fshadow"):
        log.web(ip, url, 400, "curl/8.5.0")
        log.passa(2, 4)


def scanner(log, ip):
    for url in ("/robots.txt", "/admin", "/wp-login.php", "/.env", "/.git/config", "/phpmyadmin/"):
        log.web(ip, url, log.rng.choice((403, 404)), "Nikto/2.5.0")
        log.passa(1, 2)


def blacklist(log, _ip):
    for porta in (22, 445, 3389):
        log.firewall("BLOCK", IP_BLACKLIST, porta)
        log.passa(1, 3)
    log.web(IP_BLACKLIST, "/admin/config.php", 404, "masscan/1.3")


def gerar(ataques=ATAQUES, normais=40, sucesso=False, semente=None, inicio=None):
    """Monta o log e devolve (linhas, resumo de quem atacou o quê)."""
    rng = random.Random(semente)
    log = Log(inicio or datetime.now().replace(hour=9, minute=0, second=0, microsecond=0), rng)
    resumo = {}
    atacante_web = ip_atacante(rng)
    atacante_rede = ip_atacante(rng)
    while atacante_rede == atacante_web:
        atacante_rede = ip_atacante(rng)

    trafego_normal(log, normais // 2)
    for nome in ataques:
        ip = atacante_rede if nome in ("forca_bruta", "port_scan") else atacante_web
        if nome == "blacklist":
            ip = IP_BLACKLIST
        if nome == "forca_bruta":
            forca_bruta(log, ip, sucesso)
        else:
            globals()[nome](log, ip)
        resumo.setdefault(ip, []).append(nome + (" (com login aceito)" if nome == "forca_bruta" and sucesso else ""))
        log.passa(30, 120)
        trafego_normal(log, rng.randint(1, 4))
    trafego_normal(log, normais - normais // 2)
    return log.linhas, resumo


def main():
    p = argparse.ArgumentParser(description="Gera um arquivo de log de teste para o SecuraPy")
    p.add_argument("--saida", default="ataque_gerado.log", help="arquivo a criar (padrão: ataque_gerado.log)")
    p.add_argument("--normais", type=int, default=40, help="quantidade de eventos normais (padrão: 40)")
    p.add_argument("--ataques", nargs="+", choices=ATAQUES, default=list(ATAQUES), help="quais ataques incluir")
    p.add_argument("--sucesso", action="store_true", help="a força bruta termina com um login aceito")
    p.add_argument("--semente", type=int, help="número fixo para gerar sempre o mesmo arquivo")
    a = p.parse_args()
    if a.normais < 0:
        p.error("--normais não pode ser negativo")

    linhas, resumo = gerar(a.ataques, a.normais, a.sucesso, a.semente)
    with open(a.saida, "w", encoding="utf-8") as f:
        f.write("\n".join(linhas) + "\n")

    print(f"Log criado: {a.saida} ({len(linhas)} linhas)")
    print("Atacantes neste arquivo:")
    for ip, lista in resumo.items():
        print(f"  {ip:16s} {', '.join(lista)}")
    print("Envie em: Dashboard → 'Analisar um arquivo de log seu'.")


if __name__ == "__main__":
    main()
