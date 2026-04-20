import os
import json
import stat
import subprocess
from datetime import datetime

# ============================================================
#   BYEVIRUS - Scanner de Segurança v2.0
#   Detecta: extensões perigosas, arquivos suspeitos,
#            portas abertas, permissões erradas, processos,
#            persistência no sistema
# ============================================================

print("=" * 60)
print("   BYEVIRUS - Anti-Ameaça de Código Aberto v2.0")
print("=" * 60)

# ── Permissões perigosas em extensões ───────────────────────
PERMISSOES_PERIGOSAS = [
    "tabs", "webRequest", "webRequestBlocking",
    "cookies", "history", "passwords", "bookmarks",
    "downloads", "clipboardRead", "geolocation",
    "nativeMessaging", "proxy", "privacy",
    "contentSettings", "management",
    "declarativeNetRequest", "declarativeNetRequestFeedback",
]

# ── Palavras suspeitas dentro de arquivos de script ─────────
PALAVRAS_SUSPEITAS_CODIGO = [
    "wannacry", "bruteforce", "keylogger",
    "import socket", "reverse_shell", "bind_shell",
    "subprocess.call", "os.system", "eval(base64",
    "exec(base64", "base64.b64decode", "ctypes.windll",
    "payload", "metasploit", "msfvenom",
    "nmap.PortScanner", "paramiko", "rootkit",
    "covert_channel", "steganography", "reflective",
    "dll_inject", "zero-day", "exploit", "overflow",
    "sql injection", "xss", "privilege escalat",
]

# ── Extensões de arquivo perigosas ──────────────────────────
EXTENSOES_ARQUIVO_PERIGOSAS = [
    ".exe", ".bat", ".sh", ".bin", ".run",
    ".vbs", ".ps1", ".php", ".jar", ".msi",
    ".elf", ".out", ".ko", ".so",
]

# ── Pastas para verificar arquivos suspeitos ────────────────
PASTAS_SUSPEITAS = [
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~/Desktop"),
]

# ── Portas usadas por ferramentas de ataque ─────────────────
PORTAS_SUSPEITAS = {
    "4444":  "Metasploit reverse shell",
    "1337":  "Backdoor clássico",
    "31337": "Back Orifice",
    "5555":  "ADB / Android Debug",
    "6666":  "Malware comum",
    "9999":  "Trojan comum",
    "1234":  "Backdoor genérico",
    "8888":  "Tunnel/Proxy suspeito",
    "2222":  "SSH alternativo suspeito",
    "12345": "NetBus trojan",
}

# ── Processos de ferramentas de ataque ──────────────────────
PROCESSOS_SUSPEITOS = [
    "ncat", "netcat", "nc -l",
    "msfconsole", "msfvenom",
    "wireshark", "tcpdump",
    "keylogger", "hydra", "sqlmap",
    "john", "hashcat", "aircrack",
    "ettercap", "bettercap", "arpspoof",
    "mimikatz", "responder",
]


# ============================================================
#   MÓDULO 1 — Extensões do Navegador
# ============================================================

def escanear_extensoes():
    print("\n🔌 ESCANEANDO EXTENSÕES DO NAVEGADOR...")
    print("-" * 60)

    navegadores = {
        "Chrome":   os.path.expanduser("~/.config/google-chrome/Default/Extensions"),
        "Chromium": os.path.expanduser("~/.config/chromium/Default/Extensions"),
        "Brave":    os.path.expanduser("~/.config/brave-browser/Default/Extensions"),
        "Edge":     os.path.expanduser("~/.config/microsoft-edge/Default/Extensions"),
        "Vivaldi":  os.path.expanduser("~/.config/vivaldi/Default/Extensions"),
        "Opera":    os.path.expanduser("~/.config/opera/Extensions"),
    }

    resultados = []
    encontrou_navegador = False

    for nome_nav, pasta in navegadores.items():
        if not os.path.exists(pasta):
            continue

        encontrou_navegador = True
        print(f"\n  Navegador: {nome_nav}")

        for id_ext in os.listdir(pasta):
            caminho_ext = os.path.join(pasta, id_ext)
            if not os.path.isdir(caminho_ext):
                continue

            for versao in os.listdir(caminho_ext):
                manifest_path = os.path.join(caminho_ext, versao, "manifest.json")
                if not os.path.exists(manifest_path):
                    continue

                try:
                    with open(manifest_path, "r", encoding="utf-8") as f:
                        manifest = json.load(f)

                    nome      = manifest.get("name", "Desconhecido")
                    versao_n  = manifest.get("version", "?")
                    perms     = manifest.get("permissions", [])
                    perms    += manifest.get("host_permissions", [])
                    descricao = manifest.get("description", "")

                    perms = [p for p in perms if isinstance(p, str)]
                    riscos = [p for p in perms if p in PERMISSOES_PERIGOSAS]

                    acesso_total = any(
                        p in ["<all_urls>", "http://*/*", "https://*/*"]
                        for p in perms
                    )
                    if acesso_total:
                        riscos.append("ACESSO A TODOS OS SITES")

                    if len(riscos) >= 3:
                        nivel = "🔴 ALTO"
                    elif len(riscos) >= 1:
                        nivel = "🟡 MEDIO"
                    else:
                        nivel = "🟢 BAIXO"

                    resultado = {
                        "tipo":   "extensao",
                        "nav":    nome_nav,
                        "nome":   nome,
                        "versao": versao_n,
                        "riscos": riscos,
                        "nivel":  nivel,
                        "desc":   descricao[:80],
                    }
                    resultados.append(resultado)
                    print(f"    {nivel} | {nome} (v{versao_n})")
                    if riscos:
                        print(f"           ⚠ Permissões: {', '.join(riscos)}")

                except Exception:
                    pass

    if not encontrou_navegador:
        print("  Nenhum navegador com extensões encontrado.")

    return resultados


# ============================================================
#   MÓDULO 2 — Arquivos Suspeitos + Análise de Conteúdo
# ============================================================

def escanear_arquivos():
    print("\n📁 ESCANEANDO ARQUIVOS SUSPEITOS...")
    print("-" * 60)

    resultados = []

    for pasta in PASTAS_SUSPEITAS:
        if not os.path.exists(pasta):
            continue

        print(f"\n  Verificando: {pasta}")

        try:
            for arquivo in os.listdir(pasta):
                caminho = os.path.join(pasta, arquivo)
                if not os.path.isfile(caminho):
                    continue

                _, ext = os.path.splitext(arquivo)
                ext = ext.lower()

                if ext not in EXTENSOES_ARQUIVO_PERIGOSAS:
                    continue

                palavras_encontradas = []

                try:
                    with open(caminho, "r", encoding="utf-8", errors="ignore") as f:
                        conteudo = f.read(5000).lower()
                    for palavra in PALAVRAS_SUSPEITAS_CODIGO:
                        if palavra.lower() in conteudo:
                            palavras_encontradas.append(palavra)
                except Exception:
                    pass

                try:
                    info  = os.stat(caminho)
                    perms = oct(stat.S_IMODE(info.st_mode))
                    tam   = info.st_size

                    resultado = {
                        "tipo":     "arquivo",
                        "caminho":  caminho,
                        "ext":      ext,
                        "tamanho":  tam,
                        "perms":    perms,
                        "nivel":    "🔴 ALTO",
                        "palavras": palavras_encontradas,
                    }
                    resultados.append(resultado)
                    print(f"    🔴 ALTO | {caminho}")
                    print(f"           Tipo: {ext} | {tam} bytes | Perms: {perms}")
                    if palavras_encontradas:
                        print(f"           ⚠ Código suspeito: {', '.join(palavras_encontradas[:5])}")

                except Exception:
                    pass

        except PermissionError:
            print(f"    ⚠ Sem permissão para acessar {pasta}")

    # Verifica scripts Python na pasta atual
    print(f"\n  Verificando scripts Python na pasta atual...")
    try:
        for arquivo in os.listdir("."):
            if arquivo.endswith(".py") and arquivo != "byevirus.py":
                caminho = os.path.join(".", arquivo)
                try:
                    with open(caminho, "r", encoding="utf-8", errors="ignore") as f:
                        conteudo = f.read().lower()
                    palavras = [p for p in PALAVRAS_SUSPEITAS_CODIGO if p.lower() in conteudo]
                    if palavras:
                        resultado = {
                            "tipo":     "arquivo",
                            "caminho":  caminho,
                            "ext":      ".py",
                            "tamanho":  os.path.getsize(caminho),
                            "perms":    "—",
                            "nivel":    "🟡 MEDIO",
                            "palavras": palavras,
                        }
                        resultados.append(resultado)
                        print(f"    🟡 MEDIO | {caminho}")
                        print(f"           ⚠ Palavras suspeitas: {', '.join(palavras[:5])}")
                except Exception:
                    pass
    except Exception:
        pass

    if not resultados:
        print("  Nenhum arquivo suspeito encontrado.")

    return resultados


# ============================================================
#   MÓDULO 3 — Portas Abertas
# ============================================================

def escanear_portas():
    print("\n🌐 ESCANEANDO PORTAS ABERTAS...")
    print("-" * 60)

    resultados = []

    try:
        saida = subprocess.check_output(
            ["ss", "-tuln"],
            stderr=subprocess.DEVNULL
        ).decode("utf-8")

        for linha in saida.splitlines():
            for porta, descricao in PORTAS_SUSPEITAS.items():
                if f":{porta} " in linha or linha.endswith(f":{porta}"):
                    resultado = {
                        "tipo":      "porta",
                        "porta":     porta,
                        "descricao": descricao,
                        "linha":     linha.strip(),
                        "nivel":     "🔴 ALTO",
                    }
                    resultados.append(resultado)
                    print(f"  🔴 ALTO | Porta {porta} aberta — {descricao}")
                    print(f"         {linha.strip()}")

        if not resultados:
            print("  Nenhuma porta suspeita encontrada.")

    except Exception as e:
        print(f"  Erro ao verificar portas: {e}")

    return resultados


# ============================================================
#   MÓDULO 4 — Processos Suspeitos
# ============================================================

def escanear_processos():
    print("\n⚙️  ESCANEANDO PROCESSOS ATIVOS...")
    print("-" * 60)

    resultados = []

    try:
        saida = subprocess.check_output(
            ["ps", "aux"],
            stderr=subprocess.DEVNULL
        ).decode("utf-8").lower()

        for processo in PROCESSOS_SUSPEITOS:
            if processo.lower() in saida:
                resultado = {
                    "tipo":     "processo",
                    "processo": processo,
                    "nivel":    "🔴 ALTO",
                }
                resultados.append(resultado)
                print(f"  🔴 ALTO | Processo suspeito ativo: {processo}")

        if not resultados:
            print("  Nenhum processo suspeito encontrado.")

    except Exception as e:
        print(f"  Erro: {e}")

    return resultados


# ============================================================
#   MÓDULO 5 — Persistência no Sistema
# ============================================================

def escanear_persistencia():
    print("\n🚀 VERIFICANDO PERSISTÊNCIA (inicialização automática)...")
    print("-" * 60)

    locais = [
        os.path.expanduser("~/.bashrc"),
        os.path.expanduser("~/.zshrc"),
        os.path.expanduser("~/.profile"),
        os.path.expanduser("~/.bash_profile"),
        os.path.expanduser("~/.config/autostart"),
        "/etc/cron.d",
        "/var/spool/cron",
        "/etc/init.d",
    ]

    resultados = []

    for local in locais:
        if not os.path.exists(local):
            continue

        if os.path.isfile(local):
            try:
                with open(local, "r", encoding="utf-8", errors="ignore") as f:
                    conteudo = f.read().lower()
                palavras = [p for p in PALAVRAS_SUSPEITAS_CODIGO if p.lower() in conteudo]
                if palavras:
                    resultado = {
                        "tipo":     "persistencia",
                        "local":    local,
                        "nivel":    "🔴 ALTO",
                        "palavras": palavras,
                    }
                    resultados.append(resultado)
                    print(f"  🔴 ALTO | Código suspeito em: {local}")
                    print(f"         ⚠ Encontrado: {', '.join(palavras[:3])}")
            except Exception:
                pass

        elif os.path.isdir(local):
            try:
                arquivos = os.listdir(local)
                if arquivos:
                    print(f"  ℹ️  {local}: {len(arquivos)} item(s) — verifique manualmente")
            except Exception:
                pass

    if not resultados:
        print("  Nenhuma persistência suspeita encontrada.")

    return resultados


# ============================================================
#   RELATÓRIO FINAL
# ============================================================

def gerar_relatorio(todos_resultados):
    agora    = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    nome_arq = f"relatorio_{agora}.txt"

    altos  = [r for r in todos_resultados if "ALTO"  in r.get("nivel", "")]
    medios = [r for r in todos_resultados if "MEDIO" in r.get("nivel", "")]

    with open(nome_arq, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("   BYEVIRUS v2.0 - RELATÓRIO DE SEGURANÇA\n")
        f.write(f"   Gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
        f.write(f"   Host: {os.uname().nodename}\n")
        f.write("=" * 60 + "\n\n")

        f.write("RESUMO:\n")
        f.write(f"  Total de ameaças:  {len(todos_resultados)}\n")
        f.write(f"  Risco ALTO:        {len(altos)}\n")
        f.write(f"  Risco MEDIO:       {len(medios)}\n\n")

        if len(altos) == 0 and len(medios) == 0:
            f.write("  ✅ Sistema aparentemente limpo!\n\n")
        elif len(altos) > 0:
            f.write("  ⚠️  ATENÇÃO: Ameaças de alto risco detectadas!\n\n")

        f.write("=" * 60 + "\n")
        f.write("DETALHES:\n")
        f.write("=" * 60 + "\n\n")

        for r in todos_resultados:
            tipo = r.get("tipo", "")

            if tipo == "extensao":
                f.write(f"[EXTENSÃO] {r['nivel']}\n")
                f.write(f"  Navegador:  {r['nav']}\n")
                f.write(f"  Nome:       {r['nome']} (v{r['versao']})\n")
                if r.get("desc"):
                    f.write(f"  Descrição:  {r['desc']}\n")
                if r["riscos"]:
                    f.write(f"  Perigos:    {', '.join(r['riscos'])}\n")

            elif tipo == "arquivo":
                f.write(f"[ARQUIVO] {r['nivel']}\n")
                f.write(f"  Caminho:    {r['caminho']}\n")
                f.write(f"  Extensão:   {r['ext']}\n")
                f.write(f"  Tamanho:    {r['tamanho']} bytes\n")
                if r.get("palavras"):
                    f.write(f"  Cód. susp.: {', '.join(r['palavras'][:5])}\n")

            elif tipo == "porta":
                f.write(f"[PORTA] {r['nivel']}\n")
                f.write(f"  Porta:      {r['porta']}\n")
                f.write(f"  Motivo:     {r['descricao']}\n")
                f.write(f"  Info:       {r['linha']}\n")

            elif tipo == "processo":
                f.write(f"[PROCESSO] {r['nivel']}\n")
                f.write(f"  Nome:       {r['processo']}\n")

            elif tipo == "persistencia":
                f.write(f"[PERSISTÊNCIA] {r['nivel']}\n")
                f.write(f"  Local:      {r['local']}\n")
                if r.get("palavras"):
                    f.write(f"  Encontrado: {', '.join(r['palavras'][:3])}\n")

            f.write("-" * 60 + "\n")

    print(f"\n📄 Relatório salvo em: {nome_arq}")
    return nome_arq


# ============================================================
#   MAIN
# ============================================================

def main():
    todos = []
    todos += escanear_extensoes()
    todos += escanear_arquivos()
    todos += escanear_portas()
    todos += escanear_processos()
    todos += escanear_persistencia()

    altos  = len([r for r in todos if "ALTO"  in r.get("nivel", "")])
    medios = len([r for r in todos if "MEDIO" in r.get("nivel", "")])
    baixos = len(todos) - altos - medios

    print("\n" + "=" * 60)
    print(f"   SCAN COMPLETO — {len(todos)} ameaças encontradas")
    print("=" * 60)
    print(f"  🔴 Risco ALTO:   {altos}")
    print(f"  🟡 Risco MEDIO:  {medios}")
    print(f"  🟢 Risco BAIXO:  {baixos}")

    if altos == 0 and medios == 0:
        print("\n  ✅ Sistema aparentemente limpo!")
    else:
        print("\n  ⚠️  Verifique o relatório para mais detalhes.")

    gerar_relatorio(todos)


main()