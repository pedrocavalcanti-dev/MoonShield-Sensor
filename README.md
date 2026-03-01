# Jarvis Guard Sensor

```
     ██╗ ██████╗      ███████╗███████╗███╗   ██╗███████╗ ██████╗ ██████╗
     ██║██╔════╝      ██╔════╝██╔════╝████╗  ██║██╔════╝██╔═══██╗██╔══██╗
     ██║██║  ███╗     ███████╗█████╗  ██╔██╗ ██║███████╗██║   ██║██████╔╝
██   ██║██║   ██║     ╚════██║██╔══╝  ██║╚██╗██║╚════██║██║   ██║██╔══██╗
╚█████╔╝╚██████╔╝     ███████║███████╗██║ ╚████║███████║╚██████╔╝██║  ██║
 ╚════╝  ╚═════╝      ╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
```

**Sensor Agent v2.0 — Jarvis Guard**  
Instala e configura o Suricata, monitora o `eve.json` e envia eventos em tempo real para o painel SOC.

---

## O que é isso?

O **Jarvis Guard Sensor** é o agente que roda na máquina Linux com Suricata (geralmente o gateway da rede).  
Na v2.0 ele ganhou um instalador completo do Suricata com detecção automática de topologia de rede, regras próprias (Jarvis Guard Ruleset) e um diagnóstico integrado.

```
Linux Gateway (Suricata)                     Servidor Jarvis Guard
────────────────────────                     ──────────────────────
Suricata → /var/log/suricata/eve.json
    └── sensor.py  ─────── POST ──────────▶  /incidentes/api/ingest/
                                                   └── Dashboard SOC
```

---

## Novidades da v2.0

- **Instalador automático do Suricata** — detecta WAN/LAN, redes (HOME\_NET), DNS interno e aplica os patches no `suricata.yaml` sem precisar editar nada manualmente
- **Jarvis Guard Ruleset v1** — 50 regras Suricata customizadas (SIDs 9900001–9900050) divididas em 7 grupos: Recon, Auth, Lateral, DNS/Policy, P2P/Mineração, Anomalia/Bot, TLS/QUIC
- **Diagnóstico integrado** — 15 checks automáticos que verificam toda a stack: instalação, configuração, serviço, permissões, topologia e regras
- **Estrutura modular** — separado em `nucleo/` e `suricata/` para facilitar manutenção e evolução
- **Topologia salva no config.json** — interface de captura, WAN, HOME\_NET e DNS interno persistem entre sessões

---

## Estrutura do repositório

```
Jarvis-Guard-Sensor/
│
├── sensor.py                   ← Entry point principal
├── config.json                 ← Gerado automaticamente (não sobe no git)
├── requirements.txt
├── .gitignore
├── README.md
│
├── nucleo/
│   ├── __init__.py
│   ├── configuracao.py         ← Constantes, config_padrao(), carregar/salvar
│   ├── interface.py            ← TUI completo (menu, wizard, todas as telas)
│   ├── monitoramento.py        ← Loop do sensor, envio HTTP em lotes, modo_auto
│   └── utilitarios.py          ← is_root, run_cmd, detectar pacote, helpers
│
└── suricata/
    ├── __init__.py
    ├── instalador.py           ← Instalação + detecção de topologia + patches yaml
    ├── diagnostico.py          ← Doctor: 15 checks automáticos
    └── regras_jg.rules         ← Jarvis Guard Ruleset v1 (50 regras)
```

---

## Pré-requisitos

- Linux (Ubuntu 20.04+ / Debian 11+ / CentOS 8+ / Arch)
- Python 3.9 ou superior
- `sudo` / root (necessário para instalar o Suricata e ler o `eve.json`)

---

## Instalação

### Passo 1 — Git (se não tiver)

```bash
# Debian / Ubuntu
sudo apt install git -y

# CentOS / Fedora
sudo dnf install git -y

# Arch
sudo pacman -S git
```

### Passo 2 — Clone o repositório

```bash
git clone https://github.com/pedrocavalcanti-dev/Jarvis-Guard-Sensor.git
cd Jarvis-Guard-Sensor
```

### Passo 3 — Ambiente virtual e dependências

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Passo 4 — Execute

```bash
sudo python3 jg_sensor.py```

> **Primeira execução:** o wizard abre automaticamente.  
> Informe a URL do Jarvis Guard, o nome do sensor e a severidade mínima.  
> Tudo é salvo em `config.json` — próximas execuções vão direto pro menu.

---

## Instalação rápida (tudo de uma vez)

```bash
sudo apt install git python3 python3-pip python3-venv -y
git clone https://github.com/pedrocavalcanti-dev/Jarvis-Guard-Sensor.git
cd Jarvis-Guard-Sensor
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
sudo python3 jg_sensor.py```

---

## Menu principal

```
╔══════════════════════════════════════════════════════╗
║              JARVIS GUARD — SENSOR v2.0              ║
╠══════════════════════════════════════════════════════╣
║  Status  : ● CONECTADO                               ║
║  Jarvis  : http://192.168.0.105:8000                 ║
║  Sensor  : IDS-GATEWAY-01                            ║
╠══════════════════════════════════════════════════════╣
║  [0] Instalar / Configurar Suricata                  ║
║  [1] Iniciar sensor                                  ║
║  [2] Configurar IP do Jarvis                         ║
║  [3] Configurar nome do sensor                       ║
║  [4] Configurar severidade mínima                    ║
║  [5] Configurar caminho do eve.json                  ║
║  [6] Testar conexão com Jarvis                       ║
║  [7] Ver configuração atual                          ║
║  [9] Diagnóstico do sistema                          ║
║  [8] Sair                                            ║
╚══════════════════════════════════════════════════════╝
```

---

## Instalador do Suricata — opção [0]

Ao entrar em **[0] Instalar / Configurar Suricata**, o instalador executa automaticamente:

1. Verifica Linux + root
2. Instala o Suricata via `apt` / `dnf` / `yum` / `pacman` (se não estiver instalado)
3. Localiza o `suricata.yaml` nos caminhos padrão — ou pergunta
4. **Detecta a topologia da rede automaticamente:**
   - Interface WAN pelo `ip route show default`
   - Interfaces com IP via `ip -o -4 addr show` (ignora `lo`, `docker0`, `veth*`, `tun*`, `wg*` etc.)
   - HOME\_NET: CIDRs de todas as interfaces internas
   - DNS interno: lê `/etc/resolv.conf`, verifica se algum nameserver está na subnet LAN, usa o IP da interface LAN como fallback
5. **Exibe a topologia detectada e pede confirmação em 4 passos:**
   - Passo 1: confirmar interface WAN
   - Passo 2: confirmar interface LAN (captura do Suricata)
   - Passo 3: confirmar HOME\_NET (CIDRs, separados por vírgula)
   - Passo 4: confirmar DNS interno / AdGuard
6. Copia as regras JG para `/etc/suricata/rules/jarvis-guard/jg.rules`
7. Faz backup do `suricata.yaml` → `suricata.yaml.jg.bak`
8. Aplica 4 patches no `suricata.yaml`:
   - `HOME_NET` com os CIDRs informados
   - `rule-files` com a entrada `jarvis-guard/jg.rules`
   - `eve-log` habilitado com `alert`, `dns`, `http`, `tls` em `/var/log/suricata/eve.json`
   - `af-packet` com a interface LAN de captura
9. Valida com `suricata -T` — restaura o backup automaticamente se falhar
10. Habilita e reinicia via `systemctl enable --now suricata`
11. Verifica se o `eve.json` foi criado

Ao final, a topologia completa é salva no `config.json`:

```json
{
  "interface_captura": "enp0s8",
  "interface_wan":     "enp0s3",
  "home_net":          ["192.168.10.0/24", "10.0.0.0/8"],
  "dns_interno":       "192.168.10.1",
  "suricata_yaml":     "/etc/suricata/suricata.yaml",
  "eve_path":          "/var/log/suricata/eve.json"
}
```

---

## Jarvis Guard Ruleset v1 — 50 regras customizadas

Instaladas em `/etc/suricata/rules/jarvis-guard/jg.rules`.  
SID range reservado: **9900001 – 9900050**.

| Grupo | SIDs | O que cobre |
|---|---|---|
| **A — Recon / Varredura** | 9900001–9900008 | Port scan SYN, ping sweep, host sweep TCP, SNMP, scan de painéis web, UDP multiporta, ARP excessivo, fingerprinting de firewall |
| **B — Brute Force / Auth** | 9900009–9900016 | SSH, RDP, FTP, SMB, WinRM HTTP/HTTPS (5985/5986), Telnet, brute em painel web |
| **C — Movimento Lateral** | 9900017–9900022 | RPC (135), NetBIOS (139), SMB sweep (445), SQL Server, MySQL, PostgreSQL |
| **D — DNS / Policy DNS** | 9900023–9900032 | Bypass Google DNS / Cloudflare / Quad9, volume alto de queries, NXDOMAIN em massa, consultas a ip-api.com / ifconfig.me / ipify / checkip.amazonaws / whatismyip (regex), DGA |
| **E — P2P / Mineração** | 9900033–9900038 | BitTorrent handshake, tracker HTTP por user-agent, Stratum mining.subscribe / .authorize, pools de mineração por DNS, Tor |
| **F — Anomalia / Bot** | 9900039–9900046 | TCP externo em massa, ICMP tunnel, TLS beaconing, DNS beaconing, C2 ports conhecidos, User-Agent vazio, download EXE via HTTP, DGA regex |
| **G — TLS / QUIC** | 9900047–9900050 | QUIC (UDP/443) informativo, SNI com subdomínio numérico, TLS sem SNI, QUIC volume alto |

> As regras usam `detection_filter` para evitar falsos positivos.  
> Os limiares são ponto de partida — ajuste `count` e `seconds` conforme o tráfego do seu ambiente.

---

## Diagnóstico — opção [9]

Executa **15 checks** automáticos organizados por grupo:

| Grupo | Checks |
|---|---|
| **Sistema** | Linux, root |
| **Suricata** | Binário instalado (exibe versão), `suricata.yaml` encontrado, `suricata -T` válido |
| **Configuração** | HOME\_NET correto no yaml, regras JG instaladas, yaml referencia `jg.rules` |
| **Serviço** | `systemctl is-active suricata`, interface de captura existe e está `up` |
| **Logs** | `eve.json` existe (tamanho), `eve.json` crescendo em 4s, permissão de leitura |
| **Topologia** | DNS interno configurado, regra de bypass DNS ativa |

Ao final exibe:
- Ações recomendadas para cada falha
- Resumo da topologia salva (WAN, LAN, HOME\_NET, DNS, caminhos)
- Lista de comandos úteis prontos para copiar

---

## Severidade mínima — opção [4]

O sensor filtra eventos antes de enviar ao Jarvis Guard:

| Opção | Envia |
|---|---|
| **[1] Crítico** | Só alertas severity 1 |
| **[2] Alto** | Severity 1 e 2 |
| **[3] Médio** | Severity 1, 2 e 3 |
| **[4] Todos** | Sem filtro (padrão) |

> Recomendado para produção: **[3] Médio** — equilibra cobertura e volume.

---

## Rodar como serviço systemd (produção)

```bash
sudo nano /etc/systemd/system/jg-sensor.service
```

```ini
[Unit]
Description=Jarvis Guard Sensor Agent v2
After=network.target suricata.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/Jarvis-Guard-Sensor
ExecStart=/opt/Jarvis-Guard-Sensor/venv/bin/python sensor.py --auto
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable jg-sensor
sudo systemctl start jg-sensor
sudo systemctl status jg-sensor
```

> O flag `--auto` pula o menu e inicia o sensor direto.  
> Um heartbeat é enviado ao Jarvis Guard a cada 30s para manter o status online no painel.

---

## Requisitos de rede

- O sensor precisa alcançar o Jarvis Guard via HTTP (porta padrão `8000`)
- O Jarvis Guard deve estar rodando com `python gerenciar.py runserver 0.0.0.0:8000`
- O `eve.json` precisa ter permissão de leitura:

```bash
sudo chmod 644 /var/log/suricata/eve.json
```

---

## Problemas comuns

**`eve.json` não encontrado**
```bash
sudo systemctl status suricata
grep -A5 "eve-log" /etc/suricata/suricata.yaml
# Ou use [9] Diagnóstico — ele verifica isso automaticamente
```

**Jarvis Guard não acessível**
```bash
# Garanta que o Jarvis está ouvindo em 0.0.0.0
python gerenciar.py runserver 0.0.0.0:8000
# Verifique ALLOWED_HOSTS no settings.py
```

**Permissão negada no `eve.json`**
```bash
sudo chmod 644 /var/log/suricata/eve.json
```

**`suricata -T` falhou após instalação**
```bash
# O instalador restaura o backup automaticamente
# Para inspecionar manualmente:
suricata -T -c /etc/suricata/suricata.yaml
# Para restaurar o backup:
sudo cp /etc/suricata/suricata.yaml.jg.bak /etc/suricata/suricata.yaml
```

**Sensor aparece online mas sem alertas**
```bash
# Verifique se o Suricata está capturando
tail -f /var/log/suricata/eve.json
# Gere tráfego de teste — isso deve gerar alerta SID 9900028:
curl http://ip-api.com/json/
```

---

## Compatibilidade

| Sistema | Suporte |
|---|---|
| Ubuntu 20.04+ | ✅ |
| Debian 11+ | ✅ |
| CentOS / RHEL 8+ | ✅ |
| Arch Linux | ✅ |
| Windows WSL | ⚠️ Só sensor (sem instalador Suricata) |

---

## Relacionado

- [Jarvis Guard](https://github.com/pedrocavalcanti-dev/Jarvis-Guard) — Dashboard SOC principal

---

<div align="center">
Parte do ecossistema <strong>Jarvis Guard</strong> &nbsp;•&nbsp; v2.0
</div>