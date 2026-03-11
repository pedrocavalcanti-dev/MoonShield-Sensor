# MOONSHIELD Sensor

```
     ██╗ ██████╗      ███████╗███████╗███╗   ██╗███████╗ ██████╗ ██████╗
     ██║██╔════╝      ██╔════╝██╔════╝████╗  ██║██╔════╝██╔═══██╗██╔══██╗
     ██║██║  ███╗     ███████╗█████╗  ██╔██╗ ██║███████╗██║   ██║██████╔╝
██   ██║██║   ██║     ╚════██║██╔══╝  ██║╚██╗██║╚════██║██║   ██║██╔══██╗
╚█████╔╝╚██████╔╝     ███████║███████╗██║ ╚████║███████║╚██████╔╝██║  ██║
 ╚════╝  ╚═════╝      ╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
```

**Sensor Agent v2.0 — MOONSHIELD**

> Instala e configura o Suricata, monitora o `eve.json` e envia eventos em tempo real para o painel SOC.

---

## O que é isso?

O **MOONSHIELD Sensor** é o agente que roda na máquina Linux com Suricata (geralmente o gateway da rede).

Na **v2.0** ele ganhou:
- Instalador completo do Suricata com detecção automática de topologia de rede
- Regras próprias (**MOONSHIELD Ruleset**)
- Autenticação por usuário/senha com sessão persistente
- Diagnóstico integrado com **15 checks automáticos**

```
Linux Gateway (Suricata)                     Servidor MOONSHIELD
────────────────────────                     ──────────────────────
Suricata → /var/log/suricata/eve.json
    └── ms_sensor.py  ─────── POST ──────────▶  /incidentes/api/ingest/
                                                   └── Dashboard SOC
```

---

## ✨ Novidades da v2.0

| # | Novidade |
|---|----------|
| 🔐 | **Autenticação por usuário/senha** — sessão HTTP persistente com cookies, renovada automaticamente a cada hora. Credenciais salvas no `config.json` |
| ⚙️ | **Gerenciamento de credenciais no menu** — opção `[8]` permite ver, atualizar e testar usuário/senha sem rodar o wizard novamente |
| 🛠️ | **Instalador automático do Suricata** — detecta WAN/LAN, redes (`HOME_NET`), DNS interno e aplica patches no `suricata.yaml` automaticamente |
| 📋 | **Regras Emerging Threats (ET Open)** — ~40.000 assinaturas (malware, C2, exploits, botnets) via `suricata-update` |
| 🛡️ | **MOONSHIELD Ruleset v1** — 50 regras customizadas (SIDs `9900001–9900050`) em 7 grupos |
| 🩺 | **Diagnóstico integrado** — 15 checks automáticos para toda a stack |
| 🧩 | **Estrutura modular** — separado em `nucleo/` e `suricata/` para fácil manutenção |
| 💾 | **Topologia salva no config.json** — interface, WAN, HOME_NET e DNS persistem entre sessões |

---

## 📁 Estrutura do repositório

```
moonshield-Sensor/
│
├── ms_sensor.py                   ← Entry point principal
├── config.json                    ← Gerado automaticamente (não sobe no git)
├── requirements.txt
├── .gitignore
├── README.md
│
├── nucleo/
│   ├── __init__.py
│   ├── configuracao.py            ← Constantes, config_padrao(), carregar/salvar
│   ├── interface.py               ← TUI completo (menu, wizard, todas as telas)
│   ├── monitoramento.py           ← Loop do sensor, envio HTTP em lotes, modo_auto
│   └── utilitarios.py             ← is_root, run_cmd, detectar pacote, helpers
│
└── suricata/
    ├── __init__.py
    ├── instalador.py              ← Instalação + detecção de topologia + patches yaml
    ├── diagnostico.py             ← Doctor: 15 checks automáticos
    └── regras_ms.rules            ← MOONSHIELD Ruleset v1 (50 regras)
```

---

## 📋 Pré-requisitos

- Linux (Ubuntu 20.04+ / Debian 11+ / CentOS 8+ / Arch)
- Python 3.9 ou superior
- `sudo` / root (necessário para instalar o Suricata e ler o `eve.json`)

---

## ⚠️ Nota importante: como executar com root

O sensor precisa de privilégios de root para instalar o Suricata e ler o `eve.json`. Porém, em ambientes Linux (especialmente VMs), rodar `sudo python3` pode falhar porque o sudo cria um ambiente isolado onde o `python3` do venv ativado pelo usuário comum não está disponível.

```bash
# ✅ Recomendado — chama o python do venv diretamente com sudo
sudo venv/bin/python3 ms_sensor.py

# ✅ Alternativa — entrar como root e ativar o venv no shell root
sudo su
source venv/bin/activate
python3 ms_sensor.py

# ❌ Pode falhar — sudo não enxerga o venv ativado pelo usuário comum
sudo python3 ms_sensor.py
```

> Se você já está logado como root diretamente (sem sudo), ative o venv normalmente e execute `python3 ms_sensor.py` sem prefixo.

---

## 🚀 Instalação

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
git clone https://github.com/pedrocavalcanti-dev/moonshield-Sensor.git
cd moonshield-Sensor
```

### Passo 3 — Ambiente virtual e dependências

```bash
apt install python3-venv -y
python3 -m venv venv
source venv/bin/activate
pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
```

### Passo 4 — Execute

```bash
sudo venv/bin/python3 ms_sensor.py
```

> **Primeira execução:** o wizard abre automaticamente. Informe a URL do MOONSHIELD, faça login com usuário/senha, defina o nome do sensor e a severidade mínima. Tudo é salvo em `config.json` — próximas execuções vão direto pro menu.

---

## ⚡ Instalação rápida (tudo de uma vez)

```bash
sudo apt install git python3 python3-pip python3-venv -y
git clone https://github.com/pedrocavalcanti-dev/moonshield-Sensor.git
cd moonshield-Sensor
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
sudo venv/bin/python3 ms_sensor.py
```

---

## 🖥️ Menu principal

```
╔══════════════════════════════════════════════════════╗
║              MOONSHIELD — SENSOR v2.0              ║
╠══════════════════════════════════════════════════════╣
║  Status  : ● JARVIS ACESSÍVEL                        ║
║  Jarvis  : http://192.168.0.105:8000                 ║
║  Sensor  : IDS-GATEWAY-01                            ║
║  Eve.json: /var/log/suricata/eve.json                ║
╠══════════════════════════════════════════════════════╣
║  [0] Instalar / Configurar Suricata                  ║
║  [1] Iniciar sensor                                  ║
║  [2] Configurar IP do Jarvis                         ║
║  [3] Configurar nome do sensor                       ║
║  [4] Configurar severidade mínima                    ║
║  [5] Configurar caminho do eve.json                  ║
║  [6] Testar conexão com Jarvis                       ║
║  [7] Ver configuração atual                          ║
║  [8] Credenciais do Jarvis  (admin ✔)                ║
║  [9] Diagnóstico do sistema                          ║
║  [Q] Sair                                            ║
╚══════════════════════════════════════════════════════╝
```

---

## 🔐 Autenticação — wizard e opção [8]

O sensor autentica no MOONSHIELD usando sessão HTTP com cookies (mesmo mecanismo do painel web Django). Isso garante que eventos só sejam aceitos por sensores autorizados.

**No wizard (primeira execução):**
- Passo 2 pede usuário e senha do MOONSHIELD
- Testa o login em tempo real antes de salvar
- Até 3 tentativas antes de continuar sem autenticação

**Opção [8] — Credenciais do Jarvis:**
- Exibe o usuário atual e se a senha está configurada
- Permite atualizar usuário e senha a qualquer momento
- Valida o login antes de salvar (com opção de forçar sem validação)

**Durante o monitoramento:**
- Sessão renovada automaticamente a cada 1 hora
- Se receber HTTP 401/403, tenta reautenticar antes de desistir
- Status de login exibido em tempo real na tela do sensor

---

## 🛠️ Instalador do Suricata — opção [0]

Ao entrar em **[0] Instalar / Configurar Suricata**, o instalador executa automaticamente:

1. Verifica Linux + root
2. Instala o Suricata via `apt` / `dnf` / `yum` / `pacman` (se não estiver instalado)
3. Baixa regras Emerging Threats Open via `suricata-update` (~40.000 assinaturas, gratuitas)
4. Localiza o `suricata.yaml` nos caminhos padrão — ou pergunta
5. **Detecta a topologia da rede automaticamente:**
   - Interface WAN pelo `ip route show default`
   - Interfaces com IP via `ip -o -4 addr show` (ignora `lo`, `docker0`, `veth*`, `tun*`, `wg*` etc.)
   - HOME_NET: CIDRs de todas as interfaces internas
   - DNS interno: lê `/etc/resolv.conf`, verifica se algum nameserver está na subnet LAN
6. **Exibe a topologia detectada e pede confirmação em 4 passos:**
   - Passo 1: confirmar interface WAN
   - Passo 2: confirmar interface LAN (captura do Suricata)
   - Passo 3: confirmar HOME_NET (CIDRs, separados por vírgula)
   - Passo 4: confirmar DNS interno / AdGuard
7. Copia as regras JG para `/var/lib/suricata/rules/moonshield/ms.rules`
8. Faz backup do `suricata.yaml` → `suricata.yaml.jg.bak`
9. **Aplica 4 patches no `suricata.yaml`:**
   - `HOME_NET` com os CIDRs informados
   - `rule-files` com a entrada `moonshield/ms.rules`
   - `eve-log` habilitado com `alert`, `dns`, `http`, `tls` em `/var/log/suricata/eve.json`
   - `af-packet` com a interface LAN de captura
10. Valida com `suricata -T` — restaura o backup automaticamente se falhar
11. Habilita e reinicia via `systemctl enable --now suricata`
12. Verifica se o `eve.json` foi criado

**Ao final, a topologia completa é salva no `config.json`:**

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

## 🛡️ MOONSHIELD Ruleset v1 — 50 regras customizadas

Instaladas em `/var/lib/suricata/rules/moonshield/ms.rules`.  
**SID range reservado:** `9900001 – 9900050`

| Grupo | SIDs | O que cobre |
|-------|------|-------------|
| **A — Recon / Varredura** | 9900001–9900008 | Port scan SYN, ping sweep, host sweep TCP, SNMP, scan de painéis web, UDP multiporta, ARP excessivo, fingerprinting de firewall |
| **B — Brute Force / Auth** | 9900009–9900016 | SSH, RDP, FTP, SMB, WinRM HTTP/HTTPS (5985/5986), Telnet, brute em painel web |
| **C — Movimento Lateral** | 9900017–9900022 | RPC (135), NetBIOS (139), SMB sweep (445), SQL Server, MySQL, PostgreSQL |
| **D — DNS / Policy DNS** | 9900023–9900032 | Bypass Google DNS / Cloudflare / Quad9, volume alto de queries, NXDOMAIN em massa, consultas a ip-api.com / ifconfig.me / ipify / checkip.amazonaws / whatismyip (regex), DGA |
| **E — P2P / Mineração** | 9900033–9900038 | BitTorrent handshake, tracker HTTP por user-agent, Stratum mining.subscribe / .authorize, pools de mineração por DNS, Tor |
| **F — Anomalia / Bot** | 9900039–9900046 | TCP externo em massa, ICMP tunnel, TLS beaconing, DNS beaconing, C2 ports conhecidos, User-Agent vazio, download EXE via HTTP, DGA regex |
| **G — TLS / QUIC** | 9900047–9900050 | QUIC (UDP/443) informativo, SNI com subdomínio numérico, TLS sem SNI, QUIC volume alto |

> As regras usam `detection_filter` para evitar falsos positivos. Os limiares são ponto de partida — ajuste `count` e `seconds` conforme o tráfego do seu ambiente.

---

## 🩺 Diagnóstico — opção [9]

Executa **15 checks automáticos** organizados por grupo:

| Grupo | Checks |
|-------|--------|
| **Sistema** | Linux, root |
| **Suricata** | Binário instalado (exibe versão), `suricata.yaml` encontrado, `suricata -T` válido |
| **Configuração** | HOME_NET correto no yaml, regras JG instaladas, yaml referencia `ms.rules` |
| **Serviço** | `systemctl is-active suricata`, interface de captura existe e está up |
| **Logs** | `eve.json` existe (tamanho), `eve.json` crescendo em 4s, permissão de leitura |
| **Topologia** | DNS interno configurado, regra de bypass DNS ativa |

Ao final exibe: ações recomendadas para cada falha, resumo da topologia salva e lista de comandos úteis prontos para copiar.

---

## 🎚️ Severidade mínima — opção [4]

O sensor filtra eventos antes de enviar ao MOONSHIELD:

| Opção | Envia |
|-------|-------|
| **[1] Crítico** | Só alertas severity 1 |
| **[2] Alto** | Severity 1 e 2 |
| **[3] Médio** | Severity 1, 2 e 3 |
| **[4] Todos** | Sem filtro (padrão) |

> ✅ **Recomendado para produção:** `[3] Médio` — equilibra cobertura e volume.

---

## ⚙️ Rodar como serviço systemd (produção)

```bash
sudo nano /etc/systemd/system/jg-sensor.service
```

```ini
[Unit]
Description=MOONSHIELD Sensor Agent v2
After=network.target suricata.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/moonshield-Sensor
ExecStart=/opt/moonshield-Sensor/venv/bin/python ms_sensor.py --auto
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

> O flag `--auto` pula o menu e inicia o sensor direto. Um heartbeat é enviado ao MOONSHIELD a cada 30s para manter o status online no painel. No modo `--auto` o login é feito automaticamente usando as credenciais salvas no `config.json`.

---

## 🌐 Requisitos de rede

- O sensor precisa alcançar o MOONSHIELD via HTTP (porta padrão `8000`)
- O MOONSHIELD deve estar rodando com `python gerenciar.py runserver 0.0.0.0:8000`
- O `eve.json` precisa ter permissão de leitura:

```bash
sudo chmod 644 /var/log/suricata/eve.json
```

---

## 🔧 Problemas comuns

<details>
<summary><strong>sudo python3 não encontra o python do venv</strong></summary>

```bash
sudo venv/bin/python3 ms_sensor.py

# Ou entre como root e ative o venv:
sudo su
source venv/bin/activate
python3 ms_sensor.py
```
</details>

<details>
<summary><strong>eve.json não encontrado</strong></summary>

```bash
sudo systemctl status suricata
grep -A5 eve-log /etc/suricata/suricata.yaml
# Ou use [9] Diagnóstico — ele verifica isso automaticamente
```
</details>

<details>
<summary><strong>MOONSHIELD não acessível</strong></summary>

```bash
python gerenciar.py runserver 0.0.0.0:8000
# Verifique ALLOWED_HOSTS no settings.py
```
</details>

<details>
<summary><strong>Permissão negada no eve.json</strong></summary>

```bash
sudo chmod 644 /var/log/suricata/eve.json
```
</details>

<details>
<summary><strong>suricata -T falhou após instalação</strong></summary>

```bash
suricata -T -c /etc/suricata/suricata.yaml
sudo cp /etc/suricata/suricata.yaml.jg.bak /etc/suricata/suricata.yaml
```
</details>

<details>
<summary><strong>Login falhou no wizard ou opção [8]</strong></summary>

```bash
curl http://<IP>:8000/auth/login/
```
</details>

<details>
<summary><strong>Sensor aparece online mas sem alertas</strong></summary>

```bash
tail -f /var/log/suricata/eve.json
# Gere tráfego de teste — isso deve gerar alerta SID 9900028:
curl http://ip-api.com/json/
```
</details>

<details>
<summary><strong>suricata-update não encontrado (sem regras ET)</strong></summary>

```bash
pip3 install suricata-update
sudo suricata-update
sudo systemctl restart suricata
```
</details>

---

## 🖥️ Compatibilidade

| Sistema | Suporte |
|---------|---------|
| Ubuntu 20.04+ | ✅ |
| Debian 11+ | ✅ |
| CentOS / RHEL 8+ | ✅ |
| Arch Linux | ✅ |
| Windows WSL | ⚠️ Só sensor (sem instalador Suricata) |

---

## 🔗 Relacionado

- [MOONSHIELD — Dashboard SOC principal](https://github.com/pedrocavalcanti-dev/moonshield)

---

<div align="center">
  Parte do ecossistema <strong>MOONSHIELD</strong> &nbsp;•&nbsp; v2.0
</div>
