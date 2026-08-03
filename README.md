# giga-setup

Bootstrap e desired state Windows para endpoints GigaNet gerenciados pelo [Action1](https://www.action1.com/).

## Arquivos

| Arquivo | Função |
|---------|--------|
| [`agent/install-agent.ps1`](agent/install-agent.ps1) | Instala o agente Action1 (GigaNet), de forma silenciosa e idempotente |
| [`run.ps1`](run.ps1) | Desired state idempotente: admin local, OpenSSH, firewall TCP 22 |

## 1. Instalar o agente Action1

Em um PowerShell **elevado** na máquina:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\agent\install-agent.ps1
```

Se o agente já estiver instalado, o script sai com `[OK]` e não reinstala.

## 2. Desired state (`run.ps1`)

O script garante, a cada execução:

1. Conta **Administrator** built-in (SID `*-500`) ativa, no grupo Administradores, com a senha corporativa definida no script
2. **OpenSSH Server** instalado, serviço `sshd` em Automatic + Running
3. Regra de firewall **GigaNet-OpenSSH-22** (Allow inbound TCP 22)

Execução manual (elevada):

```powershell
.\run.ps1
```

Códigos de saída:

- `0` — tudo conforme ou corrigido com sucesso
- `1` — uma ou mais ensures falharam (veja linhas `[FAIL]`)

Logs usam `[OK]`, `[CHANGED]`, `[FAIL]` e `[INFO]`.

## 3. Agendar no Action1

O schedule fica no console Action1 (fonte da verdade). Não há Task Scheduler local criado por estes scripts.

Passos sugeridos:

1. No Action1, abra **Automate** → **Scripts** (ou equivalente de automation)
2. Crie um script com o conteúdo de `run.ps1` (cole o arquivo ou faça download de um raw URL do repositório, se hospedado)
3. Agende a execução periódica nos endpoints do grupo GigaNet
4. Frequência sugerida: **a cada 1–6 horas**
5. Execute como **SYSTEM** / elevated

Após a instalação do agente, o Action1 passa a chamar `run.ps1` no intervalo definido e reconverge o estado se alguém alterar admin, SSH ou firewall.

## Segurança

A senha do administrador local está em texto claro em `run.ps1` (break-glass corporativo). Restrinja acesso ao repositório e às automações Action1. Qualquer pessoa com o script consegue a senha.
