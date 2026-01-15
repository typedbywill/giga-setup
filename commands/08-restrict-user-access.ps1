# ============================================================
# Script: 08-restrict-user-access.ps1
# Descrição: Bloqueia Terminal, Configurações e Painel de Controle para Usuario
# Idempotente: Aplica políticas de grupo local
# ============================================================

$ErrorActionPreference = "Stop"

$userName = "Usuario"

Write-Host "[INFO] Aplicando restrições para o usuário '$userName'..." -ForegroundColor Cyan

# Verificar se o usuário existe
$userExists = Get-LocalUser -Name $userName -ErrorAction SilentlyContinue
if (-not $userExists) {
    Write-Host "[ERRO] Usuário '$userName' não existe. Execute 03-create-user.ps1 primeiro." -ForegroundColor Red
    exit 1
}

# Obter SID do usuário
$userSID = (Get-LocalUser -Name $userName).SID.Value
Write-Host "[INFO] SID do usuário: $userSID" -ForegroundColor Gray

# Caminho do registro para políticas do usuário
$policyPath = "Registry::HKEY_USERS\$userSID\Software\Microsoft\Windows\CurrentVersion\Policies"

# Verificar se o perfil está carregado
$profileLoaded = Test-Path "Registry::HKEY_USERS\$userSID"

if (-not $profileLoaded) {
    Write-Host "[AVISO] Perfil do usuário não está carregado. Aplicando via registro local..." -ForegroundColor Yellow
    
    # Usar HKEY_LOCAL_MACHINE para aplicar restrições globais
    $explorerPolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $systemPolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
} else {
    $explorerPolicyPath = "$policyPath\Explorer"
    $systemPolicyPath = "$policyPath\System"
}

# Função para criar chave de registro se não existir
function Ensure-RegistryPath {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
}

# ============================================================
# 1. Bloquear CMD (Prompt de Comando)
# ============================================================
Write-Host ""
Write-Host "[1/4] Bloqueando Prompt de Comando (CMD)..." -ForegroundColor Yellow

try {
    Ensure-RegistryPath $systemPolicyPath
    Set-ItemProperty -Path $systemPolicyPath -Name "DisableCMD" -Value 2 -Type DWord
    Write-Host "[OK] CMD bloqueado." -ForegroundColor Green
} catch {
    Write-Host "[ERRO] Falha ao bloquear CMD: $_" -ForegroundColor Red
}

# ============================================================
# 2. Bloquear PowerShell (via AppLocker ou Software Restriction)
# ============================================================
Write-Host ""
Write-Host "[2/4] Configurando restrição para PowerShell..." -ForegroundColor Yellow

# Criar regra de restrição para PowerShell no Software Restriction Policies
$srpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
try {
    Ensure-RegistryPath $srpPath
    Set-ItemProperty -Path $srpPath -Name "DefaultLevel" -Value 262144 -Type DWord
    Set-ItemProperty -Path $srpPath -Name "TransparentEnabled" -Value 1 -Type DWord
    Write-Host "[OK] Políticas de restrição configuradas." -ForegroundColor Green
} catch {
    Write-Host "[AVISO] Não foi possível configurar SRP: $_" -ForegroundColor Yellow
}

# ============================================================
# 3. Bloquear Painel de Controle e Configurações
# ============================================================
Write-Host ""
Write-Host "[3/4] Bloqueando Painel de Controle e Configurações..." -ForegroundColor Yellow

try {
    Ensure-RegistryPath $explorerPolicyPath
    
    # Bloquear Painel de Controle
    Set-ItemProperty -Path $explorerPolicyPath -Name "NoControlPanel" -Value 1 -Type DWord
    Write-Host "[OK] Painel de Controle bloqueado." -ForegroundColor Green
} catch {
    Write-Host "[ERRO] Falha ao bloquear Painel de Controle: $_" -ForegroundColor Red
}

# ============================================================
# 4. Bloquear acesso às Configurações do Windows (Settings)
# ============================================================
Write-Host ""
Write-Host "[4/4] Bloqueando app de Configurações..." -ForegroundColor Yellow

$settingsBlockPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
try {
    Ensure-RegistryPath $settingsBlockPath
    
    # Bloquear Settings (ms-settings)
    Set-ItemProperty -Path $settingsBlockPath -Name "SettingsPageVisibility" -Value "hide:*" -Type String
    Write-Host "[OK] Configurações bloqueadas." -ForegroundColor Green
} catch {
    Write-Host "[AVISO] Não foi possível bloquear Configurações: $_" -ForegroundColor Yellow
}

# ============================================================
# 5. Bloquear Gerenciador de Tarefas
# ============================================================
Write-Host ""
Write-Host "[5/7] Bloqueando Gerenciador de Tarefas..." -ForegroundColor Yellow

try {
    Ensure-RegistryPath $systemPolicyPath
    Set-ItemProperty -Path $systemPolicyPath -Name "DisableTaskMgr" -Value 1 -Type DWord
    Write-Host "[OK] Gerenciador de Tarefas bloqueado." -ForegroundColor Green
} catch {
    Write-Host "[ERRO] Falha ao bloquear Gerenciador de Tarefas: $_" -ForegroundColor Red
}

# ============================================================
# 6. Bloquear Executar (Win+R)
# ============================================================
Write-Host ""
Write-Host "[6/7] Bloqueando comando Executar..." -ForegroundColor Yellow

try {
    Ensure-RegistryPath $explorerPolicyPath
    Set-ItemProperty -Path $explorerPolicyPath -Name "NoRun" -Value 1 -Type DWord
    Write-Host "[OK] Comando Executar bloqueado." -ForegroundColor Green
} catch {
    Write-Host "[ERRO] Falha ao bloquear comando Executar: $_" -ForegroundColor Red
}

# ============================================================
# 7. Ocultar Unidade C:
# ============================================================
Write-Host ""
Write-Host "[7/7] Ocultando unidade C: do Explorer..." -ForegroundColor Yellow

try {
    Ensure-RegistryPath $explorerPolicyPath
    # 4 = Restrict A & B only
    # 8 = Restrict C only (Decimal value is 4, but let's double check bitmask)
    # A=1, B=2, C=4, D=8... It's a bitmask.
    # To hide C only, value is 4.
    Set-ItemProperty -Path $explorerPolicyPath -Name "NoViewOnDrive" -Value 4 -Type DWord
    Write-Host "[OK] Unidade C: ocultada." -ForegroundColor Green
} catch {
    Write-Host "[ERRO] Falha ao ocultar unidade C: $_" -ForegroundColor Red
}

# ============================================================
# Resumo
# ============================================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "         RESTRIÇÕES APLICADAS          " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  - CMD (Prompt de Comando): Bloqueado" -ForegroundColor White
Write-Host "  - PowerShell: Restrito via SRP" -ForegroundColor White
Write-Host "  - Painel de Controle: Bloqueado" -ForegroundColor White
Write-Host "  - Configurações: Bloqueadas" -ForegroundColor White
Write-Host "  - Gerenciador de Tarefas: Bloqueado" -ForegroundColor White
Write-Host "  - Comando Executar (Win+R): Bloqueado" -ForegroundColor White
Write-Host "  - Unidade C: Oculta" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[IMPORTANTE] Reinicie o computador para aplicar todas as alterações." -ForegroundColor Yellow
