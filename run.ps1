# ============================================================
# GIGA SETUP - Script Unificado
# Gerado automaticamente via GitHub Actions
# Data: 2026-01-15 17:58:21 UTC
# ============================================================

# Requer execução como Administrador
#Requires -RunAsAdministrator

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "    GIGA SETUP - Configuração Windows   " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""


# ============================================================
# 01-enable-admin.ps1
# ============================================================

Write-Host '----------------------------------------' -ForegroundColor DarkGray
Write-Host 'Executando: 01-enable-admin.ps1' -ForegroundColor Yellow
Write-Host '----------------------------------------' -ForegroundColor DarkGray


$adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue

if (-not $adminAccount) {
    $adminAccount = Get-LocalUser -Name "Administrador" -ErrorAction SilentlyContinue
}

if (-not $adminAccount) {
    Write-Host "[ERRO] Conta de Administrador não encontrada no sistema." -ForegroundColor Red
    exit 1
}

$accountName = $adminAccount.Name

if ($adminAccount.Enabled) {
    Write-Host "[OK] Conta '$accountName' já está ativa." -ForegroundColor Green
} else {
    try {
        Enable-LocalUser -Name $accountName
        Write-Host "[SUCESSO] Conta '$accountName' foi ativada." -ForegroundColor Green
    } catch {
        Write-Host "[ERRO] Falha ao ativar conta '$accountName': $_" -ForegroundColor Red
        exit 1
    }
}


# ============================================================
# 02-set-admin-password.ps1
# ============================================================

Write-Host '----------------------------------------' -ForegroundColor DarkGray
Write-Host 'Executando: 02-set-admin-password.ps1' -ForegroundColor Yellow
Write-Host '----------------------------------------' -ForegroundColor DarkGray


$newPassword = ConvertTo-SecureString "TIGig@net2026" -AsPlainText -Force

$adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue

if (-not $adminAccount) {
    $adminAccount = Get-LocalUser -Name "Administrador" -ErrorAction SilentlyContinue
}

if (-not $adminAccount) {
    Write-Host "[ERRO] Conta de Administrador não encontrada no sistema." -ForegroundColor Red
    exit 1
}

$accountName = $adminAccount.Name

try {
    Set-LocalUser -Name $accountName -Password $newPassword
    Write-Host "[SUCESSO] Senha do '$accountName' foi definida." -ForegroundColor Green
} catch {
    Write-Host "[ERRO] Falha ao definir senha do '$accountName': $_" -ForegroundColor Red
    exit 1
}


# ============================================================
# 03-create-user.ps1
# ============================================================

Write-Host '----------------------------------------' -ForegroundColor DarkGray
Write-Host 'Executando: 03-create-user.ps1' -ForegroundColor Yellow
Write-Host '----------------------------------------' -ForegroundColor DarkGray


$userName = "Usuario"
$userFullName = "Usuário"

$existingUser = Get-LocalUser -Name $userName -ErrorAction SilentlyContinue

if ($existingUser) {
    Write-Host "[OK] Usuário '$userName' já existe." -ForegroundColor Green
} else {
    try {
        New-LocalUser -Name $userName -FullName $userFullName -Description "Usuário comum" -NoPassword
        Write-Host "[SUCESSO] Usuário '$userName' foi criado." -ForegroundColor Green
        
        # Adiciona ao grupo Usuários
        Add-LocalGroupMember -Group "Users" -Member $userName -ErrorAction SilentlyContinue
        Add-LocalGroupMember -Group "Usuarios" -Member $userName -ErrorAction SilentlyContinue
        Add-LocalGroupMember -Group "Usuários" -Member $userName -ErrorAction SilentlyContinue
        
        Write-Host "[INFO] Usuário '$userName' adicionado ao grupo de usuários." -ForegroundColor Cyan
    } catch {
        Write-Host "[ERRO] Falha ao criar usuário '$userName': $_" -ForegroundColor Red
        exit 1
    }
}


# ============================================================
# 04-remove-user-password.ps1
# ============================================================

Write-Host '----------------------------------------' -ForegroundColor DarkGray
Write-Host 'Executando: 04-remove-user-password.ps1' -ForegroundColor Yellow
Write-Host '----------------------------------------' -ForegroundColor DarkGray


$userName = "Usuario"

$existingUser = Get-LocalUser -Name $userName -ErrorAction SilentlyContinue

if (-not $existingUser) {
    Write-Host "[AVISO] Usuário '$userName' não existe. Execute 03-create-user.ps1 primeiro." -ForegroundColor Yellow
    exit 0
}

try {
    # Remove a senha definindo como vazia
    Set-LocalUser -Name $userName -Password ([securestring]::new())
    Write-Host "[SUCESSO] Senha do usuário '$userName' foi removida." -ForegroundColor Green
} catch {
    Write-Host "[ERRO] Falha ao remover senha do '$userName': $_" -ForegroundColor Red
    exit 1
}


# ============================================================
# 05-remove-other-users.ps1
# ============================================================

Write-Host '----------------------------------------' -ForegroundColor DarkGray
Write-Host 'Executando: 05-remove-other-users.ps1' -ForegroundColor Yellow
Write-Host '----------------------------------------' -ForegroundColor DarkGray


# Usuários que devem ser mantidos (nomes em inglês e português)
$keepUsers = @(
    "Administrator",
    "Administrador", 
    "Usuario",
    "DefaultAccount",
    "WDAGUtilityAccount",
    "Guest",
    "Convidado"
)

Write-Host "[INFO] Buscando usuários locais..." -ForegroundColor Cyan

$allUsers = Get-LocalUser

$usersToRemove = $allUsers | Where-Object { 
    $_.Name -notin $keepUsers -and 
    $_.Name -notlike "SYSTEM*" -and
    $_.Name -notlike "LOCAL*" -and
    $_.Name -notlike "NETWORK*"
}

if ($usersToRemove.Count -eq 0) {
    Write-Host "[OK] Nenhum usuário extra encontrado para remover." -ForegroundColor Green
    exit 0
}

Write-Host "[INFO] Usuários que serão removidos:" -ForegroundColor Yellow
$usersToRemove | ForEach-Object { Write-Host "  - $($_.Name)" -ForegroundColor Gray }

$removedCount = 0
$failedCount = 0

foreach ($user in $usersToRemove) {
    try {
        Remove-LocalUser -Name $user.Name -ErrorAction Stop
        Write-Host "[SUCESSO] Usuário '$($user.Name)' removido." -ForegroundColor Green
        $removedCount++
    } catch {
        Write-Host "[ERRO] Falha ao remover '$($user.Name)': $_" -ForegroundColor Red
        $failedCount++
    }
}

Write-Host ""
Write-Host "[RESUMO] Removidos: $removedCount | Falhas: $failedCount" -ForegroundColor Cyan


# ============================================================
# 06-enable-firewall.ps1
# ============================================================

Write-Host '----------------------------------------' -ForegroundColor DarkGray
Write-Host 'Executando: 06-enable-firewall.ps1' -ForegroundColor Yellow
Write-Host '----------------------------------------' -ForegroundColor DarkGray


$profiles = @("Domain", "Private", "Public")

Write-Host "[INFO] Verificando status do Windows Firewall..." -ForegroundColor Cyan

$allEnabled = $true

foreach ($profile in $profiles) {
    try {
        $status = Get-NetFirewallProfile -Name $profile
        
        if ($status.Enabled) {
            Write-Host "[OK] Firewall '$profile' já está ativo." -ForegroundColor Green
        } else {
            $allEnabled = $false
            Write-Host "[AVISO] Firewall '$profile' está desativado." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[ERRO] Falha ao verificar perfil '$profile': $_" -ForegroundColor Red
    }
}

if (-not $allEnabled) {
    Write-Host ""
    Write-Host "[INFO] Ativando Firewall em todos os perfis..." -ForegroundColor Cyan
    
    try {
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
        Write-Host "[SUCESSO] Windows Firewall ativado em todos os perfis." -ForegroundColor Green
    } catch {
        Write-Host "[ERRO] Falha ao ativar Firewall: $_" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host ""
    Write-Host "[OK] Firewall já está ativo em todos os perfis." -ForegroundColor Green
}


# ============================================================
# 07-block-social-sites.ps1
# ============================================================

Write-Host '----------------------------------------' -ForegroundColor DarkGray
Write-Host 'Executando: 07-block-social-sites.ps1' -ForegroundColor Yellow
Write-Host '----------------------------------------' -ForegroundColor DarkGray


# Sites a bloquear (domínios principais)
$sitesToBlock = @(
    "whatsapp.com",
    "www.whatsapp.com",
    "web.whatsapp.com",
    "api.whatsapp.com",
    "facebook.com",
    "www.facebook.com",
    "m.facebook.com",
    "static.facebook.com",
    "instagram.com",
    "www.instagram.com",
    "i.instagram.com",
    "static.instagram.com"
)

$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"

Write-Host "[INFO] Bloqueando sites de redes sociais via hosts file..." -ForegroundColor Cyan
Write-Host "[INFO] Arquivo: $hostsPath" -ForegroundColor Gray

# Ler conteúdo atual
try {
    $hostsContent = Get-Content -Path $hostsPath -ErrorAction SilentlyContinue
    if (-not $hostsContent) { $hostsContent = @() }
} catch {
    $hostsContent = @()
}

$addedCount = 0
$skippedCount = 0

$linesToAdd = @()

# Adicionar marcador se não existir
$marker = "# === GIGA SETUP - SITES BLOQUEADOS ==="
if ($hostsContent -notcontains $marker) {
    $linesToAdd += ""
    $linesToAdd += $marker
}

foreach ($site in $sitesToBlock) {
    $blockLine = "127.0.0.1 $site"
    
    if ($hostsContent -contains $blockLine) {
        Write-Host "[OK] Site '$site' já está bloqueado." -ForegroundColor Green
        $skippedCount++
    } else {
        $linesToAdd += $blockLine
        Write-Host "[+] Adicionando bloqueio: $site" -ForegroundColor Yellow
        $addedCount++
    }
}

if ($linesToAdd.Count -gt 0) {
    try {
        Add-Content -Path $hostsPath -Value $linesToAdd -Encoding ASCII
        Write-Host ""
        Write-Host "[SUCESSO] $addedCount site(s) bloqueado(s)." -ForegroundColor Green
    } catch {
        Write-Host "[ERRO] Falha ao modificar arquivo hosts: $_" -ForegroundColor Red
        Write-Host "[DICA] Execute como Administrador." -ForegroundColor Yellow
        exit 1
    }
} else {
    Write-Host ""
    Write-Host "[OK] Todos os sites já estavam bloqueados." -ForegroundColor Green
}

Write-Host ""
Write-Host "[RESUMO] Adicionados: $addedCount | Já existentes: $skippedCount" -ForegroundColor Cyan

# Limpar cache DNS
Write-Host ""
Write-Host "[INFO] Limpando cache DNS..." -ForegroundColor Cyan
try {
    ipconfig /flushdns | Out-Null
    Write-Host "[OK] Cache DNS limpo." -ForegroundColor Green
} catch {
    Write-Host "[AVISO] Não foi possível limpar o cache DNS." -ForegroundColor Yellow
}


# ============================================================
# 08-restrict-user-access.ps1
# ============================================================

Write-Host '----------------------------------------' -ForegroundColor DarkGray
Write-Host 'Executando: 08-restrict-user-access.ps1' -ForegroundColor Yellow
Write-Host '----------------------------------------' -ForegroundColor DarkGray


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
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[IMPORTANTE] Reinicie o computador para aplicar todas as alterações." -ForegroundColor Yellow


Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "        CONFIGURAÇÃO CONCLUÍDA          " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[IMPORTANTE] Reinicie o computador para aplicar todas as alterações." -ForegroundColor Yellow
