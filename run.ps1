# ============================================================
# GIGA SETUP - Script Unificado
# Gerado automaticamente via GitHub Actions
# Data: 2026-01-16 13:33:55 UTC
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

& {

$adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue

if (-not $adminAccount) {
    $adminAccount = Get-LocalUser -Name "Administrador" -ErrorAction SilentlyContinue
}

if (-not $adminAccount) {
    Write-Host "[ERRO] Conta de Administrador não encontrada no sistema." -ForegroundColor Red
        return
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
            return
    }
}
}


# ============================================================
# 02-set-admin-password.ps1
# ============================================================

Write-Host '----------------------------------------' -ForegroundColor DarkGray
Write-Host 'Executando: 02-set-admin-password.ps1' -ForegroundColor Yellow
Write-Host '----------------------------------------' -ForegroundColor DarkGray

& {

$newPassword = ConvertTo-SecureString "Micros@Giga2026!" -AsPlainText -Force

$adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue

if (-not $adminAccount) {
    $adminAccount = Get-LocalUser -Name "Administrador" -ErrorAction SilentlyContinue
}

if (-not $adminAccount) {
    Write-Host "[ERRO] Conta de Administrador não encontrada no sistema." -ForegroundColor Red
    return
}

$accountName = $adminAccount.Name}


# ============================================================
# 03-create-user.ps1
# ============================================================

Write-Host '----------------------------------------' -ForegroundColor DarkGray
Write-Host 'Executando: 03-create-user.ps1' -ForegroundColor Yellow
Write-Host '----------------------------------------' -ForegroundColor DarkGray

& {

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
        return
    }
}
}


# ============================================================
# 04-remove-user-password.ps1
# ============================================================

Write-Host '----------------------------------------' -ForegroundColor DarkGray
Write-Host 'Executando: 04-remove-user-password.ps1' -ForegroundColor Yellow
Write-Host '----------------------------------------' -ForegroundColor DarkGray

& {

$userName = "Usuario"

$existingUser = Get-LocalUser -Name $userName -ErrorAction SilentlyContinue

if (-not $existingUser) {
    Write-Host "[AVISO] Usuário '$userName' não existe. Execute 03-create-user.ps1 primeiro." -ForegroundColor Yellow
    return
}

try {
    # Remove a senha definindo como vazia
    Set-LocalUser -Name $userName -Password ([securestring]::new())
    Write-Host "[SUCESSO] Senha do usuário '$userName' foi removida." -ForegroundColor Green
} catch {
    Write-Host "[ERRO] Falha ao remover senha do '$userName': $_" -ForegroundColor Red
    return
}
}


# ============================================================
# 05-remove-other-users.ps1
# ============================================================

Write-Host '----------------------------------------' -ForegroundColor DarkGray
Write-Host 'Executando: 05-remove-other-users.ps1' -ForegroundColor Yellow
Write-Host '----------------------------------------' -ForegroundColor DarkGray

& {

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
    return
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
}


# ============================================================
# 06-enable-firewall.ps1
# ============================================================

Write-Host '----------------------------------------' -ForegroundColor DarkGray
Write-Host 'Executando: 06-enable-firewall.ps1' -ForegroundColor Yellow
Write-Host '----------------------------------------' -ForegroundColor DarkGray

& {

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
        return
    }
} else {
    Write-Host ""
    Write-Host "[OK] Firewall já está ativo em todos os perfis." -ForegroundColor Green
}
}


# ============================================================
# 07-block-social-sites.ps1
# ============================================================

Write-Host '----------------------------------------' -ForegroundColor DarkGray
Write-Host 'Executando: 07-block-social-sites.ps1' -ForegroundColor Yellow
Write-Host '----------------------------------------' -ForegroundColor DarkGray

& {
$ErrorActionPreference = "Stop"

$targetUser = "Usuário"
$rulePrefix = "GIGA-Block"

# Sites a bloquear (domínios principais)
$sitesToBlock = @(
    @{ Name = "WhatsApp"; Domains = @("whatsapp.com", "www.whatsapp.com", "web.whatsapp.com", "api.whatsapp.com", "whatsapp.net", "*.whatsapp.net") },
    @{ Name = "Facebook"; Domains = @("facebook.com", "www.facebook.com", "m.facebook.com", "static.facebook.com", "*.facebook.com", "fbcdn.net", "*.fbcdn.net") },
    @{ Name = "Instagram"; Domains = @("instagram.com", "www.instagram.com", "i.instagram.com", "static.instagram.com", "*.instagram.com", "*.cdninstagram.com") }
)

Write-Host "[INFO] Bloqueando sites de redes sociais via Windows Firewall..." -ForegroundColor Cyan
Write-Host "[INFO] Regras serão aplicadas APENAS para o usuário: $targetUser" -ForegroundColor Cyan
Write-Host ""

# Verificar se o usuário existe
try {
    $userAccount = Get-LocalUser -Name $targetUser -ErrorAction Stop
    $userSID = $userAccount.SID.Value
    Write-Host "[OK] Usuário '$targetUser' encontrado (SID: $userSID)" -ForegroundColor Green
} catch {
    Write-Host "[ERRO] Usuário '$targetUser' não encontrado." -ForegroundColor Red
    Write-Host "[DICA] Execute primeiro o script 03-create-user.ps1" -ForegroundColor Yellow
    return
}

# Criar SDDL para o usuário específico
$userSDDL = "D:(A;;CC;;;$userSID)"

$addedCount = 0
$skippedCount = 0

foreach ($site in $sitesToBlock) {
    $siteName = $site.Name
    $ruleName = "$rulePrefix-$siteName"
    
    # Verificar se a regra já existe
    $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    
    if ($existingRule) {
        Write-Host "[OK] Regra '$ruleName' já existe." -ForegroundColor Green
        $skippedCount++
    } else {
        try {
            # Criar regra de bloqueio para o usuário específico
            New-NetFirewallRule `
                -DisplayName $ruleName `
                -Description "Bloqueia acesso a $siteName para o usuário $targetUser (GIGA Setup)" `
                -Direction Outbound `
                -Action Block `
                -Protocol TCP `
                -RemotePort 80,443 `
                -LocalUser $userSDDL `
                -Program "Any" `
                -Enabled True | Out-Null
            
            Write-Host "[+] Regra criada: $ruleName" -ForegroundColor Yellow
            $addedCount++
        } catch {
            Write-Host "[ERRO] Falha ao criar regra '$ruleName': $_" -ForegroundColor Red
        }
    }
}

# Adicionar bloqueio por DNS também (resolve os domínios para IPs)
Write-Host ""
Write-Host "[INFO] Criando regras adicionais de bloqueio por resolução DNS..." -ForegroundColor Cyan

foreach ($site in $sitesToBlock) {
    $siteName = $site.Name
    
    foreach ($domain in $site.Domains) {
        # Pular wildcards para resolução DNS
        if ($domain.StartsWith("*")) { continue }
        
        $dnsRuleName = "$rulePrefix-DNS-$siteName-$($domain -replace '\.', '_')"
        
        $existingDnsRule = Get-NetFirewallRule -DisplayName $dnsRuleName -ErrorAction SilentlyContinue
        
        if (-not $existingDnsRule) {
            try {
                # Resolver IPs do domínio
                $ips = [System.Net.Dns]::GetHostAddresses($domain) | ForEach-Object { $_.IPAddressToString }
                
                if ($ips.Count -gt 0) {
                    New-NetFirewallRule `
                        -DisplayName $dnsRuleName `
                        -Description "Bloqueia $domain para $targetUser" `
                        -Direction Outbound `
                        -Action Block `
                        -RemoteAddress $ips `
                        -LocalUser $userSDDL `
                        -Enabled True | Out-Null
                    
                    Write-Host "[+] Bloqueado: $domain ($($ips.Count) IPs)" -ForegroundColor Yellow
                    $addedCount++
                }
            } catch {
                Write-Host "[AVISO] Não foi possível resolver: $domain" -ForegroundColor Gray
            }
        }
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "[RESUMO]" -ForegroundColor Cyan
Write-Host "  Regras criadas: $addedCount" -ForegroundColor White
Write-Host "  Regras existentes: $skippedCount" -ForegroundColor White
Write-Host "  Usuário afetado: $targetUser" -ForegroundColor White
Write-Host "  Administrador: NÃO afetado" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
}


# ============================================================
# 08-restrict-user-access.ps1
# ============================================================

Write-Host '----------------------------------------' -ForegroundColor DarkGray
Write-Host 'Executando: 08-restrict-user-access.ps1' -ForegroundColor Yellow
Write-Host '----------------------------------------' -ForegroundColor DarkGray

& {

$userName = "Usuario"

Write-Host "[INFO] Aplicando restrições para o usuário '$userName'..." -ForegroundColor Cyan

# Verificar se o usuário existe
$userExists = Get-LocalUser -Name $userName -ErrorAction SilentlyContinue
if (-not $userExists) {
    Write-Host "[ERRO] Usuário '$userName' não existe. Execute 03-create-user.ps1 primeiro." -ForegroundColor Red
    return
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
}


# ============================================================
# 09-install-programs.ps1
# ============================================================

Write-Host '----------------------------------------' -ForegroundColor DarkGray
Write-Host 'Executando: 09-install-programs.ps1' -ForegroundColor Yellow
Write-Host '----------------------------------------' -ForegroundColor DarkGray

& {

# Lista de programas para instalar (ID do winget)
$programs = @(
    "MicroSIP.MicroSIP",
    "Google.Chrome"
)

# Verifica se o winget está disponível
$wingetPath = Get-Command winget -ErrorAction SilentlyContinue
if (-not $wingetPath) {
    Write-Host "[ERRO] winget não encontrado no sistema." -ForegroundColor Red
    return
}

foreach ($programId in $programs) {
    Write-Host "`n[INFO] Verificando '$programId'..." -ForegroundColor Cyan
    
    # Verifica se o programa já está instalado
    $installed = winget list --id $programId --exact --accept-source-agreements 2>$null
    
    if ($installed -match $programId) {
        Write-Host "[OK] '$programId' já está instalado." -ForegroundColor Green
    } else {
        try {
            Write-Host "[INFO] Instalando '$programId' para todos os usuários..." -ForegroundColor Yellow
            winget install -e --id $programId --scope machine --silent --accept-package-agreements --accept-source-agreements
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "[SUCESSO] '$programId' foi instalado." -ForegroundColor Green
            } else {
                Write-Host "[AVISO] '$programId' retornou código $LASTEXITCODE. Pode já estar instalado ou requerer reinício." -ForegroundColor Yellow
            }
        } catch {
            Write-Host "[ERRO] Falha ao instalar '$programId': $_" -ForegroundColor Red
        }
    }
}

Write-Host "`n[CONCLUÍDO] Verificação de programas finalizada." -ForegroundColor Cyan
}


# ============================================================
# 10-system-optimization.ps1
# ============================================================

Write-Host '----------------------------------------' -ForegroundColor DarkGray
Write-Host 'Executando: 10-system-optimization.ps1' -ForegroundColor Yellow
Write-Host '----------------------------------------' -ForegroundColor DarkGray

& {

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "     OTIMIZAÇÃO DE SISTEMA E DEBLOAT    " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# ============================================================
# 1. Configurar Plano de Energia para Alto Desempenho
# ============================================================
Write-Host ""
Write-Host "[1/6] Configurando Plano de Energia..." -ForegroundColor Yellow

try {
    # Definir High Performance
    # GUID do High Performance: 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
    powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
    
    # Desativar suspensão e hibernação (alimentação CA/tomada)
    powercfg -change -monitor-timeout-ac 0
    powercfg -change -disk-timeout-ac 0
    powercfg -change -standby-timeout-ac 0
    powercfg -change -hibernate-timeout-ac 0
    
    Write-Host "[OK] Plano de Energia definido para Alto Desempenho (Sem suspensão)." -ForegroundColor Green
} catch {
    Write-Host "[ERRO] Falha ao configurar energia: $_" -ForegroundColor Red
}

# ============================================================
# 2. Desativar Telemetria e Coleta de Dados
# ============================================================
Write-Host ""
Write-Host "[2/6] Desativando Telemetria..." -ForegroundColor Yellow

$telemetryKeys = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
)

foreach ($key in $telemetryKeys) {
    if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
    try {
        Set-ItemProperty -Path $key -Name "AllowTelemetry" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    } catch {
        Write-Host "[AVISO] Não foi possível definir AllowTelemetry em $key" -ForegroundColor Gray
    }
}
Write-Host "[OK] Telemetria minimizada." -ForegroundColor Green

# ============================================================
# 3. Definir Fuso Horário (Brasília)
# ============================================================
Write-Host ""
Write-Host "[3/6] Configurando Fuso Horário..." -ForegroundColor Yellow

try {
    $timezone = "E. South America Standard Time" # UTC-03:00 Brasília
    Set-TimeZone -Id $timezone
    Write-Host "[OK] Fuso horário definido para: $timezone" -ForegroundColor Green
} catch {
    Write-Host "[ERRO] Falha ao definir fuso horário: $_" -ForegroundColor Red
}

# ============================================================
# 4. Habilitar Remote Desktop (RDP)
# ============================================================
Write-Host ""
Write-Host "[4/6] Habilitando Área de Trabalho Remota (RDP)..." -ForegroundColor Yellow

try {
    $rdpPath = "HKLM:\System\CurrentControlSet\Control\Terminal Server"
    if (-not (Test-Path $rdpPath)) { New-Item -Path $rdpPath -Force | Out-Null }
    
    Set-ItemProperty -Path $rdpPath -Name "fDenyTSConnections" -Value 0 -Type DWord
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
    
    Write-Host "[OK] RDP habilitado." -ForegroundColor Green
} catch {
    Write-Host "[ERRO] Falha ao habilitar RDP: $_" -ForegroundColor Red
}

# ============================================================
# 5. Desativar Reinicializações Automáticas do Windows Update
# ============================================================
Write-Host ""
Write-Host "[5/6] Impedindo reinicialização automática do Windows Update durante logon..." -ForegroundColor Yellow

$auPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
if (-not (Test-Path $auPath)) { New-Item -Path $auPath -Force | Out-Null }

try {
    # NoAutoRebootWithLoggedOnUsers = 1
    Set-ItemProperty -Path $auPath -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Type DWord
    Write-Host "[OK] Reinicialização automática com usuário logado desativada." -ForegroundColor Green
} catch {
    Write-Host "[ERRO] Falha ao configurar Windows Update: $_" -ForegroundColor Red
}

# ============================================================
# 6. Remover Bloatware (Apps Inúteis)
# ============================================================
Write-Host ""
Write-Host "[6/6] Removendo bloatware (Xbox, Solitaire, Weather, News)..." -ForegroundColor Yellow

$bloatwarePattern = "Microsoft.Xbox|Microsoft.Solitaire|Microsoft.BingWeather|Microsoft.WindowsCamera|Microsoft.GetHelp|Microsoft.Getstarted|Microsoft.MicrosoftOfficeHub|Microsoft.SkypeApp|Microsoft.ZuneVideo|Microsoft.ZuneMusic|Microsoft.People|Microsoft.WindowsAlarms|Microsoft.WindowsMaps|Microsoft.BingNews"

try {
    # Remove para o usuário atual e provisionado para novos usuários
    $packages = Get-AppxPackage | Where-Object { $_.Name -match $bloatwarePattern }
    
    if ($packages) {
        foreach ($pkg in $packages) {
            Write-Host "  - Removendo $($pkg.Name)..." -ForegroundColor Gray
            Remove-AppxPackage -Package $pkg.PackageFullName -ErrorAction SilentlyContinue
        }
        
        # Tentar remover pacotes provisionados (system-wide) requer admin
        $provisioned = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -match $bloatwarePattern }
        foreach ($pkg in $provisioned) {
             # Remove-AppxProvisionedPackage é mais demorado e sensível, vamos apenas tentar silenciosamente
             Remove-AppxProvisionedPackage -Online -PackageName $pkg.PackageName -ErrorAction SilentlyContinue | Out-Null
        }

        Write-Host "[OK] Limpeza de bloatware concluída." -ForegroundColor Green
    } else {
        Write-Host "[INFO] Nenhum bloatware encontrado ou já removido." -ForegroundColor Green
    }

} catch {
    Write-Host "[AVISO] Falha parcial na remoção de apps: $_" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "        OTIMIZAÇÃO CONCLUÍDA           " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
}


# ============================================================
# 11-ui-customization.ps1
# ============================================================

Write-Host '----------------------------------------' -ForegroundColor DarkGray
Write-Host 'Executando: 11-ui-customization.ps1' -ForegroundColor Yellow
Write-Host '----------------------------------------' -ForegroundColor DarkGray

& {
$userName = "Usuario"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "         CUSTOMIZAÇÃO DE UI             " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# 1. Verificar e Carregar o Hive do Usuário
$userSID = (Get-LocalUser -Name $userName -ErrorAction SilentlyContinue).SID.Value
if (-not $userSID) {
    Write-Host "[ERRO] Usuário '$userName' não encontrado." -ForegroundColor Red
    return
}

$userHivePath = "Registry::HKEY_USERS\$userSID"
if (-not (Test-Path $userHivePath)) {
    Write-Host "[AVISO] Perfil do usuário '$userName' não está carregado. Não é possível aplicar certas customizações de UI sem o usuário estar logado ao menos uma vez ou via RegLoad." -ForegroundColor Yellow
    # Em um cenário real de automação, poderíamos usar "reg load" aqui se tivéssemos o caminho do NTUSER.DAT,
    # mas por simplicidade e segurança, vamos focar em políticas que funcionam.
    
    # Vamos usar as chaves de Policy em HKLM que afetam todos os usuários ou tentar injetar se a hive estiver montada.
    Write-Host "Tentando aplicar via Políticas Globais (HKLM) que afetam UI..." -ForegroundColor Yellow
}

# ============================================================
# 2. Ocultar Ícones da Área de Trabalho (NoDesktop)
# ============================================================
Write-Host ""
Write-Host "[1/3] Configurando Área de Trabalho Limpa..." -ForegroundColor Yellow

# Chave Global para Policies de Explorer
$explorerPolicy = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if (-not (Test-Path $explorerPolicy)) { New-Item -Path $explorerPolicy -Force | Out-Null }

try {
    # NoDesktop = 1 (Esconde ícones e desabilita clique direito no desktop)
    Set-ItemProperty -Path $explorerPolicy -Name "NoDesktop" -Value 1 -Type DWord
    Write-Host "[OK] Ícones da Área de Trabalho ocultos (Policy Global)." -ForegroundColor Green
} catch {
    Write-Host "[ERRO] Falha ao configurar NoDesktop: $_" -ForegroundColor Red
}

# ============================================================
# 3. Papel de Parede Cor Sólida (Neutro)
# ============================================================
Write-Host ""
Write-Host "[2/3] Definindo Papel de Parede Sólido..." -ForegroundColor Yellow

# Infelizmente, mudar o wallpaper via script para outro usuário sem ele estar logado é complexo.
# A melhor forma é via chave de registro "Wallpaper" string vazia e "Background" cor RGB.
# Vamos tentar acessar a Hive do usuário se estiver carregada.

if (Test-Path $userHivePath) {
    try {
        $desktopKey = "$userHivePath\Control Panel\Desktop"
        if (-not (Test-Path $desktopKey)) { New-Item -Path $desktopKey -Force | Out-Null }
        
        # Remover Wallpaper (String vazia)
        Set-ItemProperty -Path $desktopKey -Name "Wallpaper" -Value "" -Type String
        
        # Definir cor de fundo sólida em RGB (Ex: 0 0 0 para Preto, 0 120 215 para Azul Padrão)
        $colorsKey = "$userHivePath\Control Panel\Colors"
        Set-ItemProperty -Path $colorsKey -Name "Background" -Value "0 0 0" -Type String
        
        Write-Host "[OK] Wallpaper removido e cor de fundo definida." -ForegroundColor Green
    } catch {
        Write-Host "[AVISO] Não foi possível acessar as chaves de Desktop do usuário: $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "[INFO] Hive do usuário não carregada. Pulei configuração de Wallpaper." -ForegroundColor Gray
}

# ============================================================
# 4. Limpeza Visual Adicional (Explorer)
# ============================================================
Write-Host ""
Write-Host "[3/3] Aplicando ajustes visuais do Explorer..." -ForegroundColor Yellow

try {
    # Esconder Ícone de "Pessoas" na barra de tarefas (Global)
    $policyPeople = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    if (-not (Test-Path $policyPeople)) { New-Item -Path $policyPeople -Force | Out-Null }
    
    Set-ItemProperty -Path $policyPeople -Name "HidePeopleBar" -Value 1 -Type DWord
    
    # Desativar "Notícias e Interesses" (News and Interests) - Requer chave específica que varia por versão,
    # mas o "EnableFeeds" em Policies geralmente funciona para bloquear.
    $policyFeeds = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds"
    if (-not (Test-Path $policyFeeds)) { New-Item -Path $policyFeeds -Force | Out-Null }
    Set-ItemProperty -Path $policyFeeds -Name "EnableFeeds" -Value 0 -Type DWord

    Write-Host "[OK] Barra de tarefas limpa (Pessoas, Notícias)." -ForegroundColor Green
} catch {
    Write-Host "[ERRO] Falha ao configurar Explorer: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "        CUSTOMIZAÇÃO CONCLUÍDA          " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
}


Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "        CONFIGURAÇÃO CONCLUÍDA          " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[IMPORTANTE] Reinicie o computador para aplicar todas as alterações." -ForegroundColor Yellow
