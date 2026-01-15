# ============================================================
# Script: 10-system-optimization.ps1
# Descrição: Otimiza desempenho, ajusta energia, remove bloatware e ajusta configurações gerais
# Idempotente: Sim
# ============================================================

$ErrorActionPreference = "Stop"

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
