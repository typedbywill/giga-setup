# ============================================================
# Script: 06-enable-firewall.ps1
# Descrição: Ativa o Windows Firewall em todos os perfis
# Idempotente: Verifica status antes de ativar
# ============================================================

$ErrorActionPreference = "Stop"

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
