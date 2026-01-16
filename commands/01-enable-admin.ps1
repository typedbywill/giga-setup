# ============================================================
# Script: 01-enable-admin.ps1
# Descrição: Ativa a conta de Administrador built-in do Windows
# Idempotente: Verifica se já está ativa antes de ativar
# ============================================================

$ErrorActionPreference = "Stop"

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
