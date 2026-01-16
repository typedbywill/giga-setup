# ============================================================
# Script: 02-set-admin-password.ps1
# Descrição: Define a senha do Administrador para Micros@Giga
# Idempotente: Sempre redefine a senha
# ============================================================

$ErrorActionPreference = "Stop"

$newPassword = ConvertTo-SecureString "Micros@Giga2026!" -AsPlainText -Force

$adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue

if (-not $adminAccount) {
    $adminAccount = Get-LocalUser -Name "Administrador" -ErrorAction SilentlyContinue
}

if (-not $adminAccount) {
    Write-Host "[ERRO] Conta de Administrador não encontrada no sistema." -ForegroundColor Red
    exit 1
}

$accountName = $adminAccount.Name