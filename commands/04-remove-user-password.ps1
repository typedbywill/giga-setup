# ============================================================
# Script: 04-remove-user-password.ps1
# Descrição: Remove a senha do usuário comum "Usuário"
# Idempotente: Define senha vazia (sem senha)
# ============================================================

$ErrorActionPreference = "Stop"

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
