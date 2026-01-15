# ============================================================
# Script: 05-remove-other-users.ps1
# Descrição: Remove todos os usuários exceto Administrador e Usuario
# Idempotente: Verifica existência antes de remover
# ============================================================

$ErrorActionPreference = "Stop"

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
