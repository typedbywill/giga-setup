# ============================================================
# Script: 03-create-user.ps1
# Descrição: Cria o usuário "Usuário" se não existir
# Idempotente: Verifica existência antes de criar
# ============================================================

$ErrorActionPreference = "Stop"

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
