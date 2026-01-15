# ============================================================
# Script: 07-block-social-sites.ps1
# Descrição: Bloqueia WhatsApp, Facebook e Instagram via hosts file
# Idempotente: Verifica se já está bloqueado antes de adicionar
# ============================================================

$ErrorActionPreference = "Stop"

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
