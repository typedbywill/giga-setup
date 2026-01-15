# ============================================================
# Script: 09-install-programs.ps1
# Descrição: Instala programas usando winget para todos os usuários
# Idempotente: Verifica se já está instalado antes de instalar
# ============================================================

$ErrorActionPreference = "Stop"

# Lista de programas para instalar (ID do winget)
$programs = @(
    "MicroSIP.MicroSIP",
    "Google.Chrome"
)

# Verifica se o winget está disponível
$wingetPath = Get-Command winget -ErrorAction SilentlyContinue
if (-not $wingetPath) {
    Write-Host "[ERRO] winget não encontrado no sistema." -ForegroundColor Red
    exit 1
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
