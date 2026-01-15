# ============================================================
# Script: 11-ui-customization.ps1
# Descrição: Customiza a interface (Desktop, Wallpaper) para o usuário padrão
# Idempotente: Sim
# ============================================================

$ErrorActionPreference = "Stop"
$userName = "Usuario"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "         CUSTOMIZAÇÃO DE UI             " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# 1. Verificar e Carregar o Hive do Usuário
$userSID = (Get-LocalUser -Name $userName -ErrorAction SilentlyContinue).SID.Value
if (-not $userSID) {
    Write-Host "[ERRO] Usuário '$userName' não encontrado." -ForegroundColor Red
    exit 1
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
