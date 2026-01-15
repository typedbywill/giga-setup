# ============================================================
# Script: 07-block-social-sites.ps1
# Descrição: Bloqueia WhatsApp, Facebook e Instagram via Firewall
#            Aplica APENAS para o usuário "Usuário", não afeta Admin
# Idempotente: Verifica se regras já existem antes de criar
# ============================================================

$ErrorActionPreference = "Stop"

$targetUser = "Usuário"
$rulePrefix = "GIGA-Block"

# Sites a bloquear (domínios principais)
$sitesToBlock = @(
    @{ Name = "WhatsApp"; Domains = @("whatsapp.com", "www.whatsapp.com", "web.whatsapp.com", "api.whatsapp.com", "whatsapp.net", "*.whatsapp.net") },
    @{ Name = "Facebook"; Domains = @("facebook.com", "www.facebook.com", "m.facebook.com", "static.facebook.com", "*.facebook.com", "fbcdn.net", "*.fbcdn.net") },
    @{ Name = "Instagram"; Domains = @("instagram.com", "www.instagram.com", "i.instagram.com", "static.instagram.com", "*.instagram.com", "*.cdninstagram.com") }
)

Write-Host "[INFO] Bloqueando sites de redes sociais via Windows Firewall..." -ForegroundColor Cyan
Write-Host "[INFO] Regras serão aplicadas APENAS para o usuário: $targetUser" -ForegroundColor Cyan
Write-Host ""

# Verificar se o usuário existe
try {
    $userAccount = Get-LocalUser -Name $targetUser -ErrorAction Stop
    $userSID = $userAccount.SID.Value
    Write-Host "[OK] Usuário '$targetUser' encontrado (SID: $userSID)" -ForegroundColor Green
} catch {
    Write-Host "[ERRO] Usuário '$targetUser' não encontrado." -ForegroundColor Red
    Write-Host "[DICA] Execute primeiro o script 03-create-user.ps1" -ForegroundColor Yellow
    exit 1
}

# Criar SDDL para o usuário específico
$userSDDL = "D:(A;;CC;;;$userSID)"

$addedCount = 0
$skippedCount = 0

foreach ($site in $sitesToBlock) {
    $siteName = $site.Name
    $ruleName = "$rulePrefix-$siteName"
    
    # Verificar se a regra já existe
    $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    
    if ($existingRule) {
        Write-Host "[OK] Regra '$ruleName' já existe." -ForegroundColor Green
        $skippedCount++
    } else {
        try {
            # Criar regra de bloqueio para o usuário específico
            New-NetFirewallRule `
                -DisplayName $ruleName `
                -Description "Bloqueia acesso a $siteName para o usuário $targetUser (GIGA Setup)" `
                -Direction Outbound `
                -Action Block `
                -Protocol TCP `
                -RemotePort 80,443 `
                -LocalUser $userSDDL `
                -Program "Any" `
                -Enabled True | Out-Null
            
            Write-Host "[+] Regra criada: $ruleName" -ForegroundColor Yellow
            $addedCount++
        } catch {
            Write-Host "[ERRO] Falha ao criar regra '$ruleName': $_" -ForegroundColor Red
        }
    }
}

# Adicionar bloqueio por DNS também (resolve os domínios para IPs)
Write-Host ""
Write-Host "[INFO] Criando regras adicionais de bloqueio por resolução DNS..." -ForegroundColor Cyan

foreach ($site in $sitesToBlock) {
    $siteName = $site.Name
    
    foreach ($domain in $site.Domains) {
        # Pular wildcards para resolução DNS
        if ($domain.StartsWith("*")) { continue }
        
        $dnsRuleName = "$rulePrefix-DNS-$siteName-$($domain -replace '\.', '_')"
        
        $existingDnsRule = Get-NetFirewallRule -DisplayName $dnsRuleName -ErrorAction SilentlyContinue
        
        if (-not $existingDnsRule) {
            try {
                # Resolver IPs do domínio
                $ips = [System.Net.Dns]::GetHostAddresses($domain) | ForEach-Object { $_.IPAddressToString }
                
                if ($ips.Count -gt 0) {
                    New-NetFirewallRule `
                        -DisplayName $dnsRuleName `
                        -Description "Bloqueia $domain para $targetUser" `
                        -Direction Outbound `
                        -Action Block `
                        -RemoteAddress $ips `
                        -LocalUser $userSDDL `
                        -Enabled True | Out-Null
                    
                    Write-Host "[+] Bloqueado: $domain ($($ips.Count) IPs)" -ForegroundColor Yellow
                    $addedCount++
                }
            } catch {
                Write-Host "[AVISO] Não foi possível resolver: $domain" -ForegroundColor Gray
            }
        }
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "[RESUMO]" -ForegroundColor Cyan
Write-Host "  Regras criadas: $addedCount" -ForegroundColor White
Write-Host "  Regras existentes: $skippedCount" -ForegroundColor White
Write-Host "  Usuário afetado: $targetUser" -ForegroundColor White
Write-Host "  Administrador: NÃO afetado" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
