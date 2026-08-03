#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Instala o agente Action1 (GigaNet) de forma silenciosa e idempotente.
#>

$ErrorActionPreference = 'Stop'

$AgentUrl = 'https://app.action1.com/agent/ca010c74-f205-11f0-8a96-0d827193591e/Windows/agent(GigaNet).msi'
$MsiName = 'action1_agent_GigaNet.msi'
$MsiPath = Join-Path $env:TEMP $MsiName
$ServiceNames = @('Action1Agent', 'A1Agent')

function Write-Status {
    param(
        [Parameter(Mandatory)][ValidateSet('OK', 'CHANGED', 'FAIL', 'INFO')][string]$Level,
        [Parameter(Mandatory)][string]$Message
    )
    Write-Host "[$Level] $Message"
}

function Test-Action1Installed {
    foreach ($name in $ServiceNames) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($svc) { return $true }
    }

    $uninstallKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($path in $uninstallKeys) {
        $hit = Get-ItemProperty $path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like '*Action1*' }
        if ($hit) { return $true }
    }

    return $false
}

try {
    if (Test-Action1Installed) {
        Write-Status -Level OK -Message 'Action1 Agent already installed.'
        exit 0
    }

    Write-Status -Level INFO -Message "Downloading Action1 MSI from $AgentUrl"
    Invoke-WebRequest -Uri $AgentUrl -OutFile $MsiPath -UseBasicParsing

    Write-Status -Level CHANGED -Message "Installing Action1 Agent from $MsiPath"
    $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList @(
        '/i', "`"$MsiPath`"",
        '/quiet',
        '/qn',
        '/norestart'
    ) -Wait -PassThru

    if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
        throw "msiexec failed with exit code $($proc.ExitCode)"
    }

    if (-not (Test-Action1Installed)) {
        throw 'Action1 Agent install finished but service/product was not detected.'
    }

    Write-Status -Level CHANGED -Message 'Action1 Agent installed successfully.'
    exit 0
}
catch {
    Write-Status -Level FAIL -Message $_.Exception.Message
    exit 1
}
finally {
    if (Test-Path -LiteralPath $MsiPath) {
        Remove-Item -LiteralPath $MsiPath -Force -ErrorAction SilentlyContinue
    }
}
