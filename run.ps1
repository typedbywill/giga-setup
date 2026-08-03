#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Desired state GigaNet: admin local, OpenSSH Server e firewall TCP 22.
.DESCRIPTION
    Script idempotente. Seguro para ser reexecutado periodicamente pelo Action1.
#>

$ErrorActionPreference = 'Stop'

$AdminPassword = 'Micros@Gig@Net2026'
$FirewallRuleName = 'GigaNet-OpenSSH-22'
$OpenSshCapability = 'OpenSSH.Server~~~~0.0.1.0'

$script:HadFailure = $false

function Write-Status {
    param(
        [Parameter(Mandatory)][ValidateSet('OK', 'CHANGED', 'FAIL', 'INFO')][string]$Level,
        [Parameter(Mandatory)][string]$Message
    )
    Write-Host "[$Level] $Message"
    if ($Level -eq 'FAIL') {
        $script:HadFailure = $true
    }
}

function Get-BuiltInAdministrator {
    Get-LocalUser | Where-Object { $_.SID.Value -match '-500$' } | Select-Object -First 1
}

function Get-AdministratorsGroupName {
    # SID S-1-5-32-544 = BUILTIN\Administrators (locale-independent)
    $sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    return $sid.Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
}

function Ensure-LocalAdmin {
    Write-Status -Level INFO -Message 'Ensuring built-in Administrator account...'

    $admin = Get-BuiltInAdministrator
    if (-not $admin) {
        Write-Status -Level FAIL -Message 'Built-in Administrator account (SID *-500) not found.'
        return
    }

    $changed = $false

    if (-not $admin.Enabled) {
        Enable-LocalUser -Name $admin.Name
        Write-Status -Level CHANGED -Message "Enabled local user '$($admin.Name)'."
        $changed = $true
    }

    # Password cannot be read back; re-apply each run to enforce company standard.
    $securePassword = ConvertTo-SecureString -String $AdminPassword -AsPlainText -Force
    Set-LocalUser -Name $admin.Name -Password $securePassword -PasswordNeverExpires $true

    $adminsGroup = Get-AdministratorsGroupName
    $members = Get-LocalGroupMember -Group $adminsGroup -ErrorAction Stop |
        Where-Object { $_.SID.Value -eq $admin.SID.Value }
    if (-not $members) {
        Add-LocalGroupMember -Group $adminsGroup -Member $admin.Name
        Write-Status -Level CHANGED -Message "Added '$($admin.Name)' to group '$adminsGroup'."
        $changed = $true
    }

    if ($changed) {
        Write-Status -Level CHANGED -Message "Administrator '$($admin.Name)' enabled/configured; password enforced."
    }
    else {
        Write-Status -Level OK -Message "Administrator '$($admin.Name)' already active; password enforced."
    }
}

function Ensure-OpenSSH {
    Write-Status -Level INFO -Message 'Ensuring OpenSSH Server...'

    $cap = Get-WindowsCapability -Online -Name $OpenSshCapability -ErrorAction SilentlyContinue
    if (-not $cap) {
        # Fallback: resolve by partial name on some builds
        $cap = Get-WindowsCapability -Online |
            Where-Object { $_.Name -like 'OpenSSH.Server*' } |
            Select-Object -First 1
    }

    if (-not $cap) {
        Write-Status -Level FAIL -Message 'OpenSSH.Server Windows capability not found on this image.'
        return
    }

    if ($cap.State -ne 'Installed') {
        Write-Status -Level CHANGED -Message "Installing capability '$($cap.Name)'..."
        Add-WindowsCapability -Online -Name $cap.Name | Out-Null
        Write-Status -Level CHANGED -Message "Installed '$($cap.Name)'."
    }
    else {
        Write-Status -Level OK -Message "Capability '$($cap.Name)' already installed."
    }

    $sshd = Get-Service -Name 'sshd' -ErrorAction SilentlyContinue
    if (-not $sshd) {
        Write-Status -Level FAIL -Message "Service 'sshd' not found after OpenSSH install."
        return
    }

    if ($sshd.StartType -ne 'Automatic') {
        Set-Service -Name 'sshd' -StartupType Automatic
        Write-Status -Level CHANGED -Message "Set 'sshd' startup type to Automatic."
    }
    else {
        Write-Status -Level OK -Message "'sshd' startup type already Automatic."
    }

    if ($sshd.Status -ne 'Running') {
        Start-Service -Name 'sshd'
        Write-Status -Level CHANGED -Message "Started service 'sshd'."
    }
    else {
        Write-Status -Level OK -Message "Service 'sshd' already Running."
    }

    $agent = Get-Service -Name 'ssh-agent' -ErrorAction SilentlyContinue
    if ($agent) {
        if ($agent.StartType -ne 'Automatic') {
            Set-Service -Name 'ssh-agent' -StartupType Automatic
            Write-Status -Level CHANGED -Message "Set 'ssh-agent' startup type to Automatic."
        }
        if ($agent.Status -ne 'Running') {
            Start-Service -Name 'ssh-agent'
            Write-Status -Level CHANGED -Message "Started service 'ssh-agent'."
        }
    }
}

function Ensure-FirewallSsh {
    Write-Status -Level INFO -Message 'Ensuring firewall rule for TCP 22...'

    $rule = Get-NetFirewallRule -DisplayName $FirewallRuleName -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if (-not $rule) {
        New-NetFirewallRule `
            -DisplayName $FirewallRuleName `
            -Name $FirewallRuleName `
            -Direction Inbound `
            -Protocol TCP `
            -LocalPort 22 `
            -Action Allow `
            -Profile Any `
            -Enabled True | Out-Null
        Write-Status -Level CHANGED -Message "Created firewall rule '$FirewallRuleName' (Allow TCP 22)."
        return
    }

    $changed = $false

    if ($rule.Enabled -ne 'True') {
        Enable-NetFirewallRule -Name $rule.Name
        Write-Status -Level CHANGED -Message "Enabled firewall rule '$FirewallRuleName'."
        $changed = $true
    }

    if ($rule.Action -ne 'Allow') {
        Set-NetFirewallRule -Name $rule.Name -Action Allow
        Write-Status -Level CHANGED -Message "Set firewall rule '$FirewallRuleName' action to Allow."
        $changed = $true
    }

    $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule
    $localPorts = @($portFilter.LocalPort | ForEach-Object { "$_" })
    if ($portFilter.Protocol -ne 'TCP' -or $localPorts -notcontains '22') {
        # Recreate rule to guarantee TCP/22 — Set-NetFirewallRule port change is limited
        Remove-NetFirewallRule -Name $rule.Name
        New-NetFirewallRule `
            -DisplayName $FirewallRuleName `
            -Name $FirewallRuleName `
            -Direction Inbound `
            -Protocol TCP `
            -LocalPort 22 `
            -Action Allow `
            -Profile Any `
            -Enabled True | Out-Null
        Write-Status -Level CHANGED -Message "Recreated firewall rule '$FirewallRuleName' for TCP 22."
        return
    }

    if (-not $changed) {
        Write-Status -Level OK -Message "Firewall rule '$FirewallRuleName' already allows TCP 22."
    }
}

# --- Main ---
Write-Status -Level INFO -Message 'Starting GigaNet desired-state run.'

try {
    Ensure-LocalAdmin
}
catch {
    Write-Status -Level FAIL -Message "Ensure-LocalAdmin: $($_.Exception.Message)"
}

try {
    Ensure-OpenSSH
}
catch {
    Write-Status -Level FAIL -Message "Ensure-OpenSSH: $($_.Exception.Message)"
}

try {
    Ensure-FirewallSsh
}
catch {
    Write-Status -Level FAIL -Message "Ensure-FirewallSsh: $($_.Exception.Message)"
}

if ($script:HadFailure) {
    Write-Status -Level FAIL -Message 'Desired-state run finished with failures.'
    exit 1
}

Write-Status -Level OK -Message 'Desired-state run finished successfully.'
exit 0
