# Windows Sandbox Configuration Script for Secure Edge Browsing

# Step 1: Update Administrator Account Password
Write-Host "Updating Administrator account password..."
try {
    # Prompt user for the new Administrator password
    $adminPassword = Read-Host -Prompt "Enter a new secure password for the Administrator account"
    $secureAdminPassword = ConvertTo-SecureString -String $adminPassword -AsPlainText -Force
    Set-LocalUser -Name "Administrator" -Password $secureAdminPassword
    Write-Host "Administrator account password updated successfully."
} catch {
    Write-Host "Failed to update the Administrator account password: $($_.Exception.Message)" -ForegroundColor Red
}

# Step 2: Update WDAGUtilityAccount Password
Write-Host "Updating WDAGUtilityAccount password..."
try {
    # Prompt user for the new WDAGUtilityAccount password
    $wdagPassword = Read-Host -Prompt "Enter a new secure password for the WDAGUtilityAccount"
    $secureWdagPassword = ConvertTo-SecureString -String $wdagPassword -AsPlainText -Force
    Set-LocalUser -Name "WDAGUtilityAccount" -Password $secureWdagPassword
    Write-Host "WDAGUtilityAccount password updated successfully."
} catch {
    Write-Host "Failed to update the WDAGUtilityAccount password: $($_.Exception.Message)" -ForegroundColor Red
}

# Step 3: Disable Unnecessary Services
Write-Host "Disabling unnecessary services..."
$servicesToDisable = @(
    "PrintNotify", "MapsBroker", "DiagTrack", "RemoteRegistry",
    "Fax", "RetailDemo", "WMPNetworkSvc", "XblAuthManager",
    "XboxGipSvc", "XblGameSave", "AppXSvc", "PhoneSvc"
)

foreach ($service in $servicesToDisable) {
    try {
        Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
        Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Host "Disabled $service"
    } catch {
        Write-Host "Failed to disable $service." -ForegroundColor Yellow
    }
}

# Step 4: Configure Windows Firewall Rules
Write-Host "Configuring Windows Firewall rules..."
try {
    netsh advfirewall firewall add rule name="Allow Edge Outbound" `
        program="C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" `
        dir=out action=allow

    netsh advfirewall firewall add rule name="Allow QUIC Protocol" `
        protocol=UDP remoteport=443 dir=out action=allow `
        description="Allow QUIC protocol for Edge"

    netsh advfirewall firewall add rule name="Allow DNS Traffic" `
        protocol=UDP remoteport=53 dir=out action=allow `
        description="Allow DNS resolution traffic"

    netsh advfirewall firewall add rule name="Allow HTTPS Traffic" `
        protocol=TCP remoteport=443 dir=out action=allow `
        description="Allow HTTPS web traffic"

    netsh advfirewall firewall add rule name="Allow System Traffic Outbound" `
        program="%SystemRoot%\System32\svchost.exe" dir=out action=allow `
        description="Allow svchost for essential internet communication"

    netsh advfirewall firewall add rule name="Block All Inbound Traffic" `
        dir=in action=block `
        description="Block all unsolicited inbound traffic"

    netsh advfirewall firewall add rule name="Block Private IP Traffic (10.x.x.x)" `
        dir=out action=block remoteip=10.0.0.0/8 `
        description="Block traffic to 10.0.0.0/8 private network"

    netsh advfirewall firewall add rule name="Block Private IP Traffic (172.16.x.x)" `
        dir=out action=block remoteip=172.16.0.0/12 `
        description="Block traffic to 172.16.0.0/12 private network"

    netsh advfirewall firewall add rule name="Block Private IP Traffic (192.168.x.x)" `
        dir=out action=block remoteip=192.168.0.0/16 `
        description="Block traffic to 192.168.0.0/16 private network"

    netsh advfirewall firewall add rule name="Block Link-Local Traffic (169.254.x.x)" `
        dir=out action=block remoteip=169.254.0.0/16 `
        description="Block traffic to 169.254.0.0/16 link-local addresses"

    Write-Host "Firewall rules configured successfully."
} catch {
    Write-Host "Failed to configure firewall rules: $($_.Exception.Message)" -ForegroundColor Red
}

# Step 5: Harden Microsoft Edge
Write-Host "Hardening Microsoft Edge..."
$edgePolicies = @(
    @{ Key = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "SmartScreenEnabled"; Value = 1; Description = "Enable SmartScreen Filter for phishing/malware protection" },
    @{ Key = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "EnhancedSecurityMode"; Value = 1; Description = "Enable Enhanced Security Mode" },
    @{ Key = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "BlockThirdPartyCookies"; Value = 1; Description = "Block third-party cookies" },
    @{ Key = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "EnableDoNotTrack"; Value = 1; Description = "Send Do Not Track requests" },
    @{ Key = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "HSTSEnforcementEnabled"; Value = 1; Description = "Enable HTTPS-Only Mode" },
    @{ Key = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "SmartScreenPUAEnabled"; Value = 1; Description = "Enable PUA (Potentially Unwanted Applications) protection" },
    @{ Key = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "PasswordLeakDetectionEnabled"; Value = 1; Description = "Enable Password Leak Detection" },
    @{ Key = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "SitePerProcess"; Value = 1; Description = "Enable Site Isolation for added security" }
)

foreach ($policy in $edgePolicies) {
    try {
        if (-not (Test-Path $policy.Key)) {
            New-Item -Path $policy.Key -Force | Out-Null
        }
        Set-ItemProperty -Path $policy.Key -Name $policy.Name -Value $policy.Value
        Write-Host "Configured Edge policy: $($policy.Description)"
    } catch {
        Write-Host "Failed to configure Edge policy: $($policy.Description)" -ForegroundColor Yellow
    }
}

# Step 6: Demote WDAGUtilityAccount and Harden User Privileges
Write-Host "Reducing user privileges for WDAGUtilityAccount..."
$userToDemote = "WDAGUtilityAccount"

try {
    # Remove user from the Administrators group
    Write-Host "Removing $userToDemote from Administrators group..."
    if (net localgroup administrators | Select-String $userToDemote) {
        net localgroup administrators $userToDemote /delete
        Write-Host "$userToDemote removed from Administrators group."
    } else {
        Write-Host "$userToDemote is not in the Administrators group."
    }
} catch {
    Write-Host "Failed to demote $userToDemote : $($_.Exception.Message)" -ForegroundColor Red
}

# Step 7: Restrict Access to Admin Tools
Write-Host "Restricting access to admin tools..."
try {
    # Disable Task Manager
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableTaskMgr" -Value 1
    Write-Host "Task Manager disabled for standard users."

    # Restrict cmd.exe and PowerShell
    if (-not (Test-Path "HKLM:\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers")) {
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers" -Name "AuthenticodeEnabled" -Value 1
    if (-not (Test-Path "HKLM:\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths")) {
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths" -Force | Out-Null
    }
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths" -Name "0" -Value "C:\Windows\System32\cmd.exe" -Force
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths" -Name "1" -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Force
    Write-Host "Access to cmd.exe and PowerShell restricted for standard users."
} catch {
    Write-Host "Failed to restrict access to admin tools: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "Windows Sandbox has been securely configured with hardened settings."
