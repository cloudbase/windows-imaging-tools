$ErrorActionPreference = "Stop"
$resourcesDir = "$ENV:SystemDrive\UnattendResources"
$configIniPath = "$resourcesDir\config.ini"
$customScriptsDir = "$resourcesDir\CustomScripts"
$logFile = "$resourcesDir\image-generation-log.txt"

function Set-PersistDrivers {
    Param(
    [parameter(Mandatory=$true)]
    [string]$Path,
    [switch]$Persist
    )
    if (!(Test-Path $Path)) {
        return $false
    }
    try {
        $xml = [xml](Get-Content $Path)
    } catch {
        Write-Error "Failed to load $Path"
        return $false
    }
    if (!$xml.unattend.settings) {
        return $false
    }
    foreach ($i in $xml.unattend.settings) {
        if ($i.pass -eq "generalize") {
            $index = [array]::IndexOf($xml.unattend.settings, $i)
            if ($xml.unattend.settings[$index].component -and $xml.unattend.settings[$index].component.PersistAllDeviceInstalls -ne $Persist.ToString()) {
                $xml.unattend.settings[$index].component.PersistAllDeviceInstalls = $Persist.ToString()
            }
        }
    }
    $xml.Save($Path)
    Write-Log "Drivers" "PersistDrivers was set to ${Persist} in the unattend.xml"
}

function Set-UnattendEnableSwap {
    Param(
    [parameter(Mandatory=$true)]
    [string]$Path
    )
    if (!(Test-Path $Path)) {
        return $false
    } try {
        $xml = [xml](Get-Content $Path)
    } catch {
        Write-Error "Failed to load $Path"
        return $false
    }
    if (!$xml.unattend.settings) {
        return $false
    }
    foreach ($i in $xml.unattend.settings) {
        if ($i.pass -eq "specialize") {
            $index = [array]::IndexOf($xml.unattend.settings, $i)
            if ($xml.unattend.settings[$index].component.RunSynchronous.RunSynchronousCommand.Order) {
                $xml.unattend.settings[$index].component.RunSynchronous.RunSynchronousCommand.Order = "2"
            }
            [xml]$RunSynchronousCommandXml = @"
        <RunSynchronousCommand xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <Order>1</Order>
          <Path>"C:\Windows\System32\reg.exe" ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagingFiles" /d "?:\pagefile.sys" /f</Path>
          <Description>Set page file to be automatically managed by the system</Description>
          <WillReboot>Never</WillReboot>
        </RunSynchronousCommand>
"@
          $xml.unattend.settings[$index].component.RunSynchronous.AppendChild($xml.ImportNode($RunSynchronousCommandXml.RunSynchronousCommand, $true))
        }
    }
    $xml.Save($Path)
    Write-Log "Swap(1)" "Was enabled in the unattend.xml"
}

function Optimize-SparseImage {
    $zapfree = "$resourcesDir\zapfree.exe"
    if ( Test-Path $zapfree ) {
        Write-Host "Optimizing for sparse image..."
        & $zapfree -z $ENV:SystemDrive
        Write-Log "ZapFree" "Image was zeroed successfully"
    } else {
        Write-Debug "No zapfree. Image not optimized."
    }
}

function Clean-UpdateResources {
    $HOST.UI.RawUI.WindowTitle = "Running update resources cleanup"
    # We're done, disable AutoLogon
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name Unattend*
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoLogonCount -ErrorAction SilentlyContinue

    # Cleanup
    Remove-Item -Recurse -Force $resourcesDir
    Remove-Item -Force "$ENV:SystemDrive\Unattend.xml"
    Write-Log "Cleanup(1)" "Image was cleaned up successfully"

}

function Clean-WindowsUpdates {
    Param(
        $PurgeUpdates
    )
    $HOST.UI.RawUI.WindowTitle = "Running Dism cleanup..."
    if (([System.Environment]::OSVersion.Version.Major -gt 6) -or ([System.Environment]::OSVersion.Version.Minor -ge 2))
    {
        if (!$PurgeUpdates) {
            Dism.exe /Online /Cleanup-Image /StartComponentCleanup
        } else {
            Dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase
        }
        if ($LASTEXITCODE) {
            throw "Dism.exe clean failed"
        }
        Write-Log "Cleanup" "Updates were cleaned up successfully"
    }
}

function Run-Defragment {
    $HOST.UI.RawUI.WindowTitle = "Running Defrag..."
    #Defragmenting all drives at normal priority
    defrag.exe /C /H /V
    if ($LASTEXITCODE) {
        throw "Defrag.exe failed"
    }
    Write-Log "Defragment" "Image was defragemented successfully"
}

function Release-IP {
    $HOST.UI.RawUI.WindowTitle = "Releasing IP..."
    ipconfig.exe /release
    if ($LASTEXITCODE) {
        throw "IPconfig release failed"
    }
    Write-Log "Ipconfig" "IPs were released successfully"
}

function Install-WindowsUpdates {
    Import-Module "$resourcesDir\WindowsUpdates\WindowsUpdates"
    $BaseOSKernelVersion = [System.Environment]::OSVersion.Version
    $OSKernelVersion = ($BaseOSKernelVersion.Major.ToString() + "." + $BaseOSKernelVersion.Minor.ToString())

    #Note (cgalan): Some updates are black-listed as they are either failing to install or superseded by the newer updates.
    $KBIdsBlacklist = @{
        "6.3" = @("KB2887595")
    }
    $excludedUpdates = $KBIdsBlacklist[$OSKernelVersion]
    $updates = ExecRetry {
        Get-WindowsUpdate -Verbose -ExcludeKBId $excludedUpdates
    } -maxRetryCount 30 -retryInterval 1
    $maximumUpdates = 100
    if (!$updates.Count) {
        $updates = [array]$updates
    }
    if ($updates) {
        $availableUpdatesNumber = $updates.Count
        Write-Host "Found $availableUpdatesNumber updates. Installing..."
        try {
            #Note (cgalan): In case the update fails, we need to reboot the instance in order for the updates
            # to be retrieved on a changed system state and be applied correctly.
            Install-WindowsUpdate -Updates $updates[0..$maximumUpdates]
         } finally {
            Write-Log "Updates(${availableUpdatesNumber})" "Available updates were installed successfully. Rebooting..."
            Restart-Computer -Force
            exit 0
         }
    } elseif ((Get-RebootRequired)) {
        Write-Log "Updates(reboot)" "No updates available, but a reboot is required. Rebooting..."
        Restart-Computer -Force
        exit 0
    }
    Write-Log "Updates" "All available updates were installed successfully"
}

function ExecRetry($command, $maxRetryCount=4, $retryInterval=4) {
    $currErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"

    $retryCount = 0
    while ($true) {
        try {
            $res = Invoke-Command -ScriptBlock $command
            $ErrorActionPreference = $currErrorActionPreference
            return $res
        } catch [System.Exception] {
            $retryCount++
            if ($retryCount -ge $maxRetryCount) {
                $ErrorActionPreference = $currErrorActionPreference
                throw
            } else {
                if($_) {
                    Write-Warning $_
                }
                Start-Sleep $retryInterval
            }
        }
    }
}

function Disable-Swap {
    $computerSystem = Get-WmiObject Win32_ComputerSystem
    if ($computerSystem.AutomaticManagedPagefile) {
        $computerSystem.AutomaticManagedPagefile = $False
        $computerSystem.Put()
    }
    $pageFileSetting = Get-WmiObject Win32_PageFileSetting
    if ($pageFileSetting) {
        $pageFileSetting.Delete()
    }
    Write-Log "Swap" "Swap was disabled successfully"
}

function License-Windows {
    Param(
         [parameter(Mandatory=$true)]
         [string]$ProductKey
    )
    $licenseWindows = $false
    $slmgrOutput = cscript.exe "$env:windir\system32\slmgr.vbs" /dli
    if ($lastExitCode) {
        throw "Windows license details could not be retrieved."
    }

    if ($ProductKey -eq "default_kms_key") {
        if (!([System.Environment]::OSVersion.Version.Major -gt 6 `
            -or [System.Environment]::OSVersion.Version.Minor -ge 2)) {
            Write-Log "License" 'KMS trial licensing reset not required. Running on Windows lte Windows 2008 R2'
            return
        }
        if ($slmgrOutput -like "*VOLUME_KMSCLIENT*") {
            $licensingOutput = cscript.exe "$env:windir\system32\slmgr.vbs" /upk
            if ($LASTEXITCODE) {
                Write-Log "License" "Error: KMS trial licensing could not be reset"
                throw $licensingOutput
            }
            Write-Log "License" "KMS trial licensing was reset"
        }
        return
    }

    if ($slmgrOutput -like "*License Status: Licensed*") {
       $partialKey = ($slmgrOutput -like "Partial Product Key*").Replace("Partial Product Key:","").Trim()
       Write-Host "Windows is already licensed with partial key: $partialKey"
       if (!(($ProductKey -split "-") -contains $partialKey)) {
           $licenseWindows = $true
       }
    } else {
        $licenseWindows = $true
    }
    if ($licenseWindows) {
       $licensingOutput = cscript.exe "$env:windir\system32\slmgr.vbs" /ipk $ProductKey
       if ($lastExitCode) {
           Write-Log "License" "Error: Windows could not be licensed"
           throw $licensingOutput
       } else {
           Write-Host "Windows has been successfully licensed."
       }
        Write-Log "License" "Windows was licensed successfully"
    } else {
       Write-Host "Windows will not be licensed."
    }
}

function Get-AdministratorAccount {
    <#
    .SYNOPSIS
    Helper function to return the local Administrator account name.
    This works with internationalized versions of Windows.
    #>
    PROCESS {
        $version = $PSVersionTable.PSVersion.Major
        if ($version -lt 4) {
            # Get-CimInstance is not supported on powershell versions earlier then 4
            New-Alias -Name Get-ManagementObject -Value Get-WmiObject
        } else {
            New-Alias -Name Get-ManagementObject -Value Get-CimInstance
        }
        $SID = "S-1-5-21-%-500"
        $modifier = " LIKE "
        $query = ("SID{0}'{1}'" -f @($modifier, $SID))
        $s = Get-ManagementObject -Class Win32_UserAccount -Filter $query
        if (!$s) {
            throw "SID not found: $SID"
        }
        return $s.Name
    }
}

function Enable-AdministratorAccount {
    [string]$username = Get-AdministratorAccount
    $setupCompletePath = "$env:windir\Setup\Scripts\SetupComplete.cmd"
    $activate = "powershell -c net user {0} /active:yes" -f $username
    $expiration = 'wmic path Win32_UserAccount WHERE Name="{0}" set PasswordExpires=true' -f $username
    $logonReset = "net.exe user {0} /logonpasswordchg:yes" -f $username
    Add-Content -Encoding Ascii -Value $activate -Path $setupCompletePath
    Add-Content -Encoding Ascii -Value $expiration -Path $setupCompletePath
    Add-Content -Encoding Ascii -Value $logonReset -Path $setupCompletePath
    & cmd.exe /c "net.exe user $username """
    # Note(atira): net.exe can set an empty password only if it is run from cmd.exe
    if ($LASTEXITCODE) {
        Write-Log "Administrator" "Error: Account could not be enabled"
        throw "Resetting $username password failed."
    }
    Write-Log "Administrator" "Account was enabled successfully"
}

function Is-WindowsClient {
        $Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\\'
    try {
        if ((Get-ItemProperty -Path $Path -Name InstallationType).InstallationType -eq "Client") {
            return $true
        }
    } catch { }
    return $false
}

function Run-CustomScript {
    Param($ScriptFileName)
    $fullScriptFilePath = Join-Path $customScriptsDir $ScriptFileName
    if (Test-Path $fullScriptFilePath) {
        Write-Host "Executing script $fullScriptFilePath"
        & $fullScriptFilePath
        if ($LastExitCode -eq 1004) {
            Write-Log "CustomScripts(${ScriptFileName})" "Required to exit"
            exit 0
        }
        if ($LastExitCode -eq 1005) {
            # exit this script and reboot
            Write-Log "CustomScripts(${ScriptFileName})" "Required to reboot. Rebooting..."
            shutdown -r -t 0 -f
            exit 0
        }
        if ($LastExitCode -eq 1006) {
            # exit this script and shutdown
            Write-Log "CustomScripts(${ScriptFileName})" "Required to shut down. Shutting down..."
            shutdown -s -t 0 -f
            exit 0
        }
        if ($LastExitCode -eq 1) {
            Write-Log "CustomScripts(${ScriptFileName})" "${ScriptFileName} failed to run"
            throw "Script $ScriptFileName executed unsuccessfully"
        }
        Write-Log "CustomScripts(${ScriptFileName})" "${ScriptFileName} executed successfully"
    }
}

function Install-VMwareTools {
    $Host.UI.RawUI.WindowTitle = "Installing VMware tools..."
    $vmwareToolsInstallArgs = "/s /v /qn REBOOT=R /l $ENV:Temp\vmware_tools_install.log"
    if (Test-Path $resourcesDir) {
        $vmwareToolsPath = Join-Path $resourcesDir "\VMware-tools.exe"
    }
    $p = Start-Process -FilePath $vmwareToolsPath -ArgumentList $vmwareToolsInstallArgs -Wait -verb runAS
    if ($p.ExitCode) {
        Write-Log "VMwareTools" "Error: Tools could not be installed"
        throw "VMware tools setup failed" 
    }
    Write-Log "VMwareTools" "Tools installed successfully"
}

function Write-HostLog {
    <#
    .SYNOPSIS
     Uses KVP to communicate to the Hyper-V host the status of the various stages
     of the imaging generation. This feature works only if the VM where this script
     runs is spawned on Hyper-V and the 'Data Exchange' (aka Key Value Pair Exchange)
     is enabled for the instance. On KVM / ESXi / baremetal, this method is NOOP.
    #>
    Param($Stage = "Default",
          $StageLog
    )

    $KVPOutgoingRegistryKey = "HKLM://SOFTWARE/Microsoft/Virtual Machine/Auto"
    if ($Stage -and $StageLog -and (Test-Path $KVPOutgoingRegistryKey)) {
        Set-ItemProperty $KVPOutgoingRegistryKey -Name "ImageGenerationLog-${Stage}" `
            -Value $StageLog -ErrorAction SilentlyContinue
    }
}

function Write-Log {
    <#
    .SYNOPSIS
     Writes timestamped logs to the console, to the log file and via KVP if on Hyper-V platform.
    #>
    Param($Stage = "Default",
          $StageLog
    )

    $logMessage = "{0} - {1}: {2}" -f @((Get-Date), $Stage, $StageLog)
    Write-Host $logMessage
    Add-Content -Value $logMessage -Path $logFile -Force -Encoding Ascii -ErrorAction SilentlyContinue
    Write-HostLog $Stage $StageLog
}

function Disable-FirstLogonAnimation {
    if (([System.Environment]::OSVersion.Version.Major -gt 6) -or ([System.Environment]::OSVersion.Version.Minor -ge 2)) {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -Name "EnableFirstLogonAnimation" -Value 0 -Type DWORD -Force
    }
    Write-Log "FirstLogonAnimation" "First logon animation was disabled"
}

function Enable-AlwaysActiveMode {
    # This mode is the High Performance plus some tweaks to keep
    # the screen always on and to not sleep

    # The user should not automatically log off or the screen to become black
    New-ItemProperty `
        -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name "InactivityTimeoutSecs" `
        -PropertyType "DWord" `
        -Value "0" -Force

    # This is changing the settings from the machine (power mode) perspective
    powercfg /setactive "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" # High performance mode
    powercfg -change -monitor-timeout-ac 0
    powercfg -change -monitor-timeout-dc 0
    powercfg -change -standby-timeout-ac 0
    powercfg -change -standby-timeout-dc 0
    powercfg -hibernate OFF
    Write-Log "AlwaysActive" "Always active mode was set."
}

function Set-CustomTimezone {
    Param(
        [parameter(Mandatory=$true)]
        [String]$CustomTimezone
    )

    tzutil.exe /s "${CustomTimezone}"
    if ($LastExitCode) {
        throw "Failed to set custom timezone: ${CustomTimezone}"
    }
    Write-Log "Customization(1)" "Set timezone: ${CustomTimezone}"
}

function Set-CustomNtpServers {
    Param(
        [parameter(Mandatory=$true)]
        [String]$CustomNtpServers
    )

    w32tm.exe /config /syncfromflags:manual /manualpeerlist:"${CustomNtpServers}"
    if ($LastExitCode) {
        throw "Failed to set custom ntp servers: ${CustomNtpServers}"
    }
    Set-Service "W32time" -StartupType Automatic
    Write-Log "Customization(2)" "Set ntp servers: ${CustomNtpServers}"
}

function Enable-PingFirewallRules {
    netsh.exe advfirewall firewall add rule name="Allow IPv4 ping requests" protocol="icmpv4:8,any" dir=in action=allow
    if ($LASTEXITCODE) {
        throw "Failed to enable IPv4 ping firewall rules"
    }
    netsh.exe advfirewall firewall add rule name="Allow IPv6 ping requests" protocol="icmpv6:8,any" dir=in action=allow
    if ($LASTEXITCODE) {
        throw "Failed to enable IPv6 ping firewall rules"
    }
    Write-Log "Ping" "Enabled ping for IPv4 and IPv6"
}

function Disable-IPv6TemporaryAddress {
    Set-NetIPv6Protocol -RandomizeIdentifiers Disabled
    Set-NetIPv6Protocol -UseTemporaryAddresses Disabled
    Write-Log "IPv6" "RandomizeIdentifiers and UseTemporaryAddresses were disabled"
}

function Enable-ShutdownWithoutLogon {
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" `
       -Name shutdownwithoutlogon -Value 1 -Type DWord
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\" `
       -Name ShutdownWarningDialogTimeout -Value 1 -Type DWord
    Write-Log "ShutdownWithoutLogon" "Shutdown without logon was enabled"
}

try {
    Write-Log "StatusInitial" "Automated instance configuration started..."
    $psVersion = "PS version {0}." -f $PSVersionTable.PSVersion.ToString()
    $windowsVersion = "Windows version {0}." -f [System.Environment]::OSVersion.Version.ToString()
    Write-Log "WindowsInfo" "${windowsVersion} ${psVersion}"

    Import-Module "$resourcesDir\ini.psm1"

    $installUpdates = Get-IniFileValue -Path $configIniPath -Section "updates" -Key "install_updates" -Default $false -AsBoolean
    $persistDrivers = Get-IniFileValue -Path $configIniPath -Section "sysprep" -Key "persist_drivers_install" -Default $true -AsBoolean
    $purgeUpdates = Get-IniFileValue -Path $configIniPath -Section "updates" -Key "purge_updates" -Default $false -AsBoolean
    $disableSwap = Get-IniFileValue -Path $configIniPath -Section "sysprep" -Key "disable_swap" -Default $false -AsBoolean
    $enableAdministrator = Get-IniFileValue -Path $configIniPath -Section "DEFAULT" `
                                            -Key "enable_administrator_account" -Default $false -AsBoolean
    $goldImage = Get-IniFileValue -Path $configIniPath -Section "DEFAULT" -Key "gold_image" -Default $false -AsBoolean
    try {
        $vmwareToolsPath = Get-IniFileValue -Path $configIniPath -Section "DEFAULT" -Key "vmware_tools_path"
    } catch {}
    try {
        $productKey = Get-IniFileValue -Path $configIniPath -Section "DEFAULT" -Key "product_key"
    } catch {}
    $serialPortName = Get-IniFileValue -Path $configIniPath -Section "cloudbase_init" -Key "serial_logging_port"
    try {
        $runCloudbaseInitUnderLocalSystem = Get-IniFileValue -Path $configIniPath -Section "cloudbase_init" `
            -Key "cloudbase_init_use_local_system" -Default $false -AsBoolean
    } catch {}
    try {
        $enableShutdownWithoutLogon = Get-IniFileValue -Path $configIniPath -Key "enable_shutdown_without_logon" `
            -Default $false -AsBoolean
    } catch {}
    try {
        $enablePing = Get-IniFileValue -Path $configIniPath -Key "enable_ping_requests" `
            -Default $false -AsBoolean
    } catch {}
    try {
        $useIpv6EUI64 = Get-IniFileValue -Path $configIniPath -Key "enable_ipv6_eui64" `
            -Default $false -AsBoolean
    } catch {}
    try {
        $disableFirstLogonAnimation = Get-IniFileValue -Path $configIniPath -Section "DEFAULT" -Key "disable_first_logon_animation" `
            -Default $false -AsBoolean
    } catch{}
    try {
        $enableAlwaysActiveMode = Get-IniFileValue -Path $configIniPath -Section "DEFAULT" -Key "enable_active_mode" `
            -Default $false -AsBoolean
    } catch{}
    try {
        $cleanUpdatesOnline = Get-IniFileValue -Path $configIniPath -Section "updates" -Key "clean_updates_online" `
            -Default $true -AsBoolean
    } catch{}
    try {
        $customTimezone = Get-IniFileValue -Path $configIniPath -Section "custom" -Key "time_zone"
    } catch{}
    try {
        $customNtpServers = Get-IniFileValue -Path $configIniPath -Section "custom" -Key "ntp_servers"
    } catch{}
    try {
        $setCloudbaseInitDelayedStart = Get-IniFileValue -Path $configIniPath -Section "cloudbase_init" -Key "cloudbase_init_delayed_start" `
            -Default $false -AsBoolean
    } catch{}

    if ($productKey) {
        License-Windows $productKey
    }

    Run-CustomScript "RunBeforeWindowsUpdates.ps1"
    if ($installUpdates) {
        Install-WindowsUpdates
    }

    if ($cleanUpdatesOnline) {
        try {
            ExecRetry {
                Clean-WindowsUpdates -PurgeUpdates $purgeUpdates
            }
        } catch {
            Write-Log "DISM" "Failed to cleanup updates. Rebooting..."
            Restart-Computer -Force
            exit 0
        }
    }

    Run-CustomScript "RunAfterWindowsUpdates.ps1"

    if ($goldImage) {
        # Cleanup and shutting down the instance
        Remove-Item -Recurse -Force $resourcesDir
        shutdown -s -t 0 -f
    }

    if ($vmwareToolsPath) {
        Install-VMwareTools
    }

    Run-CustomScript "RunBeforeCloudbaseInitInstall.ps1"
    $Host.UI.RawUI.WindowTitle = "Installing Cloudbase-Init..."

    $cloudbaseInitInstallDir = Join-Path $ENV:ProgramFiles "Cloudbase Solutions\Cloudbase-Init"
    $CloudbaseInitMsiPath = "$resourcesDir\CloudbaseInit.msi"
    $CloudbaseInitConfigPath = "$resourcesDir\cloudbase-init.conf"
    $CloudbaseInitUnattendedConfigPath = "$resourcesDir\cloudbase-init-unattend.conf"
    $CloudbaseInitMsiLog = "$resourcesDir\CloudbaseInit.log"

    if (!$serialPortName) {
        $serialPorts = Get-WmiObject Win32_SerialPort
        if ($serialPorts) {
            $serialPortName = $serialPorts[0].DeviceID
        }
    }

    $msiexecArgumentList = "/i $CloudbaseInitMsiPath /qn /l*v $CloudbaseInitMsiLog"
    if ($serialPortName) {
        $msiexecArgumentList += " LOGGINGSERIALPORTNAME=$serialPortName"
    }

    $cloudbaseInitUser = 'cloudbase-init'
    if ($runCloudbaseInitUnderLocalSystem) {
        $msiexecArgumentList += " RUN_SERVICE_AS_LOCAL_SYSTEM=1"
        $cloudbaseInitUser = "LocalSystem"
    }

    $p = Start-Process -Wait -PassThru -FilePath msiexec -ArgumentList $msiexecArgumentList
    if ($p.ExitCode -ne 0) {
        Write-Log "Cloudbase-Init" "Failed to install cloudbase-init"
        throw "Installing $CloudbaseInitMsiPath failed. Log: $CloudbaseInitMsiLog"
    }

    if (Test-Path $CloudbaseInitConfigPath) {
        Copy-Item -Force $CloudbaseInitConfigPath "${cloudbaseInitInstallDir}\conf\cloudbase-init.conf"
        Write-Log "CustomCloudbaseInitConfig" $CloudbaseInitConfigPath
    }
    if (Test-Path $CloudbaseInitUnattendedConfigPath) {
        Copy-Item -Force $CloudbaseInitUnattendedConfigPath "${cloudbaseInitInstallDir}\conf\cloudbase-init-unattend.conf"
        Write-Log "CustomCloudbaseInitUnattendConfig" $CloudbaseInitUnattendedConfigPath
    }

    if (!$setCloudbaseInitDelayedStart) {
        Write-Log "Cloudbase-InitSetupComplete" "Cloudbase-Init service set to start using SetupComplete"
        & "${cloudbaseInitInstallDir}\bin\SetSetupComplete.cmd"
    } else {
        cmd /c "sc config cloudbase-init start= delayed-auto"
        if ($LASTEXITCODE) {
            throw "Cloudbase-Init service startup type could not be set to delayed-auto"
        }
        Write-Log "Cloudbase-InitDelayedStart" "Cloudbase-Init service startup type set to delayed-auto"
    }
    Write-Log "Cloudbase-Init" "Service installed successfully under user ${cloudbaseInitUser}"
    Run-CustomScript "RunAfterCloudbaseInitInstall.ps1"

    Run-Defragment

    Release-IP

    $windowsClient = Is-WindowsClient

    if ($enableShutdownWithoutLogon) {
        Enable-ShutdownWithoutLogon
    }

    if ($windowsClient -and $disableFirstLogonAnimation) {
        Disable-FirstLogonAnimation
    }

    if ($enablePing) {
        Enable-PingFirewallRules
    }

    if ($useIpv6EUI64) {
        Disable-IPv6TemporaryAddress
    }

    if ($windowsClient -and $enableAdministrator) {
        Enable-AdministratorAccount
    }

    if ($enableAlwaysActiveMode) {
        Enable-AlwaysActiveMode
    }

    if ($customTimezone) {
        Set-CustomTimezone $customTimezone
    }

    if ($customNtpServers) {
        Set-CustomNtpServers $customNtpServers
    }

    $Host.UI.RawUI.WindowTitle = "Running Sysprep..."
    $unattendedXmlPath = "${cloudbaseInitInstallDir}\conf\Unattend.xml"
    Set-PersistDrivers -Path $unattendedXmlPath -Persist:$persistDrivers

    if ($disableSwap) {
        ExecRetry {
            Disable-Swap
        }
        Set-UnattendEnableSwap -Path $unattendedXmlPath
    }

    Run-CustomScript "RunBeforeSysprep.ps1"
    Optimize-SparseImage
    & "$ENV:SystemRoot\System32\Sysprep\Sysprep.exe" `/generalize `/oobe `/shutdown `/unattend:"$unattendedXmlPath"
    Write-Log "Sysprep" "Sysprep initiated successfully"
    Run-CustomScript "RunAfterSysprep.ps1"
    Clean-UpdateResources
    Write-Log "StatusFinal" "Waiting for sysprep to stop machine..."
} catch {
    Write-Log "ERROR" $_.Exception.ToString()
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    throw
}
