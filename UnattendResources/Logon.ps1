$ErrorActionPreference = "Stop"
$resourcesDir = "$ENV:SystemDrive\UnattendResources"
$configIniPath = "$resourcesDir\config.ini"
$customScriptsDir = "$resourcesDir\CustomScripts"

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
}

function Clean-UpdateResources {
    $HOST.UI.RawUI.WindowTitle = "Running update resources cleanup"
    # We're done, disable AutoLogon
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name Unattend*
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoLogonCount -ErrorAction SilentlyContinue

    # Cleanup
    Remove-Item -Recurse -Force $resourcesDir
    Remove-Item -Force "$ENV:SystemDrive\Unattend.xml"

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
    }
}

function Run-Defragment {
    $HOST.UI.RawUI.WindowTitle = "Running Defrag..."
    #Defragmenting all drives at normal priority
    defrag.exe /C /H /V
    if ($LASTEXITCODE) {
        throw "Defrag.exe failed"
    }
}

function Release-IP {
    $HOST.UI.RawUI.WindowTitle = "Releasing IP..."
    ipconfig.exe /release
    if ($LASTEXITCODE) {
            throw "IPconfig release failed"
        }
}

function Install-WindowsUpdates {
    Import-Module "$resourcesDir\WindowsUpdates\WindowsUpdates"
    $BaseOSKernelVersion = [System.Environment]::OSVersion.Version
    $OSKernelVersion = ($BaseOSKernelVersion.Major.ToString() + "." + $BaseOSKernelVersion.Minor.ToString())

    #Note (cgalan): Some updates are black-listed as they are either failing to install or superseeded by the newer updates.
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
            Restart-Computer -Force
            exit 0
         }
    }
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
           throw $licensingOutput
       } else {
           Write-Host "Windows has been succesfully licensed."
       }
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
        throw "Resetting $username password failed."
    }
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
	    # exit this script
	    exit 0
	}
	if ($LastExitCode -eq 1005) {
	    # exit this script and reboot
	    shutdown -r -t 0 -f
	    exit 0
	}
	if ($LastExitCode -eq 1006) {
	    # exit this script and shutdown
	    shutdown -s -t 0 -f
	    exit 0
	}
	if ($LastExitCode -eq 1) {
	    throw "Script $ScriptFileName executed unsuccessfuly"
	}

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
        throw "VMware tools setup failed" 
    }
}

<#
.Synopsis
    Disables NetBIOS over TCP
.Description
    This cmdlet disables NetBIOS over TCP by configuring the network interfaces
    and by disabling all associated firewall rules.  Additionally, the ports
    used by NetBIOS over TCP are explicitly blocked.
#>
function Disable-NetBIOS {

    # Disable NetBIOS over TCP at the network interface level

    $NoInstances=$false
    WMIC.exe NICCONFIG WHERE '(TcpipNetbiosOptions=0 OR TcpipNetbiosOptions=1)' GET Caption,Index,TcpipNetbiosOptions 2>&1 | foreach {
        $NoInstances = $NoInstances -or $_ -like '*No Instance(s) Available*'
    }
    if ($NoInstances) {
         Write-Host "NetBIOS over TCP is not enabled on any network interfaces"
    } else {
        # List Interfaces that will be changed
         Write-Host "NetBIOS over TCP will be disabled on the following network interfaces:"
        WMIC.exe NICCONFIG WHERE '(TcpipNetbiosOptions=0 OR TcpipNetbiosOptions=1)' GET Caption,Index,TcpipNetbiosOptions

        # Disable NetBIOS over TCP
        WMIC.exe NICCONFIG WHERE '(TcpipNetbiosOptions=0 OR TcpipNetbiosOptions=1)' CALL SetTcpipNetbios 2
    }

    # Disable NetBIOS firewall rules

    $BuiltinNetBIOSRules=@(
        "NETDIS-NB_Name-In-UDP",
        "NETDIS-NB_Name-Out-UDP",
        "NETDIS-NB_Datagram-In-UDP",
        "NETDIS-NB_Datagram-Out-UDP",
        "FPS-NB_Session-In-TCP",
        "FPS-NB_Session-Out-TCP",
        "FPS-NB_Name-In-UDP",
        "FPS-NB_Name-Out-UDP",
        "FPS-NB_Datagram-In-UDP",
        "FPS-NB_Datagram-Out-UDP"
    )
    foreach ($name in $BuiltinNetBIOSRules) {
         Write-Host "Disabling firewall rule: $name"
        Disable-NetFirewallRule -Name $name
    }

    # Explicitly block NetBIOS Over TCP/IP:
    #
    # This blocks access to the below ports:
    #
    #   - UDP port 137 (name services)
    #   - UDP port 138 (datagram services)
    #   - TCP port 139 (session services)
    #
    # source: https://technet.microsoft.com/en-us/library/cc940063.aspx

    if (-Not ((Get-NetFirewallRule).Name -contains "NB_Name-Disable-In-UDP")) {
         Write-Host "Creating firewall rule: NB_Name-Disable-In-UDP"
        New-NetFirewallRule `
            -Name "NB_Name-Disable-In-UDP" `
            -DisplayName "Disable File and Printer Sharing (NB-Session-In)" `
            -Direction Inbound `
            -Action Block `
            -Protocol UDP `
            -LocalPort 137
    }

    if (-Not ((Get-NetFirewallRule).Name -contains "NB_Name-Disable-Out-UDP")) {
         Write-Host "Creating firewall rule: NB_Name-Disable-Out-UDP"
        New-NetFirewallRule `
            -Name "NB_Name-Disable-Out-UDP" `
            -DisplayName "Disable File and Printer Sharing (NB-Session-Out)" `
            -Direction Outbound `
            -Action Block `
            -Protocol UDP `
            -RemotePort 137
    }

    if (-Not ((Get-NetFirewallRule).Name -contains "NB_Datagram-Disable-In-UDP")) {
         Write-Host "Creating firewall rule: NB_Datagram-Disable-In-UDP"
        New-NetFirewallRule `
            -Name "NB_Datagram-Disable-In-UDP" `
            -DisplayName "Disable File and Printer Sharing (NB-Session-In)" `
            -Direction Inbound `
            -Action Block `
            -Protocol UDP `
            -LocalPort 138
    }

    if (-Not ((Get-NetFirewallRule).Name -contains "NB_Datagram-Disable-Out-UDP")) {
         Write-Host "Creating firewall rule: NB_Datagram-Disable-Out-UDP"
        New-NetFirewallRule `
            -Name "NB_Datagram-Disable-Out-UDP" `
            -DisplayName "Disable File and Printer Sharing (NB-Session-Out)" `
            -Direction Outbound `
            -Action Block `
            -Protocol UDP `
            -RemotePort 138
    }

    if (-Not ((Get-NetFirewallRule).Name -contains "NB_Session-Disable-In-TCP")) {
         Write-Host "Creating firewall rule: NB_Session-Disable-In-TCP"
        New-NetFirewallRule `
            -Name "NB_Session-Disable-In-TCP" `
            -DisplayName "Disable File and Printer Sharing (NB-Session-In)" `
            -Direction Inbound `
            -Action Block `
            -Protocol TCP `
            -LocalPort 139
    }

    if (-Not ((Get-NetFirewallRule).Name -contains "NB_Session-Disable-Out-TCP")) {
         Write-Host "Creating firewall rule: NB_Session-Disable-Out-TCP"
        New-NetFirewallRule `
            -Name "NB_Session-Disable-Out-TCP" `
            -DisplayName "Disable File and Printer Sharing (NB-Session-Out)" `
            -Direction Outbound `
            -Action Block `
            -Protocol TCP `
            -RemotePort 139
    }

    $ExplicitBlockNetBIOSRules=@(
        "NB_Name-Disable-In-UDP",
        "NB_Name-Disable-Out-UDP",
        "NB_Datagram-Disable-In-UDP",
        "NB_Datagram-Disable-Out-UDP",
        "NB_Session-Disable-In-TCP",
        "NB_Session-Disable-Out-TCP"
    )
    foreach ($name in $ExplicitBlockNetBIOSRules) {
         Write-Host "Enabling firewall rule: $name"
        Enable-NetFirewallRule -Name $name
    }

     Write-Host "Disable-NetBIOS: Complete"
}

try
{
    Import-Module "$resourcesDir\ini.psm1"
    $installUpdates = Get-IniFileValue -Path $configIniPath -Section "updates" -Key "install_updates" -Default $false -AsBoolean
    $persistDrivers = Get-IniFileValue -Path $configIniPath -Section "sysprep" -Key "persist_drivers_install" -Default $true -AsBoolean
    $purgeUpdates = Get-IniFileValue -Path $configIniPath -Section "updates" -Key "purge_updates" -Default $false -AsBoolean
    $disableSwap = Get-IniFileValue -Path $configIniPath -Section "sysprep" -Key "disable_swap" -Default $false -AsBoolean
    $enableAdministrator = Get-IniFileValue -Path $configIniPath -Section "DEFAULT" `
                                            -Key "enable_administrator_account" -Default $false -AsBoolean
    $enableAdvancedSecurity = Get-IniFileValue -Path $configIniPath -Section "DEFAULT" `
                                               -Key "enable_advanced_security" -Default $false -AsBoolean
    $goldImage = Get-IniFileValue -Path $configIniPath -Section "DEFAULT" -Key "gold_image" -Default $false -AsBoolean
    try {
        $vmwareToolsPath = Get-IniFileValue -Path $configIniPath -Section "DEFAULT" -Key "vmware_tools_path"
    } catch {}
    try {
        $productKey = Get-IniFileValue -Path $configIniPath -Section "DEFAULT" -Key "product_key"
    } catch {}
    $serialPortName = Get-IniFileValue -Path $configIniPath -Section "cloudbase_init" -Key "serial_logging_port"

    if ($productKey) {
        License-Windows $productKey
    }

    Run-CustomScript "RunBeforeWindowsUpdates.ps1"
    if ($installUpdates) {
        Install-WindowsUpdates
    }

    ExecRetry {
        Clean-WindowsUpdates -PurgeUpdates $purgeUpdates
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

    $programFilesDir = $ENV:ProgramFiles

    $CloudbaseInitMsiPath = "$resourcesDir\CloudbaseInit.msi"
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

    $p = Start-Process -Wait -PassThru -FilePath msiexec -ArgumentList $msiexecArgumentList
    if ($p.ExitCode -ne 0) {
        throw "Installing $CloudbaseInitMsiPath failed. Log: $CloudbaseInitMsiLog"
    }

    $Host.UI.RawUI.WindowTitle = "Running SetSetupComplete..."
    & "$programFilesDir\Cloudbase Solutions\Cloudbase-Init\bin\SetSetupComplete.cmd"
    Run-CustomScript "RunAfterCloudbaseInitInstall.ps1"

    Run-Defragment

    Release-IP

    if (Is-WindowsClient -and $enableAdministrator) {
        Enable-AdministratorAccount
    }

    $Host.UI.RawUI.WindowTitle = "Running Sysprep..."
    $unattendedXmlPath = "$programFilesDir\Cloudbase Solutions\Cloudbase-Init\conf\Unattend.xml"
    Set-PersistDrivers -Path $unattendedXmlPath -Persist:$persistDrivers
    
    if ($enableAdvancedSecurity) {
        Disable-NetBIOS
    }
    if ($disableSwap) {
        ExecRetry {
            Disable-Swap
        }
        Set-UnattendEnableSwap -Path $unattendedXmlPath
    }
    Run-CustomScript "RunBeforeSysprep.ps1"
    & "$ENV:SystemRoot\System32\Sysprep\Sysprep.exe" `/generalize `/oobe `/shutdown `/unattend:"$unattendedXmlPath"
    Run-CustomScript "RunAfterSysprep.ps1"
    Clean-UpdateResources
} catch {
    $host.ui.WriteErrorLine($_.Exception.ToString())
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    throw
}
