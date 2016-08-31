$ErrorActionPreference = "Stop"
$resourcesDir = "$ENV:SystemDrive\UnattendResources"
$configIniPath = "$resourcesDir\config.ini"

function Set-PersistDrivers {
    Param(
    [parameter(Mandatory=$true)]
    [string]$Path,
    [switch]$Persist=$true
    )
    if (!(Test-Path $Path)){
        return $false
    }
    try {
        $xml = [xml](Get-Content $Path)
    }catch{
        Write-Error "Failed to load $Path"
        return $false
    }
    if (!$xml.unattend.settings){
        return $false
    }
    foreach ($i in $xml.unattend.settings) {
        if ($i.pass -eq "generalize"){
            $index = [array]::IndexOf($xml.unattend.settings, $i)
            if ($xml.unattend.settings[$index].component -and $xml.unattend.settings[$index].component.PersistAllDeviceInstalls -ne $Persist.ToString()){
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
    if (!(Test-Path $Path)){
        return $false
    }
    try {
        $xml = [xml](Get-Content $Path)
    }catch{
        Write-Error "Failed to load $Path"
        return $false
    }
    if (!$xml.unattend.settings){
        return $false
    }
    foreach ($i in $xml.unattend.settings) {
        if ($i.pass -eq "specialize"){
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
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoLogonCount

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
        if ($LASTEXITCODE)
        {
            throw "Dism.exe clean failed"
        }
    }
}

function Run-Defragment {
    $HOST.UI.RawUI.WindowTitle = "Running Defrag..."
    #Defragmenting all drives at normal priority
    defrag.exe /C /H /V
    if ($LASTEXITCODE)
    {
        throw "Defrag.exe failed"
    }
}

function Release-IP {
    $HOST.UI.RawUI.WindowTitle = "Releasing IP..."
    ipconfig.exe /release
    if ($LASTEXITCODE)
        {
            throw "IPconfig release failed"
        }
}

function Install-WindowsUpdates {
    Import-Module "$resourcesDir\WindowsUpdates\WindowsUpdates"


    $updates = ExecRetry {
        Get-WindowsUpdate -Verbose
    } -maxRetryCount 30 -retryInterval 1
    $maximumUpdates = 100
    if (!$updates.Count) {
        $updates = [array]$updates
    }
    if ($updates) {
        $availableUpdatesNumber = $updates.Count
        Write-Host "Found $availableUpdatesNumber updates. Installing..."
        
        try {
            #Note (cgalan): We have observed that in case the update fails to install
            #we need to restart the computer in order to apply the eariler ones
            Install-WindowsUpdate -Updates $updates[0..$maximumUpdates]
        } catch {
            Restart-Computer -Force
            exit 0
        } finally {
            Restart-Computer -Force
        }

    }
}

function ExecRetry($command, $maxRetryCount=4, $retryInterval=4) {
    $currErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"

    $retryCount = 0
    while ($true)
    {
        try
        {
            $res = Invoke-Command -ScriptBlock $command
            $ErrorActionPreference = $currErrorActionPreference
            return $res
        }
          catch [System.Exception]
        {
            $retryCount++
            if ($retryCount -ge $maxRetryCount)
            {
                $ErrorActionPreference = $currErrorActionPreference
                throw
            }
            else
            {
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

try
{
    Import-Module "$resourcesDir\ini.psm1"
    $installUpdates = Get-IniFileValue -Path $configIniPath -Section "DEFAULT" -Key "InstallUpdates" -Default $false -AsBoolean
    $persistDrivers = Get-IniFileValue -Path $configIniPath -Section "DEFAULT" -Key "PersistDriverInstall" -Default $true -AsBoolean
    $purgeUpdates = Get-IniFileValue -Path $configIniPath -Section "DEFAULT" -Key "PurgeUpdates" -Default $false -AsBoolean
    $disableSwap = Get-IniFileValue -Path $configIniPath -Section "DEFAULT" -Key "DisableSwap" -Default $false -AsBoolean

    if($installUpdates)
    {
        Install-WindowsUpdates
    }
    
    Clean-WindowsUpdates -PurgeUpdates $purgeUpdates

    $Host.UI.RawUI.WindowTitle = "Installing Cloudbase-Init..."
    
    $programFilesDir = $ENV:ProgramFiles

    $CloudbaseInitMsiPath = "$resourcesDir\CloudbaseInit.msi"
    $CloudbaseInitMsiLog = "$resourcesDir\CloudbaseInit.log"

    $serialPortName = @(Get-WmiObject Win32_SerialPort)[0].DeviceId

    $p = Start-Process -Wait -PassThru -FilePath msiexec -ArgumentList "/i $CloudbaseInitMsiPath /qn /l*v $CloudbaseInitMsiLog LOGGINGSERIALPORTNAME=$serialPortName"
    if ($p.ExitCode -ne 0)
    {
        throw "Installing $CloudbaseInitMsiPath failed. Log: $CloudbaseInitMsiLog"
    }

    $Host.UI.RawUI.WindowTitle = "Running SetSetupComplete..."
    & "$programFilesDir\Cloudbase Solutions\Cloudbase-Init\bin\SetSetupComplete.cmd"
    
    Run-Defragment

    Clean-UpdateResources

    Release-IP

    $Host.UI.RawUI.WindowTitle = "Running Sysprep..."
    $unattendedXmlPath = "$programFilesDir\Cloudbase Solutions\Cloudbase-Init\conf\Unattend.xml"
    Set-PersistDrivers -Path $unattendedXmlPath -Persist:$persistDrivers

    if ($disableSwap) {
        ExecRetry {
            Disable-Swap
        }
        Set-UnattendEnableSwap -Path $unattendedXmlPath
    }

    & "$ENV:SystemRoot\System32\Sysprep\Sysprep.exe" `/generalize `/oobe `/shutdown `/unattend:"$unattendedXmlPath"
}
catch
{
    $host.ui.WriteErrorLine($_.Exception.ToString())
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    throw
}
