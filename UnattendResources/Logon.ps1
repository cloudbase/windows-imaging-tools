$ErrorActionPreference = "Stop"
$resourcesDir = "$ENV:SystemDrive\UnattendResources"
$configIniPath = "$resourcesDir\config.ini"

try
{
    $needsReboot = $false

    Import-Module "$resourcesDir\ini.psm1"
    $installUpdates = Get-IniFileValue -Path $configIniPath -Section "DEFAULT" -Key "InstallUpdates" -Default $false -AsBoolean

    if($installUpdates)
    {
        if (!(Test-Path "$resourcesDir\PSWindowsUpdate"))
        {
            #Fixes Windows Server 2008 R2 inexistent Unblock-File command Bug
            if ($(Get-Host).version.major -eq 2)
            {
                $psWindowsUpdatePath = "$resourcesDir\PSWindowsUpdate_1.4.5.zip"
            }
            else
            {
                $psWindowsUpdatePath = "$resourcesDir\PSWindowsUpdate.zip"
            }

            & "$resourcesDir\7za.exe" x $psWindowsUpdatePath -o"$resourcesDir"
            if($LASTEXITCODE) { throw "7za.exe failed to extract PSWindowsUpdate" }
        }

        $Host.UI.RawUI.WindowTitle = "Installing updates..."

        Import-Module "$resourcesDir\PSWindowsUpdate"

        Get-WUInstall -AcceptAll -IgnoreReboot -IgnoreUserInput -NotCategory "Language packs"
        if (Get-WURebootStatus -Silent)
        {
            $needsReboot = $true
            $Host.UI.RawUI.WindowTitle = "Updates installation finished. Rebooting."
            shutdown /r /t 0
        }
    }

    if(!$needsReboot)
    {
        $Host.UI.RawUI.WindowTitle = "Installing Cloudbase-Init..."

        $osArch = (Get-WmiObject  Win32_OperatingSystem).OSArchitecture
        if($osArch -eq "64-bit")
        {
            $programFilesDir = ${ENV:ProgramFiles(x86)}
        }
        else
        {
            $programFilesDir = $ENV:ProgramFiles
        }

        $CloudbaseInitMsiPath = "$resourcesDir\CloudbaseInit.msi"
        $CloudbaseInitMsiLog = "$resourcesDir\CloudbaseInit.log"

        $serialPortName = @(Get-WmiObject Win32_SerialPort)[0].DeviceId

        $p = Start-Process -Wait -PassThru -FilePath msiexec -ArgumentList "/i $CloudbaseInitMsiPath /qn /l*v $CloudbaseInitMsiLog LOGGINGSERIALPORTNAME=$serialPortName"
        if ($p.ExitCode -ne 0)
        {
            throw "Installing $CloudbaseInitMsiPath failed. Log: $CloudbaseInitMsiLog"
        }

         # We're done, disable AutoLogon
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name Unattend*
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoLogonCount

        # Cleanup
        Remove-Item -Recurse -Force $resourcesDir
        Remove-Item -Force "$ENV:SystemDrive\Unattend.xml"

        $Host.UI.RawUI.WindowTitle = "Running SetSetupComplete..."
        & "$programFilesDir\Cloudbase Solutions\Cloudbase-Init\bin\SetSetupComplete.cmd"

        $Host.UI.RawUI.WindowTitle = "Running Sysprep..."
        $unattendedXmlPath = "$programFilesDir\Cloudbase Solutions\Cloudbase-Init\conf\Unattend.xml"
        & "$ENV:SystemRoot\System32\Sysprep\Sysprep.exe" `/generalize `/oobe `/shutdown `/unattend:"$unattendedXmlPath"
    }
}
catch
{
    $host.ui.WriteErrorLine($_.Exception.ToString())
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    throw
}
