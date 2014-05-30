$ErrorActionPreference = "Stop"

try
{
    $Host.UI.RawUI.WindowTitle = "Downloading PSWindowsUpdate..."

    $psWindowsUpdateBaseUrl = "http://gallery.technet.microsoft.com/scriptcenter/2d191bcd-3308-4edd-9de2-88dff796b0bc/file/"

    #Fixes Windows Server 2008 R2 inexistent Unblock-File command Bug
    if ($(Get-Host).version.major -eq 2)
    {
        $psWindowsUpdateUrl = $psWindowsUpdateBaseUrl + "66095/1/PSWindowsUpdate_1.4.5.zip"
    }
    else
    {
        $psWindowsUpdateUrl = $psWindowsUpdateBaseUrl + "41459/25/PSWindowsUpdate.zip"
    }

    $psWindowsUpdatePath = "$ENV:Temp\PSWindowsUpdate.zip"
    (new-object System.Net.WebClient).DownloadFile($psWindowsUpdateUrl, $psWindowsUpdatePath)

    $Host.UI.RawUI.WindowTitle = "Installing PSWindowsUpdate..."
    foreach($item in (New-Object -com shell.application).NameSpace($psWindowsUpdatePath).Items())
    {
        $yesToAll = 16
        (New-Object -com shell.application).NameSpace("$ENV:SystemRoot\System32\WindowsPowerShell\v1.0\Modules").copyhere($item, $yesToAll)
    }
    del $psWindowsUpdatePath

    Import-Module PSWindowsUpdate

    $Host.UI.RawUI.WindowTitle = "Installing updates..."

    Get-WUInstall -AcceptAll -IgnoreReboot -IgnoreUserInput -NotCategory "Language packs"
    if (Get-WURebootStatus -Silent)
    {
        $Host.UI.RawUI.WindowTitle = "Updates installation finished. Rebooting."
        shutdown /r /t 0
    }
    else
    {
        $Host.UI.RawUI.WindowTitle = "Downloading Cloudbase-Init..."

        $CloudbaseInitMsi = "$ENV:Temp\CloudbaseInitSetup_Beta.msi"
        $CloudbaseInitMsiUrl = "http://www.cloudbase.it/downloads/CloudbaseInitSetup_Beta.msi"
        $CloudbaseInitMsiLog = "$ENV:Temp\CloudbaseInitSetup_Beta.log"

        (new-object System.Net.WebClient).DownloadFile($CloudbaseInitMsiUrl, $CloudbaseInitMsi)

        $Host.UI.RawUI.WindowTitle = "Installing Cloudbase-Init..."

        $serialPortName = @(Get-WmiObject Win32_SerialPort)[0].DeviceId

        $p = Start-Process -Wait -PassThru -FilePath msiexec -ArgumentList "/i $CloudbaseInitMsi /qn /l*v $CloudbaseInitMsiLog LOGGINGSERIALPORTNAME=$serialPortName"
        if ($p.ExitCode -ne 0)
        {
            throw "Installing $CloudbaseInitMsi failed. Log: $CloudbaseInitMsiLog"
        }

         # We're done, remove LogonScript and disable AutoLogon
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name Unattend*
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoLogonCount

        $Host.UI.RawUI.WindowTitle = "Running SetSetupComplete..."
        & "$ENV:ProgramFiles (x86)\Cloudbase Solutions\Cloudbase-Init\bin\SetSetupComplete.cmd"

        $Host.UI.RawUI.WindowTitle = "Running Sysprep..."
        $unattendedXmlPath = "$ENV:ProgramFiles (x86)\Cloudbase Solutions\Cloudbase-Init\conf\Unattend.xml"
        & "$ENV:SystemRoot\System32\Sysprep\Sysprep.exe" `/generalize `/oobe `/shutdown `/unattend:"$unattendedXmlPath"
    }
}
catch
{
    $host.ui.WriteErrorLine($_.Exception.ToString())
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    throw
}
