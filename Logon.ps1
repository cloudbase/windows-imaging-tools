$ErrorActionPreference = "Stop"

$Host.UI.RawUI.WindowTitle = "Installing updates..."

Get-WUInstall -AcceptAll -IgnoreReboot
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

    $p = Start-Process -Wait -PassThru -FilePath msiexec -ArgumentList "/i $CloudbaseInitMsi /qn /l*v $CloudbaseInitMsiLog"
    if ($p.ExitCode -ne 0)
    {
        throw "Installing $CloudbaseInitMsi failed. Log: $CloudbaseInitMsiLog"  
    }
    
     # We're done, remove LogonScript and disable AutoLogon
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name Unattend*
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoLogonCount
          
    $Host.UI.RawUI.WindowTitle = "Running Sysprep..."
    $unattendedXmlPath = "$ENV:ProgramFiles (x86)\Cloudbase Solutions\Cloudbase-Init\conf\Unattend.xml"    
    & "$ENV:SystemRoot\System32\Sysprep\Sysprep.exe" `/generalize `/oobe `/shutdown `/unattend:"$unattendedXmlPath"
}
