$ErrorActionPreference = "Stop"

try
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

        $Host.UI.RawUI.WindowTitle = "Running SetSetupComplete..."
        & "$ENV:ProgramFiles\Cloudbase Solutions\Cloudbase-Init\bin\SetSetupComplete.cmd"

}
catch
{
    $host.ui.WriteErrorLine($_.Exception.ToString())
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    throw
}
