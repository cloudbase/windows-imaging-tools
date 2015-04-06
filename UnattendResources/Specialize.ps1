$ErrorActionPreference = "Stop"
$resourcesDir = "$ENV:SystemDrive\UnattendResources"
$configIniPath = "$resourcesDir\config.ini"

try
{
    Import-Module "$resourcesDir\ini.psm1"

    $wallpaper = "$resourcesDir\Wallpaper.png"
    if(Test-Path $wallpaper)
    {
        $Host.UI.RawUI.WindowTitle = "Configuring wallpaper..."

        # Put the wallpaper in place
        $wallpaper_dir = "$ENV:SystemRoot\web\Wallpaper\Cloudbase"
        if (!(Test-Path $wallpaper_dir))
        {
            mkdir $wallpaper_dir
        }

        copy "$wallpaper" "$wallpaper_dir\Wallpaper-Cloudbase-2013.png"
        $gpoZipPath = "$resourcesDir\GPO.zip"
        foreach($item in (New-Object -com shell.application).NameSpace($gpoZipPath).Items())
        {
            $yesToAll = 16
            (New-Object -com shell.application).NameSpace("$ENV:SystemRoot\System32\GroupPolicy").copyhere($item, $yesToAll)
        }
    }

    # Enable ping (ICMP Echo Request on IPv4 and IPv6)
    # TODO: replace with with a netsh advfirewall command
    # possibly avoiding duplicates with "File and printer sharing (Echo Request - ICMPv[4,6]-In)"
    netsh firewall set icmpsetting 8

    #Configure Windows Emergency Management Services
    $emsSerialConsolePort = Get-IniFileValue -Path $configIniPath -Section "DEFAULT" -Key "EMSSerialConsolePort" -Default $null
    if ($emsSerialConsolePort) {
        bcdedit.exe /ems on
        if (!$?) { throw "EMS enable failed" }

        bcdedit.exe /emssettings EMSPORT:$emsSerialConsolePort EMSBAUDRATE:115200
        if (!$?) { throw "EMS configuration failed" }
    }
}
catch
{
    $host.ui.WriteErrorLine($_.Exception.ToString())
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    throw
}
