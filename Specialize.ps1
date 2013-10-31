$ErrorActionPreference = "Stop"

$wallpaper = "Wallpaper-Cloudbase-2013.png"
$virtioscript = "InstallVirtIODrivers.js"
$gpoZipFile = "GPO.zip"

$resources = @("FirstLogon.ps1", "Logon.ps1", $virtioscript, $gpoZipFile, $wallpaper)

$temp = "$ENV:SystemRoot\Temp"
$baseUrl = "https://raw.github.com/cloudbase/windows-openstack-imaging-tools/master"

foreach($resource in $resources)
{
    $url = "$baseUrl/$resource"
    $Host.UI.RawUI.WindowTitle = "Downloading $resource..."
    (new-object System.Net.WebClient).DownloadFile($url, "$temp\$resource")
}

$Host.UI.RawUI.WindowTitle = "Configuring GPOs..."

# Put the wallpaper in place
$wallpaper_dir = "$ENV:SystemRoot\web\Wallpaper\Cloudbase"
if (!(Test-Path $wallpaper_dir))
{
    mkdir $wallpaper_dir
}
move "$temp\$wallpaper" $wallpaper_dir -Force

$gpoZipPath = "$temp\$gpoZipFile"
foreach($item in (New-Object -com shell.application).NameSpace($gpoZipPath).Items())
{
    $yesToAll = 16
    (New-Object -com shell.application).NameSpace("$ENV:SystemRoot\System32\GroupPolicy").copyhere($item, $yesToAll)
}
del $gpoZipPath
