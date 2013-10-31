$ErrorActionPreference = "Stop"

$wallpaper = "Wallpaper-Cloudbase-2013.png"
$virtioscript = "InstallVirtIODrivers.js"
$gpoZipFile = "GPO.zip"

$resources = @("FirstLogon.sp1", "Logon.sp1", $virtioscript, $gpoZipFile, $wallpaper)

$temp = "$ENV:SystemRoot\Temp"
$baseUrl = "https://raw.github.com/cloudbase/windows-openstack-imaging-tools/master"

foreach($resource in $resources)
{
    $url = "$baseUrl/$resource"
    $Host.UI.RawUI.WindowTitle = "Downloading $resource..."
    (new-object System.Net.WebClient).DownloadFile($url, "$temp\$resource")
}

$virtPlatform = (gwmi Win32_ComputerSystem).Model
Write-Host "Virtual platform: $virtPlatform"

# TODO: Add XenServer / XCP
switch($virtPlatform)
{
    "VMware Virtual Platform"
    {
        $Host.UI.RawUI.WindowTitle = "Installing VMware tools..."
        E:\setup64.exe `/s `/v `"/qn REBOOT=ReallySuppress`" `/l $temp\vmware_tools_install.log
        if (!$?) { throw "VMware tools setup failed"}
    }
    "KVM"
    {
        $Host.UI.RawUI.WindowTitle = "Installing VirtIO drivers..."    
        & cscript $temp\$virtioscript "E:\Win8\AMD64\*.inf"
        if (!$?) { throw "InstallVirtIO failed"}
        del $temp\$virtioscript
    }
}

$Host.UI.RawUI.WindowTitle = "Configuring GPOs..."    

# Put the wallpaper in place
$wallpaper_dir = "$ENV:SystemRoot\web\Wallpaper\Cloudbase"
mkdir $wallpaper_dir
move "$temp\$wallpaper" $wallpaper_dir

$gpoZipPath = "$temp\$gpoZipFile"
foreach($item in (New-Object -com shell.application).NameSpace(gpoZipPath).Items())
{
    (New-Object -com shell.application).NameSpace("$ENV:SystemRoot\System32\GroupPolicy").copyhere($item)
}
del gpoZipPath
