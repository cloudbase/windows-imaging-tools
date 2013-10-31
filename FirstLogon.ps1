$ErrorActionPreference = "Stop"

$virtPlatform = (gwmi Win32_ComputerSystem).Model
Write-Host "Virtual platform: $virtPlatform"

# TODO: Add XenServer / XCP
switch($virtPlatform)
{
    "VMware Virtual Platform"
    {
        $Host.UI.RawUI.WindowTitle = "Installing VMware tools..."
        E:\setup64.exe `/s `/v `"/qn REBOOT=ReallySuppress`" `/l `"$ENV:Temp\vmware_tools_install.log`"
        if (!$?) { throw "VMware tools setup failed"}
    }
    "KVM"
    {
        $Host.UI.RawUI.WindowTitle = "Downloading VirtIO drivers script..."
        $virtioScriptPath = "$ENV:Temp\InstallVirtIODrivers.js"
        $url = "https://raw.github.com/cloudbase/windows-openstack-imaging-tools/master/InstallVirtIODrivers.js"
        (new-object System.Net.WebClient).DownloadFile($url, $virtioScriptPath)

        $Host.UI.RawUI.WindowTitle = "Installing VirtIO drivers..."
        & cscript $virtioScriptPath "E:\Win8\AMD64\*.inf"
        if (!$?) { throw "InstallVirtIO failed"}
        del $virtioScriptPath
    }
}

