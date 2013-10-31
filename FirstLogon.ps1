$ErrorActionPreference = "Stop"

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

