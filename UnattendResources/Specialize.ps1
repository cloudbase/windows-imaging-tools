$ErrorActionPreference = "Stop"

try {
    # Enable ping (ICMP Echo Request on IPv4 and IPv6)
    # TODO: replace with with a netsh advfirewall command
    # possibly avoiding duplicates with "File and printer sharing (Echo Request - ICMPv[4,6]-In)"
    netsh firewall set icmpsetting 8

    # Disable Windows Store Autodownload
    $autoDownloadRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
    New-Item -Force -Path $autoDownloadRegPath
    New-ItemProperty -Force -Path $autoDownloadRegPath -Name "AutoDownload" -Type DWORD -Value 2

    # Disable Consumer Experience
    $customerExperienceRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    New-Item -Force -Path $customerExperienceRegPath
    New-ItemProperty -Force -Path $customerExperienceRegPath -Name "DisableWindowsConsumerFeatures" -Type DWORD -Value 1

    # Stop InstallerService
    $installerServiceName = "InstallService"
    Stop-Service -Force $installerServiceName -ErrorAction SilentlyContinue
    & sc.exe config $installerServiceName start= demand
} catch {
    $host.ui.WriteErrorLine($_.Exception.ToString())
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    throw
}
