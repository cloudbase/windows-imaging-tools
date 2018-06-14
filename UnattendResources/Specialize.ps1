$ErrorActionPreference = "Stop"
$resourcesDir = "$ENV:SystemDrive\UnattendResources"

try
{
    # Enable ping (ICMP Echo Request on IPv4 and IPv6)
    # TODO: replace with with a netsh advfirewall command
    # possibly avoiding duplicates with "File and printer sharing (Echo Request - ICMPv[4,6]-In)"
    netsh firewall set icmpsetting 8
}
catch
{
    $host.ui.WriteErrorLine($_.Exception.ToString())
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    throw
}
