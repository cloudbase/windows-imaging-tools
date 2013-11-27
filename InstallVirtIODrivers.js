function getWmiCimV2Svc() {
    return GetObject("winmgmts:\\\\.\\root\\cimv2");
}

var OSArchitecturesDirectories = {
    "32-bit": "X86",
    "64-bit": "AMD64"
}

var OSVersionsDirectories = {
    "0": "VISTA",
    "1": "WIN7",
    "2": "WIN8",
    "3": "WIN8"
}
function getWindowsArchitecture() {
    var wmiSvc = getWmiCimV2Svc();
    var q = wmiSvc.InstancesOf("Win32_OperatingSystem")
    var os = new Enumerator(q).item()
    // NOTE: does not work on Windows XP / 2003
    return os.OSArchitecture
}

function getWindowsVersion() {
    var wmiSvc = getWmiCimV2Svc();
    var q = wmiSvc.InstancesOf("Win32_OperatingSystem")
    var os = new Enumerator(q).item()
    return os.Version.split('.')
}

function getVirtioDirectory(){
    var osArchitecture = getWindowsArchitecture();
    var osArchitectureDirectory = OSArchitecturesDirectories[osArchitecture];
    var osVersion = getWindowsVersion();
    var osVersionDirectory = "";
    if(osVersion[0] == "6"){
        osVersionDirectory = OSVersionsDirectories[osVersion[1]];
    }
    else {
        throw "Windows version not supported";
    }
    return osVersionDirectory + "\\" + osArchitectureDirectory;
}

var baseDir = WScript.arguments(0);
var virtioDir = getVirtioDirectory();
var infPath = baseDir + virtioDir + "\\*.inf";

var ws = new ActiveXObject("WScript.Shell");
ws.Run("pnputil -i -a " + infPath);

var interval = 3000;

for (var i = 0; i < 3; i++) {
    WScript.Sleep(interval);
    ws.AppActivate("Windows Security");
    ws.SendKeys("i");
}
