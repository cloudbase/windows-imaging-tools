var infPath = WScript.arguments(0)

var ws = new ActiveXObject("WScript.Shell");
ws.Run("pnputil -i -a " + infPath);

var interval = 3000;

for (var i = 0; i < 3; i++) {
    WScript.Sleep(interval);
    ws.AppActivate("Windows Security");
    ws.SendKeys("i");
}

//Wait for PNPUtil to finish
WScript.Sleep(5000)
