
function Set-IPv6 {
    netsh interface ipv6 set global randomizeidentifiers=disabled store=active
    netsh interface ipv6 set global randomizeidentifiers=disabled store=persistent
    netsh interface ipv6 set privacy state=disabled store=active
    netsh interface ipv6 set privacy state=disabled store=persistent
    netsh int ip reset
}

Set-IPv6