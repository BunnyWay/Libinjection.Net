# Libinjection.Net
Simple C# library bindings around libinjection to detect SQLi and XSS attacks. Currently the binary is only compiled for usage on Linux.

# Usage
The library contains two simple static methods IsSQLi and IsXSS that return a bool value determining if an attack was found.

```
var isSQLi = LibInjection.IsXSS("' OR 1=1;--");
var isXss = LibInjection.IsXSS("<script>alert('hello')</script>");
```
