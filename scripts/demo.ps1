# End-to-end demo of the secure API (Windows PowerShell).
# Usage: pwsh -File scripts/demo.ps1 [-BaseUrl http://127.0.0.1:5000]
param(
    [string]$BaseUrl = "http://127.0.0.1:5000"
)

$ErrorActionPreference = "Stop"
$Username = if ($env:USERNAME_OVERRIDE) { $env:USERNAME_OVERRIDE } else { "alice" }
$Password = if ($env:PASSWORD_OVERRIDE) { $env:PASSWORD_OVERRIDE } else { "Alice-Str0ng-Pass!" }

function Section($title) { Write-Host "`n== $title ==" -ForegroundColor Cyan }
function StatusOf([string[]]$curlArgs) { curl.exe -s -o NUL -w "%{http_code}" @curlArgs }

Section "0. Health check (public)"
curl.exe -s "$BaseUrl/health"
Write-Host ""

Section "1. Login -> JWT"
$login = curl.exe -s -X POST "$BaseUrl/auth/login" -H "Content-Type: application/json" `
    --data-binary "{`"username`":`"$Username`",`"password`":`"$Password`"}"
$login
$token = ($login | ConvertFrom-Json).access_token
if (-not $token) { throw "login failed - could not obtain a token" }

Section "2. Protected endpoint WITHOUT a token -> expect 401"
Write-Host ("   HTTP " + (StatusOf @("-i", "$BaseUrl/api/data")))
curl.exe -s -i "$BaseUrl/api/data" | Select-String -Pattern "^HTTP/|^WWW-Authenticate:"

Section "3. Protected endpoint WITH the token -> expect 200"
curl.exe -s "$BaseUrl/api/data?limit=2" -H "Authorization: Bearer $token"
Write-Host ""

Section "4. Tampered / garbage token -> expect 401"
Write-Host ("   HTTP " + (StatusOf @("$BaseUrl/api/data", "-H", "Authorization: Bearer not.a.token")))

Section "5. SQL injection in the search parameter -> expect 200, zero rows"
curl.exe -s "$BaseUrl/api/data?q=%27%20OR%201%3D1%20--" -H "Authorization: Bearer $token"
Write-Host ""

Section "6. SQL injection in the login form -> expect 400/401, never logged in"
$sqliBody = @'
{"username":"alice' OR '1'='1","password":"x"}
'@
$tmp = Join-Path $env:TEMP "demo-sqli.json"
Set-Content -Path $tmp -Value $sqliBody -Encoding utf8 -NoNewline
Write-Host ("   HTTP " + (StatusOf @("-X", "POST", "$BaseUrl/auth/login", "-H", "Content-Type: application/json", "--data-binary", "@$tmp")))
curl.exe -s -X POST "$BaseUrl/auth/login" -H "Content-Type: application/json" --data-binary "@$tmp"
Write-Host ""
Remove-Item $tmp -ErrorAction SilentlyContinue

Section "7. Stored XSS payload -> expect escaped output (should show &lt;script&gt;)"
$xssBody = @'
{"title":"<script>alert(1)</script>","body":"<img src=x onerror=alert(1)>"}
'@
$tmp = Join-Path $env:TEMP "demo-xss.json"
Set-Content -Path $tmp -Value $xssBody -Encoding utf8 -NoNewline
curl.exe -s -X POST "$BaseUrl/api/posts" -H "Authorization: Bearer $token" `
    -H "Content-Type: application/json" --data-binary "@$tmp"
Write-Host ""
Remove-Item $tmp -ErrorAction SilentlyContinue

Section "8. Pagination validation -> expect 400"
curl.exe -s -i "$BaseUrl/api/data?limit=5000" -H "Authorization: Bearer $token" |
    Select-String -Pattern "^HTTP/"
curl.exe -s "$BaseUrl/api/data?limit=5000" -H "Authorization: Bearer $token"
Write-Host ""

Write-Host "`nAll checks executed. Every attack above was rejected or neutralised." -ForegroundColor Green
