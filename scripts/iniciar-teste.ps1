param(
    [int]$Port = 3100,
    [switch]$ComLimitesAltos
)

# Reinicia o servidor de teste em segundo plano.
$ErrorActionPreference = 'SilentlyContinue'
$pidFile = "$env:TEMP\opencode\freela-teste.pid"

if (Test-Path $pidFile) {
    $antigo = Get-Content $pidFile
    Stop-Process -Id $antigo -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

$env:PORT = "$Port"
if ($ComLimitesAltos) {
    # Afrouxa apenas os limitadores de /auth para que o fluxo funcional
    # (que cria varias contas) nao esbote no cadastro/login.
    $env:RL_CADASTRO_MAX = "200"
    $env:RL_LOGIN_MAX = "100"
    $env:RL_CANDIDATURA_MAX = "100"
    $env:RL_ESCRITA_MAX = "500"
    $env:RL_GLOBAL_MAX = "2000"
}

$log = "$env:TEMP\opencode\freela-server.log"
$p = Start-Process -FilePath "node" -ArgumentList "server.js" `
    -WorkingDirectory "C:\Users\erick\OneDrive\Desktop\freela-seguro" `
    -RedirectStandardOutput $log -RedirectStandardError "$log.err" `
    -PassThru -NoNewWindow

$p.Id | Out-File $pidFile

# Aguarda o health check responder.
for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 500
    try {
        $r = Invoke-RestMethod -Uri "http://localhost:$Port/api/saude" -TimeoutSec 2
        if ($r.status -eq 'ok') {
            Write-Output "servidor pronto em http://localhost:$Port (pid $($p.Id))"
            exit 0
        }
    } catch { }
}

Write-Output "servidor nao respondeu; veja $log"
exit 1
