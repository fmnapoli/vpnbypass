# Verificar se o script está sendo executado como administrador

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Se não estiver sendo executado como administrador, reinicia o script com privilégios elevados
    Start-Process -FilePath pwsh -Verb RunAs -ArgumentList "-File $($MyInvocation.MyCommand.Path)" #-Wait
    exit
}

# Definir listas
$VPN_BYPASSED_IPS_LIST = @(
    "189.126.135.50",
    "181.41.180.91",
    "181.41.180.123",
    "181.41.181.227"
)

$VPN_DOMAINS_NOT_BYPASSED_LIST = @(
    "totvs.fluigidentity.com",
    "nemesis.nuvemintera.com.br",
    "tesp3-nemesis.nuvemintera.com.br",
    "tece1-nemesis.nuvemintera.com.br",
    "tesp5-nemesis.nuvemintera.com.br",
    "nemesis-mock.cloudtotvs.com.br",
    "cofre-tcloud.cloudtotvs.com.br",
    "cofre-tesp01.cloudtotvs.com.br",
    "cofre-tesp02.cloudtotvs.com.br",
    "cofre-tesp03.cloudtotvs.com.br",
    "cofre-tesp04.cloudtotvs.com.br",
    "cofre-tesp05.cloudtotvs.com.br",
    "cofre-tece01.cloudtotvs.com.br",
    "slack.com",
    "slack-edge.com",
    "github.com",
    "stackoverflow.com",
    "wss-primary.slack.com",
    "wss-backup.slack.com",
    "wss-mobile.slack.com",
    "a.slack-edge.com",
    "avatars.slack-edge.com",
    "cdn.speedcurve.com",
    "slack-imgs.com",
    "ca.slack-edge.com",
    "files.slack.com",
    "tcw-api.cloudtotvs.com.br"
)

Write-Output "[vpn-bypass-config] Configurando variáveis de ambiente ..."

# Converter listas para strings separadas por vírgula
$VPN_BYPASSED_IPS_STRING = $VPN_BYPASSED_IPS_LIST -join ","
$VPN_DOMAINS_NOT_BYPASSED_STRING = $VPN_DOMAINS_NOT_BYPASSED_LIST -join ","

# Setar variáveis de ambiente
[System.Environment]::SetEnvironmentVariable("VPN_BYPASS_PUBLIC_IPS", "TRUE", [System.EnvironmentVariableTarget]::Machine)
[System.Environment]::SetEnvironmentVariable("VPN_BYPASSED_IPS", $VPN_BYPASSED_IPS_STRING, [System.EnvironmentVariableTarget]::Machine)
[System.Environment]::SetEnvironmentVariable("VPN_DOMAINS_NOT_BYPASSED", $VPN_DOMAINS_NOT_BYPASSED_STRING, [System.EnvironmentVariableTarget]::Machine)

Write-Output "[vpn-bypass-config] Variáveis de ambiente configuradas com sucesso!"

Start-Sleep 5
