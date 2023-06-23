# VPN Bypass

## Uso

Executar com powershell 7 (pwsh) como Administrador

## Efeitos

Atualiza rotas para a Rede Local e WSL, permitindo o uso durante a execução da VPN.

## VPN Profile 

Atribuir à variável $VPN_PROFILE_NAME o nome (ou parte do nome) do perfil de rede da VPN

Exemplo: 
```pwsh
$VPN_PROFILE_NAME = "VPN"
```

## Bypassed IPs

Atribuindo à variável $VPN_BYPASSED_IPS e/ou variável de ambiente $env:VPN_BYPASSED_IPS uma lista de IPs para não passarem pela VPN, os mesmos serão alcançados via Default Gateway da Rede Local.

Exemplo: 
```pwsh
$env:VPN_BYPASSED_IPS = "186.192.90.12,172.217.173.78"
```

## Bypass Public IPs

Atribuindo à variável $VPN_BYPASS_PUBLIC_IPS e/ou variável de ambiente $env:VPN_BYPASS_PUBLIC_IPS o valor "TRUE", os IPs publicos serão removidos da rota da VPN.
Exemplo: 
```pwsh
$env:VPN_BYPASS_PUBLIC_IPS = "TRUE"
```

Ao mesmo tempo atribuindo à variável $VPN_DOMAINS_NOT_BYPASSED e/ou variável de ambiente $env:VPN_DOMAINS_NOT_BYPASSED uma lista de domínios para passarem pela VPN, os mesmos serão alcançados via Gateway da VPN.

Exemplo: 
```pwsh
$env:VPN_DOMAINS_NOT_BYPASSED = "orkut.com,zipmail.com"
```
