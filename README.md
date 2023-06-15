# vpnbypass

## Uso

Executar com ppowershell 7 (pwsh) como Administrador

## Efeitos

Atualiza rotas para a Rede Local e WSL, permitindo o uso durante a execução da VPN.

## Bypassed IPs

Atribuindo à variável $VPN_BYPASSED_IPS e/ou variável de ambiente $env:VPN_BYPASSED_IPS uma lista de IPs para não passarem pela VPN, os mesmos serão alcançados via Default Gateway da Rede Local.

Exemplo: 
```pwsh
$env:VPN_BYPASSED_IPS = "186.192.90.12,172.217.173.78"
```