# Verificar se o script está sendo executado como administrador
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Se não estiver sendo executado como administrador, reinicia o script com privilégios elevados
    Start-Process -FilePath pwsh -Verb RunAs -ArgumentList "-File $($MyInvocation.MyCommand.Path)" #-Wait
    exit
}

$VPN_BYPASSED_IPS = ""
$VPN_BYPASS_PUBLIC_IPS = "FALSE"
$VPN_DOMAINS_NOT_BYPASSED = ""
$VPN_PROFILE_NAME = "VPN"

if (-not([string]::IsNullOrEmpty($env:VPN_BYPASSED_IPS))) {
    $sep = ","
    if (([string]::IsNullOrEmpty($VPN_BYPASSED_IPS))) {
        $sep = ""
    }    
    $VPN_BYPASSED_IPS = $VPN_BYPASSED_IPS + "$sep$env:VPN_BYPASSED_IPS"
}

if (-not([string]::IsNullOrEmpty($env:VPN_BYPASS_PUBLIC_IPS))) {
    $VPN_BYPASS_PUBLIC_IPS = $env:VPN_BYPASS_PUBLIC_IPS
}

if (-not([string]::IsNullOrEmpty($env:VPN_DOMAINS_NOT_BYPASSED))) {
    $sep = ","
    if (([string]::IsNullOrEmpty($VPN_DOMAINS_NOT_BYPASSED))) {
        $sep = ""
    }    
    $VPN_DOMAINS_NOT_BYPASSED = $VPN_DOMAINS_NOT_BYPASSED + "$sep$env:VPN_DOMAINS_NOT_BYPASSED"
}

$ErrorActionPreference = "SilentlyContinue"

function Write-LogMessage {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR')]
        [string]$LogLevel = 'INFO'
    )

    $currentDate = Get-Date -Format "yyyy-MM-dd"
    $currentTime = Get-Date -Format "HH:mm:ss.fff"
    $logLine = "$currentDate $currentTime [$LogLevel] - $Message"
    Write-Output $logLine
}

function Get-BroadcastAddress {
   
    param
    (
        [Parameter(Mandatory = $true)]
        $IPAddress,
        $SubnetMask = '255.255.255.0'
    )

    filter Convert-IP2Decimal {
        ([IPAddress][String]([IPAddress]$_)).Address
    }


    filter Convert-Decimal2IP {
    ([System.Net.IPAddress]$_).IPAddressToString 
    }


    [UInt32]$ip = $IPAddress | Convert-IP2Decimal
    [UInt32]$subnet = $SubnetMask | Convert-IP2Decimal
    [UInt32]$broadcast = $ip -band $subnet 
    $broadcast -bor -bnot $subnet | Convert-Decimal2IP
}
function Convert-Subnetmask {
    [CmdLetBinding(DefaultParameterSetName = 'CIDR')]
    param( 
        [Parameter( 
            ParameterSetName = 'CIDR',       
            Position = 0,
            Mandatory = $true,
            HelpMessage = 'CIDR like /24 without "/"')]
        [ValidateRange(0, 32)]
        [Int32]$CIDR,

        [Parameter(
            ParameterSetName = 'Mask',
            Position = 0,
            Mandatory = $true,
            HelpMessage = 'Subnetmask like 255.255.255.0')]
        [ValidateScript({
                if ($_ -match "^(254|252|248|240|224|192|128).0.0.0$|^255.(254|252|248|240|224|192|128|0).0.0$|^255.255.(254|252|248|240|224|192|128|0).0$|^255.255.255.(255|254|252|248|240|224|192|128|0)$") {
                    return $true
                }
                else {
                    throw "Enter a valid subnetmask (like 255.255.255.0)!"    
                }
            })]
        [String]$Mask
    )

    Begin {

    }

    Process {
        switch ($PSCmdlet.ParameterSetName) {
            "CIDR" {                          
                # Make a string of bits (24 to 11111111111111111111111100000000)
                $CIDR_Bits = ('1' * $CIDR).PadRight(32, "0")
                
                # Split into groups of 8 bits, convert to Ints, join up into a string
                $Octets = $CIDR_Bits -split '(.{8})' -ne ''
                $Mask = ($Octets | ForEach-Object -Process { [Convert]::ToInt32($_, 2) }) -join '.'
            }

            "Mask" {
                # Convert the numbers into 8 bit blocks, join them all together, count the 1
                $Octets = $Mask.ToString().Split(".") | ForEach-Object -Process { [Convert]::ToString($_, 2) }
                $CIDR_Bits = ($Octets -join "").TrimEnd("0")

                # Count the "1" (111111111111111111111111 --> /24)                     
                $CIDR = $CIDR_Bits.Length             
            }               
        }

        [pscustomobject] @{
            Mask = $Mask
            CIDR = $CIDR
        }
    }

    End {
        
    }
}

function Get-InterfaceAlias {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ProfileName
    )

    $connectionProfile = Get-NetConnectionProfile | Where-Object { $_.InterfaceAlias -match $ProfileName }

    if ($connectionProfile) {
        return $connectionProfile.InterfaceAlias
    }
    else {
        Write-LogMessage "Não foi possível encontrar o perfil de conexão com o nome '$ProfileName'."
    }
}

function Get-Interface {
    param (
        [string]$alias
    )
    
    return Get-NetIPConfiguration | Where-Object { $_.InterfaceAlias -eq $alias }
}

function Get-NetAddress {
    param (
        $ipaddress,
        $subnetmask
    )
    $ip = [ipaddress]$ipaddress
    $subnet = [ipaddress]$subnetmask
    $netid = [ipaddress]($ip.address -band $subnet.address)

    return $netid.ipaddresstostring
    
}
function Get-IPV4-Info {
    param (
        [string]$alias
    )

    $interface = Get-NetIPConfiguration $alias
    $IpAddress = $interface.IPv4Address.IPAddress
    $Mask = $(Convert-Subnetmask -CIDR $interface.IPv4Address.PrefixLength).Mask
    
    $IPV4Info = @{
        IpAddress        = $IpAddress
        Mask             = $Mask
        NetAddress       = Get-NetAddress $IpAddress $Mask
        BroadcastAddress = Get-BroadcastAddress $IpAddress $Mask
        IfaceId          = $interface.InterfaceIndex
        IfaceStatus      = $interface.NetAdapter.Status
    }
    return $IPV4Info    
}

function Get-NetworkAddresses {
  
    # Obtém a tabela de rotas
    $routes = Get-NetRoute 

    # Lista para armazenar os endereços de rede
    $networkAddresses = @()

    # Itera sobre cada rota e extrai o endereço de rede
    foreach ($route in $routes) {
        $networkAddresses += [string]($route.DestinationPrefix).Split("/")[0]
    }

    # Retorna a lista de endereços de rede
    return $networkAddresses
}


function Test-PrivateIP {
    param(
        [parameter(Mandatory, ValueFromPipeline)]
        [string]
        $IP
    )
    process {

        if ($IP -Match '(^127\.)|(^192\.168\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)') {
            $true
        }
        else {
            $false
        }
    }    
}

function Get-ResolvedIPs {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Urls
    )

    $resolvedIPs = @()

    foreach ($url in $Urls) {
        try {
            $resolved = Resolve-DnsName -Name $url -ErrorAction Stop
            $ip = $resolved.IPAddress
            $resolvedIPs += $ip
        }
        catch {
            Write-LogMessage -LogLevel ERROR -Message "Falhar ao resolver IP para URL: $url"
        }
    }

    return $resolvedIPs
}

function Get-PublicIPAddresses {
    param (
        [string[]] $Addresses
    )

    # Lista para armazenar os endereços IP públicos válidos
    $publicAddresses = @()

    foreach ($address in $Addresses) {
        $ip = [System.Net.IPAddress]::Parse($address)

        $isPrivateIP = $(Test-PrivateIP $address)
        $isIPv6 = $ip.AddressFamily -eq 'InterNetworkV6'
        $isLoopback = $address -eq '127.0.0.1'
        $isMulticast = $address -eq '224.0.0.0'
        $startsWithZero = $address.StartsWith("0.")
        $startsWith255 = $address.StartsWith("255.")

        # Verifica se o endereço IP é público, não é um endereço privado, não é IPv6,
        # não é loopback, não é broadcast e não termina com .0 ou .255
        if (!$isPrivateIP -and !$isIPv6 -and !$isLoopback -and !$isMulticast -and !$startsWithZero -and !$startsWith255) {
            $publicAddresses += $ip.ToString()
        }
    }

    # Retorna a lista de endereços IP públicos válidos
    return $publicAddresses
}

function Remove-PublicIPs {
    param (
        $ipAddress
    )

    $publicIPs = Get-PublicIPAddresses -Addresses $ipAddress

    foreach ($publicIP in $publicIPs) {
        Write-LogMessage -Message "Removendo Rotas para $publicIP"
        route delete $publicIP 
    }   
    
}
function Get-DefaultGateway {
    $routes = Get-NetRoute -AddressFamily IPv4
    $defaultRoute = $routes | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' }
    
    if ($defaultRoute) {
        return $defaultRoute.NextHop
    }
    
    return $null
}
function Add-notBypassedPublicIPs {
    param (
        $notBypassedPublicIPs
    )
    foreach ($ipAddress in $notBypassedPublicIPs) {
        Write-LogMessage -Message "Adicionando o IP não Bypassed: $ipAddress"
        route ADD $ipAddress MASK 255.255.255.255 0.0.0.0 IF $vpn.IfaceId        
    }    
}

Write-LogMessage -Message "Coletando Informações das Interfaces..."

$defaultGateway = Get-DefaultGateway

$permitedList = $VPN_BYPASSED_IPS.Split(",")

$vpnInterfaceAlias = Get-InterfaceAlias $VPN_PROFILE_NAME

$vpn = Get-IPV4-Info $vpnInterfaceAlias

$localEth = Get-IPV4-Info "Ethernet"
$localWifi = Get-IPV4-Info "Wi-Fi"
$wsl = Get-IPV4-Info "vEthernet (WSL)"

if ($localWifi.IfaceStatus -ne "Disconnected") {
    $local = $localWifi
}
else {
    $local = $localEth
}

$addresses = $(Get-NetworkAddresses) | Where-Object { $_.ifindex -ne $local.IfaceId }
Write-LogMessage -Message "Informações das Interfaces coletadas!"


# Ajusta Rede Local

Write-LogMessage -Message "Ajuste de Rotas da Rede Local..."

if ($addresses -contains $local.NetAddress) {
    route delete $local.NetAddress 
    Write-LogMessage -Message "Rota $($local.NetAddress) Removida!"
}
route ADD $local.NetAddress MASK $local.Mask 0.0.0.0 METRIC 1 IF $local.IfaceId | Out-Null
Write-LogMessage -Message "Rota $($local.NetAddress) Adicionada!"

Write-LogMessage -Message "Rotas da Rede Local ajustadas!"


#Ajusta WSL

Write-LogMessage -Message "Ajuste de Rotas WSL..."

if ($addresses -contains $wsl.BroadcastAddress) {
    route delete $wsl.BroadcastAddress | Out-Null
    Write-LogMessage -Message "Rota $($wsl.BroadcastAddress) Removida!"
}

if ($addresses -contains $wsl.NetAddress) {
    route delete $wsl.NetAddress | Out-Null
    Write-LogMessage -Message "Rota $($wsl.NetAddress) Removida!"
}

if ($addresses -contains $wsl.IpAddress) {
    route delete $wsl.IpAddress | Out-Null
    Write-LogMessage -Message "Rota $($wsl.IpAddress) Removida!"
}

route ADD $wsl.BroadcastAddress MASK 255.255.255.255 0.0.0.0 IF $wsl.IfaceId 
Write-LogMessage -Message "Rota $($wsl.BroadcastAddress) Adicionada!"

route ADD $wsl.NetAddress MASK $wsl.Mask 0.0.0.0 IF $wsl.IfaceId 
Write-LogMessage -Message "Rota $($wsl.Mask) Adicionada!"

route ADD $wsl.IpAddress MASK 255.255.255.255 0.0.0.0 IF $wsl.IfaceId 
Write-LogMessage -Message "Rota $($wsl.IpAddress) Adicionada!"


Write-LogMessage -Message "Rotas WSL ajustadas!"

# Remover IPs Publicos 

$removePublicIPs = ($VPN_BYPASS_PUBLIC_IPS -eq "TRUE")

if ($removePublicIPs) {   
    $VPN_DOMAINS_NOT_BYPASSED = $VPN_DOMAINS_NOT_BYPASSED.Split(",")
    Remove-PublicIPs $addresses
    $addresses = $(Get-NetworkAddresses) | Where-Object { $_.ifindex -ne $local.IfaceId }
    $notBypassedPublicIPs = Get-ResolvedIPs -Urls $VPN_DOMAINS_NOT_BYPASSED    
    Add-notBypassedPublicIPs $notBypassedPublicIPs
}


Write-LogMessage -Message "Atualizando Rotas para IPs Permitidos..."


foreach ($ipAddress in $permitedList) {
    $ipAddressNotExists = [string]::IsNullOrEmpty($ipAddress)
    if ($ipAddressNotExists) {
        break
    }
    Write-LogMessage -Message "Atualizando Rota para $ipAddress"
    if ($addresses -contains $ipAddress) {
        route delete $ipAddress | Out-Null
        Write-LogMessage -Message "Rota $ipAddress Removida!"
    }    
    route ADD $ipAddress MASK 255.255.255.255 $defaultGateway METRIC 1 IF $local.IfaceId
    Write-LogMessage -Message "Rota $ipAddress Adicionada!"
}

Write-LogMessage -Message "Rotas para IPs Permitidos atualizadas!"

Write-LogMessage -Message "VPN Bypass finalizado!!!"

Start-Sleep 5


