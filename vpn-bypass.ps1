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
    param(
        $interface
    )    
    # Obtém a tabela de rotas
    $routes = Get-NetRoute | Where-Object { $_.ifindex -ne $interface }

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



$localEth = Get-IPV4-Info "Ethernet"
$localWifi = Get-IPV4-Info "Wi-Fi"
$wsl = Get-IPV4-Info "vEthernet (WSL)"

if ($localWifi.IfaceStatus -ne "Disconnected") {
    $local = $localWifi
}
else {
    $local = $localEth
}


# Remover IPs Publicos 

$addresses = Get-NetworkAddresses  $local.IfaceId
$publicIPs = Get-PublicIPAddresses -Addresses $addresses

Write-LogMessage -Message "Removendo Rotas para IPs Publicos..."

foreach ($publicIP in $publicIPs) {
    Write-LogMessage -Message "Removendo Rotas para $publicIP"
    route delete $publicIP | Out-Null
}

Write-LogMessage -Message "Rotas removidas!"


# Ajusta Rede Local

Write-LogMessage -Message "Ajuste de Rotas da Rede Local..."

route delete $local.NetAddress | Out-Null
route ADD $local.NetAddress MASK $local.Mask 0.0.0.0 METRIC 1 IF $local.IfaceId | Out-Null

Write-LogMessage -Message "Rotas da Rede Local ajustadas!"


#Ajusta WSL

Write-LogMessage -Message "Ajuste de Rotas WSL..."

route delete $wsl.NetAddress | Out-Null
route delete $wsl.IpAddress | Out-Null
route delete $wsl.BroadcastAddress | Out-Null

route ADD $wsl.NetAddress MASK $wsl.Mask 0.0.0.0 IF $wsl.IfaceId | Out-Null
route ADD $wsl.IpAddress MASK 255.255.255.255 0.0.0.0 IF $wsl.IfaceId | Out-Null
route ADD $wsl.BroadcastAddress MASK 255.255.255.255 0.0.0.0 IF $wsl.IfaceId | Out-Null

Write-LogMessage -Message "Rotas WSL ajustadas!"

Write-LogMessage -Message "VPN Bypass finalizado!!!"

Start-Sleep 5


