<#
.SYNOPSIS
Generates one or more ESXi Host SSL Signing Requests and their respective keys.

.DESCRIPTION
This function is a cross-platform bridge/wrapper between vSphere PowerCLI and OpenSSL to generate Certificate Signing Requests for ESXi hosts.

.PARAMETER VMHost
The ESXi Host to generate the SSL Certificate for.
If the -FQDN parameter is passed, that value overrides the below checks.

Since the certificate CN/SAN is based on the FQDN, several checks are done.

* If the name is already in FQDN format and resolvable in DNS, the .Name value is used.
* If the name is just the Hostname, but it is resolvable with the default domain, the FQDN is constructed and used.
* If the name matches an IPv4 Address, a reverse lookup is performed and that FQDN value is used.

Since a proper DNS A/PTR record is required for ESXi and this functionality to work, if these checks fail the function will throw an exception at this stage.

.PARAMETER Hostname
The VMHost's "hostname" to use for the Certificate Signing Request.
Overrides any derived values.

.PARAMETER Domain
The DNS Domain to append to the VMHost hostname value. 
Overrides any derived values.

.PARAMETER ConfigFile
Path to the OpenSSL Configuration file (typically 'openssl.cfg') that is used to generate the certificates.
If you are creating your own, ensure that you reference the VMware KB 2015387 for the proper template and values.
If not specified, will check for 'openssl.cfg' or 'openssl.conf' in the current working directory.

.PARAMETER Country
The Country the host resides in. Maps to the 'countryName' field in the request configuration.

.PARAMETER State
The State (or Province) the host resides in. Maps to the 'stateOrProvinceName' field in the request configuration.

.PARAMETER City
The City the host resides in. Maps to the 'localityName' field in the request configuration.

.PARAMETER Organization
The Name of the Organization signing the certificate. Maps to the '0.organizationName' field in the request configuration.

.PARAMETER Path
The folder path where to store the resulting files.
If not specified, one is created under the current working directory called "ESX_Requests\<FQDN of Host>"

.EXAMPLE
$MyHost = Get-VMHost "esx001.domain.local"
$CSR = New-EsxiCertificate -VMHost $MyHost -Path "C:\Temp"

Generates SSL Request and Key for the host "esx001.domain.local" and places the output in "C:\Temp"
.OUTPUTS
Folder containing the CSR and Private Key for further processing
.NOTES
This function requires the VMware.PowerCLI module (any version) to work.
#>
function New-ESXiCertificate {
    [CmdletBinding(
        DefaultParameterSetName = 'VMHost'
    )]
    param(
        [Parameter(
            Mandatory = $true,
            ParameterSetName = 'VMHost',
            HelpMessage = 'Specify a VMHost object',
            ValueFromPipeline = $true,
            Position = 0
        )]
        [ValidateScript({
            if($_.ConnectionState -eq "Disconnected" -or $_.ConnectionState -eq "NotResponding") {
                throw("The VMHost is disconnected or not responding. Ensure it is connected before running the function against it.")
            } else {
                $true
            }
        })]
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VMHost]$VMHost,
        
        # Hostname parameter sets
        [Parameter(
            Mandatory = $true,
            ParameterSetName = 'Hostname',
            HelpMessage = 'Specify a Hostname to generate the SSL cert with'
        )]
        [string]$Hostname,

        # Domain parameter sets
        [Parameter(
            Mandatory = $true,
            ParameterSetName = 'Hostname',
            HelpMessage = 'Specify a DNS Domain to generate the SSL cert with'
        )]
        [string]$Domain,

        # Certificate Inputs
        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Specify the Country'
        )]
        [string]$Country,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Specify the State/Province'
        )]
        [string]$State,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Specify the City/Locality'
        )]
        [string]$City,

        [Parameter(
            Mandatory = $true,
            HelpMessage = 'Specify the Organization'
        )]
        [string]$Organization,
        [string]$Path
    )


    # Test for OpenSSL (this should be x-platform)
    # If this requirement isn't met, it is a critical error.
    try {
        Write-Host "New-EsxiCertificate :: Confirming a compatible OpenSSL version is present on the system ... " -ForegroundColor Cyan -NoNewline
        $OpenSSLPath = (Get-Command openssl -ErrorAction Stop).Path
        # Version
        [Version]$OpenSSLVersion = (Invoke-Expression -Command "$($OpenSSLPath) version").Split(" ")[1]
        # Test the version for >= 0.9.8
        [Version]$MinVersion = '0.9.8'
        if($OpenSSLVersion -ge $MinVersion) {
            Write-Host "success!" -ForegroundColor Green
        } else {
            Write-Host "failed." -ForegroundColor Red
            $OpenSSLError = "You must have an OpenSSL binary of version $MinVersion or higher. This system has version $OpenSSLVersion installed."
        }
    } catch {
        Write-Host "error!" -ForegroundColor Red
        $Caught = "Unhandled exception when querying the OpenSSL installation :: $($_.Exception)"
        throw($Caught)
    } finally {
        if($OpenSSLError) {
            throw($OpenSSLError)
        }
    }
    
    # Extract needed values for the OpenSSL template.
    if($VMHost) {
        Write-Host "New-EsxiCertificate :: Checking the VMHost inventory object [$($VMHost.Name)]... " -ForegroundColor Cyan -NoNewline
        # Use the Management Interface stack to get the IP, Hostname, Domain for comparison later.
        $NetStack = Get-VMHostNetworkstack -Name "defaultTcpipStack" -VMHost $VMHost -ErrorAction Stop
        $_ip = (Get-VMHostNetworkAdapter -VMHost $VMHost -ErrorAction Stop | Where ManagementTrafficEnabled -eq $true).IP
        $_hostname = $NetStack.DnsHostName
        $_domain = $NetStack.DnsDomainName
        if($_domain -ne "") {
            $_hostfqdn = "$($_hostname).$($_domain)"
        } else {
            $_hostfqdn = $_hostname
        }
        $_dnsrecord = (Test-Connection $_IP -ResolveDestination -Count 1).Destination
        Write-Host "done." -ForegroundColor Green
        if($($VMHost.Name -eq $_ip)) {
            Write-Warning "WARNING : The Inventory object [$VMHost] is joined using an IP address rather than DNS Name! You can resolve this using the `'ReconnectHost_Task`' API."
        } 
    } elseif($Hostname -and $Domain) {
        # Set the values to the locals
        $_hostname = $Hostname
        $_domain = $Domain
        $_hostfqdn = "$($_hostname).$($_domain)"
        Write-Host "New-EsxiCertificate :: Checking DNS for the FQDN of [$_hostfqdn] ... " -ForegroundColor Cyan -NoNewline
        try {
            $ConnTest = Test-Connection $_hostfqdn -Count 1 -ErrorAction Stop
            if($ConnTest.Status -eq "Success") {
                $_ip = $ConnTest.Address.IPAddressToString
                Write-Host "done." -ForegroundColor Green
            } else {
                # Record isn't in DNS! Toss a warning that it needs to be!
                Write-Host "warning!" -ForegroundColor Yellow
                Write-Warning "New-EsxiCertificate :: The requested FQDN is not currently in DNS."
                $_ip = "127.0.0.1"
            }
        } catch {
            Write-Host "warning!" -ForegroundColor Red
            Write-Warning "New-EsxiCertificate :: The requested FQDN is not currently in DNS."
            $_ip = "127.0.0.1"
        }
    } 

    # OpenSSL config file template
$Template = @"
[ req ]
default_bits = 2048
default_keyfile = rui.key
distinguished_name = req_distinguished_name
encrypt_key = no
prompt = no
string_mask = nombstr
req_extensions = v3_req

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = DNS:$_hostname, IP:$_ip, DNS:$_hostfqdn

[ req_distinguished_name ]
countryName = $Country
stateOrProvinceName = $State
localityName = $City
0.organizationName = $Organization
organizationalUnitName = vSphere
commonName = $_hostfqdn
"@
    
    # Create directory for holding the files based on inputs.
    if(Test-Path $Path) {
        $OutputPath = $Path
    } else {
        Write-Warning "New-EsxiCertificate :: Output Path for the files not specified, using default based on current directory."
        $OutputPath = Join-Path -Path "ESX_Requests" -ChildPath $_hostfqdn
    }
    $OutputDir = New-Item -ItemType Directory -path $OutputPath -Force
   
    # Generate the path variables for cross-platform
    $TemplateFilePath = Join-Path -Path $OutputDir -ChildPath "openssl.cfg"
    $CSRPath = Join-Path -Path $OutputDir -ChildPath "rui.csr"
    $RuiKeyOrigPath = Join-Path -Path $OutputDir -ChildPath "rui-orig.key"
    $RuiKeyPath = Join-Path -Path $OutputDir -ChildPath "rui.key"
    # Output the template file for OpenSSL to use
    $Template | Out-File -FilePath $TemplateFilePath -Encoding ascii    
    # Use OpenSSL binary to generate CSR and Private Key
    $CSRCommand = "$OpenSSLPath req -new -nodes -out `"$CSRPath`" -keyout `"$RuiKeyOrigPath`" -config `"$TemplateFilePath`" 2>&1"
    $RSACommand = "$OpenSSLPath rsa -in `"$RuiKeyOrigPath`" -out `"$RuiKeyPath`" 2>&1"
    Write-Host "New-EsxiCertificate :: Generating CSR and Private Key for [$_hostfqdn]..." -ForegroundColor Cyan -NoNewline
    $cmd_csr = Invoke-Expression -Command $CSRCommand
    $cmd_rsa = Invoke-Expression -Command $RSACommand

    Write-Host "success!" -ForegroundColor Green
    Write-Host "New-EsxiCertificate :: Certificate request output found in" -ForegroundColor Cyan -NoNewline
    Write-Host " [$outputdir]" -ForegroundColor Yellow

    return $OutputDir
}