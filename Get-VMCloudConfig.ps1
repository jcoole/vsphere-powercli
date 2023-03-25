function Get-VMCloudConfig {
    param(
        [Parameter(Mandatory=$true)][VMware.VimAutomation.Types.VirtualMachine]$VM,
        [switch]$Decode
    )
    
    $ConfigExists = (Get-VM $VM).ExtensionData.Config.VAppConfig.Property | ?{$_.Id -eq "user-data"}
    if($ConfigExists) {
        $CloudConfig = $ConfigExists.Value
    } else {
        Write-Host "No cloud-config found in the vApp properties!" -ForegroundColor Yellow
        break
    }

    if($Decode) {
        return [Text.Encoding]::Utf8.GetString([Convert]::FromBase64String($CloudConfig))
    } else {
        return $CloudConfig
    }
}