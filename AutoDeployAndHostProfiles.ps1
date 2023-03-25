function Manage-LocalHostAccount {
<#
.SYNOPSIS
Manages the Local ESXi Host accounts, such as root.
.DESCRIPTION
This function can be used to manage the root account password directly from vCenter.
Traditionally, you would have to know the previous password and connect directly to the ESXi host to reset it.
In vCenter 6.0+ you can manage local users from the vCenter API, which performs the tasks using the 'vpxuser' account.
.PARAMETER VMHost
The ESXi Host to manage users on.
.PARAMETER Credential
The username/password credentials to specify for the ESXi Host.
.PARAMETER Description
A description that will be applied to the user account on the ESXi Host.
If nothing is specified, a default one indicating the date/time it was last modified will be applied instead.
.PARAMETER Action
The type of action to take - it can be CreateUser, UpdateUser, or RemoveUser as required.
.EXAMPLE
$MyHost = Get-VMHost "MyVMHost.domain.local"
$MyCredential = Get-Credential -Prompt "Enter the user/password to specify"

Manage-LocalHostAccount -VMHost $MyHost -Credential $MyCredential -Action CreateUser

Creates the specified user account credentials on the ESXi host.
.EXAMPLE
$MyHost = Get-VMHost "MyVMHost.domain.local"
$MyCredential = Get-Credential -Prompt "Enter the user/password to specify"
$MyDescription = "Updated on $(Get-Date) by Jesse.Pinkman@domain.com"

Manage-LocalHostAccount -VMHost $MyHost -Credential $MyCredential -Description $MyDescription -Action UpdateUser

Updates the specified user account credentials on the ESXi host.
.EXAMPLE
$MyHost = Get-VMHost "MyVMHost.domain.local"
$MyCredential = Get-Credential -Prompt "Enter the user/password to specify"
$MyDescription = "Updated on $(Get-Date) by Jesse.Pinkman@domain.com"

Manage-LocalHostAccount -VMHost $MyHost -Credential $MyCredential -Action RemoveUser

Removes the specified user account credentials on the ESXi host.
In the case of a RemoveUser action, the credentials don't matter - only the username will be used.

If this is attempting to remove the last local user with DCUI access, or if trying to remove the last local user with full administrative privileges, or if the system has encountered an error while trying to remove user's permissions, or if the account cannot be removed due to permission issues - an error will be thrown.
.OUTPUTS
None
.NOTES
This function requires PowerCLI version 11.0+ to run properly.
.LINK
https://pubs.vmware.com/vsphere-6-5/topic/com.vmware.wssdk.smssdk.doc/vim.host.LocalAccountManager.html#createUser
.LINK
https://pubs.vmware.com/vsphere-6-5/topic/com.vmware.wssdk.smssdk.doc/vim.host.LocalAccountManager.html#updateUser
.LINK
https://pubs.vmware.com/vsphere-6-5/topic/com.vmware.wssdk.smssdk.doc/vim.host.LocalAccountManager.html#removeUser
#>    
    param(
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Impl.V1.Inventory.VMHostImpl]$VMHost,
        [Parameter(Mandatory=$true)][System.Management.Automation.PSCredential]$Credential,
        [string]$Description,
        [Parameter(Mandatory=$true)][ValidateSet("CreateUser","UpdateUser","RemoveUser")][string]$Action
    )
    # No native cmdlet, so go straight to the API of the host.
    $MoRef = New-Object VMware.Vim.ManagedObjectReference
    $MoRef.Type = $VMHost.ExtensionData.ConfigManager.AccountManager.Type
    $MoRef.Value = $VMHost.ExtensionData.ConfigManager.AccountManager.Value
    $AccountSystem = Get-View -Id $MoRef
    
    # Set up API call for create/update
    $Spec = New-Object VMware.Vim.HostAccountSpec
    $Spec.Id = $Credential.GetNetworkCredential().UserName
    $Spec.Password = $Credential.GetNetworkCredential().Password
    if(!$Description) {
        # Generic description
        $Description = "Last Modified $(Get-Date)"
    }
    $Spec.Description = $Description

    # Choose API call
    try {
        Switch($Action) {
            "CreateUser" { 
                $AccountSystem.CreateUser($Spec)                
                break                    
            }
            "UpdateUser" { 
                $AccountSystem.UpdateUser($Spec)                
                break              
            }
            "RemoveUser" { 
                $AccountSystem.RemoveUser($Spec.Id)                
                break              
            }
        }
        Write-Information "Successfully performed [$Action] task on [$VMHost] Local Account [$($Spec.Id)]."
    } catch {
        Write-Information "Error during update of local user: $($Error[0].Exception)"
    }
}
function Get-VMHostAnswerFile {
<#
.SYNOPSIS
Generates the Answer File used in remediation tasks for the ESXi Host.
.DESCRIPTION
This will generate the Answer File for the given ESXi Host.
The output of this function would be passed to "Get-HostProfileConfigurationTasks" to generate the related tasks for the remediation.
.PARAMETER VMHost
The ESXi Host to get the Answer File from.
.EXAMPLE
$MyHost = Get-VMHost "MyVMHost.domain.local"
$MyAnswerFile = Get-VMHostAnswerFile -VMHost $MyHost

Generates the Answer File for the specified ESXi Host to be used with Remediation.
.OUTPUTS
The Answer File object for the ESXi Host
.NOTES
This function requires PowerCLI version 11.0+ to run properly.
.LINK
https://pubs.vmware.com/vsphere-6-5/topic/com.vmware.wssdk.smssdk.doc/vim.profile.host.ProfileManager.html#retrieveAnswerFile
#>
    param(
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Impl.V1.Inventory.VMHostImpl]$VMHost
    )

    # Connect to the Host Profile Manager
    $MoRef = New-Object VMware.Vim.ManagedObjectReference
    $MoRef.Type = "HostProfileManager"
    $MoRef.Value = "HostProfileManager"
    $HostProfileManager = Get-View -Id $MoRef

    # Get the content of the current customizations for the host.
    # The return type is a AnswerFile for a single host, if a batch remediation is needed:
    #   * New-Object VMware.Vim.StructuredCustomizations, assign entity => Moref, and customizations => the answer file object.
    $AnswerFile = $HostProfileManager.RetrieveAnswerFile($VMHost.ExtensionData.MoRef)
    return $AnswerFile
}

function Get-HostProfileConfigurationTasks {
<#
.SYNOPSIS
Generates a list Host Profile Remediation tasks.
.DESCRIPTION
This will generate the "Remediate" tasks needed for the given ESXi Host and specified Answer File.
The output of this function would be passed to "Remediate-Host" to execute the remediation.
.PARAMETER VMHost
The ESXi Host to get the task list from.
.PARAMETER AnswerFile
The Answer File (Host Customizations) for the specified Host. This contains items such as the IP Addresses of the VMKernel interfaces and their MAC Addresses.
.EXAMPLE
$MyHost = Get-VMHost "MyVMHost.domain.local"
$MyAnswerFile = Get-VMHostAnswerFile -VMHost $MyHost

$MyRemediationTasks = Get-HostProfileConfigurationTasks -VMHost $MyHost -AnswerFile $MyAnswerFile

Generates the remediation task list for the specified ESXi Host with the specified Answer File.
.OUTPUTS
The Remediation Task list
.NOTES
This function requires PowerCLI version 11.0+ to run properly.
.LINK
https://pubs.vmware.com/vsphere-6-5/topic/com.vmware.wssdk.smssdk.doc/vim.profile.host.ProfileManager.html#generateHostConfigTaskSpec
#>
    param(
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Impl.V1.Inventory.VMHostImpl]$VMHost,
        [Parameter(Mandatory=$true)][VMware.Vim.AnswerFile]$AnswerFile
    )

    # Connect to the Host Profile Manager
    $MoRef = New-Object VMware.Vim.ManagedObjectReference
    $MoRef.Type = "HostProfileManager"
    $MoRef.Value = "HostProfileManager"
    $HostProfileManager = Get-View -Id $MoRef

    # Create the array of StructuredCustomizations for the 'GenerateHostConfigTaskSpec_Task'
    $StructuredCustomizationsArray = @()
    $StructuredCustomization = New-Object VMware.Vim.StructuredCustomizations
    $StructuredCustomization.Customizations = $AnswerFile
    $StructuredCustomization.Entity = $VMHost.ExtensionData.MoRef
    $StructuredCustomizationsArray += $StructuredCustomization
    
    # Retrieve the configuration task data. This is equivalent to the 'Pre-Check Remediation'
    $TaskResult = $HostProfileManager.GenerateHostConfigTaskSpec($StructuredCustomizationsArray)
    return $TaskResult
}

function Remediate-Host {
<#
.SYNOPSIS
Performs a Host Profile Remediation task.
.DESCRIPTION
This will perform the "Remediate" task for the given inputs.
To get the tasks for this function, see the function "Get-HostProfileConfigurationTasks"
.PARAMETER HostTasks
The remediation tasks to execute. This can be a set of tasks for multiple hosts (in a cluster, for example).
.PARAMETER Reboot
If the remediation result requires a reboot, initiate the reboot. It is probably best to only do this
.EXAMPLE
$MyHost = Get-VMHost "MyVMHost.domain.local"
$MyAnswerFile = Get-VMHostAnswerFile -VMHost $MyHost
$MyRemediationTasks = Get-HostProfileConfigurationTasks -VMHost $MyHost -AnswerFile $MyAnswerFile

$Result = Remediate-Host -HostTasks $MyRemediationTasks -Reboot

Performs the remediation task on the specified ESXi Host with the specified Answer File.
If the Remediation requires a reboot, it will automatically perform it.
.OUTPUTS
The Remediation Results, including success or failures.
.NOTES
This function requires PowerCLI version 11.0+ to run properly.
.LINK
https://pubs.vmware.com/vsphere-6-5/topic/com.vmware.wssdk.smssdk.doc/vim.profile.host.ProfileManager.html#applyEntitiesConfiguration
#>
    param(
        [Parameter(Mandatory=$true)][VMware.Vim.ApplyHostProfileConfigurationSpec]$HostTasks,
        [switch]$Reboot
    )

    # Connect to the Host Profile Manager
    $MoRef = New-Object VMware.Vim.ManagedObjectReference
    $MoRef.Type = "HostProfileManager"
    $MoRef.Value = "HostProfileManager"
    $HostProfileManager = Get-View -Id $MoRef 

    # First, check to see if the task list will require a reboot. Ensure that the 'Reboot' flag has been set as a guard-rail.
    if($HostTasks.RebootStateless -eq $true) {
        # Requires a stateless reboot to take effect.
        if($Reboot) {
            Write-Information -MessageData "The task list provided requires a reboot, beginning remediation. Once done the host will be rebooted!" -InformationAction Continue
        } else {
            $HostName = ($HostTasks.Host | Get-VIObjectByVIView).Name
            Write-Information -MessageData "The Host [$HostName] requires a stateless reboot to continue. Please re-run the function with the -Reboot parameter set." -InformationAction Continue
            break
        }
    } else {
        # No reboot required, proceed.
        Write-Information -MessageData "The task list provided does not require a reboot, beginning remediation." -InformationAction Continue
        $Configurations = @()
        $Configurations += $HostTasks
        $RemediateTask = $HostProfileManager.ApplyEntitiesConfig_Task($Configurations)
        $RemediateResult = Wait-Task -Task (Get-Task -Id $RemediateTask)
        Write-Information -MessageData "The remediation task should now be completed." -InformationAction Continue
        return $RemediateResult
    }
}


function Set-VMHostName {
<#
.SYNOPSIS
Renames an ESX Host that is currently registered in the vCenter inventory from an IP address to DNS Name.
.DESCRIPTION
This command allows the ESXi host to be renamed without losing the Managed Object Reference, which would potentially break upstream integrations.
.PARAMETER VMHost
The ESXi Host to rename in the inventory.
.PARAMETER SetIP
(TESTING ONLY) Resets the host back to the IP Address of the Management VMKernel. This is used only for testing purposes.
.EXAMPLE
$MyHost = Get-VMHost -Name "172.16.21.1"

Set-VMHostName -VMHost $MyHost

Renames the specified host to the FQDN value specified in its Management Network configuration.
.OUTPUTS
The renamed VMHost object.
.NOTES
This function requires PowerCLI version 11.0+ to run properly.
.LINK
https://pubs.vmware.com/vsphere-6-5/topic/com.vmware.wssdk.smssdk.doc/vim.HostSystem.html#reconnect
#>
    param(
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Impl.V1.Inventory.VMHostImpl]$VMHost,
        [switch]$SetIP
    )
    # This function takes an existing host and disconnect/reconnects with the proper hostname.
    # Auto-Deploy hosts will join vCenter with their IP by default.
    # This assumes an empty root password.
    
    # Start by verifying the hostname values needed are set.
    $PreferredHostName = (Get-AdvancedSetting -Entity $VMHost -Name Misc.PreferredHostName).Value
    $HostName = (Get-VMHostNetwork -VMHost $VMHost).HostName
    $Domain = (Get-VMHostNetwork -VMHost $VMHost).DomainName
    $HostFQDN = "$HostName.$Domain"

    if($PreferredHostName -ne $HostFQDN) {
        Write-Information -MessageData "The VMHost $VMHost values for Misc.PreferredHostName ($PreferredHostName) and FQDN ($HostFQDN) are either not set or do not match. Please correct this and re-run the Set-VMHostName function."
        exit
    }

    # Assuming the name is set properly, proceed with the reconnect task.
    try {
        # Configure Custom API object for task to reconnect.
        $ConnectSpec = New-Object VMware.Vim.HostConnectSpec
        $ReconnectSpec = New-Object VMware.Vim.HostSystemReconnectSpec
        $ReconnectSpec.SyncState = $true
        if($SetIP) {
            $ConnectSpec.HostName = (Get-VMHostNetworkAdapter -VMHost $VMHost -VMKernel -Name "vmk0").IP
        } else {
            $ConnectSpec.HostName = $HostFQDN
        }
        # Set to maintenance and disconnect.
        Get-VMHost $VMHost | Set-VMHost -State Maintenance -Confirm:$false | out-null
        Write-Information -MessageData "[$VMHost] has been set into maintenance mode." -InformationAction Continue
        Get-VMHost $VMHost | Set-VMHost -State Disconnected -Confirm:$false | out-null
        Write-Information -MessageData "[$VMHost] has been disconnected." -InformationAction Continue
        # Perform API Call
        $ReconnectTask = $VMHost.ExtensionData.ReconnectHost_Task($ConnectSpec,$ReconnectSpec)
        Write-Information -MessageData "[$VMHost] is being reconnected with updated hostname [$($ConnectSpec.HostName)]." -InformationAction Continue
        $TaskResult = Wait-Task (Get-Task -Id $ReconnectTask)
        Write-Information -MessageData "[$VMHost] has successfully reconnected with updated hostname [$($ConnectSpec.HostName)]." -InformationAction Continue
    } catch {
        Write-Information -MessageData "Unhandled Error: $($Error[0].Exception)"
    }

    if($TaskResult) { return $TaskResult }
}


function Check-RunningTasks {
<#
.SYNOPSIS
Checks for any running tasks that may be running on the ESXi host, and waits for their completion.
.DESCRIPTION
This function is used primarily to catch other services/users making changes to an ESXi host not created by the current PowerCLI session.
.PARAMETER VMHost
The ESX Host to check for running tasks.
.EXAMPLE
$MyHost = Get-VMHost -Name "MyVMHost.domain.local"
Check-RunningTasks -VMHost $MyHost

Checks to see if there are any running tasks and waits for their completion.

.OUTPUTS
None
#>    
    param(
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Types.V1.Inventory.VMHost]$VMHost
    )
    $RunningTasks = Get-Task -Status "Running" | ?{$_.ExtensionData.Info.EntityName -eq $VMHost.Name}
    if($RunningTasks) {
        Wait-Task -Task $RunningTasks | Out-Null
    }
}


function Rescan-VMHostSpecificHba {
<#
.SYNOPSIS
Rescans only the specified HBA on a particular ESX host.
.DESCRIPTION
This function is for rescanning a particular HBA, as the default functionality only allows Rescan All, which adds quite a lot of time.
.PARAMETER VMHost
The ESX Host to rescan.
.PARAMETER DeviceName
The name of the device, such as 'vmhba37', to rescan on the host.
.EXAMPLE
$MyHost = Get-VMHost -Name "MyVMHost.domain.local"
$MyDevice = "vmhba44"

Rescan-VMHostSpecificHba -VMHost $MyHost -DeviceName $MyDevice

Performs a rescan operation on the specified ESXi host and Device.
This task is synchronous, so when the function completes you can begin querying for LUNs or other changes.

.OUTPUTS
None
.NOTES
This function requires PowerCLI version 11.0+ to run properly.
.LINK
https://pubs.vmware.com/vsphere-6-5/topic/com.vmware.wssdk.smssdk.doc/vim.host.StorageSystem.html#rescanHba
#>
    param(
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Impl.V1.Inventory.VMHostImpl]$VMHost,
        [Parameter(Mandatory=$true)][string]$DeviceName
    )

    # If device isn't specified, just get the iSCSI HBA.
    if(!$DeviceName) {
        $DeviceName = (Get-VMHostHba -VMHost $VMHost -Type IScsi).Device
    }

    # Go to the StorageSystem API on the host.
    $MoRef = New-Object VMware.Vim.ManagedObjectReference
    $MoRef.Type = $VMHost.ExtensionData.ConfigManager.StorageSystem.Type
    $MoRef.Value = $VMHost.ExtensionData.ConfigManager.StorageSystem.Value
    $StorageSystem = Get-View -Id $MoRef

    # Call the RescanHba method.
    $StorageSystem.RescanHba($DeviceName)
}

# Updates Host Profile to remove the System Resource Pool Configuration section. This is an annoyance.
function Update-HostProfileRemoveSystemResourcePoolConfiguration {
    param(
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Types.V1.Host.Profile.VMHostProfile]$HostProfile
    )
    # Create Spec based on the Profile and populate changes.
    $HostProfileSpec = New-Object -TypeName VMware.Vim.HostProfileCompleteConfigSpec
    $HostProfileSpec.ApplyProfile = $HostProfile.ExtensionData.Config.ApplyProfile

    $HostProfileSpec.ApplyProfile.Property | Where PropertyName -match "RPConfigProfile" | select -ExpandProperty Profile | %{$_.Enabled = $False}
    
    # Execute the reconfiguration of the host profile
    $HostProfile.ExtensionData.UpdateHostProfile($HostProfileSpec)
    Write-Information "The Host Profile [$HostProfile] has been updated to remove the System Resource Pool Configuration entries." -InformationAction Continue
}


# Updates Host Profile to remove the System Resource Pool Configuration section. This is an annoyance.
function Update-HostProfileRemoveSFCBConfiguration {
    param(
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Types.V1.Host.Profile.VMHostProfile]$HostProfile
    )
    # Create Spec based on the Profile and populate changes.
    $HostProfileSpec = New-Object -TypeName VMware.Vim.HostProfileCompleteConfigSpec
    $HostProfileSpec.ApplyProfile = $HostProfile.ExtensionData.Config.ApplyProfile

    ($HostProfileSpec.ApplyProfile.Property | Where PropertyName -match "SfcbConfigProfile" | select -ExpandProperty Profile).Enabled = $False
    
    # Execute the reconfiguration of the host profile
    $HostProfile.ExtensionData.UpdateHostProfile($HostProfileSpec)
    Write-Information "The Host Profile [$HostProfile] has been updated to remove the SFCB entries." -InformationAction Continue
}

# Updates Host Profile to specify the IPv4 DNS Servers and remove any additional values.
function Update-HostProfileDNSConfiguration {
    param(
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Types.V1.Host.Profile.VMHostProfile]$HostProfile
    )
    # Create Spec based on the Profile and populate changes.
    $HostProfileSpec = New-Object -TypeName VMware.Vim.HostProfileCompleteConfigSpec
    $HostProfileSpec.ApplyProfile = $HostProfile.ExtensionData.Config.ApplyProfile
    
    # Reconfigure the DNS Policy to remove any addresses or domains, and simply specify DHCP for DNS.
    $DNSConfig = New-Object VMware.Vim.PolicyOption
    $DNSConfig.Id = "FixedDnsConfig"
    $DNSConfig.Parameter += New-Object VMware.Vim.KeyAnyValue
    $DNSConfig.Parameter[0].Key = "dhcp"
    $DNSConfig.Parameter[0].Value = $True
    $DNSConfig.Parameter += New-Object VMware.Vim.KeyAnyValue
    $DNSConfig.Parameter[1].Key = "domainName"
    $DNSConfig.Parameter[1].Value = ""

    ($HostProfileSpec.ApplyProfile.Network.Property | Where PropertyName -match "GenericNetStackInstanceProfile" | Select-Object -ExpandProperty Profile | Where Key -Match "defaultTcpipStack" | Select-Object -ExpandProperty Property | Where PropertyName -match "GenericDnsConfigProfile" | Select-Object -ExpandProperty Profile | Select-Object -ExpandProperty Policy | Where Id -Match "DnsConfigPolicy").PolicyOption = $DNSConfig
        
    # Execute the reconfiguration of the host profile
    $HostProfile.ExtensionData.UpdateHostProfile($HostProfileSpec)
    Write-Information "The Host Profile [$HostProfile] has been updated to specify DHCP for DNS Policy." -InformationAction Continue
}

# Host Profile management
function Update-HostProfileISCSIChapSettings {
    param(
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Types.V1.Host.Profile.VMHostProfile]$HostProfile,
        [Parameter(Mandatory=$true)][System.Management.Automation.PSCredential]$ISCSIChapCredential
    )
    # Create Spec based on the Profile and populate changes.
    $HostProfileSpec = New-Object -TypeName VMware.Vim.HostProfileCompleteConfigSpec
    $HostProfileSpec.ApplyProfile = $HostProfile.ExtensionData.Config.ApplyProfile
    
    # Add the iSCSI CHAP Credential to the profile.
    
    # Enable Unidirectional CHAP
    $CHAPEnabled = New-Object VMware.Vim.PolicyOption
    $CHAPEnabled.Id = "iscsi.iscsiPolicies.UseChap"
    ($HostProfileSpec.ApplyProfile.Storage.Property | Where PropertyName -match "IscsiInitiatorProfile" | select -ExpandProperty Profile | select -ExpandProperty Property | Where PropertyName -match "SoftwareIscsiInitiatorProfile" | select -ExpandProperty Profile | select -ExpandProperty Property | Where PropertyName -match SoftwareIscsiInitiatorConfigProfile | select -ExpandProperty Profile | select -ExpandProperty Policy | Where Id -match "InitiatorChapTypeSelectionPolicy").PolicyOption = $CHAPEnabled

    # Username field for CHAP
    $ISCSIUser = New-Object VMware.Vim.PolicyOption
    $ISCSIUser.Id = "iscsi.iscsiPolicies.UseFixedChapName"
    $ISCSIUser.Parameter += New-Object VMware.Vim.KeyAnyValue
    $ISCSIUser.Parameter[0].Key = "chapName"
    $ISCSIUser.Parameter[0].Value = $ISCSIChapCredential.GetNetworkCredential().UserName
    ($HostProfileSpec.ApplyProfile.Storage.Property | Where PropertyName -match "IscsiInitiatorProfile" | select -ExpandProperty Profile | select -ExpandProperty Property | Where PropertyName -match "SoftwareIscsiInitiatorProfile" | select -ExpandProperty Profile | select -ExpandProperty Property | Where PropertyName -match SoftwareIscsiInitiatorConfigProfile | select -ExpandProperty Profile | select -ExpandProperty Policy | Where Id -match "InitiatorChapNameSelectionPolicy").PolicyOption = $ISCSIUser

    # Password field for CHAP
    $ISCSIPass = New-Object VMware.Vim.PolicyOption
    $ISCSIPass.Id = "iscsi.iscsiPolicies.UseFixedChapSecret"
    $ISCSIPass.Parameter += New-Object VMware.Vim.KeyAnyValue
    $ISCSIPass.Parameter[0].Key = "chapSecret"
    $ISCSIPass.Parameter[0].Value = New-Object VMware.Vim.PasswordField
    $ISCSIPass.Parameter[0].Value.Value = $ISCSIChapCredential.GetNetworkCredential().Password
    ($HostProfileSpec.ApplyProfile.Storage.Property | Where PropertyName -match "IscsiInitiatorProfile" | select -ExpandProperty Profile | select -ExpandProperty Property | Where PropertyName -match "SoftwareIscsiInitiatorProfile" | select -ExpandProperty Profile | select -ExpandProperty Property | Where PropertyName -match SoftwareIscsiInitiatorConfigProfile | select -ExpandProperty Profile | select -ExpandProperty Policy | Where Id -match "InitiatorChapSecretSelectionPolicy").PolicyOption = $ISCSIPass
    
    # Execute the reconfiguration of the host profile
    $HostProfile.ExtensionData.UpdateHostProfile($HostProfileSpec)
    Write-Information "The Host Profile [$HostProfile] has been updated to use the updated CHAP Information." -InformationAction Continue
}

# Updates Host Profile to remove the specified firewall rulesets from monitoring.
function Update-HostProfileRemoveFirewallRulesets {
    param(
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Types.V1.Host.Profile.VMHostProfile]$HostProfile,
        [Parameter(Mandatory=$true)][string[]]$Rulesets
    )
    # Create Spec based on the Profile and populate changes.
    $HostProfileSpec = New-Object -TypeName VMware.Vim.HostProfileCompleteConfigSpec
    $HostProfileSpec.ApplyProfile = $HostProfile.ExtensionData.Config.ApplyProfile

    # Construct a dynamic Regular Expression to filter out the items specified in a single go.
    [regex]$ExceptionRegex = '(?:' + ($Rulesets -join '|') + ')'
    $UpdatedRuleset = $HostProfileSpec.ApplyProfile.Firewall.Ruleset | ?{$_.Key -notmatch $ExceptionRegex}
    $HostProfileSpec.ApplyProfile.Firewall.Ruleset = $UpdatedRuleset

    # Execute the reconfiguration of the host profile
    $HostProfile.ExtensionData.UpdateHostProfile($HostProfileSpec)
    Write-Information "The Host Profile [$HostProfile] has been updated to remove the following firewall rulesets if present: $Rulesets" -InformationAction Continue
}

# Updates Host Profile to remove the CIM Indications section.
function Update-HostProfileRemoveCIMIndications {
    param(
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Types.V1.Host.Profile.VMHostProfile]$HostProfile
    )
    # Create Spec based on the Profile and populate changes.
    $HostProfileSpec = New-Object -TypeName VMware.Vim.HostProfileCompleteConfigSpec
    $HostProfileSpec.ApplyProfile = $HostProfile.ExtensionData.Config.ApplyProfile

    ($HostProfileSpec.ApplyProfile.Property | Where PropertyName -eq cimIndications_cimIndicationsProfile_CimIndications | select -ExpandProperty profile | select -ExpandProperty property | select -ExpandProperty profile).Enabled = $false

    # Execute the reconfiguration of the host profile
    $HostProfile.ExtensionData.UpdateHostProfile($HostProfileSpec)
    Write-Information "The Host Profile [$HostProfile] has been updated to remove the CIM Indications subsection." -InformationAction Continue
}

# Updates Host Profile to remove the PSA Storage Configuration.
function Update-HostProfileRemovePSAConfiguration {
    param(
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Types.V1.Host.Profile.VMHostProfile]$HostProfile
    )
    # Create Spec based on the Profile and populate changes.
    $HostProfileSpec = New-Object -TypeName VMware.Vim.HostProfileCompleteConfigSpec
    $HostProfileSpec.ApplyProfile = $HostProfile.ExtensionData.Config.ApplyProfile

    $HostProfileSpec.ApplyProfile.Storage.Property | Where PropertyName -match "PluggableStorageArchitectureProfile" | select -ExpandProperty Profile | select -ExpandProperty Property | Where PropertyName -match "PsaDeviceSharingProfile" | select -ExpandProperty Profile | %{$_.Enabled = $false}
    $HostProfileSpec.ApplyProfile.Storage.Property | Where PropertyName -match "PluggableStorageArchitectureProfile" | select -ExpandProperty Profile | select -ExpandProperty Property | Where PropertyName -match "PsaDeviceSettingProfile" | select -ExpandProperty Profile | %{$_.Enabled = $false}
    $HostProfileSpec.ApplyProfile.Storage.Property | Where PropertyName -match "PluggableStorageArchitectureProfile" | select -ExpandProperty Profile | select -ExpandProperty Property | Where PropertyName -match "PsaDeviceConfigurationProfile" | select -ExpandProperty Profile | %{$_.Enabled = $false}
    
    # Execute the reconfiguration of the host profile
    $HostProfile.ExtensionData.UpdateHostProfile($HostProfileSpec)
    Write-Information "The Host Profile [$HostProfile] has been updated to remove the PSA Configurations." -InformationAction Continue
}

# Updates Host Profile to remove the NMP Storage Configuration.
function Update-HostProfileRemoveNMPConfiguration {
    param(
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Types.V1.Host.Profile.VMHostProfile]$HostProfile
    )
    # Create Spec based on the Profile and populate changes.
    $HostProfileSpec = New-Object -TypeName VMware.Vim.HostProfileCompleteConfigSpec
    $HostProfileSpec.ApplyProfile = $HostProfile.ExtensionData.Config.ApplyProfile

    # Get the NMP (Native Multi-Pathing) object and disable the Device SATP Configuration
    ($HostProfileSpec.ApplyProfile.Storage.Property | Where PropertyName -match "NativeMultiPathingProfile" | select -ExpandProperty Profile | select -ExpandProperty Property | Where PropertyName -Match "NmpDeviceProfile" | select -ExpandProperty Profile | select -ExpandProperty Property | Where PropertyName -match "NmpDeviceConfigurationProfile").Profile | %{$_.Enabled = $false}
    
    # SATPDeviceProfile may not exist.
    $SatpDeviceProfiles = ($HostProfileSpec.ApplyProfile.Storage.Property | Where PropertyName -match "NativeMultiPathingProfile" | select -ExpandProperty Profile | select -ExpandProperty Property | Where PropertyName -Match "NmpDeviceProfile" | select -ExpandProperty Profile | select -ExpandProperty Property | Where PropertyName -match "SatpDeviceProfile")
    if($SatpDeviceProfiles.Profile) {
        $SatpDeviceProfiles.Profile | %{$_.Enabled = $false}
    }
    
    # Execute the reconfiguration of the host profile
    $HostProfile.ExtensionData.UpdateHostProfile($HostProfileSpec)
    Write-Information "The Host Profile [$HostProfile] has been updated to remove the NMP Configurations." -InformationAction Continue
}

# Updates Host Profile to remove the IPv6 VMKernel Configurations.
function Update-HostProfileRemoveVMKernelIPv6Configuration {
    param(
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Types.V1.Host.Profile.VMHostProfile]$HostProfile
    )
    # Create Spec based on the Profile and populate changes.
    $HostProfileSpec = New-Object -TypeName VMware.Vim.HostProfileCompleteConfigSpec
    $HostProfileSpec.ApplyProfile = $HostProfile.ExtensionData.Config.ApplyProfile

    foreach($HostNic in $HostProfileSpec.ApplyProfile.Network.DvsHostNic) {
        # Reset all values to 'NoOption' related to IPV6 in policies.
        foreach($Policy in $HostNic.IpConfig.Policy) {
            if($Policy.Id -match "StatelessAutoconfPolicy" -or $Policy.Id -match "FixedDhcp6Policy" -or $Policy.Id -match "Ip6AddressPolicy") {
                # Create the 'NoOption' object.
                $NoOption = New-Object VMware.Vim.PolicyOption
                $NoOption.Id = "NoDefaultOption"

                # Assign to the policy option.
                $Policy.PolicyOption = $NoOption
            }
        }
    }    
    # Execute the reconfiguration of the host profile
    $HostProfile.ExtensionData.UpdateHostProfile($HostProfileSpec)
    Write-Information "The Host Profile [$HostProfile] has been updated to remove the VMKernel IPv6 Configurations." -InformationAction Continue
}



function Update-HostProfileSettings {
<#
.SYNOPSIS
Updates a particular Host Profile by removing and standardizing various settings.
.DESCRIPTION
This function is used to disable common items inside of a Host Profile, such as the NMP, PSA, and SATP settings.
.PARAMETER HostProfile
The Host Profile to modify.
.EXAMPLE
$MyProfile = Get-VMHostProfile -Name "MyHostProfile"

Updates the Host Profile and removes extraneous configuration such as the NMP, PSA, and SATP settings.

.OUTPUTS
None
.NOTES
This function requires PowerCLI version 11.0+ to run properly.

This function is a wrapper of several others, including:
    Update-HostProfileRemoveVMKernelIPv6Configuration
    Update-HostProfileRemoveCIMIndications
    Update-HostProfileRemovePSAConfiguration
    Update-HostProfileRemoveNMPConfiguration
    Update-HostProfileRemoveESXUpdateFirewallRuleset
#>
    param(
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Types.V1.Host.Profile.VMHostProfile]$HostProfile
    )
    # Remove IPv6 information from VMKernel entries.
    Update-HostProfileRemoveVMKernelIPv6Configuration -HostProfile $HostProfile    
    
    # Remove CIM Indications
    Update-HostProfileRemoveCIMIndications -HostProfile $HostProfile

    # Remove PSA, SATP, and NMP Configurations
    Update-HostProfileRemovePSAConfiguration -HostProfile $HostProfile
    Update-HostProfileRemoveNMPConfiguration -HostProfile $HostProfile

    # Remove various firewall settings. If others are desired add them to the list below.
    $RulesToRemove = "esxupdate","bfdDP","netCP","Replication-to-CloudTraffic","vSFW-UW"
    Update-HostProfileRemoveFirewallRulesets -HostProfile $HostProfile -Rulesets $RulesToRemove
    
    # Remove SFCB Configuration complaints.
    Update-HostProfileRemoveSFCBConfiguration -HostProfile $HostProfile

    # Configure DNS on Management interface.
    Update-HostProfileDNSConfiguration -HostProfile $HostProfile
    
    # Remove System Resource Pool configuration data.
    Update-HostProfileRemoveSystemResourcePoolConfiguration -HostProfile $HostProfile
}


function Get-VDPortgroupByTag {
<#
.SYNOPSIS
Gets a list of Distributed Virtual Portgroups by vSphere Tag assignment.
.DESCRIPTION
Gets a list of Distributed Virtual Portgroups by vSphere Tag assignment.
If none exist or multiple are found, the script requests it to be explicitly chosen.
.PARAMETER VDSwitch
The Distributed Switch to query.
.PARAMETER Tag
The name of the tag to query against.
.PARAMETER Remediate
If this is set, the tag specified will be applied to the specified portgroup when the user is prompted.
.EXAMPLE
$MyVDS = Get-VDSwitch "MyDistributedSwitch"
$MyTag = "ManagementNetworkTag"
$Portgroup = Get-VDPortgroupByTag -VDSwitch $MyVDS -Tag $MyTag

Searches the Distributed Switch "MyDistributedSwitch" for portgroups with the tag "ManagementNetworkTag" assigned to it.
.EXAMPLE
$MyVDS = Get-VDSwitch "AnotherDistributedSwitch"
$MyTag = "ReplicationNetworkTag"
$Portgroup = Get-VDPortgroupByTag -VDSwitch $MyVDS -Tag $MyTag -Remediate

Searches the Distributed Switch "AnotherDistributedSwitch" for portgroups with the tag "ReplicationNetworkTag" assigned to it.
If none are found, and the user selects one at runtime, the tag will be assigned.
.OUTPUTS
One Distributed Virtual PortGroup object.
.NOTES
This function requires PowerCLI version 11.0+ to run properly.
#>
    param(
        [Parameter(Mandatory=$true)][VMware.VimAutomation.Vds.Types.V1.VmwareVDSwitch]$VDSwitch,
        [Parameter(Mandatory=$true)][string]$Tag,
        [switch]$Remediate
    )
    $PortGroup = $VDSwitch | Get-VDPortgroup -Tag $Tag
    if($PortGroup.Count -gt 1) {
        $PortGroup = $VDSwitch | Get-VDPortgroup -Tag $Tag | Out-GridView -Title "Multiple Distributed Portgroups match tag [$Tag] - Choose the correct one." -OutputMode Single
    }
    if($PortGroup -and $PortGroup.VlanConfiguration.VlanType -eq "Vlan") {
        $Message = "Found distributed portgroup [$PortGroup] matching tag [$Tag] on Distributed Switch [$VDSwitch]."
        Write-Information -MessageData $Message -InformationAction Continue
        $Output = $PortGroup
    } else {
        # If specified, and you have the rights to do so, you can select the list of (non-uplink) portgroups and assign the tag.
        $SelectedPortgroup = Get-VDPortgroup -VDSwitch $VDSwitch | ?{!$_.ExtensionData.Tag} | Sort-Object Name | Out-GridView -Title "No Distributed Portgroup tagged as [$Tag] found - choose the Portgroup to use." -OutputMode Single
        if($SelectedPortgroup) {
            if($Remediate) {
                # Attempt to tag the portgroup.
                $TagObject = Get-TagCategory "AutoDeploy" | Get-Tag $Tag
                Get-VDPortgroup $SelectedPortgroup | New-TagAssignment -Tag $TagObject | Out-Null
                $Message = "There was no portgroup matching tag [$Tag] initially, so the portgroup [$SelectedPortgroup] was chosen and tagged for future use."
                Write-Information -MessageData $Message -InformationAction Continue
            } else {
                $Message = "There was no portgroup matching tag [$Tag] initially, so the portgroup [$SelectedPortgroup] was chosen.`nTo avoid this, tag the portgroup with value [$Tag]!"
                Write-Information -MessageData $Message -InformationAction Continue
            }
            $Output = $SelectedPortgroup
        } else {    
            $Message = "Unable to find a matching distributed portgroup tagged with the [$Tag] value, or the user input was cancelled.`nMake sure the Distributed Switch [$VDSwitch] specified has a portgroup tagged appropriately and retry the function."
            Write-Information -MessageData $Message -InformationAction Continue
            break
        }
    }

    if($Output) {
        return $Output 
    }
}


function Manage-AdapterToPortBinding {
<#
.SYNOPSIS
Manage-AdapterToPortBinding is a function that uses the vSphere API to bind/unbind VMKernel NICs to the Software iSCSI Initiator.
.DESCRIPTION
Manage-AdapterToPortBinding is a function that uses the vSphere API to bind/unbind VMKernel NICs to the Software iSCSI Initiator.
.PARAMETER VMHost
The ESX Host to modify the iSCSI Port Binding on.
.PARAMETER Adapter
The VMKernel Adapter to bind to the iSCSI Initiator.
.PARAMETER Action
The choice of Binding or Unbinding the specified kernel adapter. Must be either "Bind" or "Unbind".
.PARAMETER HBA
The iSCSI HBA device to bind to. If not specified the first one is queried on the host.
.EXAMPLE
$MyHost = Get-VMHost "MyHost.domain.local"
$MyAdapter = Get-VMHost $MyHost | Get-VMHostNetworkAdapter -VMKernel -Name "vmk3"
Manage-AdapterToPortBinding -VMHost $MyHost -Adapter $MyAdapter -Action Bind

Binds the "vmk3" VMKernel host adapter to the host $MyHost iSCSI Adapter.
.EXAMPLE
$MyHost = Get-VMHost "MyHost.domain.local"
$MyAdapter = Get-VMHost $MyHost | Get-VMHostNetworkAdapter -VMKernel -Name "vmk4"
Manage-AdapterToPortBinding -VMHost $MyHost -Adapter $MyAdapter -Action Unbind

Removes the "vmk4" VMKernel host adapter from the host $MyHost iSCSI Adapter.
.OUTPUTS
None
.NOTES
This function requires PowerCLI version 11.0+ to run properly.

.LINK
https://pubs.vmware.com/vsphere-50/index.jsp?topic=/com.vmware.wssdk.apiref.doc_50/vim.host.IscsiManager.html
.LINK
https://pubs.vmware.com/vsphere-50/index.jsp?topic=/com.vmware.wssdk.apiref.doc_50/vim.host.IscsiManager.html#bindVnic
.LINK
https://pubs.vmware.com/vsphere-50/index.jsp?topic=/com.vmware.wssdk.apiref.doc_50/vim.host.IscsiManager.html#unbindVnic
#>
    param(
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Types.V1.Inventory.VMHost]$VMHost,
        [VMware.VimAutomation.ViCore.Types.V1.Host.Storage.IScsiHba]$HBA,
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Types.V1.Host.Networking.Nic.HostVMKernelVirtualNic]$Adapter,
        [Parameter(Mandatory=$true)][ValidateSet("Bind","Unbind")][string]$Action
    )

    # Get the default iSCSI initiator if not specified.
    if(!$HBA) {
        $HBA = Get-VMHostHba -VMHost $VMHost -Type IScsi | select -First 1
    }

    # Call the vSphere API directly
    $MoRef = New-Object VMware.Vim.ManagedObjectReference
    $MoRef.Type = "IscsiManager"
    $MoRef.Value = $VMHost.ExtensionData.ConfigManager.IscsiManager.Value
    $IscsiManager = Get-View -Id $MoRef
    if($Action -eq "Bind") {
        $IscsiManager.BindVnic($HBA.Device,$Adapter.Name)
        Write-Information -MessageData "Added the [$Adapter] to the port binding for HBA [$HBA] on Host [$VMHost]." -InformationAction Continue
    }
    if($Action -eq "Unbind") {
        $IscsiManager.UnbindVnic($HBA.Device,$Adapter.Name,$true)
        Write-Information -MessageData "Removed the [$Adapter] from the port binding for HBA [$HBA] on Host [$VMHost]." -InformationAction Continue
    }
}

function Configure-ISCSIAuthentication {
<#
.SYNOPSIS
Configures the ESXi Host ISCSI CHAP based credentials.
.DESCRIPTION
Used to configure ISCSI CHAP on the ESXi host using the vCenter API.
.PARAMETER VMHost
The ESX Host to modify the iSCSI CHAP Credentials on.
.PARAMETER HBA
The ISCSI HBA to add credentials to.
.PARAMETER Credential
The Username and Password to assign to the HBA.
.EXAMPLE
$MyHost = Get-VMHost "MyHost.domain.local"
$MyHBA = Get-VMHost $MyHost | Get-VMHostHba -Type ISCSI
$MyCredential = Get-Credential
Configure-ISCSIAuthentication -VMHost $MyHost -HBA $MyHBA -Credential $MyCredential

Configures the default Software ISCSI Initiator on "MyHost.domain.local" to the specified credentials.
.OUTPUTS
None
.NOTES
This function requires PowerCLI version 11.0+ to run properly.
#>
    param(
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Types.V1.Inventory.VMHost]$VMHost,
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Types.V1.Host.Storage.IScsiHba]$HBA,
        [Parameter(Mandatory=$true)][System.Management.Automation.PSCredential]$Credential
    )
    # No native cmdlet, so go straight to the API of the host.
    $MoRef = New-Object VMware.Vim.ManagedObjectReference
    $MoRef.Type = $VMHost.ExtensionData.ConfigManager.StorageSystem.Type
    $MoRef.Value = $VMHost.ExtensionData.ConfigManager.StorageSystem.Value
    $StorageSystem = Get-View -Id $MoRef
    
    # Create the authentication object
    $Auth = New-Object VMware.Vim.HostInternetScsiHbaAuthenticationProperties
    $Auth.ChapAuthEnabled = $true
    $Auth.ChapAuthenticationType = "chapRequired"
    $Auth.ChapName = $Credential.GetNetworkCredential().UserName
    $Auth.ChapSecret = $Credential.GetNetworkCredential().Password

    # Update the authentication
    $StorageSystem.UpdateInternetScsiAuthenticationProperties($HBA.Device,$Auth,$null)

    Write-Information -MessageData "Configured the iSCSI authentication to the requested credentials on Host [$VMHost]." -InformationAction Continue
}


function Remove-ISCSIAuthentication {
<#
.SYNOPSIS
Removes all ISCSI CHAP based credentials from the specified adapter.
.DESCRIPTION
Used to reset ISCSI CHAP on the ESXi host using the vCenter API during teardown.
.PARAMETER VMHost
The ESX Host to reset the iSCSI CHAP Credentials on.
.PARAMETER HBA
The ISCSI HBA to remove credentials from.
.EXAMPLE
$MyHost = Get-VMHost "MyHost.domain.local"
$MyHBA = Get-VMHost $MyHost | Get-VMHostHba -Type ISCSI

Remove-ISCSIAuthentication -VMHost $MyHost -HBA $MyHBA

Resets the default Software ISCSI Initiator on "MyHost.domain.local" to the use no CHAP credentials.
.OUTPUTS
None
.NOTES
This function requires PowerCLI version 11.0+ to run properly.
.LINK
https://pubs.vmware.com/vsphere-6-5/index.jsp?topic=/com.vmware.wssdk.apiref.doc/vim.host.InternetScsiHba.AuthenticationProperties.html
#>
    param(
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Types.V1.Inventory.VMHost]$VMHost,
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Types.V1.Host.Storage.IScsiHba]$HBA
    )
    # No native cmdlet, so go straight to the API of the host.
    $MoRef = New-Object VMware.Vim.ManagedObjectReference
    $MoRef.Type = $VMHost.ExtensionData.ConfigManager.StorageSystem.Type
    $MoRef.Value = $VMHost.ExtensionData.ConfigManager.StorageSystem.Value
    $StorageSystem = Get-View -Id $MoRef
    
    # Create the authentication object
    $Auth = New-Object VMware.Vim.HostInternetScsiHbaAuthenticationProperties
    $Auth.ChapAuthEnabled = $false
    $Auth.ChapAuthenticationType = "chapProhibited"
    $Auth.ChapName = ""
    $Auth.ChapSecret = ""
    $Auth.MutualChapAuthenticationType = "chapProhibited"
    $Auth.MutualChapName = ""
    $Auth.MutualChapSecret = ""

    # Update the authentication
    $StorageSystem.UpdateInternetScsiAuthenticationProperties($HBA.Device,$Auth,$null)

    Write-Information -MessageData "Removed the iSCSI authentication configuration on Host [$VMHost]." -InformationAction Continue
}

# Helper function to remove the ESXi host from all related constructs.
# This will delete AutoDeploy rules, Host Profiles, and datastores! Do not use unless you are debugging a new install.
function Reset-HostToDefault {
    param(
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Types.V1.Inventory.VMHost]$VMHost,
        [switch]$Teardown
    )
    if($Teardown) {
        # Remove all changes in associations, remove the host profile, etc.
        # Reboot the host to reset the defaults in AutoDeploy.
        Write-Information -MessageData "Teardown or reset of [$VMHost] requested. This will remove it from all the things." -InformationAction Continue
        $HostProfile = Get-VMHostProfile -Entity $VMHost
        $VDS = Get-VDSwitch -VMHost $VMHost
        $Rule = Get-DeployRule | ?{$_.PatternList -match $VMHost.ExtensionData.Config.Network.DnsConfig.HostName}
        
        if($Rule) {
            try {
                Get-DeployRule | ?{$_.PatternList -match $VMHost.ExtensionData.Config.Network.DnsConfig.HostName} | Remove-DeployRule -Delete | Out-Null
                Write-Information -MessageData "Removed $($Rule.Count) Auto Deploy Rules from vCenter matching Hostname [$($VMHost.Name)]." -InformationAction Continue
            } catch {
                Write-Information -MessageData "Error Removing $($Rule.Count) Auto Deploy Rules from vCenter: `n`t$($Error[0].Exception)" -InformationAction Continue
            }
        }
        if($HostProfile) {
            #Get-VMHost $VMHost | Set-VMHost -Profile $null -Confirm:$false | Out-Null
            #Check-RunningTasks -VMHost $VMHost
            #Write-Information -MessageData "Disassociated Host [$VMHost] from any Host Profiles." -InformationAction Continue
            Get-VMHostProfile $HostProfile | Remove-VMHostProfile -Confirm:$False
            Check-RunningTasks -VMHost $VMHost
            Write-Information -MessageData "Removed Host Profile [$HostProfile] from the system." -InformationAction Continue
        }

        # Teardown any datastores attached to the host.
        Build-VMHostStorage -VMHost $VMHost -HBA $HBA -Teardown
        Check-RunningTasks -VMHost $VMHost

        # Remove from VDS
        if($VDS) {
            # Move uplinks and VMKernels
            $ManagementHostNIC = Get-VMHostNetworkAdapter -VMHost $VMHost -VMKernel -Name vmk0
            $VMOHostNIC = Get-VMHostNetworkAdapter -VMHost $VMHost -VMKernel -Name vmk1
            $ReplHostNIC = Get-VMHostNetworkAdapter -VMHost $VMHost -VMKernel -Name vmk2
            $ISCSIAHostNIC = Get-VMHostNetworkAdapter -VMHost $VMHost -VMKernel -Name vmk3
            $ISCSIBHostNIC = Get-VMHostNetworkAdapter -VMHost $VMHost -VMKernel -Name vmk4

            $MGMTPnic = Get-VMHostNetworkAdapter -VMHost $VMHost -Physical -Name vmnic0
            $ComputeHostNICs = Get-VMHostNetworkAdapter -VMHost $VMHost -Physical -Name vmnic1
            $ISCSIHostNICs = Get-VMHostNetworkAdapter -VMHost $VMHost -Physical -Name vmnic2,vmnic3
            
            # Check for standard switches to move the adapters to.
            $vs0 = Get-VirtualSwitch -VMHost $VMHost -Standard -Name "vSwitch0" -ErrorAction SilentlyContinue
            if(!$vs0) {
                $vs0 = New-VirtualSwitch -VMHost $VMHost -Name "vSwitch0"
                Write-Information "Recreated vSwitch0 on [$VMHost] for vmkernel migrations." -InformationAction Continue
            }
            $vs1 = Get-VirtualSwitch -VMHost $VMHost -Standard -Name "vSwitch1" -ErrorAction SilentlyContinue
            if(!$vs1) {
                $vs1 = New-VirtualSwitch -VMHost $VMHost -Name "vSwitch1"
                Write-Information "Recreated vSwitch1 on [$VMHost] for vmkernel migrations." -InformationAction Continue
            }
            Write-Information -MessageData "Beginning VMKernel migrations on [$VMHost] to Standard Virtual Switches." -InformationAction Continue
            # Recreate the portgroups on Standard Switch. It is usually gone after migration to VDS.
            try {
                $MGMT = Get-VirtualPortGroup -Name "Management Network" -VMHost $VMHost -VirtualSwitch $vs0 -Standard -ErrorAction Stop
            } catch {
                $MGMT = New-VirtualPortGroup -Name "Management Network" -VirtualSwitch $vs0 -VLanId (Get-VDPortgroup -VMHostNetworkAdapter $ManagementHostNIC).VlanConfiguration.VlanId
            }
            try {
                $VMO = Get-VirtualPortGroup -Name "vMotion" -VMHost $VMHost -VirtualSwitch $vs0 -Standard -ErrorAction Stop
            } catch {
                $VMO = New-VirtualPortGroup -Name "vMotion" -VirtualSwitch $vs0 -VLanId (Get-VDPortgroup -VMHostNetworkAdapter $VMOHostNIC).VlanConfiguration.VlanId
            }
            try {
                $REPL = Get-VirtualPortGroup -Name "Replication" -VMHost $VMHost -VirtualSwitch $vs0 -Standard -ErrorAction Stop
            } catch {
                $REPL = New-VirtualPortGroup -Name "Replication" -VirtualSwitch $vs0 -VLanId (Get-VDPortgroup -VMHostNetworkAdapter $ReplHostNIC).VlanConfiguration.VlanId
            }
            try {
                $ISCSIA = Get-VirtualPortGroup -Name "ISCSI_A" -VMHost $VMHost -VirtualSwitch $vs1 -Standard -ErrorAction Stop
            } catch {
                $ISCSIA = New-VirtualPortGroup -Name "ISCSI_A" -VirtualSwitch $vs1 -VLanId (Get-VDPortgroup -VMHostNetworkAdapter $ISCSIAHostNIC).VlanConfiguration.VlanId
            }
            try {
                $ISCSIB = Get-VirtualPortGroup -Name "ISCSI_B" -VMHost $VMHost -VirtualSwitch $vs1 -Standard -ErrorAction Stop
            } catch {
                $ISCSIB = New-VirtualPortGroup -Name "ISCSI_B" -VirtualSwitch $vs1 -VLanId (Get-VDPortgroup -VMHostNetworkAdapter $ISCSIBHostNIC).VlanConfiguration.VlanId
            }
            # Move the VMKs
            Write-Information -MessageData "Moving vSwitch uplinks on [$VMHost] from all attached Distributed Virtual Switches to the Standard Switches." -InformationAction Continue
            Add-VirtualSwitchPhysicalNetworkAdapter -VirtualSwitch $vs0 -VMHostPhysicalNic $ComputeHostNICs -VirtualNicPortgroup $VMO,$REPL -VMHostVirtualNic $VMOHostNIC,$ReplHostNIC -Confirm:$false
            Check-RunningTasks -VMHost $VMHost
            Add-VirtualSwitchPhysicalNetworkAdapter -VirtualSwitch $vs1 -VMHostPhysicalNic $ISCSIHostNICs -VirtualNicPortgroup $ISCSIA,$ISCSIB -VMHostVirtualNic $ISCSIAHostNIC,$ISCSIBHostNIC -Confirm:$false
            Check-RunningTasks -VMHost $VMHost
            Add-VirtualSwitchPhysicalNetworkAdapter -VirtualSwitch $vs0 -VMHostPhysicalNic $MGMTPnic -VirtualNicPortgroup $MGMT -VMHostVirtualNic $ManagementHostNIC -Confirm:$false
            Check-RunningTasks -VMHost $VMHost
            
            Get-VDSwitch $VDS | Remove-VDSwitchVMHost -VMHost $VMHost -Confirm:$false
            Check-RunningTasks -VMHost $VMHost
            Write-Information -MessageData "Removed Host [$VMHost] from all attached Distributed Virtual Switches." -InformationAction Continue
        }
        
        # Remove all iSCSI HBA Information
        $HBA = Get-VMHostHba -VMHost $VMHost -Type IScsi

        # Remove iSCSI Target
        $HBA | Get-IScsiHbaTarget | Remove-IScsiHbaTarget -Confirm:$false -ErrorAction SilentlyContinue
        Check-RunningTasks -VMHost $VMHost
        
        # Remove iSCSI bindings
        Manage-AdapterToPortBinding -VMHost $VMHost -HBA $HBA -Adapter $ISCSIAHostNIC -Action Unbind
        Check-RunningTasks -VMHost $VMHost
        Manage-AdapterToPortBinding -VMHost $VMHost -HBA $HBA -Adapter $ISCSIBHostNIC -Action Unbind
        Check-RunningTasks -VMHost $VMHost

        # Reset the iSCSI Credentials
        Remove-ISCSIAuthentication -VMHost $VMHost -HBA $HBA
        Check-RunningTasks -VMHost $VMHost

        # Reset host to use IP address
        $RenamedHost = Set-VMHostName -VMHost $VMHost -SetIP
        
        # Move host out of the cluster, reset it to default ruleset.
        Test-DeployRuleSetCompliance -DeployRuleSet (Get-DeployRuleSet) -VMHost $VMHost | Repair-DeployRuleSetCompliance
        
        Write-Information -MessageData "Reverted VMHost [$VMHost] to standard state." -InformationAction Continue
        # End teardown
        return $RenamedHost
    } else {
        Write-Information -MessageData "You must specify the -Teardown parameter to perform the teardown work. Try again!" -InformationAction Continue
    }
}

function Create-ReferenceHostProfile {
    param(
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Types.V1.Inventory.VMHost]$VMHost,
        [VMware.VimAutomation.Vds.Types.V1.VmwareVDSwitch]$ComputeVDSwitch,
        [VMware.VimAutomation.Vds.Types.V1.VmwareVDSwitch]$ISCSIVDSwitch,
        [ipaddress]$ISCSITargetAddress,
        [System.Management.Automation.PSCredential]$ISCSIChapCredential,
        [System.Management.Automation.PSCredential]$RootCredential
    )
    
    # Global variables
    $Epoch = (Get-Date -UFormat '%s').Replace((Get-Culture).NumberFormat.NumberDecimalSeparator,'')
    $Datacenter = Get-Datacenter -VMHost $VMHost

    # If the VDS objects were not passed into the function, force a lookup using GridView
    if(!$ComputeVDSwitch) {
        $SelectedComputeVDSwitch = Get-VDSwitch -Location $Datacenter | Select-Object -Property Name,Mtu,Datacenter,NumUplinkPorts,Version,LinkDiscoveryProtocol,LinkDiscoveryProtocolOperation | Sort-Object -Property Name | Out-GridView -OutputMode Single -Title "Choose your Compute Distributed Virtual Switch."
        $ComputeVDSwitch = Get-VDSwitch -Name $SelectedComputeVDSwitch.Name
    }
    if(!$ISCSIVDSwitch) {
        $SelectedISCSIVDSwitch = Get-VDSwitch -Location $Datacenter | Select-Object -Property Name,Mtu,Datacenter,NumUplinkPorts,Version,LinkDiscoveryProtocol,LinkDiscoveryProtocolOperation | Sort-Object -Property Name | Out-GridView -OutputMode Single -Title "Choose your iSCSI Distributed Virtual Switch."
        $ISCSIVDSwitch = Get-VDSwitch -Name $SelectedISCSIVDSwitch.Name
    }

    Write-Information -MessageData "Compute Switch: $ComputeVDSwitch" -InformationAction Continue
    Write-Information -MessageData "iSCSI Switch: $ISCSIVDSwitch" -InformationAction Continue
        
    # Ensure the switches used are not the same!
    if($ISCSIVDSwitch -eq $ComputeVDSwitch) {
        Write-Information -MessageData "The distributed switches specified are the same! They must be different to proceed. Please re-run the function." -InformationAction Continue
        break
    }

    # Get the Management Distributed Portgroup
    $vmk0VLAN = (Get-VirtualPortgroup -VMHost $VMHost -Name "Management Network").VlanId
    Write-Information -MessageData "Management Network portgroup is tagged on VLAN [$vmk0VLAN]." -InformationAction Continue
        
    # Now, get the Distributed Portgroup by TAG for the various components.
    # This obviously requires tags to be assigned :)
        
    # If the VDPortgroup ISNT found by tag, prompt user.
    $ManagementPortGroup = Get-VDPortgroupByTag -VDSwitch $ComputeVDSwitch -Tag "Management" -Remediate
    # Now compare the VLAN ID of the portgroup selected to the current one.
    if($ManagementPortGroup -and $ManagementPortGroup.VlanConfiguration.VlanType -eq "Vlan" -and $ManagementPortGroup.VlanConfiguration.VlanId -eq $vmk0VLAN) {
        Write-Information -MessageData "Found matching VLAN for management on Distributed Switch [$ComputeVDSwitch], on portgroup [$ManagementPortGroup]." -InformationAction Continue
    } else {
        Write-Information -MessageData "Unable to find a matching distributed portgroup for the Management interface. Make sure the Compute switch specified has VLAN [$vmk0VLAN] tagged in a portgroup and retry the function." -InformationAction Continue
        break
    }

    # These VMK interfaces we don't necessarily know the VLAN ID, so depend on tags.
    
    # Get the vMotion Distributed Portgroup
    $VMOPortGroup = Get-VDPortgroupByTag -VDSwitch $ComputeVDSwitch -Tag "vMotion" -Remediate
    # Get the Replication Distributed Portgroup
    $ReplPortGroup = Get-VDPortgroupByTag -VDSwitch $ComputeVDSwitch -Tag "Replication" -Remediate

    # Get the iSCSI 1 and 2 portgroups
    $ISCSIAPortGroup = Get-VDPortgroupByTag -VDSwitch $ISCSIVDSwitch -Tag "ISCSI_A" -Remediate
    $ISCSIBPortGroup = Get-VDPortgroupByTag -VDSwitch $ISCSIVDSwitch -Tag "ISCSI_B" -Remediate
        
    # Verify all the portgroups exist prior to changes.
    if(!$ManagementPortGroup -or !$VMOPortGroup -or !$ReplPortGroup -or !$ISCSIAPortGroup -or !$ISCSIBPortGroup) {
        Write-Information "One of the required distributed portgroups was missing. Change the Distributed Switches selected or ensure the portgroups are tagged appropriately and try again." -InformationAction Continue
        break
    }

    # Attach the switches
    Add-VDSwitchVMHost -VDSwitch $ComputeVDSwitch -VMHost $VMHost
    Check-RunningTasks -VMHost $VMHost
    Add-VDSwitchVMHost -VDSwitch $ISCSIVDSwitch -VMHost $VMHost
    Check-RunningTasks -VMHost $VMHost
    Write-Information -MessageData "Added [$VMHost] to the Distributed Switches."
        
    #Copy this for all exceptions :: Create-ReferenceHostProfile -VMHost $VMHost -Teardown
        
    # Attach uplinks and VMKernels
    $ManagementHostNIC = Get-VMHostNetworkAdapter -VMHost $VMHost -VMKernel -Name vmk0
    $VMOHostNIC = Get-VMHostNetworkAdapter -VMHost $VMHost -VMKernel -Name vmk1
    $ReplHostNIC = Get-VMHostNetworkAdapter -VMHost $VMHost -VMKernel -Name vmk2
    $ISCSIAHostNIC = Get-VMHostNetworkAdapter -VMHost $VMHost -VMKernel -Name vmk3
    $ISCSIBHostNIC = Get-VMHostNetworkAdapter -VMHost $VMHost -VMKernel -Name vmk4

    $ComputeHostNICs = Get-VMHostNetworkAdapter -VMHost $VMHost -Physical -Name vmnic0,vmnic1
    $ISCSIHostNICs = Get-VMHostNetworkAdapter -VMHost $VMHost -Physical -Name vmnic2,vmnic3
        
    # Compute Switch
    Add-VDSwitchPhysicalNetworkAdapter -VMHostPhysicalNic $ComputeHostNICs -DistributedSwitch $ComputeVDSwitch -VMHostVirtualNic $ManagementHostNIC,$VMOHostNIC,$ReplHostNIC -VirtualNicPortgroup $ManagementPortGroup,$VMOPortGroup,$ReplPortGroup -Confirm:$false
    Check-RunningTasks -VMHost $VMHost
    # ISCSI Switch
    Add-VDSwitchPhysicalNetworkAdapter -VMHostPhysicalNic $ISCSIHostNICs -DistributedSwitch $ISCSIVDSwitch -VMHostVirtualNic $ISCSIAHostNIC,$ISCSIBHostNIC -VirtualNicPortgroup $ISCSIAPortGroup,$ISCSIBPortGroup -Confirm:$false
    Check-RunningTasks -VMHost $VMHost

    # After the VDS Moves, delete the standard switches.
    Get-VirtualSwitch -VMHost $VMHost -Standard | Remove-VirtualSwitch -Confirm:$false

    # Get iSCSI HBA
    $HBA = Get-VMHostHba -Type iScsi -VMHost $VMHost

    # Configure the iSCSI Target IP in the build.
    if($ISCSITargetAddress) {
        Get-VMHostHba -Type IScsi -VMHost $VMHost | New-IScsiHbaTarget -Address $ISCSITargetAddress | Out-Null
        Check-RunningTasks -VMHost $VMHost
        Write-Information -MessageData "Added IP Address [$ISCSITargetAddress] to the iSCSI HBA for Dynamic Discovery." -InformationAction Continue
    } else {
        Write-Information -MessageData "No IP Address specified for iSCSI Targets, so skipping it for now." -InformationAction Continue
    }

    # Configure the iSCSI Port Bindings
    Manage-AdapterToPortBinding -VMHost $VMHost -HBA $HBA -Adapter $ISCSIAHostNIC -Action Bind
    Check-RunningTasks -VMHost $VMHost
    Manage-AdapterToPortBinding -VMHost $VMHost -HBA $HBA -Adapter $ISCSIBHostNIC -Action Bind
    Check-RunningTasks -VMHost $VMHost

    # Capture the host profile
    Write-Information -MessageData "Generating Host Profile from [$VMHost] for initial reference." -InformationAction Continue
    $ReferenceProfile = New-VMHostProfile -Name "$($VMHost.Name)-Profile-$Epoch" -ReferenceHost $VMHost -Description "Host Profile for host $VMHost captured at $Epoch"
       
    # Modify the reference profile based on standards.
    Update-HostProfileSettings -HostProfile $ReferenceProfile
    $FinalProfile = Get-VMHostProfile -Name "$($VMHost.Name)-Profile-$Epoch"

    # Update the root password from input. This forces the profile to require customization so you can automate the configuration.
    $UserUpdate = Get-VMHostProfileUserConfiguration -HostProfile $FinalProfile -UserName root | Set-VMHostProfileUserConfiguration -PasswordPolicy Fixed -Password $RootCredential.GetNetworkCredential().Password

    # Update the CHAP Configuration to be used in the profile
    Update-HostProfileISCSIChapSettings -HostProfile $FinalProfile -ISCSIChapCredential $ISCSIChapCredential

    # Attach the profile.
    $VMHostWithProfile = Set-VMHost -VMHost $VMHost -Profile $FinalProfile -Confirm:$false
    Write-Information -MessageData "Host Profile [$FinalProfile] applied to reference host [$VMHost] successfully." -InformationAction Continue
    
    # Assign the customizations.
    $RequiredHostCustomizations = Apply-VMHostProfile -Entity $VMHostWithProfile -Profile $FinalProfile -ApplyOnly -Confirm:$false
    Write-Information -MessageData "Host Customizations for Profile [$FinalProfile] updated on reference host [$VMHostWithProfile] successfully." -InformationAction Continue
        
    # Run Compliance Check
    $ComplianceIssues = Test-VMHostProfileCompliance -VMHost $VMHostWithProfile
    if($ComplianceIssues.IncomplianceElementList.Count -gt 0) {
        Write-Information -MessageData "Compliance Check - [$VMHost] has [$($ComplianceIssues.IncomplianceElementList.Count)] issues. Remediate any issues (if found)." -InformationAction Continue
    } else {
        Write-Information -MessageData "Compliance Check - [$VMHost] has no compliance issues. Hooray, and you probably cheated." -InformationAction Continue
    }
    # End output
    $FinalProfile = Get-VMHostProfile -Name "$($VMHostWithProfile.Name)-Profile-$Epoch"
    return $FinalProfile
}

function Build-VMHostStorage {
    param(
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Types.V1.Inventory.VMHost]$VMHost,
        [VMware.VimAutomation.ViCore.Types.V1.Host.Storage.IScsiHba]$HBA,
        [string]$DSCluster,
        [switch]$Rescan,
        [switch]$DryRun,
        [switch]$Teardown
    )
    if(!$HBA) {
        $HBA = Get-VMHostHba -Type IScsi -VMHost $VMHost
    }
    
    if($Rescan) {
        Write-Information -MessageData "Rescanning iSCSI HBAs for available SCSI LUNs to see if any are present. This may take a few minutes..." -InformationAction Continue
        Rescan-VMHostSpecificHba -VMHost $VMHost -DeviceName $HBA.Device
    }
    Check-RunningTasks -VMHost $VMHost
    
    $ExistingDatastores = Get-Datastore -RelatedObject $VMHost
    $NewDatastores = @()
    $RemovedDatastores = @()

    # The SanID values resemble [iqn.2001-05.com.equallogic:8-da6616-bab37279b-4bcd6f2d7a35bf2d-vhwstmgmt-vol-01]
    # The value should be consistent other than the IDs, so use a Regular Expression to derive the datastore name.
    $SANRegex = "\w{3}\.\d+\-\d+\.\w+\.\w+\:\w{1}\-\w{6}\-\w{9}\-\w{16}\-"

    # Get the available LUN paths and their Canonical Names by the unique SanID. This will help derive the unique datastore name from the SAN target.
    # Start with the devices on the iscsi adapter, for each one see if a datastore exists given the NAA id
    $StorageDevices = Get-ScsiLun -VmHost $VMHost | ?{$_.RuntimeName -match $HBA.Device} | Get-ScsiLunPath | ?{$_.SanID} | select SanId,ScsiCanonicalName | Sort-Object | Get-Unique -AsString
    
    # Go through the results and determine what to do next.
    foreach($StorageDevice in $StorageDevices) {
        # Check to see if the LUN is already attached to an existing datastore connected to the host.
        $MatchingDatastore = Get-Datastore -RelatedObject $VMHost | ?{$_.ExtensionData.Info.Vmfs.Extent[0].DiskName -eq $StorageDevice.ScsiCanonicalName}
        if(!$MatchingDatastore) {
            # No matching datastore to the extent, so create one.
            $DatastoreName = ($StorageDevice.SanId -replace $SANRegex,"").ToUpper()
            $DatastorePath = $StorageDevice.ScsiCanonicalName

            # Check for existing datastore by the same name.
            $DatastoreCheck = Get-Datastore -Name $DatastoreName -RelatedObject $VMHost -ErrorAction SilentlyContinue
            if($DatastoreCheck) {
                Write-Information -MessageData "The datastore already exists, continuing to the next device." -InformationAction Continue
                $DatastoreCheck
                continue
            } elseif(!$DatastoreCheck -and $Teardown) {
                Write-Information -MessageData "Teardown was requested but no datastore exists that maps to the extent. Continuing." -InformationAction Continue
            } else {
                Write-Information -MessageData "The datastore will be created with name [$DatastoreName] using path [$DatastorePath]." -InformationAction Continue
                if($DryRun) {
                    $NewDatastore = New-Datastore -VMHost $VMHost -Name $DatastoreName -Path $DatastorePath -Vmfs -WhatIf
                } else {
                    $NewDatastore = New-Datastore -VMHost $VMHost -Name $DatastoreName -Path $DatastorePath -Vmfs
                    Write-Information -MessageData "Datastore [$DatastoreName] was successfully created." -InformationAction Continue
                    $NewDatastores += $NewDatastore
                }
            }
        } else {
            if($Teardown) {
                # Delete the datastore. Used for testing.
                Write-Information -MessageData "Teardown flag specified, now deleting [$MatchingDatastore] from [$VMHost]..." -InformationAction Continue
                $HasDSC = $MatchingDatastore | Get-DatastoreCluster
                Remove-Datastore -Datastore $MatchingDatastore -VMHost $VMHost -Confirm:$false
                Write-Information -MessageData "Datastore [$MatchingDatastore] was successfully deleted." -InformationAction Continue
                if($HasDSC) {
                    Write-Information -MessageData "The Datastore specified was part of a Datastore Cluster, it will be deleted." -InformationAction Continue
                    $HasDSC | Remove-DatastoreCluster -Confirm:$false
                }
            } else {
                # Datastore found, just report it.
                Write-Information -MessageData "The Storage device [$($StorageDevice.SCSICanonicalName)] already has a datastore matched to [$MatchingDatastore], nothing to do." -InformationAction Continue
            }
        }
    }
    if($DSCluster -and $DSCluster -ne $null -and $NewDatastores) {
        # Add the new datastore(s) to an existing Datastore Cluster (by name) or create one with the name if it doesn't exist.
        $DSCExists = Get-DatastoreCluster -Name $DSCluster -ErrorAction SilentlyContinue
        if(!$DSCExists) {
            # Create a new Datastore Cluster object and add them in.
            $Location = Get-Datacenter -VMHost $VMHost
            try {
                $DSClusterObject = New-DatastoreCluster -Name $DSCluster -Location $Location -ErrorAction Stop
                Write-Information -MessageData "The datastore cluster [$DSCluster] did not show in any queries, so a new one was created with that name." -InformationAction Continue
            } catch {
                Write-Information -MessageData "There was an error creating the Datastore Cluster object [$DSCluster] : $($Error[0].Exception)" -InformationAction Stop
            }
        }
        # Add the datastores to the cluster
        try {
            $NewDatastores | Move-Datastore -Destination $DSClusterObject -Confirm:$False -ErrorAction Stop
            $DSClusterObject | Set-DatastoreCluster -SdrsAutomationLevel FullyAutomated -Confirm:$false -ErrorAction Stop
            Write-Information -MessageData "The datastores have been added to Datastore Cluster [$DSClusterObject]." -InformationAction Continue
        } catch {
            Write-Information -MessageData "There was an error adding the datastores specified to the cluster: $($Error[0].Exception)" -InformationAction Continue
        }   
    } else {
        Write-Information -MessageData "No Datastore Cluster specific criteria met, so no changes made to Datastore Clusters." -InformationAction Continue
    }
}

function Configure-AutoDeployCluster {
    param(
        [VMware.VimAutomation.ViCore.Types.V1.VIServer]$VIServer,
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.Datacenter]$Datacenter,
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.Cluster]$Cluster,
        [ValidateSet("GeneralPurpose","Dedicated")][string]$DeploymentType,
        [string]$HostList,
        [ipaddress]$ISCSITargetAddress,
        [System.Management.Automation.PSCredential]$ISCSIChapCredential,
        [System.Management.Automation.PSCredential]$RootCredential
    )
    Clear-Host
    # If not specified, get the vCenter Server.
    if(!$VIServer) {
        $VIServer = Connect-EHSVC
    }

    # If not specified, get the datacenter.
    if(!$Datacenter) {
        $Datacenter = Get-Datacenter -Server $VIServer | Sort-Object Name | Out-GridView -Title "Choose the datacenter where the Auto Deploy Cluster is." -OutputMode Single
    }
    # Verify a datacenter was chosen previously.
    if(!$Datacenter) {
        Write-Information -MessageData "A valid datacenter was not passed into the function.`nPlease run the function with a datacenter object or choose one when prompted." -InformationAction Continue
        break
    }

    # If not specified, search for a cluster in the vCenter.
    if(!$Cluster) {
        $Cluster = $Datacenter | Get-Cluster | Sort-Object Name | Out-GridView -Title "Choose the cluster to place your hosts in for AutoDeploy." -OutputMode Single
    }
    # Verify a cluster was chosen previously.
    if(!$Cluster) {
        Write-Information -MessageData "A valid cluster was not passed into the function.`nPlease run the function with a cluster object or choose one when prompted." -InformationAction Continue
        break
    }

    # Get the hostnames
    if(!$HostList) {
        $HostList = Read-Host -Prompt "Enter a comma-separated list of ESX Hostnames or FQDNs to add to the new cluster "
    }

    $HostListObjectArray = @()
    
    # Separate the hosts by comma.
    $HostListData = $HostList.split(",")
    # Ensure the array has at least one value.
    Write-Information -MessageData "Found $($HostListData.Count) entries in the Host Listing. Beginning lookups in vCenter." -InformationAction Continue
    
    # Loop through the hosts.                    
    if($HostListData.Count -gt 0) {
        foreach($HostEntry in $HostListData) {
            # Search for the VMHost to see if it is already in the inventory by name.
            try {
                $VMHost = Get-VMHost $HostEntry -ErrorAction Stop
                $HostListObjectArray += $VMHost
                Write-Information -MessageData "`tFound VMHost [$HostEntry] in vCenter, Hostname is properly configured." -InformationAction Continue
                break
            } catch {
                # Host not found by name. Check DNS.
                # The hosts may be joined to vCenter by IP, so you need to go to the actual hostname property and repair it.
                try {
                    $DNSQuery = Resolve-DnsName -Name $HostEntry -ErrorAction Stop
                    $IPAddress = $DNSQuery.IP4Address
                } catch {
                    # DNS Lookup failed, this is fatal on this host.
                    Write-Information -MessageData "`tUnable to find the Host Record [$HostEntry] in DNS! This host is being skipped." -InformationAction Continue
                    break
                }
                
                # Hostname was found in DNS, so search the host by IP in vCenter.
                try {
                    $VMHost = Get-VMHost $IPAddress -ErrorAction Stop
                    # Since it is joined by IP, perform a repair. This should only occur on initial configuration.
                    $UpdatedHost = Set-VMHostName -VMHost $VMHost
                    $HostListObjectArray += $UpdatedHost
                } catch {
                    # Host not found by IP either, this is fatal for this host. 
                    Write-Information -MessageData "`tUnable to find the Host [$HostEntry] by either name or the IP address in DNS! This host is being skipped." -InformationAction Continue
                    break
                }
            }
        }
    } else {
        # Error, you need a host! This should break it.
        Write-Information -MessageData "No values for the host list were provided. Please provide a comma-separated list of FQDN values and try again." -InformationAction Continue
        break
    }

    # Add some logic to stop the script in case no hosts are found.
    if($HostListObjectArray.Count -lt 1) {
        Write-Information -MessageData "No valid ESXi hosts were found matching the named criteria. Please confirm the ESXi hosts are online and DNS is functioning properly." -InformationAction Continue
        break
    }

    # Hosts are now named properly, so get the first host to be used as the 'template'
    $PrimaryHost = $HostListObjectArray[0]
    Write-Information -MessageData "Of the $($HostList.Count) VMHost FQDN entries submitted, $($HostListObjectArray.Count) found in vCenter." -InformationAction Continue
    
    # Begin configuration
    Write-Information -MessageData "Beginning initial configuration of the first host [$PrimaryHost] in the cluster [$Cluster]." -InformationAction Continue

    # Configuration of initial host done, host profile is complete
    $ADHostProfile = Create-ReferenceHostProfile -VMHost $PrimaryHost -ISCSITargetAddress $ISCSITargetAddress -ISCSIChapCredential $ISCSIChapCredential -RootCredential $RootCredential
    $ADImageProfile = Get-VMHostImageProfile -Entity $PrimaryHost
    $ADScriptBundle = Get-ScriptBundle -Name "HPFirmwareReportScript"

    # Rename the Host Profile
    try {
        $UpdatedHostProfile = Set-VMHostProfile -Profile $ADHostProfile -Name "Host-Profile-$Cluster" -ErrorAction Stop
        Write-Information -MessageData "Renamed Host Profile [$ADHostProfile] to [$UpdatedHostProfile] to be nice." -InformationAction Continue
    } catch {
        $UpdatedHostProfile = $ADHostProfile
        Write-Information -MessageData "Host profile rename had an issue, so leaving it alone as it is not critical." -InformationAction Continue
    }

    # Create the Deploy Rule with new profile, cluster, script bundle, image profile
    $DeployPattern = @()
    $DeployPattern += "domain=mydomain.local"
    $HostListObjectArray | %{ 
        $DeployPattern += "hostname=$($_.ExtensionData.Config.Network.DnsConfig.HostName)"
    }
    
    # Check each item going into the Deploy Rule to ensure they are valid.
    Write-Host "`tHost Profile: $UpdatedHostProfile" -ForegroundColor Cyan
    Write-Host "`tScript Bundle: $ADScriptBundle" -ForegroundColor Cyan
    Write-Host "`tImage Profile: $ADImageProfile" -ForegroundColor Cyan
    Write-Host "`tCluster: $Cluster" -ForegroundColor Cyan
    $Items = @()
    
    try {
        $NewDeployRule = New-DeployRule -Name "$($Cluster.Name)-AutoDeploy" -Pattern $DeployPattern -Item $UpdatedHostProfile,$ADScriptBundle,$Cluster,$ADImageProfile -ErrorAction Stop
        Write-Information -MessageData "Created new AutoDeploy Rule [$($NewDeployRule.Name)]." -InformationAction Continue
    } catch {
        Write-Information -MessageData "Unable to create new Auto Deploy rule: $($Error[0].exception)" -InformationAction Continue
    }

    
    # Attach the profile to the cluster.
    # NOTE: This always throws an error in PowerCLI, but succeeds in vCenter. Not sure why, so ErrorAction is set to silently continue.
    try {
        Set-Cluster -Cluster $Cluster -Profile $UpdatedHostProfile -Confirm:$false -ErrorAction Stop
        Write-Information -MessageData "Configured cluster [$Cluster] with Host Profile [$UpdatedHostProfile]. All hosts joining the cluster will remediate to it." -InformationAction Continue
    } catch {
        # Validate it got set
        $ClusterAttached = (Get-VMHostProfile -Name $UpdatedHostProfile.Name).ExtensionData.Entity | ?{$_.Type -eq "ClusterComputeResource" -and $_.Value -eq $Cluster.ExtensionData.MoRef.Value}
        if(!$ClusterAttached) {
            Write-Information "`tThe Updated Host Profile [$($UpdatedHostProfile.Name)] did not successfully attach to the Cluster object [$($Cluster.Name)] - Attach it manually to resolve."
        }
    }

    # Remediate Auto Deploy compliance rules. This will update the location of the host to its target cluster.
    $UpdatedRuleset = $NewDeployRule | Add-DeployRule -At 0
    Write-Information -MessageData "Added new rule [$($NewDeployRule.Name)] to the top of the active ruleset." -InformationAction Continue
    $UpdatedRuleset = Get-DeployRuleSet
    $RuleCompliance = Test-DeployRuleSetCompliance -DeployRuleSet $UpdatedRuleset -VMHost $PrimaryHost
    
    # Multiple changes can happen here, such as location and profile
    # Available types: FolderImpl,ClusterComputeResource,RemoteImageProfile,ScriptBundle
    if($RuleCompliance.ItemList.Count -gt 0) {
        Write-Information "There are [$($RuleCompliance.ItemList.Count)] compliance items that will be remedied."
        foreach($Rule in $RuleCompliance.ItemList) {
            $SourceTypeName = $Rule.CurrentItem.GetType().Name.Replace("Impl","")
            $SourceTypeValue = $Rule.CurrentItem.Name
            $TargetTypeName = $Rule.ExpectedItem.GetType().Name.Replace("Impl","")
            $TargetTypeValue = $Rule.ExpectedItem.Name
            Write-Information -MessageData "Auto Deploy Compliance remediation -- $VMHost updating from $SourceTypeName : $SourceTypeValue to --> $TargetTypeName : $TargetTypeValue" -InformationAction Continue
        }
        Repair-DeployRuleSetCompliance -TestResult $RuleCompliance
    }
    Write-Information -MessageData "Auto Deploy configuration is complete." -InformationAction Continue

    # Retrieve the Host Answer File, generate necessary tasks
    Write-Information -MessageData "Retrieving Host Profile Answer File for [$PrimaryHost]." -InformationAction Continue
    $AnswerFile = Get-VMHostAnswerFile -VMHost $PrimaryHost
    Write-Information -MessageData "Generating Host Profile Configuration Tasks for [$PrimaryHost]." -InformationAction Continue
    $HostTasks = Get-HostProfileConfigurationTasks -VMHost $PrimaryHost -AnswerFile $AnswerFile
    Write-Information -MessageData "Remediating [$PrimaryHost] to Host Profile compliance." -InformationAction Continue
    $Remediate = Remediate-Host -HostTasks $HostTasks

    # Now perform the storage setup.
    Write-Information -MessageData "Building Datastores for [$PrimaryHost]." -InformationAction Continue
    Build-VMHostStorage -VMHost $PrimaryHost -Rescan -DSCluster "$Cluster-DatastoreCluster"
    Write-Information -MessageData "AutoDeploy should now be all set up!" -InformationAction Continue
}



