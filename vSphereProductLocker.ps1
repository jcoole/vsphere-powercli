<#
.SYNOPSIS
Checks to ensure that the Host can utilize the Product Locker Update API.
.DESCRIPTION
Checks to ensure that the Host can utilize the Product Locker Update API.
It is a simple check against the reported API version from the Host.
.PARAMETER VMHost
The ESXi Host to check for compatibility
.EXAMPLE
$MyHost = Get-VMHost "MyVMHost.domain.local"

$APICheck = Check-VMHostProductLockerAvailability -VMHost $MyHost

Checks the compatibility of the host $MyHost and stores either True or False in the variable $APICheck.ocal user with full administrative privileges, or if the system has encountered an error while trying to remove user's permissions, or if the account cannot be removed due to permission issues - an error will be thrown.

.OUTPUTS
True/False
.NOTES
This function requires PowerCLI (Any Version) to run properly.
#>
function Check-VMHostProductLockerAvailability {
    param(
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Types.V1.Inventory.VMHost]$VMHost
    )
    # Requires 6.7 API! Return TRUE if the capability is supported on the ESXi host.
    $Major = $VMHost.ApiVersion.Split(".")[0]
    $Minor = $VMHost.ApiVersion.Split(".")[1]
    # Major and Minor should always be present - convert the string to a decimal so that it can be used in a comparison.
    $APIVersion = "$Major.$Minor"
    return [decimal]$APIVersion -ge 6.7
}

<#
.SYNOPSIS
Retrieves the current Product Locker location relative to the ESXi Host.
.DESCRIPTION
Retrieves the VMFS path to the Product Locker. This is often masking datastore names with UUID values, whether it is the internal repository, or a datastore path.
.EXAMPLE
$MyHost = Get-VMHost "MyVMHost.domain.local"
$ProductLockerPath = Get-VMHostProductLockerLocation -VMHost $MyHost

Retrieves the Product Locker location for the host $MyHost and stores it in variable $ProductLockerPath.
.OUTPUTS
The path of the Product Locker on the ESXi Host.
.NOTES
This function requires PowerCLI version 11.0+ to run properly.
.LINK
https://vdc-download.vmware.com/vmwb-repository/dcr-public/3325c370-b58c-4799-99ff-58ae3baac1bd/45789cc5-aba1-48bc-a320-5e35142b50af/doc/vim.HostSystem.html#queryProductLockerLocation
#>
function Get-VMHostProductLockerLocation {
    param(
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Types.V1.Inventory.VMHost]$VMHost
    )

    # Check for functionality on the host.
    $ProductLockerEnabled = Check-VMHostProductLockerAvailability -VMHost $VMHost
    if(!$ProductLockerEnabled) {
        throw("vSphere Product Locker -- The Host is currently running API version $($VMHost.ApiVersion) which is below the requirement of 6.7 or higher. Upgrade host before attempting this command!")
    }
    return $VMHost.ExtensionData.QueryProductLockerLocation()
}

<#
.SYNOPSIS
Updates the current Product Locker location relative to the ESXi Host.
.DESCRIPTION
Updates the path to the Product Locker from the existing location to a shared datastore folder path.
The function includes checks to ensure that the datastore specified are reachable on the host, and whether the folder exists already (or not).
If the -Force switch is specified, the folder and its tree will be created.
.EXAMPLE
$MyHost = Get-VMHost "MyVMHost.domain.local"
$MyDS = Get-Datastore "MyDatastore"
$MyPath = "/my/product/locker/folder"

Set-VMHostProductLockerLocation -VMHost $MyHost -Datastore $MyDS -FolderPath $MyPath

Updates the Product Locker path on VM Host $MyHost to point to the Datastore $MyDS under subfolder $MyPath.

NOTE: If the specified folder in $MyPath doesn't exist already, it will not be created.
.EXAMPLE
$MyHost = Get-VMHost "MyVMHost.domain.local"
$MyDS = Get-Datastore "MyDatastore"
$MyPath = "/my/product/locker/folder"

Set-VMHostProductLockerLocation -VMHost $MyHost -Datastore $MyDS -FolderPath $MyPath -Force

Updates the Product Locker path on VM Host $MyHost to point to the Datastore $MyDS under subfolder $MyPath.
If the specified folder in $MyPath doesn't exist already, it will be created prior to updating the Product Locker path.
.OUTPUTS
None
.NOTES
This function requires PowerCLI version 11.0+ to run properly.
.LINK
https://vdc-download.vmware.com/vmwb-repository/dcr-public/3325c370-b58c-4799-99ff-58ae3baac1bd/45789cc5-aba1-48bc-a320-5e35142b50af/doc/vim.HostSystem.html#updateProductLockerLocation
#>
function Set-VMHostProductLockerLocation {
    param(
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Types.V1.Inventory.VMHost]$VMHost,
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Types.V1.DatastoreManagement.VmfsDatastore]$Datastore,
        [Parameter(Mandatory=$true)]$FolderPath,
        [switch]$Force
    )    
    # Check for functionality on the host.
    $ProductLockerEnabled = Check-VMHostProductLockerAvailability -VMHost $VMHost
    if(!$ProductLockerEnabled) {
        throw("vSphere Product Locker -- The Host is currently running API version $($VMHost.ApiVersion) which is below the requirement of 6.7 or higher. Upgrade host before attempting this command!")
    }

    # Confirm the datastore specified is seen on the host.
    $DSCheck = Get-Datastore -RelatedObject $VMHost | ?{$_.Id -eq $Datastore.Id}
    if(!$DSCheck) {
        throw("vSphere Product Locker -- The Datastore [$Datastore] is not associated to the specified host. Please choose a different datastore attached to [$VMHost] and try again.")
    }

    # Ensure the FolderPath has a prefixed front-slash.
    if($FolderPath -notmatch "^/") {
        $FolderPath = "/$FolderPath"
    }

    # Get old location for output and also for backup. A new Advanced System Setting will be created as a backup value.
    $OldAdvSetting = "UserVars.ProductLockerLocationBackup"
    $OldLocation = Get-VMHostProductLockerLocation -VMHost $VMHost

    # Specify the new location.
    $LockerPath = "/$($DS.ExtensionData.Info.Url.TrimStart("ds:/").TrimEnd("/"))$FolderPath"

    # Check the specified folder path exists or not on the datastore.
    $FolderCheck = Test-Path $LockerPath
    if(!$FolderCheck -and $Force) {
        # Create the folder using the PSDrive and VIM Provider
        try {
            $TempDatastoreDrive = New-DatastoreDrive -Name TempDatastoreDrive -Datastore $Datastore
            $CreatedFolder = New-Item -Path TempDatastoreDrive:$FolderPath -ItemType Directory -ErrorAction Stop
            Write-Host "vSphere Product Locker -- The folder specified did not exist on datastore [$Datastore] and was automatically created." -ForegroundColor Cyan
        } catch [VMware.VimAutomation.ViCore.Cmdlets.Provider.Exceptions.DriveException] {
            #Write-Host "vSphere Product Locker -- The folder specified already exists on the datastore [$Datastore]!" -ForegroundColor Cyan
        } catch {
            throw("vSphere Product Locker -- Unhandled Exception attempting to create/set the Product Locker location: $($_.Exception)")
        } finally {
            if($TempDatastoreDrive) {
                Get-PSDrive -PSProvider VimDatastore -Name TempDatastoreDrive | Remove-PSDrive
            }
        }

        # Is the folder specified the same as the one in use now?
        if($LockerPath -eq $OldLocation) {
            Write-Host "vSphere Product Locker -- The specified new Product Locker is the same as the existing one. No changes made." -ForegroundColor Cyan
        } else {
            # With the folder confirmed, use the API to update the location.
            $LockerUpdated = $VMHost.ExtensionData.UpdateProductLockerLocation($LockerPath)
            if($LockerUpdated) {
                Write-Host "vSphere Product Locker -- The host [$VMHost] Product Locker has been updated from [$OldLocation] to location [$LockerPath]." -ForegroundColor Green
            } else {
                Write-Host "vSphere Product Locker -- Failed to update the locker location on [$VMHost] -- Error was: $LockerUpdated" -ForegroundColor Red
            }
        }
    } elseif(!$FolderCheck) {
        # The folder doesn't exist and must be manually created.
        Write-Host "vSphere Product Locker -- The folder specified doesn't exist. You must create it manually or re-run the function with -Force to auto-create it." -ForegroundColor Red
        break
    } else {
        # The folder exists, set the product locker.
        if($LockerPath -eq $OldLocation) {
            Write-Host "vSphere Product Locker -- The specified new Product Locker is the same as the existing one. No changes made." -ForegroundColor Cyan
        } else {
            $LockerUpdated = $VMHost.ExtensionData.UpdateProductLockerLocation($LockerPath)
            if($LockerUpdated) {
                Write-Host "vSphere Product Locker -- The host [$VMHost] Product Locker has been updated from [$OldLocation] to location [$LockerPath]." -ForegroundColor Green
            } else {
                Write-Host "vSphere Product Locker -- Failed to update the locker location on [$VMHost] -- Error was: $LockerUpdated" -ForegroundColor Red
            }
        }
    }

}