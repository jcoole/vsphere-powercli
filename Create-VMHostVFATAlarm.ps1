<#
.SYNOPSIS
Creates a custom alarm on the ESXi Host to catch issues with the local VFAT partitions.
.DESCRIPTION
Creates a custom alarm on the ESXi Host to catch issues with the local VFAT partitions.
This was written in response to a problem where HP AMS was filling up the /tmp partition and causing issues.
.PARAMETER VMHost
The VMHost Entity to add the alarm to.
.EXAMPLE
$VMHost = Get-VMHost "myhost.domain.local"
$Alarm = Create-VMHostVFATAlarm -VMHost $VMHost
$Alarm

Name                 Description                                             Enabled
----                 -----------                                             -------
VFAT Partition Is... This alarm fires when the /scratch or /root partitio... True   

--------------------------------------------------

This will add the alarm to the VMHost in vCenter. Since this is a vCenter-only change, the host can be online or offline and doesn't impact it in any way.
.OUTPUTS
Alarm Object
.NOTES
None
#>
function Create-VMHostVFATAlarm {
    param(
        [Parameter(Mandatory=$true)][VMware.VimAutomation.ViCore.Types.V1.Inventory.VMHost]$VMHost
    )

    # Utilize the vCenter AlarmManager
    $MoRef = New-Object VMware.Vim.ManagedObjectReference
    $MoRef.Type = "AlarmManager"
    $MoRef.Value = "AlarmManager"
    $AlarmManager = Get-View -Id $MoRef

    # Create the Alarm Specification for the host.
    $AlarmSpec = New-Object VMware.Vim.AlarmSpec
    $AlarmSpec.Expression = New-Object VMware.Vim.OrAlarmExpression
    $AlarmSpec.Expression.Expression = @()

    $AlarmSpec.Expression.Expression += New-Object VMware.Vim.EventAlarmExpression
    $AlarmSpec.Expression.Expression[0].EventType = "vim.event.EventEx"
    $AlarmSpec.Expression.Expression[0].EventTypeId = "esx.problem.vfat.filesystem.full.other"
    $AlarmSpec.Expression.Expression[0].ObjectType = "vim.HostSystem"
    $AlarmSpec.Expression.Expression[0].Status = "red"
    
    $AlarmSpec.Expression.Expression += New-Object VMware.Vim.EventAlarmExpression
    $AlarmSpec.Expression.Expression[1].EventType = "vim.event.EventEx"
    $AlarmSpec.Expression.Expression[1].EventTypeId = "esx.problem.visorfs.ramdisk.full"
    $AlarmSpec.Expression.Expression[1].ObjectType = "vim.HostSystem"
    $AlarmSpec.Expression.Expression[1].Status = "red"

    $AlarmSpec.Expression.Expression += New-Object VMware.Vim.EventAlarmExpression
    $AlarmSpec.Expression.Expression[2].EventType = "vim.event.EventEx"
    $AlarmSpec.Expression.Expression[2].EventTypeId = "esx.problem.visorfs.inodetable.full"
    $AlarmSpec.Expression.Expression[2].ObjectType = "vim.HostSystem"
    $AlarmSpec.Expression.Expression[2].Status = "red"

    $AlarmSpec.Expression.Expression += New-Object VMware.Vim.EventAlarmExpression
    $AlarmSpec.Expression.Expression[3].EventType = "vim.event.EventEx"
    $AlarmSpec.Expression.Expression[3].EventTypeId = "esx.problem.vfat.filesystem.full.scratch"
    $AlarmSpec.Expression.Expression[3].ObjectType = "vim.HostSystem"
    $AlarmSpec.Expression.Expression[3].Status = "red"

    # Configure the name/description.
    $AlarmSpec.Name = "VFAT Partition Is Full"
    $AlarmSpec.Description = "This alarm fires when the /scratch or /root partitions of the ESXi host are full. It is checked every 5 minutes."
    $AlarmSpec.Enabled = $true
    
    # Create the Alarm on the entity.
    $Entity = $VMHost.ExtensionData.MoRef
    try {
        $OutputAlarm = $AlarmManager.CreateAlarm($Entity,$AlarmSpec) | Get-VIObjectByVIView
        $OutputAlarmName = $OutputAlarm.ExtensionData.Info.Name
        Write-Host "Created new alarm [$OutputAlarmName] on host [$VMHost] successfully." -ForegroundColor Cyan
    } catch {
        throw("Error on creation of alarm: $($_.Exception)")
    }
    return $OutputAlarm
}