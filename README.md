# vSphere PowerCLI scripts repo

Last updated **3/24/2023**

Scripts written with vSphere PowerCLI over the years that people may find useful.

I've tried to clean them up and make them smarter and prettier for general consumption.

- New-ESXiCertificate

This one I wrote when doing bulk certificate requests against hundreds of hosts.

- vSphereProductLocker

Used this for bulk changes to the Product Locker on many hosts for VMware Tools related work.

- Create-VMHostVFATAlarm

Issues on the VFAT Partition were killing our hosts, so to catch it I wrote this to add custom alarms to vCenter. Very niche but a nice reference for using the API to create an Alarm object.
