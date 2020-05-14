<#	
	.NOTES
	===========================================================================
	 Created on:   	2/24/2020 1:11 PM
	 Created by:   	Omerf
	 Organization: 	Israel Cyber Directorate
	 Filename:     	CyberOfflineNTDS
	===========================================================================
	.DESCRIPTION
		Cyber Audit Tool - Offline ntds.dit mount
#>
CLS
. $PSScriptRoot\CyberFunctions.ps1
ShowIncd
if (![Environment]::Is64BitProcess)
{
    failed "OS architecture must be 64 bit, exiting ..."
    exit
}
DisableFirewall
Set-ExecutionPolicy -ExecutionPolicy Unrestricted
checkRsat
CheckMachineRole

$help = @"

        Offline NTDS
        ------------
        
        Run Active Directory from ntds.dit file.
        
        You need to copy this script to a domain controller 
        and run in an elevated powershell console.

        Steps:
        1- Browse and Choose the ntds.dit file to load
        2- Check ntds.dit integrity
        3- Upgrade the ntds.dit database      
        4- Run the AD on port 10389

"@

Write-Host "Browse and Choose the ntds.dit file to mount"
$ntdsfile = Get-FileName
$DomCont = Read-Host "Input name of Domain Controller Server"
$session = New-PSSession –ComputerName $DomCont
Write-Output "Creating folder on server $DomCont and copying the ntds.dit file"
Invoke-Command -Session $session -ScriptBlock {New-Item -ItemType Directory -Path "C:\TempNtds" -Force}
Copy-Item –Path $ntdsfile –Destination 'C:\TempNtds' –ToSession $session -Force
Write-Host "Checking the integrity of the ntds.dit database file"
Invoke-Command -Session $session -ScriptBlock {esentutl.exe /g "C:\TempNtds\ntds.dit"}
Write-Host "you can now mount the ntds.dit database file"
Invoke-Command -Session $session -ScriptBlock {dsamain.exe /dbpath C:\TempNtds\ntds.dit /ldapport 10389 /allownonadminaccess}

$session | Remove-PSSession
break

<#
$checkIntegrity = esentutl.exe /g $ntdsfile
if ($checkIntegrity -match "Integrity check successful")
    {
        success "Integrity check was successfull"
    }
    else
    {
        failed "Integrity check Failes"
    }
#>


$upg = "dsamain.exe /dbpath $ntdsfile /ldapport 10389  /allowupgrade"
$null = Invoke-Expression $upg
$cmd = "/c dsamain.exe /dbpath $ntdsfile /ldapport 10389  /allownonadminaccess"
Start-Process "cmd.exe" $cmd

Write-Host "Check that we can list users from this AD"
Get-ADUser  -Filter * -Server localhost:10389 | Select-Object name

#Import-Module SharpHound.ps1
#Invoke-BloodHound -DomainController localhost -LdapPort 10389 -Domain mymc.local
