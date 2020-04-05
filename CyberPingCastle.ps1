<#	
	.NOTES
	===========================================================================
	 Created on:   	2/24/2020 1:11 PM
	 Created by:   	Omerf
	 Organization: 	Israel Cyber Directorate
	 Filename:     	CyberMenu
	===========================================================================
	.DESCRIPTION
		Cyber Audit Tool - PingCastle
#>

$Host.UI.RawUI.WindowTitle = "Cyber Audit Tool 2020 - PingCastle"

Set-Location $ACQ
Copy-Item $appsDir\PingCastle\current\*.* $ACQ -Recurse -Force
$key = Read-Host "Press A for Automatically or I for Interactively running PingCastle"
switch ($key) 
{
"I" {
    .\PingCastle --interactive
    }
"A" {
    .\PingCastle --no-enum-limit --carto --healthcheck --server *
    .\PingCastle --hc-conso
    $checks = @("antivirus","corruptADDatabase","laps_bitlocker","localadmin","nullsession","nullsession-trust","share","smb","spooler","startup")
    foreach($check in $checks){
        .\PingCastle --scanner $check
        }
    }
}
Set-Location $PSScriptRoot
