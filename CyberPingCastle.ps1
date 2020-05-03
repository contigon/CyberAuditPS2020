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

push-Location $ACQ
Copy-Item $appsDir\PingCastle\current\*.* $ACQ -Recurse -Force
$key = Read-Host "Press A for Automatically or I for Interactively running PingCastle"
switch ($key) 
{
"I" {
     cmd /c start .\PingCastle --interactive
    }
"A" {
     cmd /c start .\PingCastle --no-enum-limit --carto --healthcheck --server *
     cmd /c start .\PingCastle --hc-conso
    $checks = @("antivirus","corruptADDatabase","laps_bitlocker","localadmin","nullsession","nullsession-trust","share","smb","spooler","startup")
    foreach($check in $checks){
         cmd /c start .\PingCastle --scanner $check
        }
    }
}
Pop-Location
