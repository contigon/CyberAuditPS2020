. $PSScriptRoot\CyberFunctions.ps1

$ACQ = ACQ("Network")


        $zipURLB = "http://cyberaudittool.c1.biz/$FileNamef"
        $zipURLA = "https://raw.githubusercontent.com/contigon/Downloads/master/$FileName"
        $FileName = "goUpdate.pdf"
        $FilesToUpdate = (
          "cyberAnalysers.ps1",
          "cyberAudit.ps1",
          "cyberBuild.ps1",
          "CyberCollectNetworkConfig.ps1",
          "CyberCompressGo.ps1",
          "CyberCompressGoUpdate.ps1",
          "CyberCreateRunecastRole.ps1",
          "CyberFunctions.ps1",
          "CyberLicenses.ps1",
          "CyberMenu.ps1",
          "CyberPasswordStatistics.ps1",
          "CyberPingCastle.ps1",
          "CyberAuditDevelopersHelp.txt",
          "CyberBginfo.bgi"
          )
         
        Remove-Item "$PSScriptRoot\$FileName" -Force
        try {
            $zipfile = "$PSScriptRoot\$FileName"
            Write-Host "Trying to Download Cyber Audit Tool Updates from $zipurlA to $PSScriptRoot"
            dl $zipurlA $zipfile
            }
        catch {
            Write-Host "[Failed] Error connecting to 1st download site, trying 2nd download option"
            $zipfile = "$PSScriptRoot\$FileName"
            Write-Host "Trying to Download Cyber Audit Tool Updates from $zipurlB to $PSScriptRoot"
            dl $zipurlB $zipfile
            }
        Write-Output 'Extracting Cyber Audit Tool core files updates...'
        Remove-Item -Path "$PSScriptRoot\update" -Recurse -Confirm:$false -Force
        Add-Type -Assembly "System.IO.Compression.FileSystem"
        [IO.Compression.ZipFile]::ExtractToDirectory($zipfile, "$PSScriptRoot\update")

        #replace only newer files
        $FilesToUpdate |foreach {if ((Get-Item $psscriptroot\$_).LastWriteTime -lt (Get-Item $psscriptroot\update\$_).LastWriteTime) {Write-host "[Update Available] $_" -ForegroundColor Red ; Copy-Item "$psscriptroot\update\$_" -Destination "$psscriptroot\$_" -Force} else {Write-host "[No Updates] $_" -ForegroundColor Green}}
