. $PSScriptRoot\CyberFunctions.ps1

$compressUpdates = @{
  Path = "$PSScriptRoot\cyberAnalyzers.ps1",
          "$PSScriptRoot\cyberAudit.ps1",
          "$PSScriptRoot\cyberBuild.ps1",
          "$PSScriptRoot\cyberAttack.ps1",
          "$PSScriptRoot\CyberCollectNetworkConfig.ps1",
          "$PSScriptRoot\CyberCompressGo.ps1",
          "$PSScriptRoot\CyberCreateRunecastRole.ps1",
          "$PSScriptRoot\CyberFunctions.ps1",
          "$PSScriptRoot\CyberLicenses.ps1",
          "$PSScriptRoot\CyberPasswordStatistics.ps1",
          "$PSScriptRoot\CyberPingCastle.ps1",
          "$PSScriptRoot\CyberAuditDevelopersHelp.txt",
          "$PSScriptRoot\CyberBginfo.bgi"
  CompressionLevel = "Fastest"
  DestinationPath = "$PSScriptRoot\goUpdate.zip"
}

$a = ($compressUpdates['path'] -join " ").Replace("$PSScriptRoot\","")
Write-Host [string]$a
#git add $a
#git commit -m "auto commit from powershell script"
#git push