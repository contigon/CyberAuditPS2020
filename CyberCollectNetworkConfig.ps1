<#	
	.NOTES
	===========================================================================
	 Created on:   	02/03/2020 1:11 PM
	 Created by:   	Golan Cohen
     Updated by:    Omer Friedman 29/03/2020
	 Organization: 	Israel Cyber Directorate
	 Filename:     	CyberCoolectNetworkConfig
	===========================================================================
	.DESCRIPTION
		Cyber Audit Tool - Collect Configuration and routing tables from network devices
#>

. $PSScriptRoot\CyberFunctions.ps1
$Host.UI.RawUI.WindowTitle = "Cyber Audit Tool 2020 - CollectNetworkConfig"

$ACQ = ACQ("Network")

$vendors = @("CISCO","HP","H3C","Juniper","Enterasys","Fortigate", "Asa")

$TimeStamp = UniversalTimeStamp

function Check-Table ($totalRows) {
    $counter = 0
    for ($col = 1; $col -le 5;$col++)
    {     
        for ($row = 2; $row -le $totalRows;$row++)
        {
            $cell = $worksheet.Cells.Item($row, $col).Text
            if ([string]::IsNullOrEmpty($cell)){
                    $worksheet.Cells.Item($row, $col).Interior.ColorIndex = 3
                    $counter++
                    $worksheet.Cells.Item(2,8) = "Checking excel table..."
                    $worksheet.Cells.Item(2,8).font.bold = $true
                    $worksheet.Cells.Item(2,8).font.size = 12
                    $worksheet.Cells.Item(2,8).font.colorindex = 45
                }
        }
    }
    if ($counter -ne 0) 
    {
        Write-Host "Please fill the missing data in the excel table" -ForegroundColor Red
        $worksheet.Cells.Item(2,8) = "Please fill the missing data in the excel table"
        $worksheet.Cells.Item(2,8).font.bold = $true
        $worksheet.Cells.Item(2,8).font.size = 12
        $worksheet.Cells.Item(2,8).font.colorindex = 3
        Read-Host "When finished, Press [Enter] to continue"
    }
    else
    {
        Write-Host "Data in table is filled ok"
        $worksheet.Cells.Item(2,8) = "Data in table is filled ok"
        $worksheet.Cells.Item(2,8).font.bold = $true
        $worksheet.Cells.Item(2,8).font.size = 12
        $worksheet.Cells.Item(2,8).font.colorindex = 4
        Read-Host "If all OK, Press [Enter] to continue"
    }
}

function Rename-Dir 
{
    param
    (
		[String]$Num,
        [String]$Dir,
        [String]$IP,
        [String]$Vendor,
        [String]$File
    )
    $FileContent = Get-Content $File | Out-String
    if ($Vendor -eq $vendors[0] -or $Vendor -eq $vendors[6] -or $Vendor -eq $vendors[1] -or $Vendor -eq $vendors[4]) {
        $EndDelimeter = "#"
        $StartDelimeter = "`n"
    } elseif ($Vendor -eq $vendors[2]) {
        $EndDelimeter = ">"
        $StartDelimeter = "<"
    } elseif ($Vendor -eq $vendors[3]) {
        $EndDelimeter = ">";
        $StartDelimeter = "`n"
    } 
    $LastIndex = $FileContent.LastIndexOf($EndDelimeter)
    $Tmp = $FileContent.Substring(0, $LastIndex)
    $FirstIndex = $Tmp.LastIndexOf($StartDelimeter)
    $DeviceName = $Tmp.Substring($FirstIndex + 1) + ' ' + $IP
    Rename-Item $Dir\$Num $Dir\$DeviceName
}
function Get-DeviceConfig
{
    [OutputType([String])]
    param
    (
		[String]$HostAddress,
		[Int]$HostPort,
        [String]$Vendor,
		[String]$Username,
        [SecureString]$Password,
		[String]$Command,
        [String]$Output,
        [Switch]$Append,
        [Int]$Timeout
    )
    $Credentials = New-Object System.Management.Automation.PSCredential $Username, $Password
    $SSHSession = New-SSHSession -ComputerName $HostAddress -Port $HostPort -Credential $Credentials -AcceptKey
    if ($SSHSession.Connected)
    {
        $SessionStream = New-SSHShellStream -SessionId $SSHSession.SessionId
        if ($Vendor -eq $vendors[0]){
            $SessionStream.WriteLine("enable")
            $SessionStream.WriteLine("terminal length 0")
        } elseif ($Vendor -eq $vendors[2]){
            $SessionStream.WriteLine("screen-lengh disable")
            $SessionStream.WriteLine("disable paging")
        } elseif ($Vendor -eq $vendors[1]){
            $SessionStream.WriteLine("no page")
            $SessionStream.WriteLine("enable")
        } elseif ($Vendor -eq $vendors[3]){
            $SessionStream.WriteLine("set cli screen-width 1000")
        } elseif ($Vendor -eq $vendors[4]){
            $SessionStream.WriteLine("terminal more disable")
        } elseif ($Vendor -eq $vendors[5]) {
            $SessionStream.WriteLine("config system console")
            $SessionStream.WriteLine("set output standard")
        } elseif ($Vendor -eq $vendors[6]) {
            $SessionStream.WriteLine("enable")
            $SessionStream.WriteLine("terminal pager 0")
            $SessionStream.WriteLine("no pager")
        }
        $SessionStream.WriteLine($command);
        Start-Sleep -s $Timeout;
        while ($SessionStream.DataAvailable){
            Start-Sleep -s 1;
            $SessionResponse = $SessionStream.Read() | Out-String;
        }
        Write-Host $SessionResponse
        if ($Output){
            if ($Append) {
                Add-Content $Output $SessionResponse;
            } else {
                $SessionResponse > $Output;
            }
        }
        $SSHSessionRemoveResult = Remove-SSHSession -SSHSession $SSHSession
        if (-Not $SSHSessionRemoveResult)
        {
            Write-Error "Could not remove SSH Session $($SSHSession.SessionId):$($SSHSession.Host)"
        }
    }
    else
    {
        throw [System.InvalidOperationException]"Could not connect to SSH host: $($HostAddress):$HostPort"
        $SSHSessionRemoveResult = Remove-SSHSession -SSHSession $SSHSession
        if (-Not $SSHSessionRemoveResult)
        {
            Write-Error "Could not remove SSH Session $($SSHSession.SessionId):$($SSHSession.Host)."
        }
    }
}


$help = @"

        This tool will try to automatically collect configuration and routing tables from network devices
        using SSH protocol.

        This tool is currently supporting these devices:
        1. CISCO (IOS/Nexus)
        2. HP
        3. H3C
        4. Juniper
        5. Enterasys
        6. Fortigate
        7. ASA

        The tool requires as an input an excel file in this format:
        IP | SSH Port | Username | Password | Vendor

        Please follow these steps:
        1. Excel template file will be automatically created at:
           $ACQ\NetworkDevices-$TimeStamp.xlsx
        2. please fill all the data in the correct columns before running the collection task
        3. Do not Close excel and do not use Save As 
        4. Follow the instructions in the script

"@

Write-Host $help 

if (!($Timeout = Read-Host "Choose Timeout (in seconds) between each run (or Enter for 5 seconds)")) { $Timeout = 5 }

$IPCol = 1
$PortCol = 2
$UserCol = 3
$PassCol = 4
$VendorCol = 5
$StartRow = 2

#creating the excel file for this audit
$excel = New-Object -ComObject Excel.Application
$excel.Visible = $false
$workbook = $excel.Workbooks.Add()
$worksheet = $workbook.Worksheets.Item(1)
$worksheet.Name = "DeviceList"
$worksheet._DisplayRightToLeft = $false

$worksheet.Cells.Item(1,1) = "IP"
$worksheet.Cells.Item(1,2) = "SSH Port"
$worksheet.Cells.Item(1,3) = "User Name"
$worksheet.Cells.Item(1,4) = "Password"
$worksheet.Cells.Item(1,5) = "Vendor"
$worksheet.Cells.range("A1:E1").font.bold = $true
$worksheet.Cells.range("A1:E1").font.size = 12
$worksheet.Cells.range("A1:E1").font.colorindex = 4

$worksheet.Cells.Item(1,8) = "Please save [Ctrl+S] after changes !!!"
$worksheet.Cells.Item(1,8).font.bold = $true
$worksheet.Cells.Item(1,8).font.size = 12
$worksheet.Cells.Item(1,8).font.colorindex = 3

$VendorsHeader = "CISCO,HP,H3C,Juniper,Enterasys,Fortigate,ASA"
$Range = $WorkSheet.Range("E2:E100")
$Range.Validation.add(3,1,1,$VendorsHeader)
$Range.Validation.ShowError = $False

$excel.DisplayAlerts = $false
$FilePath = "$ACQ\NetworkDevices-$TimeStamp.xlsx"
$worksheet.SaveAs($FilePath)

$excel.Visible = $true

$action = Read-Host "Press [S] to save file and start collecting config data (or Enter to quit)"
$worksheet.SaveAs($FilePath)

if ($action -eq "S") {
    $length = $worksheet.UsedRange.Rows.Count
    Check-Table ($length)
    Write-Host "Creating connection and retrieving configuration files,Please wait..."
    for ($i = $StartRow; $i -le $length; $i++){
        $ip = $worksheet.Cells.Item($i, $IPCol).Text
        $port = $null 
        $port = $worksheet.Cells.Item($i, $PortCol).Text
        if ([String]::IsNullOrEmpty($port)) {
            $port = 22
        }
        $username = $worksheet.Cells.Item($i, $UserCol).Text
        $password = $worksheet.Cells.Item($i, $PassCol).Text
        $vendor = $worksheet.Cells.Item($i, $VendorCol).Text
        $savePath = "$ACQ\$vendor-$ip-$port\"
        Write-Host "Trying to collect data from device: $Vendor ip: $ip port: $port"
        try {
        	$null = New-Item -Path $savePath -ItemType Directory 
	        switch($vendor)
	        {
	            #CISCO
	            $vendors[0]{
 				    Get-DeviceConfig -HostAddress $ip -Username $username -Password $password -AcceptKey -Vendor $vendors[0] -Command "sh run" -Output $savePath'sh run.txt'
                    Get-DeviceConfig -HostAddress $ip -Username $username -Password $password -AcceptKey -Vendor $vendors[0] -Command "show ip route vrf *" -Output $savePath'route.txt'
                    Get-DeviceConfig -HostAddress $ip -Username $username -Password $password -AcceptKey -Vendor $vendors[0] -Command "sh snmp user" -Output $savePath'snmp.txt'
                    Get-DeviceConfig -HostAddress $ip -Username $username -Password $password -AcceptKey -Vendor $vendors[0] -Command "sh conf | include hostname" -Output $savePath'run.txt'
                    Get-DeviceConfig -HostAddress $ip -Username $username -Password $password -AcceptKey -Vendor $vendors[0] -Command "sh ver" -Output $savePath'run.txt' -a
                    Get-DeviceConfig -HostAddress $ip -Username $username -Password $password -AcceptKey -Vendor $vendors[0] -Command "show access-lists" -Output $savePath'run.txt' -a
	                #Rename-Dir -Num $i -Dir $dir -IP $ip -Vendor $vendor -File $dir\$i\'run.txt'
	            }
	            #H3C
	            $vendors[2]{
                    Get-DeviceConfig -HostAddress $ip -Username $username -Password $password -AcceptKey -Vendor $vendors[2] -Command "display" -Output $savePath\'run.txt'
                    Get-DeviceConfig -HostAddress $ip -Username $username -Password $password -AcceptKey -Vendor $vendors[2] -Command "display ip routing-table" -Output $savePath\'route.txt'
	                #Rename-Dir -Num $i -Dir $dir -IP $ip -Vendor $vendor -File $dir\$i\'run.txt'
	            }
	            #HP
	            $vendors[1]{
                    Get-DeviceConfig -HostAddress $ip -Username $username -Password $password -AcceptKey -Vendor $vendors[1] -Command "sh run" -Output $savePath\'run.txt'
                    Get-DeviceConfig -HostAddress $ip -Username $username -Password $password -AcceptKey -Vendor $vendors[1] -Command "show ip route" -Output $savePath\'route.txt'
	                #Rename-Dir -Num $i -Dir $dir -IP $ip -Vendor $vendor -File $dir\$i\'run.txt'
	            }
	            #Juniper
	            $vendors[3]{
                    Get-DeviceConfig -HostAddress $ip -Username $username -Password $password -AcceptKey -Vendor $vendors[3] -Command "show configuration | display inheritance | no-more" -Output $savePath\'run.txt'
                    Get-DeviceConfig -HostAddress $ip -Username $username -Password $password -AcceptKey -Vendor $vendors[3] -Command "show chassis hardware | no-more" -Output $savePath\'run.txt' -a
                    Get-DeviceConfig -HostAddress $ip -Username $username -Password $password -AcceptKey -Vendor $vendors[3] -Command "show route logical-system all | no-more" -Output $savePath\'route.txt'
                    Get-DeviceConfig -HostAddress $ip -Username $username -Password $password -AcceptKey -Vendor $vendors[3] -Command "show route all | no-more" -Output $savePath\'route-allW.txt'
	                #Rename-Dir -Num $i -Dir $dir -IP $ip -Vendor $vendor -File $dir\$i\'run.txt'
	            }
	            #Enterasys
	            $vendors[4]{
                    Get-DeviceConfig -HostAddress $ip -Username $username -Password $password -AcceptKey -Vendor $vendors[4] -Command "show config all" -Output $savePath\'run.txt'
                    Get-DeviceConfig -HostAddress $ip -Username $username -Password $password -AcceptKey -Vendor $vendors[4] -Command "show ip route" -Output $savePath\'route.txt'
	                #Rename-Dir -Num $i -Dir $dir -IP $ip -Vendor $vendor -File $dir\$i\'run.txt'
	            }
	            #Fortigate
	            $vendors[5]{
	                Get-DeviceConfig -HostAddress $ip -HostPort $port -Username $username -Password $password -Vendor $vendors[5] -Command "get system status" -Output $savePath\'config.txt'
	                Get-DeviceConfig -HostAddress $ip -HostPort $port -Username $username -Password $password -Vendor $vendors[5] -Command "show" -Output $savePath\'config.txt' -Append
	                Get-DeviceConfig -HostAddress $ip -HostPort $port -Username $username -Password $password -Vendor $vendors[5] -Command "get router info routing-table" -Output $savePath\'route.txt'
	                #Rename-Dir -Num $i -Dir $dir -IP $ip -Vendor $vendor -File $dir\$i\'config.txt'
	            }
	            #ASA
	            $vendors[6]{
	                Get-DeviceConfig -HostAddress $ip -HostPort $port -Username $username -Password $password -Vendor $vendors[6] -Command "show run" -Output $savePath\'run.txt'
	                Get-DeviceConfig -HostAddress $ip -HostPort $port -Username $username -Password $password -Vendor $vendors[6] -Command "show access-lists" -Output $savePath\'run.txt' -Append
	                Get-DeviceConfig -HostAddress $ip -HostPort $port -Username $username -Password $password -Vendor $vendors[6] -Command "show route" -Output $savePath\'route.txt'
	                #Rename-Dir -Num $i -Dir $dir -IP $ip -Vendor $vendor -File $dir\$i\'run.txt'
	            }
            }
        }
        catch {
        	Write-Host "[Failure] Error connecting to device: $Vendor ip: $ip port: $port" -ForegroundColor Red
        }
    }
}

[void]$workbook.Close($false)
$excel.DisplayAlerts = $true
[void]$excel.quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null