# Requires -Version 3.0

<#

.SYNOPSIS
    CSC Windows Server Health Check Script

.DESCRIPTION
    Will run a number of queries against a list of servers retriving information useful to Wintel Server Engineers. The main purpose is to
    be used as an automated healthcheck script to be performed after scheduled work or during incidents.
    Will only run against Windows 2008, 2008R2, 2012 or 2012R2 servers. If executed against a Windows 2003 Server an error will be generated 
    in the Powershell console and the HTML report will be incomplete.

.PARAMETER Computers
    List of computers to perform the health check against. Can be an array of strings typed into the console or a text file containing
    the servers you wish to check. If nothing is provided will default to the local computer

.PARAMETER OutputFilePath
    Path that will contain html reports once the script is complete. If nothing is provided will be the current working directory.

.PARAMETER VerboseMode
    Switch value that will determine if all script procesing is written to the PowerShell Console. Defaults to off.

.PARAMETER EmailReport
    Switch value to have HTML report sent as an email. Defaults to off. 

.EXAMPLE
    OSHealthCheckv4.75.PS1
    Run the health check with the default values. The server scanned will be the local computer, output folder is .\ and verbose mode and email are disabled.

.EXAMPLE
    OSHealthCheckv4.75.PS1 -Computers "Server1","Server2","Server3"
    Run the health check against Server1, Server2 and Server3. 

.EXAMPLE
    OSHealthCheckv4.75.PS1 -VerboseMode -EmailReport
    Run the health check with the default values for -computers and -outputfilepath, but with VerboseMode ane EmailReport enabled.

.EXAMPLE
    OSHealthCheckv4.75.PS1 -Computers C:\Servers.txt -OutputFilePath "C:\Scripts\Out" -VerboseMode -EmailReport
    Run the health check against a list of computers stored in C:\Servers.txt. HTML reports will be saved to C:\Scripts\Out. Verbose mode is on, so all content will be written to the Powershell Console and the HTML report will be sent via email.


#>


[CmdletBinding()]
    param(
        [Parameter(Mandatory=$False,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True,
            Position=0,
            HelpMessage="List of Computers to perform health check against.")]
        [string[]]$computers = $env:COMPUTERNAME,
        [Parameter(Mandatory=$False,
            Position=1,
            HelpMessage="Output path for HTML reports")]
        [string]$OutputFilePath = "$($(Resolve-Path .\).Path)",
		[Parameter(Mandatory=$False,
		    Position=2,
		    HelpMessage="Choose whether script will be run in verbose or quiet mode.")]
        [switch]$VerboseMode,
        [Parameter(Mandatory=$False,
            Position=3,
            HelpMessage="Choose to send the HTML report via email or not.")]
        [switch]$EmailReport
)
PROCESS {

# Check if the $computers variable is a text file or an array of strings

if ($computers -match ".*\.txt$") {
        $colComputer = get-content $computers
    } else {        
        $colcomputer = $computers
}

$objFilePath = $OutputFilePath

# Number of days in the past to check event logs
$global:strEventDays = "1"

# Disk space free % thresholds for yellow and red alerts
$global:strDiskYellow = "20"
$global:strDiskRed = "10"

# Number of processes to report on for CPU % usage and Memory
$global:strProcesses = "10"

# Number of days in the past to check for installed patches
$global:strPatchDays = "30"

# Set the System locale to en-US required for the script to run due to .Net bugs with other locales
$strOriginalLocale = Get-Culture
[System.Threading.Thread]::CurrentThread.CurrentCulture = New-Object "System.Globalization.CultureInfo" "en-US"

<# A flag for the over all health state of the server being checked. Will be used for the final console report and can be the following levels:
Green - No major issues found. May still have warnings in the event logs but generally speaking the server is fine. All systems start at Green

Yellow - Server has low disk space and / or errors in the event log but is otherwise still running. The errors should be checked closely
and disk space analysed to see if space can be freed up

Red - The server has a major problem that is impacting functionality. Disk space may be less than 10% free, there are errors in the logs,
network connectivity and RDP may not be working. The server needs to be manually checked immediately.
#> 
$global:strHealthState = "Green"

# Email variables
$strEmailTo = ""
$strEmailSubject = "Automated System Health Check Report for $($objComputer)"
$strEmailSMTP = ""
$strEmailFrom = ""
$global:strEmail = $EmailReport

#css Style

$style = @"
<style>
    body {
    color:#333333;
    font-family:Calibri,Tahoma;
    font-size: 10pt;
    }
        h1 {
        text-align:center;
    }
        h2 {
        border-top:1px solid #666666;
    }
        th {
        font-weight:bold;
        color:#eeeeee;
        background-color:#333333;
    }
    .odd { background-color:#ffffff; }
    .even { background-color:#dddddd; }
    .errorOdd { 
        background-color:#BABAB9;
        color:#ff0000; }
    .errorEven { 
        background-color:#BABAB9;
        color:#ff0000; }
    .warningOdd {
        background-color:#535351;
        color:#FFCC00;
        }
    .warningEven {
        background-color:#535351;
        color:#FFCC00;
         }
</style>
"@
 

# Fiber Chanel HBA Information

function get-hbainfo {

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)][String]$objComputer
    )
    $colHBAInfo = @()
	if ($global:strVerbose){
		write-host "============================================================================================"-ForegroundColor Cyan
		write-host "Retrieving FC HBA information for $($objComputer)										" -ForegroundColor Cyan
		write-host "============================================================================================"-ForegroundColor Cyan
	}
    $colHBA = Get-WmiObject -Class MSFC_FCAdapterHBAAttributes -Namespace root\WMI -ComputerName $objComputer -ErrorAction SilentlyContinue

        if ($colhba) {
            foreach ($objHBA in $colHBA) {

            $colHBAInfo +=  [PSCustomObject] @{

                "Computername" = $objComputer
                "Node WWN" = (($objHBA.NodeWWN) | ForEach-Object {"{0:X2}" -f $_}) -join ":"
                "Model" = $objHba.Model
                "Model Description" = $objHBA.ModelDescription
                "Driver Version" = $objHBA.DriverVersion
                "Firmware Version" = $objHBA.FirmwareVersion
                "Active" = $objHBA.Active

            }    
        }
    
    
    } else {
    if ($global:strVerbose){
        write-host "No FC HBAs found on server $($objComputer)" -ForegroundColor Yellow
    }
    #$colHBAInfo = "No FC HBAs found on server $($objComputer)"
        $colHBAInfo +=  [PSCustomObject] @{

                "Computername" = "No FC HBAs found on server $($objComputer)"
                "Node WWN" = ""
                "Model" = ""
                "Model Description" = ""
                "Driver Version" = ""
                "Firmware Version" = ""
                "Active" = ""

            } 

    }
$colHBAInfo

}

# Operating System Information

function get-osinfo {

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)][String]$objComputer

    )
	if ($global:strVerbose){
		 write-host "============================================================================================" -ForegroundColor Cyan
		 Write-Host "Retrieving Operating System information from $($objComputer)                             " -ForegroundColor Cyan
		 write-host "============================================================================================" -ForegroundColor Cyan
	}
     $colOSystemInfo = Get-WmiObject -Class Win32_OperatingSystem -computername $objComputer
     $colComputerSystem = Get-WmiObject win32_computersystem -ComputerName $objComputer
        
        # Check connection to TCP 3389 for RDP
        # Create a TCP socket on port 3389/TCP to the target server
        # If the connection succeeds, report and close the port
        # Reasons for this failing could be RDP not listening, RDP using a different port,
        # 3389/TCP firewalled etc
        $objRdpState = New-Object Net.Sockets.TcpClient($objComputer, 3389)
        if ($objRdpState.Connected -eq "true") {
            $objRdpStateFinal = "RDP Connected Successfully"
            $objRdpState.Close()           
            } else {
            $objRdpStateFinal = "RDP Connection Failed"
            if ($global:strHealthState -ne "Red") {
                write-host "Warning: System health state is being set to Red as RDP connection test has failed" -ForegroundColor Red
                $global:strHealthState = "Red"
            }
        }

        $objBootTime =  ([wmi]"").ConvertToDateTime($($colOSystemInfo.LastBootUpTime))
        $colOSSystemInfoDetails += [PSCustomObject] @{
            
            "System Name" = $colOSystemInfo.CSName
            "Domain Name" = $colComputerSystem.Domain
            "Operating System" = $colOSystemInfo.Caption
            "Service Pack" = $colOSystemInfo.CSDVersion
            "OS Architecture" = $colOSystemInfo.OSArchitecture
            "RAM Total (GB)" = [Math]::Round(($colOSystemInfo.TotalVisibleMemorySize/1MB),2)
            "RAM Free (GB)" = [Math]::Round(($colOSystemInfo.FreePhysicalMemory/1MB),2)
            "Hardware Manufacturer" = $colComputerSystem.Manufacturer
            "Hardware Model" = $colComputerSystem.Model
            "Boot Device" = $colOSystemInfo.SystemDevice
            "Boot Drive" = $colOSystemInfo.SystemDrive
            "Windows Directory" = $colOSystemInfo.WindowsDirectory
            "Last Boot Time" = "$($objBootTime.ToLongDateString()), $((New-TimeSpan -Start $objBootTime  -End (get-date)).Days) days ago"
            "Server Domain Roles" = $($colComputerSystem.Roles) -join ", "
            "RDP State" = $objRdpStateFinal        
        
        } 


$colOSSystemInfoDetails 

}


# Logical Disk Information

function get-diskinfo {

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)][String]$objComputer

    )
	if ($global:strVerbose){
		write-host "============================================================================================" -ForegroundColor Cyan
		write-host "Retrieving logical disk information from $($objComputer)" -ForegroundColor Cyan
		write-host "============================================================================================" -ForegroundColor Cyan
	}
    $colDiskDetail = @()
    $colDiskInfo = Get-WmiObject win32_volume -ComputerName $objComputer -Filter "DriveType = 3"
    $objDiskCount = 0
    $objDiskTotal = $colDiskInfo.Count

    foreach ($objDiskInfo in $colDiskInfo) {
        $objDiskCount++
        $strFreeSpaceTag = "Normal"
        
        $objDiskFreeSpace = [Math]::Round($($objDiskinfo.Freespace)/$($objDiskinfo.Capacity)*100)
        
            if ($objDiskFreeSpace -le $($global:strDiskYellow)) {

                if ($objDiskFreeSpace -le $($global:strDiskRed)) {
                                              
                    $strFreeSpaceTag = "Critical"
                    write-host "Warning: Disk $($objDiskInfo.Name) has less than $($global:strDiskRed)% free space currently at $($objDiskFreeSpace)%" -ForegroundColor Red    
                    if ($global:strHealthState -ne "Red") {
                        $global:strHealthState = "Red"
                        write-host "Warning: System health state is being set to Red due to critically low disk space" -ForegroundColor Red
                    }
                } else {            
                   
                    $strFreeSpaceTag = "Warning"
                    write-host "Warning: Disk $($objDiskInfo.Name) has less than $($global:strDiskYellow)% free space currently at $($objDiskFreeSpace)%" -ForegroundColor Yellow
                    if ($global:strHealthState -ne "Red") {
                        $global:strHealthState = "Yellow"
                    write-host "Warning: System health state is being set to Yellow due to low disk space" -ForegroundColor Yellow
                    }  
                }
           

                }
                 $colDiskDetail += [PSCustomObject] @{
        
                "Drive Letter / Mount Point" = $objDiskInfo.Name
                "Free Space Rating" = $strFreeSpaceTag
                "Disk Size (GB)" = [Math]::Round($($objDiskInfo.Capacity)/1GB)
                "Disk Free Space (GB)" = [Math]::Round($($objDiskInfo.FreeSpace)/1GB)
                "Disk Free Space (%)" = [Math]::Round($($objDiskinfo.Freespace)/$($objDiskinfo.Capacity)*100)
                "Volume Name" = $objDiskinfo.Label
                "Disk Number" = "$($objDiskCount) of $($objDiskTotal)"     
            
            } 
        } 
$colDiskDetail
}

# Get a list of all running processes, but currently not used in the script (is kind of useless)

function Get-ProcessInfo {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$objComputer
    )
	if ($global:strVerbose){
		write-host "============================================================================================" -ForegroundColor Cyan
		Write-Host "Retrieving running process information from $($objComputer)" -ForegroundColor Cyan
		write-host "============================================================================================" -ForegroundColor Cyan
	}
    $colProcessess = Get-WmiObject -class Win32_Process -ComputerName $objComputer
    $colProcessDetail = @()

    foreach ($objProcess in $colProcessess) {
    
        $colProcessDetail += [PSCustomObject] @{

            "Process Name" = $objProcess.ProcessName
            "Process Path" = $objProcess.ExecutablePath
        }

    }


$colProcessDetail
}

# Get details of physical Network Interfaces installed

function get-NICinfo {

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)][String]$objComputer
    )
	if ($global:strVerbose){
		write-host "============================================================================================" -ForegroundColor Cyan
		Write-Host "Retrieving installed Network Interface Cards for $($objComputer)" -ForegroundColor Cyan
		write-host "============================================================================================" -ForegroundColor Cyan
	}
    $colNIC = Get-WmiObject win32_NetworkAdapter -ComputerName $objComputer -Filter "PhysicalAdapter=True"
    $colNICDetails = @()

    foreach ($objNic in $colNIC) {
        
        $objNicConnectionStatus = Switch ($objNic.NetConnectionStatus) {

             2 {"Connected"}
             5 {"Hardware Disabled"}
             7 {"Media Disconnected "}
             Default {"Disconnected"}

        }
        
        $colNICDetails += [PSCustomObject]@{

        "NIC Name" = $objNic.ServiceName
        #"Speed" = [Math]::Round($($objNic.Speed) / 1GB)        
        "Manufacturer" = $objNIC.Manufacturer
        "Product Name" = $objNic.ProductName
        "MAC Address" = $objNic.MACAddress
        "Enabled" = $objNic.NetEnabled
        "Connection Status" = $objNicConnectionStatus

        }

    }    


$colNICDetails
}

# Get physical CPU inventory

function get-cpuinfo {

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)][String]$objComputer
    )
	if ($global:strVerbose){
		write-host "============================================================================================" -ForegroundColor Cyan
		Write-Host "Retrieving physical CPU information for $($objComputer)" -ForegroundColor Cyan
		write-host "============================================================================================" -ForegroundColor Cyan
	}
    $colCPU = Get-WmiObject win32_processor -ComputerName $objComputer
    $colCPUDetails = @()

    foreach ($objCPU in $colCPU) {
        
        $colCPUDetails += [PSCustomObject] @{
            
            "ID" = $objCPU.DeviceID
            "Description" = $objCPU.Caption
            "Name" = $objCPU.Name
            "Manufacturer" = $objCPU.Manufacturer
            "MAx Clock Speed" = $objCPU.MaxClockSpeed
            "Socket" = $objCPU.SocketDesignation
            "Current load %" = $objCPU.LoadPercentage

        }

    }


$colCPUDetails
}

# Get any service that is set to Automatic but is currently not running

function get-AutoServicesNotrunning {

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)][String]$objComputer
    )
	if ($global:strVerbose){
		write-host "============================================================================================" -ForegroundColor Cyan
		write-host "Retrieving list of services set to Automatic not currently running for $($objComputer)" -ForegroundColor Cyan
		write-host "============================================================================================" -ForegroundColor Cyan
	}
    $colServices = get-wmiobject win32_service -ComputerName $objComputer | where {($_.StartMode -eq "Auto") -and ($_.State -eq "Stopped")}
    $colServicesInfo = @()
    foreach ($objService in $colServices) {
        if ($global:strVerbose){
            write-host "Service $($objService.Name) is set to start mode $($objService.Startmode) but is currently in state $($objService.State)" -ForegroundColor Yellow
        }
        $colServicesInfo += [PSCustomObject] @{
            "Name" = $objService.Name
            "State" = $objService.state
            "Start Mode" = $objService.Startmode
        }
    }

$colServicesInfo
}

# Get the top x processes by CPU usage

function get-topProcessesCPU {

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)][String]$objComputer

    )
    if ($global:strVerbose){
		write-host "============================================================================================" -ForegroundColor Cyan
		write-host "Retrieving list of top $($global:strProcesses) processes by CPU % usage on $($objComputer)" -ForegroundColor Cyan
		write-host "============================================================================================" -ForegroundColor Cyan
	}
    $colProcessesTop10Details = @()
    $colProcessesTop10 = Get-WmiObject Win32_PerfFormattedData_PerfProc_Process -ComputerName $objComputer | sort-object PercentProcessorTime -Descending| where-object {($_.Name -ne "_Total") -and ($_.Name -ne "Idle")} | select -first $global:strProcesses

    foreach ($objProcessTop10 in $colProcessesTop10) {

        $colProcessesTop10Details += [PSCustomObject] @{

            "Name" = $objProcessTop10.Name
            "Process ID" = $objProcessTop10.IDProcess
            "Processor Time %" = $objProcessTop10.PercentProcessorTime
        }
    }

$colProcessesTop10Details

}

# Get the top x processes by MEM consumed

function get-topProcessesMEM {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True)][string]$objComputer
    )
	if ($global:strVerbose){
		write-host "============================================================================================" -ForegroundColor Cyan
		write-host "Retrieving top $($global:strProcesses) processes by memory consumed in MB for $($objComputer)" -ForegroundColor Cyan
		write-host "============================================================================================" -ForegroundColor Cyan
	}

    $colProcessMemory = Get-Process -ComputerName $objComputer | sort-object WS -Descending | select-object -first $global:strProcesses
    $colProcessMemoryInfo =@()

    foreach ($objProcessMemory in $colProcessMemory) {

        $colProcessMemoryInfo += [PSCustomObject] @{
     
            "Process Name" = $objProcessMemory.Name
            "Process ID" = $objProcessMemory.ID
            "Working Set (MB)" = [Math]::Round(($($objProcessMemory.WorkingSet/1MB)),0)

        }

    }

$colProcessMemoryInfo

}

# Get the last reboot reason from the system log User32 event

function get-LastRebootReason {

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)][String]$objComputer
    )
	if ($global:strVerbose){
		write-host "============================================================================================" -ForegroundColor Cyan
		write-host "Retrieving the most recent shutdown details on $($objComputer)" -ForegroundColor Cyan
		write-host "============================================================================================" -ForegroundColor Cyan
	}
    

    $colRebootEvents = (Get-WinEvent -FilterHashtable @{logname='System'; id=1074} -ComputerName $objComputer | select -First 1)
    #$colRebootEvents = (Get-WinEvent -FilterHashtable @{logname='System'; id=1074} -ComputerName $objComputer | select -First 2)[1]
    $global:colRebootDetails = @()

    foreach ($objRebootEvent in $colRebootEvents) {

        $strShutdownDate = [String]$objRebootEvent.TimeCreated
        $strShutdownEvent = [String]($($objRebootEvent | select -ExpandProperty Message) -split "`n")[0]
        $strShutdownType = [String]((($($objRebootEvent | select -ExpandProperty Message) -split "`n")[2] -split "Shutdown Type: "  )[1])
        $strshutdownType = (get-culture).TextInfo.ToTitleCase($strShutdownType)
        $strShutdownComment = [String](($($objRebootEvent | select -ExpandProperty Message) -split "`n")[3] -split "Comment: ")[1]
        $global:colRebootDetails += [PSCustomObject] @{

            "Date" = $strShutdownDate
            "Shutdown Event" =  $strShutdownEvent
            "Shutdown Type" =  $strShutdownType
            "Shutdown Comment" =  $strShutdownComment
        
        }
    if ($global:strVerbose){
        $global:colRebootDetails | Format-List
    }
    
    } 
}

# Get all Microsoft Patches installed in the last x days

function get-InstalledPatches {
        
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)][String]$objComputer
    )
	if ($global:strVerbose){
		write-host "============================================================================================" -ForegroundColor Cyan
		write-host "Retrieving list of Microsoft patches installed on $($objComputer) in the last $($global:strPatchDays) days" -ForegroundColor Cyan
		write-host "============================================================================================" -ForegroundColor Cyan
	}

    $colInstalledPatches = Get-WmiObject -ComputerName $objComputer Win32_QuickFixEngineering | where-object { (Get-date($_.Installedon)) -gt (get-date).adddays(-$($global:strPatchDays)) }
    $colInstalledPatchesInfo = @()

    if (!$colInstalledPatches) {
        
        write-host "Warning: No Microsoft updates have been installed in the last $($global:strPatchDays) days" -ForegroundColor Yellow

    } else {

        foreach ($objInstalledPatch in $colInstalledPatches) {
    
            $colInstalledPatchesInfo += [PSCustomObject] @{

                "Hotfix ID" = $objInstalledPatch.HotFixID
                "Type" = $objInstalledPatch.Description
                "URL" = $objInstalledPatch.Caption
                "Installed By" = $objInstalledPatch.InstalledBy
                "Installed On" = $objInstalledPatch.InstalledOn

            }
        }
    }

$colInstalledPatchesInfo
}

# Get a collection of all warnings and errors in the application and event logs

function get-systemandapplogs {
            
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)][String]$objComputer
    )
	if ($global:strVerbose){
		write-host "============================================================================================" -ForegroundColor Cyan
		write-host "Retrieving errors and warnings from the system and application log on $($objComputer) for the last $($global:strEventDays) day(s) " -ForegroundColor Cyan
		write-host "============================================================================================" -ForegroundColor Cyan
	}

    $WinEventError = $null  
    $colSystemEvents = Get-WinEvent -FilterHashtable @{Logname='System','Application'; Level=1,2,3; starttime=$((get-date).adddays(-$($global:strEventDays)))} -ComputerName $objComputer -ErrorAction SilentlyContinue -ErrorVariable WinEventError
    $colSystemEventsInfo = @()

    if (!$WinEventError) {
        
        if ($global:strHealthState -ne "Red") {
            $global:strHealthState = "Yellow"
            write-host "Warning: System health state is being set to Yellow due to errors and warnings in the event logs" -ForegroundColor Yellow
        }
        foreach ($objSystemEvent in $colSystemEvents) {
    
            $colSystemEventsInfo += [PSCustomObject] @{
        
                "Index" = $objSystemEvent.RecordId
                "Type" = $objSystemEvent.LevelDisplayName
                "Time" = $objSystemEvent.TimeCreated
                "Event ID" = $objSystemEvent.Id
                "Log Name" = $objSystemEvent.LogName
                "Source" = $objSystemEvent.ProviderName
                "Message" = $objSystemEvent.Message
            }
        }
    } else {

        write-host "No errors or warnings found in System and Application Logs" -ForegroundColor Green
        #write-host "$(($error[0]).exception.Message)" -ForegroundColor Red
        #$colSystemEventsInfo = "$(($error[0]).exception.Message)"
        $colSystemEventsInfo += [PSCustomObject] @{
        
                "Index" = "No errors or warnings found in System and Application Logs"
                "Type" = ""
                "Time" = ""
                "Event ID" = ""
                "Log Name" = ""
                "Source" = ""
                "Message" = ""
            }
    }
    $colSystemeventsInfo
}

# Get the IP address details of each logical network connection

function get-NicIPAddress {
            
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)][String]$objComputer
    )
	if ($global:strVerbose){
		write-host "============================================================================================" -ForegroundColor Cyan
		write-host "Retrieving IP address details on $($objComputer) " -ForegroundColor Cyan
		write-host "============================================================================================" -ForegroundColor Cyan
	}
    $colNicIP = get-wmiobject -class Win32_NetworkAdapterConfiguration -computername $objComputer -filter IPEnabled=True
    $colNicIpDetails = @()

    foreach ($objNicIp in $colNicIP) {
        $colNicIpDetails += [PSCustomObject] @{
            
            "Description" = $objNicIp.Description
            "IP Address(es)" = $($objNicIp.IPAddress) -join ", "
            "Subnet Mask" = $($objNicIp.IPSubnet) -join ", "
            "Default Gateway" = $($objNicIp.DefaultIPGateway) -join ", "
            "DNS Server Search Order" = $($objNicIp.DNSServerSearchOrder) -join ", "
            "Priamry DNS Domain Suffix" = $objNicIp.DNSDomain
            "DNS Domain Suffix Search Order" = $($objNicIp.DNSDomainSuffixSearchOrder) -join ", "
            "Primary WINS Server" = $objNicIp.WINSPrimaryServer
            "Secondary WINS Server" = $objNicIp.WINSSecondaryServer
            "MAC Address" = $objNicIp.MACAddress
        }

    }
$colNicIpDetails
}

# Send html report as an email

function send-emailreport {
    
    if ($global:strEmail.IsPresent) {
        $objEmailBody = get-content "$($objFilepath)\$($objComputer).html"
        $objEmailBody = @"
            $objEmailBody
"@
        
        write-host "Sending copy of report via email"
        Send-MailMessage -to $strEmailTo -Subject $strEmailSubject -SmtpServer $strEmailSMTP -body $objEmailBody -BodyAsHtml -from $strEmailFrom
    }

}

# Test connectivity to target system

function test-SystemConnectivity {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)][String]$objComputer
    )
    $objTestDetails = @()
    $Global:objTestResult = $True
    try {
        write-host "============================================================================================" -ForegroundColor Cyan
        Write-Host "Attempting ping test to $($objComputer)" -ForegroundColor Cyan
        #write-host "============================================================================================" -ForegroundColor Cyan
        $objPingTest = Test-Connection -ComputerName $objComputer -Count 1 -ErrorAction Stop
    
    } catch {

            $Global:objTestResult = $False
            write-host "`n"
            Write-Host "Ping failed on $($objComputer)" -ForegroundColor Red
    }

    try {
        #write-host "============================================================================================" -ForegroundColor Cyan
        Write-Host "Attempting WMI test to $($objComputer)" -ForegroundColor Cyan
       # write-host "============================================================================================" -ForegroundColor Cyan
        $objWMITest = Get-WmiObject Win32_OperatingSystem -ComputerName $objComputer -ErrorAction Stop
        if ($objWMITest.Caption -like "Microsoft(R) Windows(R) Server 2003*") {
            write-host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" -ForegroundColor Red
            write-host "Warning: Windows 2003 is not supported by this script" -ForegroundColor Red
            write-host "Some of the health check functions will generate errors on the Powershell console" -ForegroundColor Red
            write-host "and the HTML report will be incomplete" -ForegroundColor Red
            write-host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" -ForegroundColor Red
            
        }

    } catch {

            $Global:objTestResult = $False
            write-host "`n"
            Write-Host "WMI Connection on $($objComputer) failed with error $($error[0].Exception.Message)" -ForegroundColor Red            
    }
}
function Set-AlternatingCSSClasses {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$True,ValueFromPipeline=$True)]
		[string]$HTMLFragment,
		[Parameter(Mandatory=$True)]
		[string]$CSSEvenClass,
		[Parameter(Mandatory=$True)]
		[string]$CssOddClass
	)
    [xml]$xml = $HTMLFragment
    $table = $xml.SelectSingleNode('table')
    $classname = $CSSEvenClass
    $counter = 1
    foreach ($tr in $table.tr) {
        
        if ($counter -eq 0) {
	        if ($classname -eq $CSSEvenClass -or $classname -eq "errorEven" -or $classname -eq "warningEven") {
                switch ($tr.td[1]) {
                 #   Stopped {$classname = "errorOdd"}
                    PoweredOff {$classname = "errorOdd"}
                    red {$classname = "errorOdd"}
                    error {$classname = "errorOdd"}
					critical {$classname = "errorOdd"}
                    yellow {$classname = "warningOdd"}
                    warning {$classname = "warningOdd"}
					default {$classname = $CssOddClass}
                }
                
	        } else {
                switch ($tr.td[1]) {
                 #   Stopped {$classname = "errorEven"}
                    PoweredOff {$classname = "errorEven"}
                    red {$classname = "errorEven"}
                    error {$classname = "errorEven"}
					critical {$classname = "errorEven"}
                    yellow {$classname = "warningEven"}
                    warning {$classname = "warningEven"}
                    default {$classname = $CSSEvenClass}
                }
                
	        }
        }
        
		$class = $xml.CreateAttribute('class')
		$class.value = $classname
        
		$tr.attributes.append($class) | Out-null
        $counter = 0
	}
	$xml.innerxml | out-string
}

foreach ($objComputer in $colComputer) {
		
	$objComputer = $($objComputer).ToUpper()

    if (!$verboseMode) {
        write-host "Starting automated health check on server $($objComputer)" -ForegroundColor Cyan
        write-host "Note: Verbose mode is OFF" -backgroundcolor Yellow -ForegroundColor Magenta 
        Write-Host "Limited information will be written to the Powershell Console" -ForegroundColor Cyan
	    $global:strVerbose = $False
    } else {
        write-host "Starting automated health check on server $($objComputer)" -ForegroundColor Cyan
        write-host "Verbose mode is ON" -backgroundcolor Yellow -ForegroundColor Magenta
        Write-Host "All information will be written to the Powershell Console" -ForegroundColor Cyan
	    $global:strVerbose = $True
    }
	Test-SystemConnectivity $objComputer

		if ($Global:objTestResult -eq $True) {
#			write-host "============================================================================================" -ForegroundColor Cyan
			write-host "Ping and WMI tests passed successfully on $($objComputer)" -ForegroundColor Cyan
			write-host "============================================================================================" -ForegroundColor Cyan

			$objFilepathOutput = Join-Path $objFilepath -ChildPath "$($objComputer).html"

			$objOSInfo = get-osinfo $objComputer
			$objOSInfo
			$objHtmlOS = @"
			<h2 id="osInfo">$($objComputer) System Information</h2>
			<table class="list">
			<th>System Name</th>
			<th> $($objOSInfo.'System Name')</th>
			<tr class="odd">
			<td>Domain Name</td>
			<td>$($objOSInfo.'Domain Name')</td>
			</tr>
			<tr class="even">
			<td>Operating System</td>
			<td>$($objOSInfo.'Operating System')</td>
			</tr>
			<tr class="odd">
			<td>Service Pack</td>
			<td>$($objOSInfo.'Service Pack')</td>
			</tr>
			<tr class="even">
			<td>OS Architecture</td>
			<td>$($objOSInfo.'OS Architecture')</td>
			</tr>
			<tr class="odd">
			<td>RAM total (GB)</td>
			<td>$($objOSInfo.'RAM Total (GB)')</td>
			</tr>
			<tr class="even">
			<td>Ram Free (GB)</td>
			<td>$($objOSInfo.'RAM Free (GB)')</td>
			</tr>
			<tr class="odd">
			<td>Hardware Manufacturer</td>
			<td>$($objOSInfo.'Hardware Manufacturer')</td>
			</tr>
			<tr class="even">
			<td>Hardware Model</td>
			<td>$($objOSInfo.'Hardware Model')</td>
			</tr>
			<tr class="odd">
			<td>Boot Device</td>
			<td>$($objOSInfo.'Boot Device')</td>
			</tr>
			<tr class="even">
			<td>Boot Drive</td>
			<td>$($objOSInfo.'Boot Drive')</td>
			</tr>
			<tr class="odd">
			<td>Windows Directory</td>
			<td>$($objOSInfo.'Windows Directory')</td>
			</tr>
			<tr class="even">
			<td>Last Boot Time</td>
			<td>$($objOSInfo.'Last Boot Time')</td>
			</tr>
			<tr class="odd">
			<td>Server Domain Roles</td>
			<td>$($objOSInfo.'Server Domain Roles')</td>
			</tr>
			<tr class="even">
			<td>RDP Connection Test</td>
			<td>$($objOSInfo.'RDP State')</td>
			</tr>
			</table>
			<br></br>
			<a href=#top>Back to Top</a>
"@

$objHtmlContents = @"
			<h2>Contents</h2>
			<table class="list">
			<th>Category</th>
			<th></th>
			<tr class="odd">
			<td><a href="#osinfo">Operating System Summary</a></td>
			<td>A summary of the Operating System, Basic Hardware Details and RDP connectivity</td>
			</tr>
			<tr class="even">
			<td><a href="#lastreboot">Last Shutdown</a></td>
			<td>The last system shutdown performed including the time, event details, shutdown type and comment</td>
			</tr>
			<tr class="odd">
			<td><a href="#nics">Network Interface Cards</a></td>
			<td>A list of all Physical Network Interface Cards installed in the system with product details, MAC address and connection state</td>
			</tr>
			<tr class="even">
			<td><a href="#IPAddresses">IP Address Details</a></td>
			<td>All IP addresses and details</td>
			</tr>
			<tr class="odd">
			<td><a href="#disks">Logical Disks</a></td>
			<td>Logical Disks installed in the system including size and usage information as well as drive letters and mount point paths</td>
			</tr>
			<tr class="even">
			<td><a href="#cpu">CPU Details</a></td>
			<td>All Physical CPUs installed including make and model, clock speed and current utilisation</td>
			</tr>
			<tr class="odd">
			<td><a href="#services">Automatic Services Not Running</a></td>
			<td>Any service set to start Automatically but currently not running</td>
			</tr>
			<tr class="even">
			<td><a href="#procs">Top $($global:strProcesses) Processes by CPU % Usage</a></td>
			<td>The top $($global:strProcesses) processes sorted by % of CPU usage</td>
			</tr>
			<tr class="odd">
			<td><a href="#procsMem">Top $($global:strProcesses) Processes by MEM consumed</a></td>
			<td>The top $($global:strProcesses) processes sorted by Memory consumed in MB</td>
			</tr>
			<tr class="even">
			<td><a href="#patches">Updates Installed Last $($global:strPatchDays) Days</a></td>
			<td>All Microsoft updates installed within the last $($global:strPatchDays) days including hotfix ID, type, who it was installed by and the install date</td>
			</tr>
			<tr class="odd">
			<td><a href="#logs">System and Application log Summary</a></td>
			<td>All events from the System and Application logs at a level of critical, error or warning for the last $($global:strEventDays) Day(s)</td>
			</tr>
			<tr class="even">
			<td><a href="#hbas">FC Host Bus Adapters</a></td>
			<td>Fibre Channel Host Bus Adapters installed including make and model, driver and firmware version as well as WWNN</td>
			</tr>			
			</table>

"@


			get-LastRebootReason $objComputer
			$objHtmlGetLastReboot = @"
			<h2 id="lastreboot">$($objComputer) Last Shutdown</h2>
			<h3>The last reported shutdown from the System event log. If possible will include the process that started the shutdown, the shutdown type and any comment left in the Windows Shutdown Tracker. Due to the non uniform nature of the events logged all details may not always be captured.</h3>
			<table class="list">
			<th>System Name</th>
			<th> $($objComputer)</th>
			<tr class="odd">
			<td>Date</td>
			<td>$($global:colRebootDetails.'Date')</td>
			</tr>
			<tr class="even">
			<td>Shutdown Event</td>
			<td>$($global:colRebootDetails.'Shutdown Event')</td>
			</tr>
			<tr class="odd">
			<td>Shutdown Type</td>
			<td>$($global:colRebootDetails.'Shutdown Type')</td>
			</tr>
			<tr class="even">
			<td>Shutdown Comment</td>
			<td>$($global:colRebootDetails.'Shutdown Comment')</td>
			</tr>
			</table>
			<br></br>
			<a href=#top>Back to Top</a>
"@

			$objHtmlNIC = get-NICinfo $objComputer | ConvertTo-Html -Fragment  | Out-String  | Set-AlternatingCSSClasses -CSSEvenClass 'even' -CssOddClass 'odd'
			$objHtmlNIC = "<h2 id=nics>Network Interfaces</h2><h3>All physical network interfaces installed in the server with manufacturer, model name, MAC address and connection state</h3>$objHtmlNIC<br></br><a href=#top>Back to Top</a>"

			$objhtmlIPAddresses = get-NicIPAddress $objComputer | sort-object 'Default Gateway' -Descending | ConvertTo-Html -Fragment  | Out-String  | Set-AlternatingCSSClasses -CSSEvenClass 'even' -CssOddClass 'odd'
			$objhtmlIPAddresses = "<h2 id=IPs>IP Addresses</h2><h3>IP address details for all network adapters in the server including subnet mask, default gateway, DNS servers and suffixes and WINS servers</h3>$objhtmlIPAddresses<br></br><a href=#top>Back to Top</a>"

			$objHtmlDisk = get-diskinfo $objComputer | ConvertTo-Html -Fragment | Out-String | Set-AlternatingCSSClasses -CSSEvenClass 'even' -CssOddClass 'odd'
			$objHtmlDisk =  "<h2 id=disks>Logical Disks</h2><h3>A list of all logical volumes installed in the server. If the volume is used as a mount point, the first column will show the path that is mounted. Otherwise it will be the drive letter assigned to the disk.</h3>$objHtmlDisk<br></br><a href=#top>Back to Top</a>"

			#$objHtmlProcess = Get-ProcessInfo $objComputer | ConvertTo-Html -Fragment | Out-String | Set-AlternatingCSSClasses -CSSEvenClass 'even' -CssOddClass 'odd'
			#$objHtmlProcess = "<h2>Processes</h2>$objHtmlProcess<a href=#top>Back to Top</a>"

			$objHtmlHba = get-hbainfo $objComputer | ConvertTo-Html -Fragment | Out-String | Set-AlternatingCSSClasses -CSSEvenClass 'even' -CssOddClass 'odd'
			$objHtmlHba = "<h2 id=hbas>HBA Details</h2><h3>A list of all Fiber Channel Host Bus Adapters installed in the system. Will include the manufacturer, model, driver, firmware and WWNN. If there are no FC HBAs installed, this table will be empty.</h3>$objHtmlHba<br></br><a href=#top>Back to Top</a>"

			$objHtmlCPU = get-cpuinfo $objComputer | ConvertTo-Html -Fragment | Out-String | Set-AlternatingCSSClasses -CSSEvenClass 'even' -CssOddClass 'odd'
			$objHtmlCPU = "<h2 id=cpu>CPU Details</h2><h3>A list of the physical CPUs instaleld in the system.</h3>$objHtmlCPU<a href=#top>Back to Top</a>"
				
			$objHtmlServices = get-AutoServicesNotrunning $objComputer | ConvertTo-Html -Fragment  | Out-String  | Set-AlternatingCSSClasses -CSSEvenClass 'even' -CssOddClass 'odd'
			$objHtmlServices = "<h2 id=services>Automatic Services Not Running</h2><h3>Any service that is set to start automatically but is currently stopped will be listed here. These should be checked to confirm this is expected behaviour and not indicative of an issue.</h3>$objHtmlServices<br></br><a href=#top>Back to Top</a>"

			$objHtmlTop10Processes =  get-topProcessesCPU $objComputer
            if ($global:strVerbose){
			    $objHtmlTop10Processes | Format-Table -AutoSize
            }
			$objHtmlTop10Processes = $objHtmlTop10Processes | ConvertTo-Html -Fragment  | Out-String  | Set-AlternatingCSSClasses -CSSEvenClass 'even' -CssOddClass 'odd'
			$objHtmlTop10Processes =  "<h2 id=procs>Top $($global:strProcesses) Processes by CPU % Usage</h2><h3>The top $($global:strProcesses) processes sorted by CPU % usage.</h3>$objHtmlTop10Processes<br></br><a href=#top>Back to Top</a>"

			$objHtmlTop10ProcessesMEM = get-topProcessesMEM $objComputer
			if ($global:strVerbose){
                $objHtmlTop10ProcessesMEM | format-table -AutoSize
            }
			$objHtmlTop10ProcessesMEM = $objHtmlTop10ProcessesMEM | ConvertTo-Html -Fragment  | Out-String  | Set-AlternatingCSSClasses -CSSEvenClass 'even' -CssOddClass 'odd'
			$objHtmlTop10ProcessesMEM = "<h2 id=procsMem>Top $($global:strProcesses) Processes by MEM consumed</h2><h3>The top $($global:strProcesses) processes sorted by memory consumed in MB.</h3>$objHtmlTop10ProcessesMEM<br></br><a href=#top>Back to Top</a>"

			$objHtmlInstalledPatches = get-InstalledPatches $objComputer  | ConvertTo-Html -Fragment  | Out-String  | Set-AlternatingCSSClasses -CSSEvenClass 'even' -CssOddClass 'odd'
			$objHtmlInstalledPatches = "<h2 id=patches>Patches Installed Last $($global:strPatchDays) Days</h2><h3>A list of all patches installed on the server in the last $($global:strPatchDays) days.</h3>$objHtmlInstalledPatches<br></br><a href=#top>Back to Top</a>"

			$objHtmlEventLogs = get-systemandapplogs $objComputer | ConvertTo-Html -Fragment  | Out-String  | Set-AlternatingCSSClasses -CSSEvenClass 'even' -CssOddClass 'odd'
			$objHtmlEventLogs = "<h2 id=logs>Errors and Warnings from the System and Application logs for the last $($global:strEventDays) day(s)</h2><h3>Any event logged in the System or Application log with a level or Warning or Error for the last $($global:strEventDays) day(s).</h3>$objHtmlEventLogs<br></br><a href=#top>Back to Top</a>"

            $objHtmlOverAllState = @"
            <table>
            <tr>
            <td bgcolor=$global:strHealthState><h1>Overall System Health State $global:strHealthState</h1></td>
            </tr>
            </table>

"@
			$objHtml = @{'Head'="<title>Health Check for $objComputer</title>$style";
				'PreContent'="<h1>Health Check for $objComputer</h1>$objHtmlOverAllState";
				'PostContent'=$objHtmlContents,$objHtmlOS,$objHtmlGetLastReboot,$objHtmlNIC,$objhtmlIPAddresses,$objHtmlDisk,$objHtmlCPU,$objHtmlServices,$objHtmlTop10Processes,$objHtmlTop10ProcessesMEM,$objHtmlInstalledPatches,$objHtmlEventLogs,$objHtmlHba}
			ConvertTo-Html @objHtml | out-file -FilePath "$($objFilepath)\$($objComputer).html"
	        

            write-host "`n"
			write-host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" -ForegroundColor $global:strHealthState
			write-host "Health Check complete. Report is located at $($objFilepath)\$($objComputer).html" -ForegroundColor $global:strHealthState
            write-host "An overall system health rating of $($global:strHealthState) has been determined" -ForegroundColor $global:strHealthState
			write-host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" -ForegroundColor $global:strHealthState
            send-emailreport

		} else {
			write-host "`n"
			write-host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" -ForegroundColor Red
			Write-Host "Server $($objComputer) is not responding to ping or WMI requests" -ForegroundColor Red
			Write-Host "Health check cannot be processed without network and WMI access" -ForegroundColor Red
			write-host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" -ForegroundColor Red
		}

	}


# Return the system locale to the original
[System.Threading.Thread]::CurrentThread.CurrentCulture = $strOriginalLocale
    
}
