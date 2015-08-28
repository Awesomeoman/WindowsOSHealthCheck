# WindowsOSHealthCheck
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
    OSHealthCheckv4.74.PS1
    Run the health check with the default values. The server scanned will be the local computer, output folder is .\ and verbose mode and email are disabled.

.EXAMPLE
    OSHealthCheckv4.74.PS1 -Computers "Server1","Server2","Server3"
    Run the health check against Server1, Server2 and Server3. 

.EXAMPLE
    OSHealthCheckv4.74.PS1 -VerboseMode -EmailReport
    Run the health check with the default values for -computers and -outputfilepath, but with VerboseMode ane EmailReport enabled.

.EXAMPLE
    OSHealthCheckv4.74.PS1 -Computers C:\Servers.txt -OutputFilePath "C:\Scripts\Out" -VerboseMode -EmailReport
    Run the health check against a list of computers stored in C:\Servers.txt. HTML reports will be saved to C:\Scripts\Out. Verbose mode is on, so all content will be written to the Powershell Console and the HTML report will be sent via email.
