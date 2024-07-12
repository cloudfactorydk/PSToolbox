#Bootstrap.ps1
# function to test if the script is running as admin
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
    $arguments = "-command irm PSToolbox.cloudfactory.dk | iex"
    Start-Process powershell -Verb runAs -ArgumentList $arguments
    Break
}

$Rootfolder = "C:\CloudFactoryToolbox"
$scriptPath = join-path -Path $Rootfolder -ChildPath "Main.ps1" 

#create rootfolder if it doesnt exist
if (!(Test-Path $Rootfolder)) {
    New-Item -ItemType Directory -Path $Rootfolder | Out-Null
}

Invoke-RestMethod "https://raw.githubusercontent.com/cloudfactorydk/PSToolbox/main/Main.ps1" | Out-File -Encoding utf8 -FilePath $scriptPath -Force
# start script elevated

$arguments="-NoExit -file $scriptPath -executionpolicy bypass"
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Start-Process powershell -runAs -ArgumentList $arguments 
}
else {
    Start-Process powershell -ArgumentList $arguments 
}

