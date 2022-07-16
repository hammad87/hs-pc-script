Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$ErrorActionPreference = 'SilentlyContinue'
$wshell = New-Object -ComObject Wscript.Shell
$Button = [System.Windows.MessageBoxButton]::YesNoCancel
$ErrorIco = [System.Windows.MessageBoxImage]::Error
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

Set-ExecutionPolicy RemoteSigned

# Check if winget is installed

Write-Host "Checking Winget"
if (Test-Path ~\AppData\Local\Microsoft\WindowsApps\winget.exe){
    'Winget Already Installed'
}  
else{
    # Installing winget from the Microsoft Store
	Write-Host "Winget not found, installing it now."
    $ResultText.text = "`r`n" +"`r`n" + "Installing Winget... Please Wait"
	Start-Process "ms-appinstaller:?source=https://aka.ms/getwinget"
	$nid = (Get-Process AppInstaller).Id
	Wait-Process -Id $nid
	Write-Host Winget Installed
    $ResultText.text = "`r`n" +"`r`n" + "Winget Installed - Ready for Next Task"
}

Write-Host "Upgrading"
winget upgrade --all

Write-Host "Installing Firefox"
winget install -e Mozilla.Firefox

Write-Host "Installing Google Chrome"
winget install -e Google.Chrome

Write-Host "Installing VLC Media Player"
winget install -e VideoLAN.VLC

Write-Host "Installing Media Player Classic"
winget install -e clsid2.mpc-hc

Write-Host "Installing 7-Zip Compression Tool"
winget install -e 7zip.7zip

Write-Host "Installing WinRAR Compression Tool"
winget install -e RARLab.WinRAR

Write-Host "Installing WhatsApp"
winget install -e WhatsApp.WhatsApp

Write-Host "Installing Adobe Acrobat Reader 64-bit"
winget install -e Adobe.Acrobat.Reader.64-bit

Write-Host "Installing Chocolatey Windows Package Manager"
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

Write-Host "Installing Office 2019"
choco install office2019proplus

Write -Host "Setting Theme to Dark"
Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Value 0

Write-Host "Enabling Hibernation..."
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 1

Write-Host "Showing known file extensions..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0

Write-Host "Changing default Explorer view to This PC..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 00000001

Write-Host "Initializing the installation of .NET 3.5..."
DISM /Online /Enable-Feature /FeatureName:NetFx3 /All
Write-Host ".NET 3.5 has been successfully installed!"

Write-Host "Initializing the installation of Internet Explorer 11"
dism /online /Add-Capability /CapabilityName:Browser.InternetExplorer~~~~0.0.11.0

Write -Host "ALL DONE :) Restarting PC"

restart-computer
