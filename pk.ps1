#Script to configure language settings for each user
#Author: Hammad Saleem
#Version Number 1

#Write settings to reg key for all users who logon to machine
$RegKeyPath = "HKU:\Control Panel\International"

# Import 'International' module to Powershell session
Import-Module International

#Set Location to Pakistan
Set-WinSystemLocale en-PK
Set-WinHomeLocation -GeoId 0xbe

# Set regional format (date/time etc.) to English (United Kingdon) - this applies to all users
Set-Culture en-PK

# Check language list for non-US input languages, exit if found
$currentlist = Get-WinUserLanguageList
$currentlist | ForEach-Object {if(($_.LanguageTag -ne "en-PK") -and ($_.LanguageTag -ne "en-US")){exit}}

# Set the language list for the user, forcing English (United Kingdom) to be the only language
Set-WinUserLanguageList en-PK -Force

exit
