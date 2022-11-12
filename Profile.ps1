# Multiple ps1 profiles scripts gathered from (https://stackoverflow.com/questions/138144/what-s-in-your-powershell-profile-ps1-file )
# and other random sources 


#region execution ps1 profile script by Dan Tsekhanskiy
<#
  .SYNOPSIS
    TsekNet PowerShell Profile.
  .DESCRIPTION
    Personal heavily customized PowerShell profile. Feel free to use and
    distrubute as you see fit. Expect frequent updates. Please file PRs for any
    errors/improvements.
    To use this profile, simply place this file in any of your $profile
    directories and restart your PowerShell console (Ex: $profile)
    Execution of functions can be found a the bottom of this profile script.
  .LINK
    TsekNet.com GitHub.com/TsekNet Twitter.com/TsekNet
    https://github.com/TsekNet/PowerShell-Profile/blob/master/profile.ps1
#>
[CmdletBinding()]
param ()

#region function declarations

# Helper function to change directory to my development workspace
function Set-Path {
  [CmdletBinding()]
  Param (
    [ValidateScript( {
        if (-Not ($_ | Test-Path) ) {
          Write-Verbose "Creating default location $_"
          New-Item -ItemType Directory -Force -Path $_
        }
        return $true
      })]
    [System.IO.FileInfo]$Path
  )
  Write-Verbose "Setting path to $Path."
  Set-Location $Path
}

# Helper function to ensure all modules are loaded, with error handling
function Import-MyModules {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory)]
    [string[]]$Modules
  )

  foreach ($Module in $Modules) {
    if (Get-Module -ListAvailable -Name $Module -Verbose:$false) {
      Write-Verbose "Module '$Module' found, skipping install."
      Continue
    }
    try {
      Write-Verbose "Attemping to install module '$Module'"
      Import-Module -Name $Module -ErrorAction Stop -Verbose:$false
    }
    catch {
      $lookup = Find-Module -Name $Module
      if (-not $lookup) {
        Write-Error "Module `"$Module`" not found."
        continue
      }
      Install-Module -Name $Module -Scope AllUsers -Force -AllowClobber
      Import-Module -Name $Module -Scope Global -Verbose:$false
    }
  }
}

# Helper function to test prompt elevation
function Get-Elevation {
  [CmdletBinding()]
  param ()
  if (Test-Administrator) {
    $script:elevation = "Admin"
    Write-Verbose "Powershell is running as: $script:elevation"
  }
  else {
    $script:elevation = "Non-Admin"
    Write-Verbose "Powershell is running as: $script:elevation"
  }
}

# Helper function to set the window title
function Set-WindowTitle {
  [CmdletBinding()]
  param ()
  $host_title = [ordered]@{
    'Elevation' = $elevation
    'Version'   = "v$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)"
    'Session'   = "$env:COMPUTERNAME".ToLower()
  }

  $formatted_title = "PS [$($host_title.Values -join ' | ')]"

  Write-Verbose "Setting Window Title to '$formatted_title'"

  $Host.UI.RawUI.WindowTitle = $formatted_title
}

# Download Files from Github
function Import-GitRepo {
  <#
  .Synopsis
    This function will download a Github Repository without using Git
  .DESCRIPTION
    This function will download files from Github without using Git.  You will
    need to know the Owner, Repository name, branch (default master), and
    FilePath.  The Filepath will include any folders and files that you want to
    download.
  .EXAMPLE
    Import-GitRepo -Owner MSAdministrator -Repository WriteLogEntry -Verbose -FilePath `
        'WriteLogEntry.psm1',
        'WriteLogEntry.psd1',
        'Public',
        'en-US',
        'en-US\about_WriteLogEntry.help.txt',
        'Public\Write-LogEntry.ps1'
  #>
  [CmdletBinding()]
  [Alias()]
  [OutputType([int])]
  param (
    # Repository owner
    [Parameter(Mandatory, ValueFromPipelineByPropertyName, Position = 0)]
    [string]$Owner,

    # Name of the repository
    [Parameter(Mandatory, ValueFromPipelineByPropertyName, Position = 1)]
    [string]$Repository,

    # Branch to download from
    [Parameter(ValueFromPipelineByPropertyName, Position = 2)]
    [string]$Branch = 'master',

    # List of files/paths to download
    [Parameter(Mandatory, ValueFromPipelineByPropertyName, Position = 3)]
    [string[]]$FilePath,

    # List of posh-git themes to download
    [Parameter(Mandatory, ValueFromPipelineByPropertyName, Position = 4)]
    [string[]]$ThemeName
  )

  $modulespath = ($env:psmodulepath -split ";")[0]
  $PowerShellModule = "$modulespath\$Repository"
  $wc = New-Object System.Net.WebClient
  $wc.Encoding = [System.Text.Encoding]::UTF8
  if (-not(Test-Path $PowerShellModule)) {
    Write-Verbose "Creating module directory"
    New-Item -Type Container -Path $PowerShellModule -Force | Out-Null
  }

  if (-not(Test-Path $profile)) {
    Write-Verbose "Creating profile"
    New-Item -Path $profile -Force | Out-Null
  }

  foreach ($item in $FilePath) {
    if ($item -like '*.*') {
      $url = "https://raw.githubusercontent.com/$Owner/$Repository/$Branch/$item"
      Write-Verbose "Attempting to download from '$url'"
      if ($item -like "*$ThemeName.psm1") {
        Write-Verbose "'$item' detected, overwriting..."
        $fullpath = "$(Join-Path -Path (Get-ChildItem $profile).Directory.FullName -ChildPath 'PoshThemes')\$ThemeName.psm1"
        if (-not(Test-Path $fullpath)) {
          Write-Verbose "Creating file '$fullpath'"
          New-Item -ItemType File -Force -Path $fullpath | Out-Null
        }
        ($wc.DownloadString("$url")) | Out-File $fullpath
      }
      elseif ($item -like '*profile.ps1') {
        Write-Verbose "'$item' detected, overwriting..."
        New-Item -ItemType File -Force -Path $profile | Out-Null
        Write-Verbose "Created file '$profile'"
        ($wc.DownloadString("$url")) | Out-File "$profile"
      }
      else {
        Write-Verbose "'$item' detected, overwriting..."
        New-Item -ItemType File -Force -Path "$PowerShellModule\$item" | Out-Null
        Write-Verbose "Created file '$PowerShellModule\$item'"
        ($wc.DownloadString("$url")) | Out-File "$PowerShellModule\$item"
      }
    }
    else {
      New-Item -ItemType Container -Force -Path "$PowerShellModule\$item" | Out-Null
      Write-Verbose "Created file '$PowerShellModule\$item'"
      $url = "https://raw.githubusercontent.com/$Owner/$Repository/$Branch/$item"
      Write-Verbose "Attempting to download from $url"
    }
  }
}

function Install-Fonts {
  [CmdletBinding()]
  param (
    [System.IO.FileInfo]$TestFont = "$env:LOCALAPPDATA\Microsoft\Windows\Fonts\DejaVu Sans Mono for Powerline.ttf"
  )
  if (-not(Test-Path $TestFont)) {
    Write-Verbose "Installing Fonts to $($TestFont.DirectoryName)"
    git clone https://github.com/PowerLine/fonts
    Set-Location fonts
    .\install.ps1 'Deja*' -Confirm:$false
  }
}

#endregion

#region helper functions

Write-Verbose "==Setting command aliases=="

# Copy the last command entered
function Copy-LastCommand {
  Get-History -Id $(((Get-History) | Select-Object -Last 1 |
        Select-Object ID -ExpandProperty ID)) |
      Select-Object -ExpandProperty CommandLine |
        clip
}

# Make it easy to edit this profile once it's installed
function Edit-Profile {
  if ($host.Name -match "ise") {
    $psISE.CurrentPowerShellTab.Files.Add($profile)
  }
  else {
    code-insiders $profile
  }
}

# Open PowerShell command history file
function Open-HistoryFile { code-insiders (Get-PSReadLineOption | Select-Object -ExpandProperty HistorySavePath) }

# Compute file hashes - useful for checking successful downloads
function Get-FileHash256 {
  $sha_256_hash = (Get-FileHash -Algorithm SHA256 $args).hash
  Write-Output "Hash for $args is '$sha_256_hash' (copied to clipboard)."
  $sha_256_hash | clip
}

function Get-ExportedFunctions {
  try {
    $helper_functions = (Get-Module $profile -ListAvailable | Select-Object -ExpandProperty ExportedCommands).Values.Name -join ', '
    Write-Host 'Profile helper functions: ' -NoNewline; Write-Host $helper_functions -ForegroundColor Green
  }
  catch {
    Write-Error "Error obtaining helper function list: $_"
  }
}

#endregion

#region statements

# Hold shift to turn on verbosity if running Windows PowerShell
if ("Desktop" -eq $PSVersionTable.PSEdition) {
  Add-Type -Assembly PresentationCore, WindowsBase
  try {
    if ([System.Windows.Input.Keyboard]::IsKeyDown([System.Windows.Input.Key]::LeftShift) -OR
      [System.Windows.Input.Keyboard]::IsKeyDown([System.Windows.Input.Key]::RightShift)) {
      $VerbosePreference = "Continue"
    }
  }
  catch {
    Write-Warning "Error displaying verbosity via SHIFT key."
  }
}

#endregion


#region execution

try {
  Write-Verbose '==Removing default start up message=='
  Clear-Host

  Write-Verbose '==Getting latest profile files from GitHub=='
  Import-GitRepo -Owner tseknet -Repository PowerShell-Profile -FilePath `
    'profile.ps1',
  'Themes/TsekNet.psm1' -ThemeName 'TsekNet'

  Write-Verbose '==Importing modules required for profile=='
  $my_modules = @('posh-git', 'oh-my-posh', 'Get-ChildItemColor', 'PSWriteHTML')
  Import-MyModules -Modules $my_modules

  Write-Verbose '==Setting custom oh-my-posh theme=='
  Set-Theme 'TsekNet' -Verbose:$false

  Write-Verbose '==Checking console elevation=='
  Get-Elevation

  Write-Verbose '==Setting the console title=='
  if ($ThemeSettings.Options) { $ThemeSettings.Options.ConsoleTitle = $false }
  Set-WindowTitle

  Write-Verbose '==Setting the default directory for new PowerShell consoles=='
  Set-Path 'C:\Tmp'

  Write-Verbose '==Installing fonts if necessary=='
  Install-Fonts

  Write-Verbose '==Changing to bash-like tab completion=='
  Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete
  Set-PSReadlineOption -ShowToolTips -BellStyle Visual

  Write-Verbose '==Setting aliases=='
  Set-Alias ll Get-ChildItemColor -Option AllScope
  Set-Alias ls Get-ChildItemColorFormatWide -Option AllScope
  Set-Alias History Open-HistoryFile -Option AllScope

  Write-Verbose '==Getting and displaying list of helper functions=='
  Get-ExportedFunctions
}
catch {
  throw "Error configuring `$profile on line $($_.InvocationInfo.ScriptLineNumber): $_"
}

#endregion

#endregion script by Dan Tsekhanskiy

#region execution ps1 profile script by Tim Sneath <tim@sneath.org>

##########################################################################################
### PowerShell template profile 
### Version 1.03 - Tim Sneath <tim@sneath.org>
### From https://gist.github.com/timsneath/19867b12eee7fd5af2ba
###
### This file should be stored in $PROFILE.CurrentUserAllHosts
### If $PROFILE.CurrentUserAllHosts doesn't exist, you can make one with the following:
###    PS> New-Item $PROFILE.CurrentUserAllHosts -ItemType File -Force
### This will create the file and the containing subdirectory if it doesn't already 
###
### As a reminder, to enable unsigned script execution of local scripts on client Windows, 
### you need to run this line (or similar) from an elevated PowerShell prompt:
###   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
### This is the default policy on Windows Server 2012 R2 and above for server Windows. For 
### more information about execution policies, run Get-Help about_Execution_Policies.

# Find out if the current user identity is elevated (has admin rights)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# If so and the current host is a command line, then change to red color 
# as warning to user that they are operating in an elevated context
if (($host.Name -match "ConsoleHost") -and ($isAdmin))
{
     $host.UI.RawUI.BackgroundColor = "DarkRed"
     $host.PrivateData.ErrorBackgroundColor = "White"
     $host.PrivateData.ErrorForegroundColor = "DarkRed"
     Clear-Host
}

# Useful shortcuts for traversing directories
function cd...  { cd ..\.. }
function cd.... { cd ..\..\.. }

# Compute file hashes - useful for checking successful downloads 
function md5    { Get-FileHash -Algorithm MD5 $args }
function sha1   { Get-FileHash -Algorithm SHA1 $args }
function sha256 { Get-FileHash -Algorithm SHA256 $args }

# Quick shortcut to start notepad
function n      { notepad $args }

# Drive shortcuts
function HKLM:  { Set-Location HKLM: }
function HKCU:  { Set-Location HKCU: }
function Env:   { Set-Location Env: }

# Creates drive shortcut for Work Folders, if current user account is using it
if (Test-Path "$env:USERPROFILE\Work Folders")
{
    New-PSDrive -Name Work -PSProvider FileSystem -Root "$env:USERPROFILE\Work Folders" -Description "Work Folders"
    function Work: { Set-Location Work: }
}

# Creates drive shortcut for OneDrive, if current user account is using it
if (Test-Path HKCU:\SOFTWARE\Microsoft\OneDrive)
{
    $onedrive = Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\OneDrive
    if (Test-Path $onedrive.UserFolder)
    {
        New-PSDrive -Name OneDrive -PSProvider FileSystem -Root $onedrive.UserFolder -Description "OneDrive"
        function OneDrive: { Set-Location OneDrive: }
    }
    Remove-Variable onedrive
}

# Set up command prompt and window title. Use UNIX-style convention for identifying 
# whether user is elevated (root) or not. Window title shows current version of PowerShell
# and appends [ADMIN] if appropriate for easy taskbar identification
function prompt 
{ 
    if ($isAdmin) 
    {
        "[" + (Get-Location) + "] # " 
    }
    else 
    {
        "[" + (Get-Location) + "] $ "
    }
}

$Host.UI.RawUI.WindowTitle = "PowerShell {0}" -f $PSVersionTable.PSVersion.ToString()
if ($isAdmin)
{
    $Host.UI.RawUI.WindowTitle += " [ADMIN]"
}

# Does the the rough equivalent of dir /s /b. For example, dirs *.png is dir /s /b *.png
function dirs
{
    if ($args.Count -gt 0)
    {
        Get-ChildItem -Recurse -Include "$args" | Foreach-Object FullName
    }
    else
    {
        Get-ChildItem -Recurse | Foreach-Object FullName
    }
}

# Simple function to start a new elevated process. If arguments are supplied then 
# a single command is started with admin rights; if not then a new admin instance
# of PowerShell is started.
function admin
{
    if ($args.Count -gt 0)
    {   
       $argList = "& '" + $args + "'"
       Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $argList
    }
    else
    {
       Start-Process "$psHome\powershell.exe" -Verb runAs
    }
}

# Set UNIX-like aliases for the admin command, so sudo <command> will run the command
# with elevated rights. 
Set-Alias -Name su -Value admin
Set-Alias -Name sudo -Value admin


# Make it easy to edit this profile once it's installed
function Edit-Profile
{
    if ($host.Name -match "ise")
    {
        $psISE.CurrentPowerShellTab.Files.Add($profile.CurrentUserAllHosts)
    }
    else
    {
        notepad $profile.CurrentUserAllHosts
    }
}

# We don't need these any more; they were just temporary variables to get to $isAdmin. 
# Delete them to prevent cluttering up the user profile. 
Remove-Variable identity
Remove-Variable principal

#endregion

#region execution ps1 profile script By Jared Parsons (jaredp@rantpack.org)

#==============================================================================
# Created By Jared Parsons PowerShell Profile (jaredp@rantpack.org) 
#==============================================================================

#==============================================================================
# Common Variables Start
#==============================================================================
$global:Rae = new-object psobject 
$Rae | add-member NoteProperty "ScriptPath" $(split-path -parent $MyInvocation.MyCommand.Definition) 
$Rae | add-member NoteProperty "ConfigPath" $(split-path -parent $Rae.ScriptPath)
$Rae | add-member NoteProperty "UtilsRawPath" $(join-path $Rae.ConfigPath "Utils")
$Rae | add-member NoteProperty "UtilsPath" $(join-path $Rae.UtilsRawPath $env:PROCESSOR_ARCHITECTURE)
$Rae | add-member NoteProperty "GoMap" @{}
$Rae | add-member NoteProperty "ScriptMap" @{}

#==============================================================================

#==============================================================================
# Functions 
#==============================================================================

# Load snapin's if they are available
function Rae.Load-Snapin([string]$name) {
    $list = @( get-pssnapin | ? { $_.Name -eq $name })
    if ( $list.Length -gt 0 ) {
        return; 
    }

    $snapin = get-pssnapin -registered | ? { $_.Name -eq $name }
    if ( $snapin -ne $null ) {
        add-pssnapin $name
    }
}

# Update the configuration from the source code server
function Rae.Update-WinConfig([bool]$force=$false) {

    # First see if we've updated in the last day 
    $target = join-path $env:temp "Rae.Update.txt"
    $update = $false
    if ( test-path $target ) {
        $last = [datetime] (gc $target)
        if ( ([DateTime]::Now - $last).Days -gt 1) {
            $update = $true
        }
    } else {
        $update = $true;
    }

    if ( $update -or $force ) {
        write-host "Checking for winconfig updates"
        pushd $Rae.ConfigPath
        $output = @(& svn update)
        if ( $output.Length -gt 1 ) {
            write-host "WinConfig updated.  Re-running configuration"
            cd $Rae.ScriptPath
            & .\ConfigureAll.ps1
            . .\Profile.ps1
        }

        sc $target $([DateTime]::Now)
        popd
    }
}

function Rae.Push-Path([string] $location) { 
    go $location $true 
}
function Rae.Go-Path([string] $location, [bool]$push = $false) {
    if ( $location -eq "" ) {
        write-output $Rae.GoMap
    } elseif ( $Rae.GoMap.ContainsKey($location) ) {
        if ( $push ) {
            push-location $Rae.GoMap[$location]
        } else {
            set-location $Rae.GoMap[$location]
        }
    } elseif ( test-path $location ) {
        if ( $push ) {
            push-location $location
        } else {
            set-location $location
        }
    } else {
        write-output "$loctaion is not a valid go location"
        write-output "Current defined locations"
        write-output $Rae.GoMap
    }
}

function Rae.Run-Script([string] $name) {
    if ( $Rae.ScriptMap.ContainsKey($name) ) {
        . $Rae.ScriptMap[$name]
    } else {
        write-output "$name is not a valid script location"
        write-output $Rae.ScriptMap
    }
}


# Set the prompt
function prompt() {
    if ( Test-Admin ) { 
        write-host -NoNewLine -f red "Admin "
    }
    write-host -NoNewLine -ForegroundColor Green $(get-location)
    foreach ( $entry in (get-location -stack)) {
        write-host -NoNewLine -ForegroundColor Red '+';
    }
    write-host -NoNewLine -ForegroundColor Green '>'
    ' '
}

#==============================================================================

#==============================================================================
# Alias 
#==============================================================================
set-alias gcid      Get-ChildItemDirectory
set-alias wget      Get-WebItem
set-alias ss        select-string
set-alias ssr       Select-StringRecurse 
set-alias go        Rae.Go-Path
set-alias gop       Rae.Push-Path
set-alias script    Rae.Run-Script
set-alias ia        Invoke-Admin
set-alias ica       Invoke-CommandAdmin
set-alias isa       Invoke-ScriptAdmin
#==============================================================================

pushd $Rae.ScriptPath

# Setup the go locations
$Rae.GoMap["ps"]        = $Rae.ScriptPath
$Rae.GoMap["config"]    = $Rae.ConfigPath
$Rae.GoMap["~"]         = "~"

# Setup load locations
$Rae.ScriptMap["profile"]       = join-path $Rae.ScriptPath "Profile.ps1"
$Rae.ScriptMap["common"]        = $(join-path $Rae.ScriptPath "LibraryCommon.ps1")
$Rae.ScriptMap["svn"]           = $(join-path $Rae.ScriptPath "LibrarySubversion.ps1")
$Rae.ScriptMap["subversion"]    = $(join-path $Rae.ScriptPath "LibrarySubversion.ps1")
$Rae.ScriptMap["favorites"]     = $(join-path $Rae.ScriptPath "LibraryFavorites.ps1")
$Rae.ScriptMap["registry"]      = $(join-path $Rae.ScriptPath "LibraryRegistry.ps1")
$Rae.ScriptMap["reg"]           = $(join-path $Rae.ScriptPath "LibraryRegistry.ps1")
$Rae.ScriptMap["token"]         = $(join-path $Rae.ScriptPath "LibraryTokenize.ps1")
$Rae.ScriptMap["unit"]          = $(join-path $Rae.ScriptPath "LibraryUnitTest.ps1")
$Rae.ScriptMap["tfs"]           = $(join-path $Rae.ScriptPath "LibraryTfs.ps1")
$Rae.ScriptMap["tab"]           = $(join-path $Rae.ScriptPath "TabExpansion.ps1")

# Load the common functions
. script common
. script tab
$global:libCommonCertPath = (join-path $Rae.ConfigPath "Data\Certs\jaredp_code.pfx")

# Load the snapin's we want
Rae.Load-Snapin "pscx"
Rae.Load-Snapin "RaeCmdlet" 

# Setup the Console look and feel
$host.UI.RawUI.ForegroundColor = "Yellow"
if ( Test-Admin ) {
    $title = "Administrator Shell - {0}" -f $host.UI.RawUI.WindowTitle
    $host.UI.RawUI.WindowTitle = $title;
}

# Call the computer specific profile
$compProfile = join-path "Computers" ($env:ComputerName + "_Profile.ps1")
if ( -not (test-path $compProfile)) { ni $compProfile -type File | out-null }
write-host "Computer profile: $compProfile"
. ".\$compProfile"
$Rae.ScriptMap["cprofile"] = resolve-path ($compProfile)

# If the computer name is the same as the domain then we are not 
# joined to active directory
if ($env:UserDomain -ne $env:ComputerName ) {
    # Call the domain specific profile data
    write-host "Domain $env:UserDomain"
    $domainProfile = join-path $env:UserDomain "Profile.ps1"
    if ( -not (test-path $domainProfile))  { ni $domainProfile -type File | out-null }
    . ".\$domainProfile"
}

# Run the get-fortune command if RaeCmdlet was loaded
if ( get-command "get-fortune" -ea SilentlyContinue ) {
    get-fortune -timeout 1000
}

# Finished with the profile, go back to the original directory
popd

# Look for updates
Rae.Update-WinConfig

# Because this profile is run in the same context, we need to remove any 
# variables manually that we don't want exposed outside this script

# to remove any left over variables manually , I found couple of soultions in one post in stackoverlow at this link 
# https://stackoverflow.com/questions/17678381/powershell-remove-all-variables/40266400#40266400
# Solution 1 to use : Get-Variable -Exclude PWD,*Preference,psEditor | Remove-Variable -EA 0
# solution 2 to use : 
<#
$existingVariables = Get-Variable
try {
    # your script here
} finally {
    Get-Variable |
        Where-Object Name -notin $existingVariables.Name |
        Remove-Variable
}
#>
#endregion

#region execution random ps1 scripts 
############################################################################## 
## Search the PowerShell help documentation for a given keyword or regular 
## expression.
## 
## Example:
##    Get-HelpMatch hashtable
##    Get-HelpMatch "(datetime|ticks)"
############################################################################## 
function apropos {

    param($searchWord = $(throw "Please specify content to search for"))

    $helpNames = $(get-help *)

    foreach($helpTopic in $helpNames)
    {
       $content = get-help -Full $helpTopic.Name | out-string
       if($content -match $searchWord)
       { 
          $helpTopic | select Name,Synopsis
       }
    }
}
#endregion



} 
<#
# to removes duplicates from your history :
Set-PSReadLineOption –HistoryNoDuplicates -ShowToolTips

# to remove any left over variables manually , I found couple of soultions in one post in stackoverlow at this link 
# https://stackoverflow.com/questions/17678381/powershell-remove-all-variables/40266400#40266400
# Solution 1 use : 
Get-Variable -Exclude PWD,*Preference,psEditor | Remove-Variable -EA 0

# Solution 2 use : 
$existingVariables = Get-Variable
try {
    # your script here
} finally {
    Get-Variable |
        Where-Object Name -notin $existingVariables.Name |
        Remove-Variable
}
#>
