# Coercer Installer

$PythonVersion = '3.13.0'
$StartingDirectory = Get-Location

$PythonInstallerPath = Join-Path -Path $Env:TEMP -ChildPath "python-$PythonVersion.exe"

$RepositoryArchivePath = Join-Path -Path $Env:TEMP -ChildPath "coercer.zip"
$RepositoryFolderPath = Join-Path -Path $Env:TEMP -ChildPath "coercer-windows-support"

$MachinePythonKey = "HKLM:\Software\Python\PythonCore"
$UserPythonKey = "HKCU:\Software\Python\PythonCore"
$FoundPython = $False

$PythonVersionParts = $PythonVersion.Split(".")
$TruncatedPythonVersion = "$($PythonVersionParts[0]).$($PythonVersionParts[1])"

$Options = New-object System.Collections.Hashtable
$Options['OutputDir'] = @{
    Name     = 'Output Directory'
    Desc     = 'Set the output directory for the built script'
    Keywords = @('-o', '--output-dir')
    Value    = $StartingDirectory
    Type     = 'Path'
}

$Flags = New-object System.Collections.Hashtable
$Flags['OverridePython'] = @{
    Name     = 'Override Installed Python'
    Desc     = "Install Python $PythonVersion even if an existing python version is installed"
    Keywords = @('-P', '--override-python')
    Value    = $False
}
$Flags['LeavePython'] = @{
    Name     = 'Leave Installed Python'
    Desc     = "If installed, do not uninstall Python $PythonVersion from the system"
    Keywords = @('-L', '--leave-python')
    Value    = $False
}
$Flags['InstallSystemWide'] = @{
    Name     = 'Install Script System-Wide'
    Desc     = 'Install script to C:\Program Files\ and add them to the PATH (Ignores Output Directory)'
    Keywords = @('-I', '--install-systemwide')
    Value    = $False
}

function GetKeyByKeyword {
    param (
        [hashtable]$HashTable,
        [string]$Keyword
    )
        
    foreach ($Key in $HashTable.Keys) {
        $Item = $HashTable[$Key]
        if ($Item.Keywords -contains $Keyword) {
            return $Key
        }
    }
    return $Null
}

$HelpMenuPadding = 25

function Show-HelpMenu {
    Write-Host '=== Coercer Installer ==='
    Write-Host 'Downloads, builds, and installs scripts from the Coercer repository'
    Write-Host ''
    Write-Host 'Usage: installer.ps1 [FLAGS] [OPTIONS]'
    Write-Host ''
    Write-Host 'Flags:'
    foreach ($Flag in $Flags.Values) {
        $FormattedKeywords = $Flag['Keywords'] -join '  '
        Write-Host "  $($FormattedKeywords.PadRight($HelpMenuPadding)) $($Flag['Desc'])"
    }
    Write-Host ''
    Write-Host 'Options:'
    Write-Host "  $('-h  --help'.PadRight($HelpMenuPadding)) Display this menu"
    foreach ($Option in $Options.Values) {
        $FormattedKeywords = $Option['Keywords'] -join '  '
        Write-Host "  $($FormattedKeywords.PadRight($HelpMenuPadding)) $($Option['Desc']) (default: $($Option['Value']))"
    }
    Write-Host ''
}

for ($I = 0; $I -lt $Args.Count; $I++) {
    if ($Args[$I] -eq '-h' -or $Args[$I] -eq '--help') {
        Show-HelpMenu
        exit 0
    }
    elseif ($Args[$I].startsWith('-')) {
        $ArgParts = $Args[$I] -split '='
        $Keyword = $ArgParts[0]
        $Value = $Null

        $FlagsKey = GetKeyByKeyword -HashTable $Flags -Keyword $Keyword
        $OptionsKey = GetKeyByKeyword -HashTable $Options -Keyword $Keyword

        if ($ArgParts.Count -eq 2) {
            $Value = $ArgParts[1]
        }
        elseif ($ArgParts.Count -gt 1) {
            throw "Error in $($Options[$OptionsKey]['Name']): Multiple equals signs (Use -h or --help for help)"
        }

        if ($FlagsKey) {
            $Flags[$FlagsKey]['Value'] = $True
        }
        elseif ($OptionsKey) {
            if (-not $Value) {
                $I++
                $Value = $Args[$I]
            }
            if (-not $Value) {
                throw "Error in $($Options[$OptionsKey]['Name']): No value recieved (Use -h or --help for help)"
            }
            if ($Options[$OptionsKey]['type'] -eq 'Path' -and -not (Test-Path $Value)) {
                throw "Error in $($Options[$OptionsKey]['Name']): Path does not exist (Use -h or --help for help)"
            }
            $Options[$OptionsKey]['Value'] = $Value
        }
        else {
            throw "Error: Unrecognized argument (Use -h or --help for help)"
        }
    }
}

# Check Local Machine Registry
if (Test-Path $MachinePythonKey) {
    Get-ChildItem $MachinePythonKey | ForEach-Object {
        if ($_.PSChildName -eq $TruncatedPythonVersion) {
            $FoundPython = $True
            Write-Host "Python $($_.PSChildName) found in Local Machine"
        }
    }
}

# Check Current User Registry
if (Test-Path $UserPythonKey) {
    Get-ChildItem $UserPythonKey | ForEach-Object {
        if ($_.PSChildName -eq $TruncatedPythonVersion) {
            $FoundPython = $True
            Write-Host "Python $($_.PSChildName) found in Current User"
        }
    }
}

# Download and install Python
if (-not $FoundPython -or $Flags['OverridePython']['Value']) {
    Write-Host "Python $PythonVersion is not installed, installing now..."
    Invoke-WebRequest -Uri "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-amd64.exe" -OutFile $PythonInstallerPath
    Start-Process $PythonInstallerPath -ArgumentList "/quiet PrependPath=1 Include_launcher=0" -Wait

    # Refresh PATH
    $Env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User") 
}

# Download and unzip repository
Write-Host 'Downloading repository...'
Invoke-WebRequest -Uri "https://github.com/p0rtL6/coercer/archive/refs/heads/windows-support.zip" -OutFile $RepositoryArchivePath
Expand-Archive -Path $RepositoryArchivePath -DestinationPath $Env:TEMP -Force
Remove-Item $RepositoryArchivePath

# Begin build process
Write-Host 'Beginning build process...'
Set-Location -Path $RepositoryFolderPath

# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1

# Setup
pip install -r requirements.txt
python setup.py install

Write-Host "Building..."

$Arguments = @('--onefile', '--collect-all', 'impacket', '--add-data', 'coercer;coercer')
pyinstaller $Arguments "Coercer.py"

$BuiltScriptPath = Join-Path -Path $RepositoryFolderPath -ChildPath "dist\Coercer.exe"

if ($Flags['InstallSystemWide']['Value']) {
    # Prepare destination folder
    Write-Host 'Copying executable to Program Files...'
    New-Item -ItemType Directory -Path 'C:\Program Files\Coercer' -Force

    # Copy built executable into program files
    Copy-Item -Path $BuiltScriptPath -Destination 'C:\Program Files\Coercer' -Force
}
else {
    Copy-Item -Path $BuiltScriptPath -Destination $Options['OutputDir']['Value'] -Force
}

if ($Flags['InstallSystemWide']['Value']) {
    # Get the current PATH environment variable
    Write-Host "Updating PATH..."
    $CurrentPath = [System.Environment]::GetEnvironmentVariable('Path', [System.EnvironmentVariableTarget]::Machine)

    # Check if the path already exists in PATH
    if ($CurrentPath -notlike "*C:\Program Files\Coercer*") {
        # Append the new path to the existing PATH variable
        $NewPath = $CurrentPath + ';' + 'C:\Program Files\Coercer'
    
        # Set the new PATH variable
        [System.Environment]::SetEnvironmentVariable('Path', $NewPath, [System.EnvironmentVariableTarget]::Machine)
    
        Write-Host 'Successfully added C:\Program Files\Coercer to PATH.'
    }
    else {
        Write-Host 'C:\Program Files\Coercer is already in PATH.'
    }
}

Write-Host 'Cleaning up...'

deactivate
Set-Location -Path $StartingDirectory
Remove-Item -Recurse -Force $RepositoryFolderPath

if (-not $Flags['LeavePython']['Value'] -and (-not $FoundPython -or $Flags['OverridePython']['Value'])) {
    Write-Host 'Uninstalling Python...'
    Start-Process $PythonInstallerPath -ArgumentList "/uninstall /quiet PrependPath=1" -Wait
}

Write-Host 'Done!'
