$ErrorActionPreference = "Stop"

$RepoUrl = "https://github.com/R3coNYT/AutoRecon.git"
$InstallDir = "C:\Tools\AutoRecon"
$GoVersion = "1.26.1"
$GoMsi = "https://go.dev/dl/go$GoVersion.windows-amd64.msi"
$GoExe = "C:\Program Files\Go\bin\go.exe"
$HttpxVersion = "1.9.0"
$NucleiVersion = "3.7.1"
$ProgressPreference = 'SilentlyContinue'
$pythonCmd = $null
$NmapUrl = "https://nmap.org/dist/nmap-7.95-setup.exe"


function Write-Info($msg) {
    Write-Host "[+]" $msg -ForegroundColor Cyan
}

function Write-Ok($msg) {
    Write-Host "[✓]" $msg -ForegroundColor Green
}

function Write-Warn($msg) {
    Write-Host "[!]" $msg -ForegroundColor Yellow
}

function Write-Err($msg) {
    Write-Host "[✗]" $msg -ForegroundColor Red
}

function Test-Cmd($name) {
    return $null -ne (Get-Command $name -ErrorAction SilentlyContinue)
}

function Invoke-Retry {
    param(
        [int]$Attempts = 3,
        [scriptblock]$Script
    )

    for ($i = 1; $i -le $Attempts; $i++) {
        try {
            & $Script
            return
        } catch {
            if ($i -eq $Attempts) { throw }
            Write-Warn "Retry $i/$Attempts..."
            Start-Sleep -Seconds 2
        }
    }
}

function New-Directory($Path) {
    if (!(Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

Write-Info "Creating install directory"
New-Directory "C:\Tools"
New-Directory $InstallDir

$env:Path += ";C:\Tools\bin"

if (!(Test-Cmd git)) {
    Write-Err "Git is required. Install Git for Windows first."
    exit 1
}

if (Test-Cmd "py") {
    $pythonCmd = "py -3"
}
elseif (Test-Cmd "python") {
    $pythonCmd = "python"
}
elseif (Test-Cmd "python3") {
    $pythonCmd = "python3"
}
else {
    Write-Err "Python 3 is required. Install Python first."
    exit 1
}

Write-Ok "Python detected: $pythonCmd"

if (!(Test-Path $GoExe)) {
    Write-Info "Installing Go $GoVersion"
    $GoInstaller = "$env:TEMP\go-$GoVersion.msi"

    Invoke-Retry -Attempts 3 -Script {
        Invoke-WebRequest -Uri $GoMsi -OutFile $GoInstaller
    }

    Start-Process msiexec.exe -ArgumentList "/i `"$GoInstaller`" /quiet /norestart" -Wait
    Remove-Item $GoInstaller -Force -ErrorAction SilentlyContinue
    Write-Ok "Go installed"
} else {
    Write-Ok "Go already installed"
}

$env:Path += ";C:\Program Files\Go\bin;$env:USERPROFILE\go\bin"

if (!(Test-Cmd nmap)) {

    Write-Info "Installing Nmap"

    $NmapInstaller = "$env:TEMP\nmap-setup.exe"

    Invoke-Retry -Attempts 3 -Script {
        Invoke-WebRequest -Uri $NmapUrl -OutFile $NmapInstaller
    }

    Start-Process $NmapInstaller -ArgumentList "/S" -Wait
    Remove-Item $NmapInstaller -Force -ErrorAction SilentlyContinue

    Write-Ok "Nmap installed"

} else {

    Write-Ok "Nmap already installed"

}

$env:Path += ";C:\Program Files (x86)\Nmap"

if (Test-Path "$InstallDir\.git") {
    Write-Info "Updating repository"
    git -C $InstallDir pull
} else {
    Write-Info "Cloning AutoRecon"
    Invoke-Retry -Attempts 3 -Script {
        git clone $RepoUrl $InstallDir
    }
}

function Install-ZipBinary {
    param(
        [string]$Name,
        [string]$Url,
        [string]$ExeName
    )

    if (Test-Cmd $Name) {
        Write-Ok "$Name already installed"
        return
    }

    $TmpZip = "$env:TEMP\$Name.zip"
    $TmpDir = "$env:TEMP\$Name-extract"

    if (Test-Path $TmpDir) {
        Remove-Item $TmpDir -Recurse -Force
    }

    Invoke-Retry -Attempts 3 -Script {
        Invoke-WebRequest -Uri $Url -OutFile $TmpZip
    }

    Expand-Archive -Path $TmpZip -DestinationPath $TmpDir -Force

    New-Directory "C:\Tools\bin"
    Copy-Item "$TmpDir\$ExeName" "C:\Tools\bin\$ExeName" -Force

    Remove-Item $TmpZip -Force -ErrorAction SilentlyContinue
    Remove-Item $TmpDir -Recurse -Force -ErrorAction SilentlyContinue

    Write-Ok "$Name installed"
}

Install-ZipBinary -Name "httpx" -Url "https://github.com/projectdiscovery/httpx/releases/download/v${HttpxVersion}/httpx_${HttpxVersion}_windows_amd64.zip" -ExeName "httpx.exe"
Install-ZipBinary -Name "nuclei" -Url "https://github.com/projectdiscovery/nuclei/releases/download/v${NucleiVersion}/nuclei_${NucleiVersion}_windows_amd64.zip" -ExeName "nuclei.exe"

if (!(Test-Cmd masscan)) {

    Write-Info "Installing Masscan"

    $MasscanUrl = "https://github.com/bi-zone/masscan-ng/releases/download/v1.3.2/masscan-ng_win.zip"

    $TmpZip = "$env:TEMP\masscan.zip"
    $TmpDir = "$env:TEMP\masscan"

    Invoke-Retry -Attempts 3 -Script {
        Invoke-WebRequest -Uri $MasscanUrl -OutFile $TmpZip
    }

    Expand-Archive -Path $TmpZip -DestinationPath $TmpDir -Force

    New-Directory "C:\Tools\bin"

    $exe = Get-ChildItem $TmpDir -Recurse -Filter "masscan-ng.exe" | Select-Object -First 1

    if ($exe) {

        $dir = Split-Path $exe.FullName

        Copy-Item "$dir\*" "C:\Tools\bin\" -Force

        Rename-Item "C:\Tools\bin\masscan-ng.exe" "masscan.exe" -Force

        Write-Ok "Masscan installed"

    } else {

        Write-Err "masscan-ng.exe not found in archive"
        exit 1

    }

    Remove-Item $TmpZip -Force -ErrorAction SilentlyContinue
    Remove-Item $TmpDir -Recurse -Force -ErrorAction SilentlyContinue

} else {

    Write-Ok "Masscan already installed"

}

if (!(Test-Path "$InstallDir\Sublist3r")) {
    Write-Info "Cloning Sublist3r"
    Invoke-Retry -Attempts 3 -Script {
        git clone https://github.com/aboul3la/Sublist3r.git "$InstallDir\Sublist3r"
    }
} else {
    Write-Ok "Sublist3r already present"
}

Write-Info "Creating Python virtual environment"
Set-Location $InstallDir

if (!(Test-Path "$InstallDir\autorecon_env")) {
    Invoke-Expression "$pythonCmd -m venv autorecon_env"
} else {
    Write-Ok "Virtual environment already exists"
}

& "$InstallDir\autorecon_env\Scripts\python.exe" -m pip install --upgrade pip
& "$InstallDir\autorecon_env\Scripts\pip.exe" install -r "$InstallDir\requirements.txt"

$BatContent = @"
@echo off
call C:\Tools\AutoRecon\autorecon_env\Scripts\activate.bat
python C:\Tools\AutoRecon\AutoRecon.py
"@

Set-Content -Path "C:\Tools\AutoRecon\AutoRecon.bat" -Value $BatContent -Encoding ASCII

$CurrentPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($CurrentPath -notlike "*C:\Tools\bin*") {
    [Environment]::SetEnvironmentVariable("Path", "$CurrentPath;C:\Tools\bin", "User")
}
if ($CurrentPath -notlike "*C:\Program Files (x86)\Nmap*") {
    [Environment]::SetEnvironmentVariable(
        "Path",
        "$CurrentPath;C:\Tools\bin;C:\Program Files (x86)\Nmap",
        "User"
    )
}

Write-Host ""
Write-Host "======================================" 
Write-Host "       Installation Completed"
Write-Host "======================================"
Write-Host ""
Write-Host "Run AutoRecon with:"
Write-Host "C:\Tools\AutoRecon\AutoRecon.bat"
Write-Host ""
Write-Host "Reopen your terminal if commands are not yet available."