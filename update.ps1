#Requires -Version 5.1
<#
.SYNOPSIS
    AutoRecon - Update Script (Windows)
.DESCRIPTION
    Pulls the latest AutoRecon code from GitHub while preserving:
      - All scan results  (results/)
      - Mapping plugin results  (plugins/mapping/results/)
      - Ping plugin results, if any  (plugins/ping/results/)
      - Any user-created plugins  (plugins/<anything not official>/)
      - Your PDF personalisation  (personalize_pdf/name.txt)

    Only code files, core modules, wordlists and official plugin
    scripts are updated.  No data is ever deleted or overwritten.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# --- Console helpers -----------------------------------------------------------

function Write-Log  { param([string]$Msg) Write-Host "[*] $Msg" -ForegroundColor Cyan   }
function Write-Ok   { param([string]$Msg) Write-Host "[+] $Msg" -ForegroundColor Green  }
function Write-Warn { param([string]$Msg) Write-Host "[!] $Msg" -ForegroundColor Yellow }
function Write-Err  { param([string]$Msg) Write-Host "[x] $Msg" -ForegroundColor Red    }
function Write-Info { param([string]$Msg) Write-Host "[i] $Msg" -ForegroundColor Gray   }

# --- Official plugins shipped with AutoRecon ----------------------------------
# Only these are updated from the remote repo.
# Any other folder found under plugins/ is treated as a user plugin and left alone.

$OFFICIAL_PLUGINS = @("mapping", "ping")

# --- Locate install directory -------------------------------------------------

function Find-InstallDir {
    # 1) Directory where this script lives
    $candidates = @(
        $PSScriptRoot,
        (Split-Path -Parent $MyInvocation.ScriptName),
        "C:\Tools\AutoRecon"
    )
    foreach ($dir in $candidates) {
        if ($dir -and (Test-Path "$dir\AutoRecon.py") -and (Test-Path "$dir\.git")) {
            return $dir
        }
    }
    Write-Err "Could not locate the AutoRecon install directory."
    Write-Err "Run this script from inside the install directory, or install first with install.ps1"
    exit 1
}

# --- Verify prerequisites -----------------------------------------------------

function Assert-Git {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Err "git is not installed or not in PATH."
        Write-Err "Install Git for Windows: https://git-scm.com/download/win"
        exit 1
    }
}

# --- Preserve / restore user customisations ----------------------------------

function Save-UserData {
    param([string]$InstallDir)

    $script:SavedNameContent = $null
    $namePath = Join-Path $InstallDir "personalize_pdf\name.txt"
    if (Test-Path $namePath) {
        $script:SavedNameContent = Get-Content $namePath -Raw -Encoding UTF8
        Write-Info "Saved personalize_pdf/name.txt"
    }
}

function Restore-UserData {
    param([string]$InstallDir)

    $namePath = Join-Path $InstallDir "personalize_pdf\name.txt"
    if ($null -ne $script:SavedNameContent) {
        # Ensure directory still exists (git checkout won't delete it, but be safe)
        $nameDir = Split-Path -Parent $namePath
        if (-not (Test-Path $nameDir)) { New-Item -ItemType Directory -Path $nameDir -Force | Out-Null }
        [System.IO.File]::WriteAllText($namePath, $script:SavedNameContent, [System.Text.Encoding]::UTF8)
        Write-Ok "Restored personalize_pdf/name.txt"
    }
}

# --- Selective git update -----------------------------------------------------
# Helper: run a git command, suppressing PS NativeCommandError from git's
# informational stderr output.  Returns $true on success (exit code 0).
function Invoke-Git {
    param([string[]]$GitArgs)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    & git @GitArgs 2>&1 | Out-Null
    $code = $LASTEXITCODE
    $ErrorActionPreference = $prev
    return ($code -eq 0)
}

# Helper: run a git command and return its stdout as an array of strings.
function Get-GitOutput {
    param([string[]]$GitArgs)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    $out = & git @GitArgs 2>&1
    $ErrorActionPreference = $prev
    return $out
}

function Update-Code {
    param([string]$InstallDir)

    Set-Location $InstallDir

    Write-Log "Fetching latest code from GitHub..."
    $ok = Invoke-Git @("fetch", "origin", "main")
    if (-not $ok) {
        $ok = Invoke-Git @("fetch", "origin")
        if (-not $ok) {
            Write-Err "git fetch failed. Check your internet connection."
            exit 1
        }
    }

    $localHash  = (Get-GitOutput @("rev-parse", "HEAD")        | Select-Object -First 1).Trim()
    $remoteHash = (Get-GitOutput @("rev-parse", "origin/main") | Select-Object -First 1).Trim()

    if ($localHash -eq $remoteHash) {
        Write-Ok "AutoRecon is already up to date  (commit: $($localHash.Substring(0,7)))"
        $script:AppliedCommit = $localHash.Substring(0, 7)
        return $false
    }

    $oldCommit = $localHash.Substring(0, 7)
    $newCommit = $remoteHash.Substring(0, 7)
    Write-Log "Update available  ($oldCommit -> $newCommit) - applying..."

    # Root-level code files
    $rootFiles = @(
        "AutoRecon.py", "main.py",
        "requirements.txt", "README.md",
        "AutoRecon.sh", "install.ps1",
        "update.ps1", "update.sh"
    )
    foreach ($f in $rootFiles) {
        if (Invoke-Git @("cat-file", "-e", "origin/main:$f")) {
            Invoke-Git @("checkout", "origin/main", "--", $f) | Out-Null
        }
    }
    Write-Ok "Root files updated"

    # core/ directory
    if (Invoke-Git @("cat-file", "-e", "origin/main:core")) {
        Invoke-Git @("checkout", "origin/main", "--", "core/") | Out-Null
        Write-Ok "core/ updated"
    }

    # wordlists/ directory
    if (Invoke-Git @("cat-file", "-e", "origin/main:wordlists")) {
        Invoke-Git @("checkout", "origin/main", "--", "wordlists/") | Out-Null
        Write-Ok "wordlists/ updated"
    }

    # Official plugins (code only; results/ sub-dirs are never git-tracked)
    foreach ($plugin in $OFFICIAL_PLUGINS) {
        if (Invoke-Git @("cat-file", "-e", "origin/main:plugins/$plugin")) {
            Invoke-Git @("checkout", "origin/main", "--", "plugins/$plugin/") | Out-Null
            Write-Ok "Plugin '$plugin' code updated"
        }
    }

    # New official plugins added to repo that don't exist locally yet
    $remotePaths = Get-GitOutput @("ls-tree", "--name-only", "origin/main:plugins")
    foreach ($remPlugin in $remotePaths) {
        $remPlugin = $remPlugin.Trim()
        if (-not $remPlugin) { continue }
        if ($OFFICIAL_PLUGINS -contains $remPlugin) { continue }
        $localPath = Join-Path $InstallDir "plugins\$remPlugin"
        if (-not (Test-Path $localPath)) {
            Invoke-Git @("checkout", "origin/main", "--", "plugins/$remPlugin/") | Out-Null
            Write-Ok "New official plugin '$remPlugin' installed"
        }
    }

    Write-Ok "Code update complete  (commit: $newCommit)"
    $script:AppliedCommit = $newCommit
    return $true
}

# --- Report untouched user plugins -------------------------------------------

function Show-UserPlugins {
    param([string]$InstallDir)

    $pluginsDir = Join-Path $InstallDir "plugins"
    if (-not (Test-Path $pluginsDir)) { return }

    Get-ChildItem $pluginsDir -Directory | ForEach-Object {
        if ($OFFICIAL_PLUGINS -notcontains $_.Name) {
            Write-Info "User plugin '$($_.Name)' - left untouched"
        }
    }
}

# --- Update Python dependencies -----------------------------------------------

function Update-Dependencies {
    param([string]$InstallDir)

    Write-Log "Updating Python dependencies..."

    # ── Locate a working Python executable ────────────────────────────────
    # Prefer venv Python, fall back to the system Python in PATH.
    function Find-WorkingPython {
        param([string]$InstallDir)
        $candidates = @(
            (Join-Path $InstallDir "autorecon_env\Scripts\python.exe"),
            "C:\Tools\AutoRecon\autorecon_env\Scripts\python.exe"
        )
        foreach ($c in $candidates) {
            if (Test-Path $c) {
                # Verify the shim actually resolves to a real Python
                $ver = & $c --version 2>&1
                if ($LASTEXITCODE -eq 0 -and $ver -match 'Python') { return $c }
            }
        }
        # Fall back to system python
        $sys = Get-Command python -ErrorAction SilentlyContinue
        if ($sys) {
            $ver = & $sys.Source --version 2>&1
            if ($LASTEXITCODE -eq 0 -and $ver -match 'Python') { return $sys.Source }
        }
        return $null
    }

    $pyExe = Find-WorkingPython -InstallDir $InstallDir

    if (-not $pyExe) {
        Write-Warn "No working Python found - skipping dependency update."
        Write-Warn "Run manually:  python -m pip install -r requirements.txt --upgrade"
        return
    }

    Write-Info "Using Python: $pyExe"

    & $pyExe -m pip install -r (Join-Path $InstallDir "requirements.txt") --upgrade --quiet
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "pip install returned a non-zero exit code. Some packages may not have updated."
    } else {
        Write-Ok "Python dependencies updated"
    }

    # Ensure Playwright browser is installed/updated
    # Temporarily relax $ErrorActionPreference so that Node.js deprecation
    # warnings written to stderr don't get promoted to terminating errors.
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    & $pyExe -m playwright install chromium 2>$null
    $playwrightExit = $LASTEXITCODE
    $ErrorActionPreference = $prevEAP
    if ($playwrightExit -ne 0) {
        Write-Warn "playwright install chromium failed (DOM XSS scanning will be skipped)"
    }
}

function Update-OptionalTools {
    # Ensure Go bin folder is on PATH
    $env:Path = "$env:Path;$env:USERPROFILE\go\bin;C:\Program Files\Go\bin"

    if (!(Get-Command go -ErrorAction SilentlyContinue)) {
        Write-Warn "Go not found -- skipping gowitness / subfinder / gobuster check"
    } else {
        $goTools = @(
            @{ Name = "gowitness"; Module = "github.com/sensepost/gowitness@latest" },
            @{ Name = "subfinder"; Module = "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" },
            @{ Name = "gobuster"; Module = "github.com/OJ/gobuster/v3@latest" },
            @{ Name = "amass";    Module = "github.com/owasp-amass/amass/v4/...@master" }
        )
        foreach ($tool in $goTools) {
            if (Get-Command $tool.Name -ErrorAction SilentlyContinue) {
                Write-Ok "$($tool.Name) already installed"
            } else {
                Write-Info "Installing $($tool.Name)"
                go install $tool.Module
                if ($LASTEXITCODE -ne 0) {
                    Write-Warn "$($tool.Name) install failed (optional)"
                } else {
                    Write-Ok "$($tool.Name) installed"
                }
            }
        }
    }

    # ── sslscan (binary download from GitHub releases) ─────────────────────────
    if (Get-Command sslscan -ErrorAction SilentlyContinue) {
        Write-Ok "sslscan already installed"
    } else {
        Write-Info "Installing sslscan"
        try {
            $rel   = Invoke-RestMethod -Uri "https://api.github.com/repos/rbsec/sslscan/releases/latest" -UseBasicParsing
            $asset = $rel.assets | Where-Object { $_.name -match "win64\.zip$" } | Select-Object -First 1
            if ($asset) {
                $TmpZip = "$env:TEMP\sslscan.zip"
                $TmpDir = "$env:TEMP\sslscan-extract"
                if (Test-Path $TmpDir) { Remove-Item $TmpDir -Recurse -Force }
                Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $TmpZip
                Expand-Archive -Path $TmpZip -DestinationPath $TmpDir -Force
                $exe = Get-ChildItem $TmpDir -Recurse -Filter "sslscan.exe" | Select-Object -First 1
                if ($exe) {
                    $null = New-Item -ItemType Directory -Path "C:\Tools\bin" -Force
                    Copy-Item $exe.FullName "C:\Tools\bin\sslscan.exe" -Force
                    Write-Ok "sslscan installed"
                } else {
                    Write-Warn "sslscan: sslscan.exe not found in archive"
                }
                Remove-Item $TmpZip -Force -ErrorAction SilentlyContinue
                Remove-Item $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
            } else {
                Write-Warn "sslscan: no Windows 64-bit release found on GitHub"
            }
        } catch {
            Write-Warn "sslscan install failed (optional): $_"
        }
    }
}

# --- Self-update (re-exec if update.ps1 itself changed on GitHub) ------------

function Invoke-SelfUpdate {
    param([string]$InstallDir)

    # $PSCommandPath is the full path of the running script (PS 3+)
    $thisScript = $PSCommandPath
    if (-not $thisScript -or -not (Test-Path $thisScript)) { return }

    Set-Location $InstallDir

    # Remote blob hash from origin/main
    $lsLine = Get-GitOutput @("ls-tree", "origin/main", "--", "update.ps1") | Select-Object -First 1
    if (-not $lsLine) { return }
    $remoteBlob = ($lsLine -split '\s+')[2].Trim()

    # Local blob hash (git-computed SHA-1 of the working-tree file)
    $localBlob = (Get-GitOutput @("hash-object", $thisScript) | Select-Object -First 1).Trim()

    if (-not $remoteBlob -or -not $localBlob -or $remoteBlob -eq $localBlob) { return }

    Write-Log "update.ps1 has changed on GitHub — applying self-update and restarting..."
    Invoke-Git @("checkout", "origin/main", "--", "update.ps1") | Out-Null
    Write-Ok "New update.ps1 applied"
    Write-Host ""

    # Re-execute the freshly downloaded script in a new PS process, then exit.
    $newScript = Join-Path $InstallDir "update.ps1"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $newScript
    exit $LASTEXITCODE
}

# --- Summary banner -----------------------------------------------------------

$script:AppliedCommit = ""

function Show-Summary {
    param([string]$InstallDir, [bool]$Updated)

    $commit = if ($script:AppliedCommit) { $script:AppliedCommit } else { (Get-GitOutput @("rev-parse", "--short", "HEAD") | Select-Object -First 1).Trim() }
    Write-Host ""
    Write-Host "  ==========================================" -ForegroundColor DarkGray
    Write-Host "       AutoRecon - Update Complete"          -ForegroundColor Cyan
    Write-Host "  ==========================================" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Install dir  : $InstallDir" -ForegroundColor Gray
    Write-Host "  Commit       : $commit" -ForegroundColor Gray
    if ($Updated) {
        Write-Host "  Status       : Code updated successfully" -ForegroundColor Green
    } else {
        Write-Host "  Status       : Already up to date" -ForegroundColor Green
    }
    Write-Host ""
    Write-Host "  Scan results, plugin results and user plugins are intact." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Run AutoRecon:  .\AutoRecon.py   or   AutoRecon.bat" -ForegroundColor Cyan
    Write-Host ""
}

# --- Main --------------------------------------------------------------------

Write-Host ""
Write-Host "  ==========================================" -ForegroundColor DarkGray
Write-Host "       AutoRecon Updater (Windows)"          -ForegroundColor Cyan
Write-Host "  ==========================================" -ForegroundColor DarkGray
Write-Host ""

Assert-Git
$installDir = Find-InstallDir
Write-Info "Install dir: $installDir"
Write-Host ""

# Early fetch so we can detect whether update.ps1 itself has changed.
Set-Location $installDir
Invoke-Git @("fetch", "origin", "main") | Out-Null
Invoke-SelfUpdate -InstallDir $installDir   # Re-execs with new script if update.ps1 changed

Save-UserData    -InstallDir $installDir
$updated = Update-Code -InstallDir $installDir
Restore-UserData -InstallDir $installDir

Show-UserPlugins -InstallDir $installDir

Update-Dependencies -InstallDir $installDir
Update-OptionalTools

Show-Summary -InstallDir $installDir -Updated $updated
