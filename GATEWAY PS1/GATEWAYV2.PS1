<#
═══════════════════════════════════════════════════════════
🔐 CRYPTO-PROTECTED CODE 🔐
═══════════════════════════════════════════════════════════

Author:           Leon Sage
Organization:     Sage Audio LLC
Copyright:        © 2025 Leon Sage. All Rights Reserved.
License:          Proprietary
Signed:           2026-01-26 18:47:12
Certificate:      CodeSigning-LeonSage

CRYPTOGRAPHIC FINGERPRINT:
SHA-256:  A0C553CFE5F142BF7F7B4FDF9E19849C3ADD3334A0541C05EA416374CAA7312D
SHA-512:  387281FE6007CB57B9B1984064BD3CB6DC019670283D689E2E52A6141BC5B30FC320E25EA431CAB680CD1C61A09ECD9354EEEC955040DDB4099F5DEEBE8C152C
MD5:      5438B2C2BAD6F7D5D3CC50119DE06DA4
File Size: 57770 bytes

LICENSE:
PROPRIETARY LICENSE

Copyright (c) 2026 Leon Sage. All Rights Reserved.
Sage Audio LLC

This software is proprietary and confidential property of Leon Sage.
UNAUTHORIZED COPYING, MODIFICATION, DISTRIBUTION, OR USE IS STRICTLY PROHIBITED.

⚠️  ANTI-THEFT NOTICE:
This code is cryptographically signed and protected. Any
unauthorized modification, distribution, or removal of this
protection constitutes copyright infringement.
═══════════════════════════════════════════════════════════
#>

<#
═══════════════════════════════════════════════════════════════════
DIGITAL SIGNATURE & COPYRIGHT PROTECTION
═══════════════════════════════════════════════════════════════════
Digitally Signed by: Leon Sage
Organization:        Sage Audio LLC
© 2025-2026 Leon Sage. All Rights Reserved.
License:             Proprietary - Digitally Signed
Signed Date:         2026-01-22 15:17:36
Certificate:         CodeSigning-LeonSage-2026

⚠️ NOTICE: This code is digitally signed and protected.
Unauthorized modification, distribution, or removal of this
signature constitutes copyright infringement.
═══════════════════════════════════════════════════════════════════
#>
<#
.SYNOPSIS
    PowerShell Script Gateway - Manage and execute multiple PS1 scripts from a single interface
.DESCRIPTION
    A centralized controller for executing, managing, and interacting with PowerShell scripts.
    Provides discovery, execution, logging, and dependency management capabilities.
.NOTES
    Version    : 2.0.0
    Author     : PowerShell Gateway System
    Created    : $(Get-Date -Format "yyyy-MM-dd")
    Requires   : PowerShell 5.1+
.LINK
    GitHub     : https://github.com/example/ps-gateway
.EXAMPLE
    .\ScriptGateway.ps1
    Launches interactive menu mode
.EXAMPLE
    .\ScriptGateway.ps1 -List
    Lists all available scripts
.EXAMPLE
    .\ScriptGateway.ps1 -Run "BackupScript,CleanupScript"
    Executes specific scripts
.EXAMPLE
    .\ScriptGateway.ps1 -ScanPath "C:\MyScripts" -AutoImport
    Scans new directory and imports scripts
#>

#region Initialization and Configuration
[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param(
    [Parameter(ParameterSetName = 'List')]
    [switch]$List,
    
    [Parameter(ParameterSetName = 'Run')]
    [string[]]$Run,
    
    [Parameter(ParameterSetName = 'Import')]
    [switch]$ImportAll,
    
    [Parameter(ParameterSetName = 'Scan')]
    [string]$ScanPath,
    
    [Parameter(ParameterSetName = 'Scan')]
    [switch]$AutoImport,
    
    [Parameter(ParameterSetName = 'Interactive')]
    [switch]$Interactive,
    
    [Parameter(ParameterSetName = 'Info')]
    [string]$GetInfo,
    
    [Parameter()]
    [hashtable]$Parameters,
    
    [Parameter()]
    [string]$LogPath = "$env:TEMP\ScriptGateway.log",
    
    [Parameter()]
    [switch]$NoColor,
    
    [Parameter()]
    [switch]$Force
)

# Clear host for clean start
if ($Interactive -or $PSCmdlet.ParameterSetName -eq 'Interactive') {
    Clear-Host
}

# Console Colors Configuration
if (-not $NoColor) {
    $Host.UI.RawUI.BackgroundColor = 'Black'
    $Host.UI.RawUI.ForegroundColor = 'White'
    Clear-Host
    
    # Color Scheme
    $Color = @{
        Header = 'Cyan'
        Success = 'Green'
        Warning = 'Yellow'
        Error = 'Red'
        Info = 'Gray'
        Highlight = 'Magenta'
        Command = 'White'
        Parameter = 'DarkCyan'
    }
} else {
    $Color = @{}
    foreach ($key in 'Header','Success','Warning','Error','Info','Highlight','Command','Parameter') {
        $Color[$key] = 'Gray'
    }
}

# ASCII Art Banner
function Show-Banner {
    Write-Host @"
    
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║    ██████╗ ███████╗ ██████╗███╗   ██╗███████╗███████╗    ║
║    ██╔══██╗██╔════╝██╔════╝████╗  ██║██╔════╝██╔════╝    ║
║    ██████╔╝███████╗██║     ██╔██╗ ██║███████╗█████╗      ║
║    ██╔═══╝ ╚════██║██║     ██║╚██╗██║╚════██║██╔══╝      ║
║    ██║     ███████║╚██████╗██║ ╚████║███████║███████╗    ║
║    ╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═══╝╚══════╝╚══════╝    ║
║                                                           ║
║              S C R I P T   G A T E W A Y   v2.0           ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
"@ -ForegroundColor $Color.Header
}

# Logging Function
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [ValidateSet('INFO','WARNING','ERROR','DEBUG','SUCCESS')]
        [string]$Level = 'INFO',
        
        [switch]$NoConsole
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to log file
    $logEntry | Out-File -FilePath $LogPath -Append -Encoding UTF8
    
    # Write to console with colors
    if (-not $NoConsole) {
        switch ($Level) {
            'SUCCESS' { Write-Host $logEntry -ForegroundColor $Color.Success }
            'WARNING' { Write-Host $logEntry -ForegroundColor $Color.Warning }
            'ERROR'   { Write-Host $logEntry -ForegroundColor $Color.Error }
            'DEBUG'   { Write-Host $logEntry -ForegroundColor $Color.Info }
            default   { Write-Host $logEntry -ForegroundColor $Color.Info }
        }
    }
}

# Initialize Log
Write-Log "Script Gateway initialized" -Level INFO -NoConsole
Write-Log "Log file: $LogPath" -Level DEBUG -NoConsole

# Script Registry (auto-discover on first run)
$ScriptGateway = @{
    Config = @{
        ScriptsRoot = "C:\ScriptGateway\Scripts"
        ConfigFile = "C:\ScriptGateway\gateway_config.json"
        MaxExecutionTime = 300  # seconds
        EnableTelemetry = $false
        DefaultScope = "Local"
    }
    State = @{
        LoadedScripts = @{}
        ExecutionHistory = [System.Collections.ArrayList]::new()
        AvailableScripts = @{}
        Dependencies = @{}
    }
}

# Ensure script directory exists
function Initialize-ScriptGateway {
    Write-Log "Initializing Script Gateway environment..." -Level INFO
    
    if (-not (Test-Path $ScriptGateway.Config.ScriptsRoot)) {
        Write-Log "Creating scripts directory: $($ScriptGateway.Config.ScriptsRoot)" -Level INFO
        New-Item -Path $ScriptGateway.Config.ScriptsRoot -ItemType Directory -Force | Out-Null
        
        # Create example scripts
        Create-ExampleScripts
    }
    
    if (-not (Test-Path $ScriptGateway.Config.ConfigFile)) {
        Save-GatewayConfig
    } else {
        Load-GatewayConfig
    }
    
    Discover-AvailableScripts
    Write-Log "Initialization complete" -Level SUCCESS
}

# Create example scripts if folder is empty
function Create-ExampleScripts {
    Write-Log "Creating example scripts..." -Level INFO
    
    # Example: System Info Script
@'
<#
.SYNOPSIS
    Get detailed system information
#>
function Get-SystemInfo {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )
    
    $info = [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        OS = (Get-CimInstance Win32_OperatingSystem).Caption
        PSVersion = $PSVersionTable.PSVersion.ToString()
        RAM_GB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
        Uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
        CPU = (Get-CimInstance Win32_Processor).Name
    }
    
    if ($Detailed) {
        $info | Add-Member -NotePropertyName "Drives" -NotePropertyValue (Get-PSDrive -PSProvider FileSystem | Where-Object Used)
        $info | Add-Member -NotePropertyName "NetworkAdapters" -NotePropertyValue (Get-NetAdapter | Where-Object Status -eq 'Up')
    }
    
    return $info
}

function Test-SystemHealth {
    [CmdletBinding()]
    param()
    
    $health = @{
        DiskSpace = @{}
        Services = @()
        Events = @()
    }
    
    # Check disk space
    Get-PSDrive -PSProvider FileSystem | ForEach-Object {
        $percentFree = ($_.Free / $_.Used) * 100
        $health.DiskSpace[$_.Name] = @{
            FreeGB = [math]::Round($_.Free / 1GB, 2)
            PercentFree = [math]::Round($percentFree, 2)
            Status = if ($percentFree -lt 10) { "CRITICAL" } elseif ($percentFree -lt 20) { "WARNING" } else { "OK" }
        }
    }
    
    return $health
}

Export-ModuleMember -Function Get-SystemInfo, Test-SystemHealth
'@ | Out-File -FilePath "$($ScriptGateway.Config.ScriptsRoot)\SystemInfo.ps1" -Encoding UTF8

    # Example: File Operations Script
@'
<#
.SYNOPSIS
    File and folder operations
#>
function Invoke-FileCleanup {
    [CmdletBinding()]
    param(
        [string]$Path = $env:TEMP,
        [int]$DaysOld = 7,
        [switch]$WhatIf
    )
    
    $cutoffDate = (Get-Date).AddDays(-$DaysOld)
    $files = Get-ChildItem -Path $Path -File -Recurse -ErrorAction SilentlyContinue | 
             Where-Object { $_.LastWriteTime -lt $cutoffDate }
    
    if ($WhatIf) {
        Write-Host "[WHATIF] Would remove $($files.Count) files older than $DaysOld days"
        return $files
    }
    
    $removed = 0
    foreach ($file in $files) {
        try {
            Remove-Item -Path $file.FullName -Force -ErrorAction Stop
            Write-Log "Removed: $($file.FullName)" -Level INFO
            $removed++
        }
        catch {
            Write-Log "Failed to remove $($file.FullName): $_" -Level ERROR
        }
    }
    
    return @{
        TotalFound = $files.Count
        SuccessfullyRemoved = $removed
        Failed = $files.Count - $removed
    }
}

function New-FolderStructure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$BasePath,
        
        [string[]]$Folders = @("Data","Logs","Backups","Temp")
    )
    
    $created = @()
    foreach ($folder in $Folders) {
        $fullPath = Join-Path $BasePath $folder
        if (-not (Test-Path $fullPath)) {
            New-Item -Path $fullPath -ItemType Directory -Force | Out-Null
            $created += $fullPath
        }
    }
    
    return $created
}

Export-ModuleMember -Function Invoke-FileCleanup, New-FolderStructure
'@ | Out-File -FilePath "$($ScriptGateway.Config.ScriptsRoot)\FileOps.ps1" -Encoding UTF8

    # Example: Network Tools Script
@'
<#
.SYNOPSIS
    Network diagnostic and utility functions
#>
function Test-NetworkConnectivity {
    [CmdletBinding()]
    param(
        [string[]]$Targets = @("8.8.8.8", "1.1.1.1", $env:COMPUTERNAME),
        [int]$Count = 4
    )
    
    $results = @()
    foreach ($target in $Targets) {
        try {
            $ping = Test-Connection -ComputerName $target -Count $Count -ErrorAction Stop
            $result = [PSCustomObject]@{
                Target = $target
                Status = "REACHABLE"
                AvgLatency = ($ping | Measure-Object ResponseTime -Average).Average
                PacketLoss = (($ping | Where-Object { $_.StatusCode -ne 0 }).Count / $Count) * 100
                LastTest = Get-Date
            }
        }
        catch {
            $result = [PSCustomObject]@{
                Target = $target
                Status = "UNREACHABLE"
                AvgLatency = $null
                PacketLoss = 100
                LastTest = Get-Date
                Error = $_.Exception.Message
            }
        }
        
        $results += $result
    }
    
    return $results
}

function Get-NetworkInfo {
    [CmdletBinding()]
    param()
    
    $adapters = Get-NetAdapter | Where-Object Status -eq 'Up'
    $info = @()
    
    foreach ($adapter in $adapters) {
        $ipConfig = Get-NetIPConfiguration -InterfaceAlias $adapter.Name
        $info += [PSCustomObject]@{
            AdapterName = $adapter.Name
            Status = $adapter.Status
            MACAddress = $adapter.MacAddress
            IPv4Address = ($ipConfig.IPv4Address.IPAddress) -join ', '
            IPv6Address = ($ipConfig.IPv6Address.IPAddress) -join ', '
            DNS = ($ipConfig.DNSServer.ServerAddresses) -join ', '
            Speed = if ($adapter.LinkSpeed) { $adapter.LinkSpeed } else { "N/A" }
        }
    }
    
    return $info
}

Export-ModuleMember -Function Test-NetworkConnectivity, Get-NetworkInfo
'@ | Out-File -FilePath "$($ScriptGateway.Config.ScriptsRoot)\NetworkTools.ps1" -Encoding UTF8
    
    Write-Log "Created 3 example scripts in $($ScriptGateway.Config.ScriptsRoot)" -Level SUCCESS
}
#endregion

#region Core Functions
function Discover-AvailableScripts {
    Write-Log "Discovering available scripts..." -Level INFO
    
    $scriptFiles = Get-ChildItem -Path $ScriptGateway.Config.ScriptsRoot -Filter "*.ps1" -Recurse -File
    
    foreach ($script in $scriptFiles) {
        try {
            # Parse script metadata
            $content = Get-Content $script.FullName -Raw
            $functions = [regex]::Matches($content, 'function\s+(\w+-[\w]+)') | 
                         ForEach-Object { $_.Groups[1].Value }
            
            # Get description from SYNOPSIS if available
            $synopsisMatch = [regex]::Match($content, '\.SYNOPSIS\s*\r?\n\s*(.+?)\r?\n\.')
            $description = if ($synopsisMatch.Success) { $synopsisMatch.Groups[1].Value.Trim() } else { "No description available" }
            
            # Get parameters if any
            $paramMatches = [regex]::Matches($content, 'param\s*\(([^)]+)\)', [System.Text.RegularExpressions.RegexOptions]::Singleline)
            $parameters = @()
            if ($paramMatches.Success) {
                $paramText = $paramMatches[0].Groups[1].Value
                $paramLines = $paramText -split "`n" | Where-Object { $_ -match '\[\w+\]' }
                foreach ($line in $paramLines) {
                    if ($line -match '\[(Parameter|string|int|switch)\]') {
                        $parameters += $line.Trim()
                    }
                }
            }
            
            $ScriptGateway.State.AvailableScripts[$script.BaseName] = @{
                Path = $script.FullName
                Name = $script.BaseName
                FullName = $script.Name
                Directory = $script.DirectoryName
                SizeKB = [math]::Round($script.Length / 1KB, 2)
                LastModified = $script.LastWriteTime
                Functions = $functions
                Description = $description
                Parameters = $parameters
                IsLoaded = $false
                Dependencies = @()  # Could parse #requires statements
            }
            
            Write-Log "Discovered: $($script.BaseName) ($($functions.Count) functions)" -Level DEBUG
        }
        catch {
            Write-Log "Error parsing script $($script.Name): $_" -Level ERROR
        }
    }
    
    Write-Log "Discovered $($ScriptGateway.State.AvailableScripts.Count) scripts" -Level SUCCESS
}

function Load-Script {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ScriptName,
        
        [switch]$ForceReload
    )
    
    if (-not $ScriptGateway.State.AvailableScripts.ContainsKey($ScriptName)) {
        Write-Log "Script '$ScriptName' not found" -Level ERROR
        return $null
    }
    
    $scriptInfo = $ScriptGateway.State.AvailableScripts[$ScriptName]
    
    # Check if already loaded
    if ($ScriptGateway.State.LoadedScripts.ContainsKey($ScriptName) -and -not $ForceReload) {
        Write-Log "Script '$ScriptName' already loaded" -Level INFO
        return $ScriptGateway.State.LoadedScripts[$ScriptName]
    }
    
    try {
        Write-Log "Loading script: $ScriptName" -Level INFO
        
        # Dot source the script to import its functions
        . $scriptInfo.Path
        
        # Store loaded script info
        $loadedScript = @{
            Info = $scriptInfo
            LoadedAt = Get-Date
            Functions = $scriptInfo.Functions
            Scope = $ScriptGateway.Config.DefaultScope
        }
        
        $ScriptGateway.State.LoadedScripts[$ScriptName] = $loadedScript
        $ScriptGateway.State.AvailableScripts[$ScriptName].IsLoaded = $true
        
        # Update execution history
        $historyEntry = @{
            Timestamp = Get-Date
            Action = 'LOAD'
            Script = $ScriptName
            Status = 'SUCCESS'
        }
        $ScriptGateway.State.ExecutionHistory.Add($historyEntry) | Out-Null
        
        Write-Log "Successfully loaded '$ScriptName' with $($scriptInfo.Functions.Count) functions" -Level SUCCESS
        
        return $loadedScript
    }
    catch {
        Write-Log "Failed to load script '$ScriptName': $_" -Level ERROR
        
        $historyEntry = @{
            Timestamp = Get-Date
            Action = 'LOAD'
            Script = $ScriptName
            Status = 'FAILED'
            Error = $_.Exception.Message
        }
        $ScriptGateway.State.ExecutionHistory.Add($historyEntry) | Out-Null
        
        return $null
    }
}

function Invoke-ScriptCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ScriptName,
        
        [string]$Command,
        
        [hashtable]$Arguments = @{},
        
        [int]$Timeout = $ScriptGateway.Config.MaxExecutionTime,
        
        [switch]$Async,
        
        [switch]$WhatIf
    )
    
    # Load script if not already loaded
    if (-not $ScriptGateway.State.LoadedScripts.ContainsKey($ScriptName)) {
        Write-Log "Script '$ScriptName' not loaded. Loading..." -Level INFO
        $loadedScript = Load-Script -ScriptName $ScriptName
        if (-not $loadedScript) {
            return $null
        }
    }
    
    $scriptInfo = $ScriptGateway.State.AvailableScripts[$ScriptName]
    
    if ($WhatIf) {
        Write-Host "[WHATIF] Would execute command from '$ScriptName'" -ForegroundColor $Color.Highlight
        if ($Command) {
            Write-Host "  Command: $Command" -ForegroundColor $Color.Command
        }
        if ($Arguments.Count -gt 0) {
            Write-Host "  Arguments:" -ForegroundColor $Color.Parameter
            $Arguments.GetEnumerator() | ForEach-Object {
                Write-Host "    $($_.Key) = $($_.Value)" -ForegroundColor $Color.Parameter
            }
        }
        return $null
    }
    
    try {
        Write-Log "Executing from '$ScriptName': $Command" -Level INFO
        
        $executionId = [guid]::NewGuid().ToString().Substring(0, 8)
        $startTime = Get-Date
        
        # Prepare script block
        $scriptBlock = {
            param($cmd, $args)
            
            if ($cmd) {
                # Execute specific command with arguments
                & $cmd @args
            } else {
                # Execute the whole script
                . $using:scriptInfo.Path
            }
        }
        
        if ($Async) {
            # Execute asynchronously
            $job = Start-Job -Name "SG_${ScriptName}_$executionId" -ScriptBlock $scriptBlock -ArgumentList $Command, $Arguments
            
            $result = @{
                JobId = $job.Id
                ExecutionId = $executionId
                Status = 'RUNNING'
                StartTime = $startTime
                Script = $ScriptName
                Command = $Command
            }
            
            Write-Log "Started async execution $executionId (Job ID: $($job.Id))" -Level INFO
        } else {
            # Execute synchronously with timeout
            $timer = [System.Diagnostics.Stopwatch]::StartNew()
            
            if ($Timeout -gt 0) {
                $job = Start-Job -ScriptBlock $scriptBlock -ArgumentList $Command, $Arguments
                
                Wait-Job $job -Timeout $Timeout | Out-Null
                
                if ($job.State -eq 'Running') {
                    Stop-Job $job
                    Remove-Job $job
                    throw "Execution timeout after $Timeout seconds"
                }
                
                $result = Receive-Job $job -ErrorAction Stop
                Remove-Job $job
            } else {
                # Execute directly without timeout
                if ($Command) {
                    $result = & $Command @Arguments
                } else {
                    $result = . $scriptInfo.Path
                }
            }
            
            $timer.Stop()
            $elapsed = $timer.Elapsed
            
            Write-Log "Execution completed in $($elapsed.TotalSeconds.ToString('0.00'))s" -Level SUCCESS
            
            # Add to history
            $historyEntry = @{
                Timestamp = $startTime
                Action = 'EXECUTE'
                Script = $ScriptName
                Command = $Command
                Duration = $elapsed.TotalSeconds
                Status = 'SUCCESS'
                ExecutionId = $executionId
            }
            $ScriptGateway.State.ExecutionHistory.Add($historyEntry) | Out-Null
            
            return $result
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        Write-Log "Execution failed: $errorMsg" -Level ERROR
        
        $historyEntry = @{
            Timestamp = Get-Date
            Action = 'EXECUTE'
            Script = $ScriptName
            Command = $Command
            Status = 'FAILED'
            Error = $errorMsg
            ExecutionId = if ($executionId) { $executionId } else { 'N/A' }
        }
        $ScriptGateway.State.ExecutionHistory.Add($historyEntry) | Out-Null
        
        throw $_
    }
}

function Save-GatewayConfig {
    Write-Log "Saving gateway configuration..." -Level INFO
    
    $config = @{
        Config = $ScriptGateway.Config
        State = @{
            AvailableScripts = $ScriptGateway.State.AvailableScripts
        }
        LastSaved = Get-Date
        Version = "2.0.0"
    }
    
    $config | ConvertTo-Json -Depth 10 | Out-File -FilePath $ScriptGateway.Config.ConfigFile -Encoding UTF8 -Force
    
    Write-Log "Configuration saved to $($ScriptGateway.Config.ConfigFile)" -Level SUCCESS
}

function Load-GatewayConfig {
    if (Test-Path $ScriptGateway.Config.ConfigFile) {
        try {
            $config = Get-Content $ScriptGateway.Config.ConfigFile -Raw | ConvertFrom-Json -AsHashtable
            
            # Merge with current config
            foreach ($key in $config.Config.Keys) {
                $ScriptGateway.Config[$key] = $config.Config[$key]
            }
            
            Write-Log "Configuration loaded from $($ScriptGateway.Config.ConfigFile)" -Level INFO
        }
        catch {
            Write-Log "Failed to load configuration: $_" -Level WARNING
        }
    }
}
#endregion

#region User Interface Functions
function Show-InteractiveMenu {
    Show-Banner
    
    $running = $true
    $selectedScript = $null
    
    while ($running) {
        Clear-Host
        Show-Banner
        
        Write-Host "`n" + ("═" * 70) + "`n" -ForegroundColor $Color.Info
        
        # Status Dashboard
        Write-Host " STATUS DASHBOARD" -ForegroundColor $Color.Header
        Write-Host " ──────────────────────────────────────────────────────────" -ForegroundColor $Color.Info
        Write-Host " Scripts Available: " -NoNewline
        Write-Host $ScriptGateway.State.AvailableScripts.Count -ForegroundColor $Color.Highlight -NoNewline
        Write-Host " | Loaded: " -NoNewline
        Write-Host $ScriptGateway.State.LoadedScripts.Count -ForegroundColor $Color.Highlight -NoNewline
        Write-Host " | History: " -NoNewline
        Write-Host $ScriptGateway.State.ExecutionHistory.Count -ForegroundColor $Color.Highlight
        
        if ($selectedScript) {
            Write-Host " Selected Script: " -NoNewline
            Write-Host $selectedScript -ForegroundColor $Color.Highlight
        }
        
        Write-Host "`n" + ("═" * 70) + "`n" -ForegroundColor $Color.Info
        
        # Main Menu
        Write-Host " MAIN MENU" -ForegroundColor $Color.Header
        Write-Host " ──────────────────────────────────────────────────────────" -ForegroundColor $Color.Info
        Write-Host " 1. Browse Available Scripts" -ForegroundColor $Color.Command
        Write-Host " 2. Load/Unload Scripts" -ForegroundColor $Color.Command
        Write-Host " 3. Execute Script/Command" -ForegroundColor $Color.Command
        Write-Host " 4. Scan for New Scripts" -ForegroundColor $Color.Command
        Write-Host " 5. View Execution History" -ForegroundColor $Color.Command
        Write-Host " 6. Script Information & Help" -ForegroundColor $Color.Command
        Write-Host " 7. Configuration Settings" -ForegroundColor $Color.Command
        Write-Host " 8. Reload All Scripts" -ForegroundColor $Color.Command
        Write-Host " 0. Exit Gateway" -ForegroundColor $Color.Error
        
        Write-Host "`n" + ("─" * 70) -ForegroundColor $Color.Info
        
        $choice = Read-Host "`nSelect option (0-8)"
        
        switch ($choice) {
            '1' { Show-ScriptBrowser }
            '2' { Show-ScriptManager }
            '3' { Show-ExecutionPanel }
            '4' { 
                Discover-AvailableScripts
                Write-Host "`nScript discovery complete!" -ForegroundColor $Color.Success
                Pause
            }
            '5' { Show-ExecutionHistory }
            '6' { Show-ScriptInfo }
            '7' { Show-Configuration }
            '8' { 
                Write-Host "Reloading all scripts..." -ForegroundColor $Color.Warning
                $ScriptGateway.State.LoadedScripts.Clear()
                foreach ($script in $ScriptGateway.State.AvailableScripts.Keys) {
                    Load-Script -ScriptName $script -ForceReload
                }
                Pause
            }
            '0' { 
                Write-Host "`nSaving configuration and exiting..." -ForegroundColor $Color.Info
                Save-GatewayConfig
                Write-Host "Goodbye!`n" -ForegroundColor $Color.Success
                $running = $false
            }
            default {
                Write-Host "Invalid selection. Please try again." -ForegroundColor $Color.Error
                Start-Sleep -Seconds 2
            }
        }
    }
}

function Show-ScriptBrowser {
    $pageSize = 10
    $currentPage = 1
    $totalPages = [math]::Ceiling($ScriptGateway.State.AvailableScripts.Count / $pageSize)
    
    do {
        Clear-Host
        Show-Banner
        
        Write-Host "`n" + ("═" * 70) + "`n" -ForegroundColor $Color.Info
        Write-Host " SCRIPT BROWSER (Page $currentPage of $totalPages)" -ForegroundColor $Color.Header
        Write-Host " ──────────────────────────────────────────────────────────" -ForegroundColor $Color.Info
        
        $startIndex = ($currentPage - 1) * $pageSize
        $endIndex = [math]::Min($startIndex + $pageSize - 1, $ScriptGateway.State.AvailableScripts.Count - 1)
        
        $i = $startIndex
        $scriptNames = $ScriptGateway.State.AvailableScripts.Keys | Sort-Object
        
        for ($i = $startIndex; $i -le $endIndex; $i++) {
            $scriptName = $scriptNames[$i]
            $scriptInfo = $ScriptGateway.State.AvailableScripts[$scriptName]
            $number = $i + 1
            
            Write-Host " $number. " -NoNewline -ForegroundColor $Color.Command
            Write-Host $scriptName -NoNewline -ForegroundColor $Color.Highlight
            
            if ($scriptInfo.IsLoaded) {
                Write-Host " [LOADED]" -NoNewline -ForegroundColor $Color.Success
            }
            
            Write-Host ""
            Write-Host "     " -NoNewline
            Write-Host $scriptInfo.Description -ForegroundColor $Color.Info
            Write-Host "     Functions: " -NoNewline -ForegroundColor $Color.Parameter
            Write-Host ($scriptInfo.Functions -join ', ') -ForegroundColor $Color.Info
            Write-Host ""
        }
        
        Write-Host "`n" + ("─" * 70) -ForegroundColor $Color.Info
        Write-Host " Navigation: N=Next, P=Previous, #=Select, L=Load, X=Execute, B=Back" -ForegroundColor $Color.Parameter
        
        $input = Read-Host "`nSelection"
        
        switch -Regex ($input) {
            '^[0-9]+$' {
                $selectedNumber = [int]$input - 1
                if ($selectedNumber -ge $startIndex -and $selectedNumber -le $endIndex) {
                    $selectedScript = $scriptNames[$selectedNumber]
                    Show-ScriptDetail -ScriptName $selectedScript
                }
            }
            '^[nN]$' { if ($currentPage -lt $totalPages) { $currentPage++ } }
            '^[pP]$' { if ($currentPage -gt 1) { $currentPage-- } }
            '^[lL]$' {
                $scriptNum = Read-Host "Enter script number to load"
                if ($scriptNum -match '^\d+$') {
                    $idx = [int]$scriptNum - 1
                    if ($idx -ge $startIndex -and $idx -le $endIndex) {
                        Load-Script -ScriptName $scriptNames[$idx]
                        Pause
                    }
                }
            }
            '^[xX]$' {
                $scriptNum = Read-Host "Enter script number to execute"
                if ($scriptNum -match '^\d+$') {
                    $idx = [int]$scriptNum - 1
                    if ($idx -ge $startIndex -and $idx -le $endIndex) {
                        $selectedScript = $scriptNames[$idx]
                        Show-ExecuteScript -ScriptName $selectedScript
                    }
                }
            }
            '^[bB]$' { return }
        }
    } while ($true)
}

function Show-ScriptDetail {
    param($ScriptName)
    
    if (-not $ScriptGateway.State.AvailableScripts.ContainsKey($ScriptName)) {
        Write-Host "Script not found!" -ForegroundColor $Color.Error
        Pause
        return
    }
    
    $scriptInfo = $ScriptGateway.State.AvailableScripts[$ScriptName]
    
    do {
        Clear-Host
        Show-Banner
        
        Write-Host "`n" + ("═" * 70) + "`n" -ForegroundColor $Color.Info
        Write-Host " SCRIPT DETAILS: $ScriptName" -ForegroundColor $Color.Header
        Write-Host " ──────────────────────────────────────────────────────────" -ForegroundColor $Color.Info
        
        # Script Information
        Write-Host " File: " -NoNewline -ForegroundColor $Color.Parameter
        Write-Host $scriptInfo.FullName -ForegroundColor $Color.Info
        
        Write-Host " Path: " -NoNewline -ForegroundColor $Color.Parameter
        Write-Host $scriptInfo.Path -ForegroundColor $Color.Info
        
        Write-Host " Size: " -NoNewline -ForegroundColor $Color.Parameter
        Write-Host "$($scriptInfo.SizeKB) KB" -ForegroundColor $Color.Info
        
        Write-Host " Modified: " -NoNewline -ForegroundColor $Color.Parameter
        Write-Host $scriptInfo.LastModified -ForegroundColor $Color.Info
        
        Write-Host " Status: " -NoNewline -ForegroundColor $Color.Parameter
        if ($scriptInfo.IsLoaded) {
            Write-Host "LOADED" -ForegroundColor $Color.Success
        } else {
            Write-Host "NOT LOADED" -ForegroundColor $Color.Warning
        }
        
        Write-Host "`n Description:" -ForegroundColor $Color.Parameter
        Write-Host "   $($scriptInfo.Description)" -ForegroundColor $Color.Info
        
        Write-Host "`n Available Functions:" -ForegroundColor $Color.Parameter
        foreach ($func in $scriptInfo.Functions) {
            Write-Host "   • $func" -ForegroundColor $Color.Command
        }
        
        if ($scriptInfo.Parameters.Count -gt 0) {
            Write-Host "`n Common Parameters:" -ForegroundColor $Color.Parameter
            foreach ($param in $scriptInfo.Parameters) {
                Write-Host "   $param" -ForegroundColor $Color.Info
            }
        }
        
        Write-Host "`n" + ("─" * 70) -ForegroundColor $Color.Info
        Write-Host " Options: L=Load/Reload, X=Execute, R=View Raw, B=Back" -ForegroundColor $Color.Parameter
        
        $choice = Read-Host "`nSelection"
        
        switch ($choice.ToUpper()) {
            'L' {
                Load-Script -ScriptName $ScriptName -ForceReload
                $scriptInfo = $ScriptGateway.State.AvailableScripts[$ScriptName]  # Refresh
                Pause
            }
            'X' {
                Show-ExecuteScript -ScriptName $ScriptName
            }
            'R' {
                Clear-Host
                Write-Host "RAW SCRIPT CONTENT:`n" -ForegroundColor $Color.Header
                Get-Content $scriptInfo.Path | Select-Object -First 100 | Write-Host
                Write-Host "`n" + ("─" * 70) -ForegroundColor $Color.Info
                Pause
            }
            'B' { return }
        }
    } while ($true)
}

function Show-ExecuteScript {
    param($ScriptName)
    
    if (-not $ScriptGateway.State.AvailableScripts.ContainsKey($ScriptName)) {
        Write-Host "Script not found!" -ForegroundColor $Color.Error
        Pause
        return
    }
    
    $scriptInfo = $ScriptGateway.State.AvailableScripts[$ScriptName]
    
    Clear-Host
    Show-Banner
    
    Write-Host "`n" + ("═" * 70) + "`n" -ForegroundColor $Color.Info
    Write-Host " EXECUTE SCRIPT: $ScriptName" -ForegroundColor $Color.Header
    Write-Host " ──────────────────────────────────────────────────────────" -ForegroundColor $Color.Info
    
    Write-Host " Available Functions:" -ForegroundColor $Color.Parameter
    foreach ($func in $scriptInfo.Functions) {
        Write-Host "   $func" -ForegroundColor $Color.Command
    }
    
    Write-Host "`n" + ("─" * 70) -ForegroundColor $Color.Info
    Write-Host " Enter function name to execute (or press Enter to run entire script)" -ForegroundColor $Color.Parameter
    
    $functionName = Read-Host "`nFunction name (optional)"
    
    $arguments = @{}
    if ($functionName) {
        Write-Host "`nEnter parameters (key=value, one per line, empty line to finish):" -ForegroundColor $Color.Parameter
        
        do {
            $paramInput = Read-Host "Parameter"
            if ($paramInput -match '^([^=]+)=(.*)$') {
                $key = $matches[1].Trim()
                $value = $matches[2].Trim()
                
                # Try to convert numeric values
                if ($value -match '^-?\d+$') { $value = [int]$value }
                elseif ($value -match '^-?\d+\.\d+$') { $value = [double]$value }
                elseif ($value -eq '$true') { $value = $true }
                elseif ($value -eq '$false') { $value = $false }
                elseif ($value -match '^@\(.*\)$') {
                    try { $value = Invoke-Expression $value } catch { }
                }
                
                $arguments[$key] = $value
            }
        } while ($paramInput -ne '')
    }
    
    $timeout = Read-Host "Timeout in seconds (default: $($ScriptGateway.Config.MaxExecutionTime))"
    if (-not [string]::IsNullOrWhiteSpace($timeout) -and $timeout -match '^\d+$') {
        $timeout = [int]$timeout
    } else {
        $timeout = $ScriptGateway.Config.MaxExecutionTime
    }
    
    $async = Read-Host "Run asynchronously? (Y/N, default: N)"
    $async = ($async -eq 'Y' -or $async -eq 'y')
    
    $whatIf = Read-Host "WhatIf mode? (Y/N, default: N)"
    $whatIf = ($whatIf -eq 'Y' -or $whatIf -eq 'y')
    
    Write-Host "`n" + ("─" * 70) -ForegroundColor $Color.Info
    Write-Host " Ready to execute:" -ForegroundColor $Color.Header
    Write-Host " Script: $ScriptName" -ForegroundColor $Color.Info
    if ($functionName) {
        Write-Host " Function: $functionName" -ForegroundColor $Color.Info
    }
    if ($arguments.Count -gt 0) {
        Write-Host " Arguments:" -ForegroundColor $Color.Info
        foreach ($key in $arguments.Keys) {
            Write-Host "   $key = $($arguments[$key])" -ForegroundColor $Color.Parameter
        }
    }
    Write-Host " Timeout: $timeout seconds" -ForegroundColor $Color.Info
    Write-Host " Async: $async" -ForegroundColor $Color.Info
    Write-Host " WhatIf: $whatIf" -ForegroundColor $Color.Info
    
    $confirm = Read-Host "`nExecute? (Y/N)"
    
    if ($confirm -eq 'Y' -or $confirm -eq 'y') {
        try {
            $result = Invoke-ScriptCommand -ScriptName $ScriptName -Command $functionName -Arguments $arguments -Timeout $timeout -Async:$async -WhatIf:$whatIf
            
            if ($whatIf) {
                Write-Host "`n[WHATIF] Execution simulation complete" -ForegroundColor $Color.Highlight
            } elseif ($async) {
                Write-Host "`nExecution started asynchronously with Job ID: $($result.JobId)" -ForegroundColor $Color.Success
            } else {
                Write-Host "`nExecution completed successfully!" -ForegroundColor $Color.Success
                Write-Host "`nResult:" -ForegroundColor $Color.Header
                
                if ($result -ne $null) {
                    if ($result -is [System.Collections.IEnumerable] -and $result -isnot [string]) {
                        $result | Format-Table -AutoSize | Out-Host
                    } else {
                        Write-Host $result -ForegroundColor $Color.Info
                    }
                }
            }
        }
        catch {
            Write-Host "`nExecution failed: $_" -ForegroundColor $Color.Error
        }
    } else {
        Write-Host "`nExecution cancelled" -ForegroundColor $Color.Warning
    }
    
    Pause
}

function Show-ScriptManager {
    Clear-Host
    Show-Banner
    
    Write-Host "`n" + ("═" * 70) + "`n" -ForegroundColor $Color.Info
    Write-Host " SCRIPT MANAGER" -ForegroundColor $Color.Header
    Write-Host " ──────────────────────────────────────────────────────────" -ForegroundColor $Color.Info
    
    Write-Host " Loaded Scripts:" -ForegroundColor $Color.Parameter
    
    if ($ScriptGateway.State.LoadedScripts.Count -eq 0) {
        Write-Host "   No scripts loaded" -ForegroundColor $Color.Warning
    } else {
        foreach ($scriptName in $ScriptGateway.State.LoadedScripts.Keys) {
            $loaded = $ScriptGateway.State.LoadedScripts[$scriptName]
            Write-Host "   • " -NoNewline -ForegroundColor $Color.Command
            Write-Host $scriptName -NoNewline -ForegroundColor $Color.Highlight
            Write-Host " (Loaded: $($loaded.LoadedAt.ToString('HH:mm:ss')), Functions: $($loaded.Functions.Count))" -ForegroundColor $Color.Info
        }
    }
    
    Write-Host "`n" + ("─" * 70) -ForegroundColor $Color.Info
    Write-Host " Options: L=Load Script, U=Unload Script, R=Reload All, B=Back" -ForegroundColor $Color.Parameter
    
    $choice = Read-Host "`nSelection"
    
    switch ($choice.ToUpper()) {
        'L' {
            $scriptName = Read-Host "Enter script name to load"
            if ($ScriptGateway.State.AvailableScripts.ContainsKey($scriptName)) {
                Load-Script -ScriptName $scriptName
            } else {
                Write-Host "Script not found!" -ForegroundColor $Color.Error
            }
            Pause
        }
        'U' {
            $scriptName = Read-Host "Enter script name to unload"
            if ($ScriptGateway.State.LoadedScripts.ContainsKey($scriptName)) {
                $ScriptGateway.State.LoadedScripts.Remove($scriptName)
                $ScriptGateway.State.AvailableScripts[$scriptName].IsLoaded = $false
                Write-Host "Script '$scriptName' unloaded" -ForegroundColor $Color.Success
            } else {
                Write-Host "Script not loaded!" -ForegroundColor $Color.Warning
            }
            Pause
        }
        'R' {
            Write-Host "Reloading all scripts..." -ForegroundColor $Color.Warning
            $ScriptGateway.State.LoadedScripts.Clear()
            foreach ($script in $ScriptGateway.State.AvailableScripts.Keys) {
                Load-Script -ScriptName $script -ForceReload
            }
            Pause
        }
        'B' { return }
    }
}

function Show-ExecutionHistory {
    Clear-Host
    Show-Banner
    
    Write-Host "`n" + ("═" * 70) + "`n" -ForegroundColor $Color.Info
    Write-Host " EXECUTION HISTORY" -ForegroundColor $Color.Header
    Write-Host " ──────────────────────────────────────────────────────────" -ForegroundColor $Color.Info
    
    if ($ScriptGateway.State.ExecutionHistory.Count -eq 0) {
        Write-Host "   No execution history available" -ForegroundColor $Color.Warning
    } else {
        $recentHistory = $ScriptGateway.State.ExecutionHistory | Select-Object -Last 20 | Sort-Object Timestamp -Descending
        
        foreach ($entry in $recentHistory) {
            $time = $entry.Timestamp.ToString("HH:mm:ss")
            $action = $entry.Action.PadRight(8)
            $script = $entry.Script.PadRight(20).Substring(0, [math]::Min(20, $entry.Script.Length))
            
            Write-Host " $time " -NoNewline -ForegroundColor $Color.Info
            Write-Host " $action " -NoNewline -ForegroundColor $Color.Parameter
            Write-Host " $script " -NoNewline -ForegroundColor $Color.Command
            
            if ($entry.Status -eq 'SUCCESS') {
                if ($entry.Duration) {
                    Write-Host "($($entry.Duration.ToString('0.00'))s)" -ForegroundColor $Color.Success
                } else {
                    Write-Host "[OK]" -ForegroundColor $Color.Success
                }
            } else {
                Write-Host "[FAILED]" -ForegroundColor $Color.Error
                if ($entry.Error) {
                    Write-Host "      Error: $($entry.Error)" -ForegroundColor $Color.Error
                }
            }
        }
    }
    
    Write-Host "`n" + ("─" * 70) -ForegroundColor $Color.Info
    Write-Host " Options: C=Clear History, E=Export to CSV, B=Back" -ForegroundColor $Color.Parameter
    
    $choice = Read-Host "`nSelection"
    
    switch ($choice.ToUpper()) {
        'C' {
            $confirm = Read-Host "Clear all history? (Y/N)"
            if ($confirm -eq 'Y' -or $confirm -eq 'y') {
                $ScriptGateway.State.ExecutionHistory.Clear()
                Write-Host "History cleared" -ForegroundColor $Color.Success
            }
            Pause
        }
        'E' {
            $exportPath = Read-Host "Enter export path (default: $env:TEMP\GatewayHistory.csv)"
            if ([string]::IsNullOrWhiteSpace($exportPath)) {
                $exportPath = "$env:TEMP\GatewayHistory.csv"
            }
            
            $ScriptGateway.State.ExecutionHistory | 
                Select-Object @{n='Timestamp';e={$_.Timestamp.ToString('yyyy-MM-dd HH:mm:ss')}}, 
                              Action, Script, Command, Duration, Status, Error, ExecutionId |
                Export-Csv -Path $exportPath -NoTypeInformation
            
            Write-Host "History exported to $exportPath" -ForegroundColor $Color.Success
            Pause
        }
        'B' { return }
    }
}

function Show-ScriptInfo {
    Clear-Host
    Show-Banner
    
    Write-Host "`n" + ("═" * 70) + "`n" -ForegroundColor $Color.Info
    Write-Host " GATEWAY INFORMATION & HELP" -ForegroundColor $Color.Header
    Write-Host " ──────────────────────────────────────────────────────────" -ForegroundColor $Color.Info
    
    Write-Host " Available Commands:" -ForegroundColor $Color.Parameter
    Write-Host "   .\ScriptGateway.ps1" -ForegroundColor $Color.Command
    Write-Host "     Launches interactive mode" -ForegroundColor $Color.Info
    
    Write-Host "   .\ScriptGateway.ps1 -List" -ForegroundColor $Color.Command
    Write-Host "     Lists all available scripts" -ForegroundColor $Color.Info
    
    Write-Host "   .\ScriptGateway.ps1 -Run Script1,Script2" -ForegroundColor $Color.Command
    Write-Host "     Executes specified scripts" -ForegroundColor $Color.Info
    
    Write-Host "   .\ScriptGateway.ps1 -ImportAll" -ForegroundColor $Color.Command
    Write-Host "     Imports all scripts" -ForegroundColor $Color.Info
    
    Write-Host "   .\ScriptGateway.ps1 -ScanPath 'C:\MyScripts'" -ForegroundColor $Color.Command
    Write-Host "     Scans directory for scripts" -ForegroundColor $Color.Info
    
    Write-Host "`n Script Directory:" -ForegroundColor $Color.Parameter
    Write-Host "   $($ScriptGateway.Config.ScriptsRoot)" -ForegroundColor $Color.Info
    
    Write-Host "`n Configuration File:" -ForegroundColor $Color.Parameter
    Write-Host "   $($ScriptGateway.Config.ConfigFile)" -ForegroundColor $Color.Info
    
    Write-Host "`n Log File:" -ForegroundColor $Color.Parameter
    Write-Host "   $LogPath" -ForegroundColor $Color.Info
    
    Write-Host "`n" + ("─" * 70) -ForegroundColor $Color.Info
    Write-Host " Press any key to return..." -ForegroundColor $Color.Parameter
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

function Show-Configuration {
    Clear-Host
    Show-Banner
    
    Write-Host "`n" + ("═" * 70) + "`n" -ForegroundColor $Color.Info
    Write-Host " CONFIGURATION SETTINGS" -ForegroundColor $Color.Header
    Write-Host " ──────────────────────────────────────────────────────────" -ForegroundColor $Color.Info
    
    Write-Host " Current Settings:" -ForegroundColor $Color.Parameter
    foreach ($key in $ScriptGateway.Config.Keys) {
        Write-Host "   $key : " -NoNewline -ForegroundColor $Color.Command
        Write-Host $ScriptGateway.Config[$key] -ForegroundColor $Color.Info
    }
    
    Write-Host "`n" + ("─" * 70) -ForegroundColor $Color.Info
    Write-Host " Options: C=Change Scripts Directory, T=Change Timeout, S=Save, B=Back" -ForegroundColor $Color.Parameter
    
    $choice = Read-Host "`nSelection"
    
    switch ($choice.ToUpper()) {
        'C' {
            $newPath = Read-Host "Enter new scripts directory path"
            if (Test-Path $newPath) {
                $ScriptGateway.Config.ScriptsRoot = $newPath
                Write-Host "Scripts directory updated. Run 'Scan for New Scripts' to discover scripts." -ForegroundColor $Color.Success
            } else {
                Write-Host "Path does not exist!" -ForegroundColor $Color.Error
            }
            Pause
        }
        'T' {
            $newTimeout = Read-Host "Enter new timeout in seconds (default: 300)"
            if ($newTimeout -match '^\d+$') {
                $ScriptGateway.Config.MaxExecutionTime = [int]$newTimeout
                Write-Host "Timeout updated to $newTimeout seconds" -ForegroundColor $Color.Success
            } else {
                Write-Host "Invalid timeout value!" -ForegroundColor $Color.Error
            }
            Pause
        }
        'S' {
            Save-GatewayConfig
            Pause
        }
        'B' { return }
    }
}
#endregion

#region Main Execution
try {
    # Initialize the gateway
    Initialize-ScriptGateway
    
    # Handle parameter sets
    switch ($PSCmdlet.ParameterSetName) {
        'List' {
            Show-Banner
            Write-Host "`nAvailable Scripts ($($ScriptGateway.State.AvailableScripts.Count) total):`n" -ForegroundColor $Color.Header
            
            foreach ($scriptName in $ScriptGateway.State.AvailableScripts.Keys | Sort-Object) {
                $scriptInfo = $ScriptGateway.State.AvailableScripts[$scriptName]
                
                Write-Host "• " -NoNewline -ForegroundColor $Color.Command
                Write-Host $scriptName -NoNewline -ForegroundColor $Color.Highlight
                
                if ($scriptInfo.IsLoaded) {
                    Write-Host " [LOADED]" -NoNewline -ForegroundColor $Color.Success
                }
                
                Write-Host ""
                Write-Host "  $($scriptInfo.Description)" -ForegroundColor $Color.Info
                Write-Host "  Functions: " -NoNewline -ForegroundColor $Color.Parameter
                Write-Host ($scriptInfo.Functions -join ', ') -ForegroundColor $Color.Info
                Write-Host ""
            }
        }
        
        'Run' {
            Show-Banner
            Write-Host "`nExecuting scripts..." -ForegroundColor $Color.Header
            
            foreach ($scriptName in $Run) {
                Write-Host "`n─ $scriptName " -NoNewline -ForegroundColor $Color.Command
                
                try {
                    $result = Invoke-ScriptCommand -ScriptName $scriptName
                    Write-Host "[SUCCESS]" -ForegroundColor $Color.Success
                    
                    if ($result -ne $null) {
                        Write-Host "  Result: " -NoNewline -ForegroundColor $Color.Parameter
                        if ($result -is [System.Collections.IEnumerable] -and $result -isnot [string]) {
                            $result | Select-Object -First 5 | Format-Table -AutoSize | Out-Host
                        } else {
                            Write-Host $result -ForegroundColor $Color.Info
                        }
                    }
                }
                catch {
                    Write-Host "[FAILED]" -ForegroundColor $Color.Error
                    Write-Host "  Error: $_" -ForegroundColor $Color.Error
                }
            }
        }
        
        'Import' {
            Show-Banner
            Write-Host "`nImporting all scripts..." -ForegroundColor $Color.Header
            
            $loadedCount = 0
            foreach ($scriptName in $ScriptGateway.State.AvailableScripts.Keys) {
                if (Load-Script -ScriptName $scriptName) {
                    $loadedCount++
                }
            }
            
            Write-Host "`nImported $loadedCount scripts. Available commands:" -ForegroundColor $Color.Success
            Get-Command -CommandType Function | Format-Table Name, Module -AutoSize | Out-Host
        }
        
        'Scan' {
            Show-Banner
            if ($ScanPath) {
                if (Test-Path $ScanPath) {
                    $ScriptGateway.Config.ScriptsRoot = $ScanPath
                    Write-Host "Set scripts directory to: $ScanPath" -ForegroundColor $Color.Success
                } else {
                    Write-Host "Path does not exist: $ScanPath" -ForegroundColor $Color.Error
                    exit 1
                }
            }
            
            Discover-AvailableScripts
            
            if ($AutoImport) {
                Write-Host "`nAuto-importing scripts..." -ForegroundColor $Color.Header
                foreach ($scriptName in $ScriptGateway.State.AvailableScripts.Keys) {
                    Load-Script -ScriptName $scriptName
                }
            }
        }
        
        'Info' {
            if ($GetInfo) {
                if ($ScriptGateway.State.AvailableScripts.ContainsKey($GetInfo)) {
                    $scriptInfo = $ScriptGateway.State.AvailableScripts[$GetInfo]
                    
                    Write-Host "`nScript Information: $GetInfo" -ForegroundColor $Color.Header
                    Write-Host "─" * 60 -ForegroundColor $Color.Info
                    
                    $scriptInfo.GetEnumerator() | ForEach-Object {
                        Write-Host "$($_.Key): " -NoNewline -ForegroundColor $Color.Parameter
                        
                        if ($_.Key -eq 'Functions' -and $_.Value.Count -gt 0) {
                            Write-Host ""
                            foreach ($func in $_.Value) {
                                Write-Host "  • $func" -ForegroundColor $Color.Command
                            }
                        } else {
                            Write-Host $_.Value -ForegroundColor $Color.Info
                        }
                    }
                } else {
                    Write-Host "Script '$GetInfo' not found" -ForegroundColor $Color.Error
                }
            }
        }
        
        default {
            # Interactive mode
            Show-InteractiveMenu
        }
    }
}
catch {
    Write-Log "Fatal error in Script Gateway: $_" -Level ERROR
    Write-Host "`nA fatal error occurred. Check the log file: $LogPath" -ForegroundColor $Color.Error
    
    if ($Error.Count -gt 0) {
        Write-Host "`nError details:" -ForegroundColor $Color.Error
        $Error[0] | Format-List * -Force | Out-Host
    }
    
    exit 1
}
finally {
    # Cleanup jobs
    Get-Job | Where-Object Name -like "SG_*" | Remove-Job -Force -ErrorAction SilentlyContinue
}
#endregion
# SIG # Begin signature block
# MIIJIgYJKoZIhvcNAQcCoIIJEzCCCQ8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD+Tu5amnnImKU8
# hIiifdMPAXF/piECxtZ1f98e76T9h6CCBWgwggVkMIIDTKADAgECAhBEeDXFXkLZ
# t0cghZwNYSKoMA0GCSqGSIb3DQEBCwUAMEoxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# DA5TYWdlIEF1ZGlvIExMQzEiMCAGA1UEAwwZQ29kZVNpZ25pbmctTGVvblNhZ2Ut
# MjAyNjAeFw0yNjAxMjIyMDA0MDBaFw0zMTAxMjIyMDEzNTdaMEoxCzAJBgNVBAYT
# AlVTMRcwFQYDVQQKDA5TYWdlIEF1ZGlvIExMQzEiMCAGA1UEAwwZQ29kZVNpZ25p
# bmctTGVvblNhZ2UtMjAyNjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AMcu7LQCZudgwCWaCwG5dSjfZv2OOeZKsMCq2cw9ZgfvDaTooyXGkGANTNcsNIre
# ZMWdIbyiy2TtU2JJR0RLRDPEg7ADhqjwtmsovOXjKIpnfOi6+CkBNYw2ORvHq02o
# s3uObI2WBUY1v+fkNKdg6mKC6J6Qj9PR0P3w3AU2tN71lr76VGM4NpcZePqocUA9
# 6YHhVXQEJOVJ0cFIlOmrUEKFZCbHRX9wNEgmcoRQHR24+VvGlJAhK4ifLNL2SnXx
# b4737Iz/ylPd7ADYgZFqoVOde1gmQZl1D0VIckjQsbXNCGCk2k93r0+UaknJZChH
# t6cur64VGbUi2BBYvM6VR7hj/FRgLc0hfgbbpoZ0AI+4kBuDhJmRYkvfMbA55Rrv
# TNpXUjVgdn1jqaAAvjirpzpnO1RvaFVufFx6vgNLlw14LtSp2Sj+3Cl1Ds0skd8d
# qrcUpdDLtqfpXr3i2CWwSKvxLx8L0EWi3pRuI6gzLKZoUO0qPaiVPF2Sp9E9EO2D
# N5P4YN8Q1dk4/GKPcPV5Vne8a09z1dGvb/JgurdTeOlY4+YnGVpOTHWtG0yCa1Qh
# h93xx8rRQMeB2cwZZcXH8WbXVA0SvTk2XXkihyNO0DzLojJ7i2m9v+ZyePxgHpCf
# HyGO/v6TUFow3Ut+qF/it7XPfDeC4aY3JP8IIqVSat+1AgMBAAGjRjBEMA4GA1Ud
# DwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUh5bbscZ/
# fvFAOQPerqajpP4jNekwDQYJKoZIhvcNAQELBQADggIBACvUVDxtyUtuRBbTzfaY
# VPFXKygu5B24PufkHNduzQruJiAQkRX6pGEnajyO2tlDONTYpziGm6zQKS5tNaRG
# tkFhXYSmIGn35uNm+Lnzuu9ITx1RqBJm19J7xVmlWK3RZ846KX/MsSkSKosfNPtU
# 68wFvBZBnkac8VW0rIjDKpw+JAamBIf+RTwXGJigKK2rf6R5tHQsQOK0nI16xZRc
# heT+LdtWG+mxxM8hI3sHbV0vmEZUghp7oz/GcUA6Z4jJXS8iC1Tp6rDSmiUBN5Da
# wZa4UcO5bY1jEo1+2VJMLX3z4UxoczJkyMr+iEDcWSyu0Z12o90KPu5y3gNYem6J
# JAddpD7GSxfD1b6gebTlBtMnfnKg1wclFoKmXaAlwQxoEaZE1MsKsDkRdmBYtHmv
# zEEZ7dY04Ykl8d12RDsVDRKhopZsitFYRdIdcAKM5DzMxVPwdsrNbu+1uuSOHWMp
# 9d+CvLS9i4NWoTJpzh9eIaZyHyBQb3Fr14Sp9SqlbdUgHLHdHjCVvEAtVQQcWwhe
# RmRKKNj+SO69hXHEM/MXeZhLTsAIXaNvha32lARl9KXEabJ8OA/Or4c/7gv7xJIw
# +qvuscBwejfU9EQWB+jiwsQyvv3AVVyiC+BJIj1VBnbj/My2IMHjb6C+DFcsOAKu
# sJimNJIzkAqUMp9jITdaR09eMYIDEDCCAwwCAQEwXjBKMQswCQYDVQQGEwJVUzEX
# MBUGA1UECgwOU2FnZSBBdWRpbyBMTEMxIjAgBgNVBAMMGUNvZGVTaWduaW5nLUxl
# b25TYWdlLTIwMjYCEER4NcVeQtm3RyCFnA1hIqgwDQYJYIZIAWUDBAIBBQCggYQw
# GAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGC
# NwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQx
# IgQgumYkB83SiMUcYwMjm08JeM7MYBmF9t4/4zHGKkn8NxAwDQYJKoZIhvcNAQEB
# BQAEggIAl6zJvvlyj0+mZmdmLHiw84v0+iaqswey41tplogNEp/gyNgdAC1i9Zup
# 71w7M85RmlpkURAQiLrRXPjoA6NAC33UNUjBgkh2ztDjCLAJtJ114+OMDzn09gaL
# eJy5o5DbvpI8cR2iooEcbTdV+uY2XZd4WC7vP68CPjgc3sXOp3brBpp56roxgrso
# bzEdCDWDRzNsAHf+21qJ7NLmDPfa8imi5BisKJbfIoD7bdnnmweQv9/gAuvrewWc
# ewxVURPBzTQcUulQPzWMkjq6KB1KL2mrrblsPM/f30WhwRIHqlqHMPcZa1l4gdW4
# 7GVFj+XCuJSncmRMkwXC+nObaC/npmwB/wy+Hj9YdCVrwMmVHNObYf+oizN4/rbt
# AZBZZW8ejUj13TgB09pgJG0QLnTo9xA01WbslzGLyikj+HxF6x1ynew27U2cchrs
# 8YpXjUPM+Ecb64QlOeqMrS85xepil6T1n15JvYsvi3ya51PHM1W0sKE6VrPfzqRv
# QuIHk5hKdkAnrLlJWG/u0i2jRqehTHbQjd7kWM4KxoqiRkdLn14ine9ggFLGIB3W
# wHX0w4BDvXncaqxmdrYkA3K2ZDEdDSh+u0bhvx1RE+fqXwii/qFFhhPJlKIITzcZ
# gkgXg8gxrbXUs1xFbPUrejWPV6detTZC36CkJcln8rL2BnB7sFQ=
# SIG # End signature block
