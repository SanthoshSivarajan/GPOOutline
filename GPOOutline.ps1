<#
================================================================================
 GPOOutline -- The Shape of Your Group Policy
 Version : 1.0
 Services: Deeper analysis, custom reporting or a full assessment --
           contact santhosh@sivarajan.com
 Author  : Santhosh Sivarajan, Microsoft MVP
 LinkedIn: https://www.linkedin.com/in/sivarajan/
 GitHub  : https://github.com/SanthoshSivarajan/GPOOutline
 License : MIT -- Free to use, modify, and distribute.
--------------------------------------------------------------------------------
 PURPOSE
   Produce a written, point-in-time record of how Group Policy is configured
   across an Active Directory forest, in a form a non-specialist can read.

   It documents what exists. It does not score, grade, rate, or recommend --
   judgement belongs to an assessment, not to a current-state document.

   One run produces one self-contained HTML report, a state file that can
   re-render that report with no directory access at all, and a log.

 MODULE-FREE BY DESIGN
   GPOOutline takes NO dependency on the ActiveDirectory or GroupPolicy
   PowerShell modules, and none on RSAT or GPMC. Everything Group Policy lives
   in two reachable places and both are read with .NET that ships in every
   Windows PowerShell:

     GPC (metadata) -- LDAP under CN=Policies,CN=System,<domain DN>, plus the
                       gPLink and gPOptions attributes on every OU, domain head
                       and site container.
     GPT (settings) -- files under \\<domain>\SYSVOL\<domain>\Policies\{GUID}\
                       parsed here directly: registry.pol (binary PReg),
                       GptTmpl.inf, Preferences\**\*.xml, scripts.ini,
                       psscripts.ini, fdeploy.ini, GPT.INI.

   "No modules" means no RSAT and no AD/GPO modules. It does not mean no
   dependencies at all: System.DirectoryServices.Protocols is a built-in
   Windows/.NET component. Where GPMC or the GroupPolicy module happen to be
   present they are used only as an optional cross-check behind a capability
   probe, and never as a requirement.

 REQUIREMENTS

   Collecting machine
     - Windows PowerShell 5.1 or PowerShell 7.x
     - Domain-joined, OR any Windows host with network line of sight to a
       domain controller when -Server and -Credential are supplied
     - NO RSAT. The ActiveDirectory and GroupPolicy modules are not used and
       do not need to be installed
     - NO local administrator rights on the collecting machine
     - NO PowerShell remoting / WinRM
     - Write access to the output directory

   Network (from collecting machine to each domain controller)
     389/tcp          LDAP    required -- all directory collection
     636/tcp          LDAPS   optional -- reported, not required
     3268/tcp         GC      optional -- forest-wide queries
     88/tcp           Kerberos required for Negotiate authentication
     445/tcp          SMB     required for SYSVOL parsing (Tier B)

     Closed ports are detected at startup. Affected sections are marked
     unavailable rather than retried.

   Active Directory rights

     TIER A -- Directory data (GPO metadata, links, scope, filtering)
       Minimum : Domain User in any domain of the forest
       Why     : Authenticated Users hold read access to the Domain and
                 Configuration naming contexts by default. Covers the GPO
                 inventory, links, OU tree, sites, WMI filters, security
                 filtering, delegation, versions and CSE lists.

     TIER B -- SYSVOL policy files (the actual settings)
       Minimum : Domain User (SYSVOL read)
       Why     : Authenticated Users can read SYSVOL by default. Covers
                 Administrative Templates, security settings, scripts,
                 preferences, folder redirection and software installation.
                 Without it the report still documents scope, but every
                 settings section is marked "not readable" rather than empty.

     TIER C -- Cross-check only (optional)
       Minimum : RSAT/GPMC present on the collecting machine
       Why     : If the GroupPolicy module is installed, GPOOutline can compare
                 its own parse against Get-GPOReport output as a confidence
                 check. Never required; absence changes nothing.

   Rights are verified at run time and reported in the "Collection Rights"
   section, so the report states what was actually readable rather than what
   should have been. A section left empty by missing access is always
   distinguished from one that is empty because the environment is.

 DISCLAIMER
   Provided "as is", without warranty of any kind. Read-only: no Active
   Directory object, SYSVOL file, registry value, or GPO is created, modified,
   or deleted. The only files written are the report, the state file and the
   log, all inside the output directory.

   Results depend on the rights of the collecting account and on domain
   controller reachability at run time. Unreachable hosts and unreadable paths
   are reported and skipped, never silently omitted. Validate findings before
   acting on them.

 NOTE ON GPP PASSWORDS
   Group Policy Preferences may contain a "cpassword" attribute. GPOOutline
   records only that one is present, and where. It never decrypts, prints, or
   stores the value, and it does not ship the published AES key. Presence is
   the fact worth documenting; the credential itself is not this tool's
   business.
================================================================================
#>

[CmdletBinding()]
param(
    # Target a specific DC or domain. Omit to use the current domain.
    [string]$Server,

    # Explicit credentials. Enables running from a non-domain-joined machine.
    [System.Management.Automation.PSCredential]$Credential,

    # One or more domains. Default is every domain in the forest.
    [string[]]$Domain,

    # Limit OU/link collection to a subtree.
    [string]$SearchBase,

    # Collection engine. Raw is the primary path and the default.
    [ValidateSet('Auto', 'Raw', 'Native')][string]$Mode = 'Auto',

    [string]$OutputPath,

    # Hard ceiling on any single LDAP operation.
    [int]$LdapTimeoutSec = 30,

    # Per-port TCP probe timeout.
    [int]$ProbeTimeoutMs = 1500,

    # Concurrent DC probes.
    [int]$ProbeThrottle = 32,

    # LDAP page size.
    [int]$PageSize = 1000,

    # Parallel workers for the SYSVOL phase. Default = CPU count, capped at 16.
    [int]$MaxConcurrency = 0,

    # Inter-batch delay, to smooth I/O against DFSR-replicated SYSVOL.
    [int]$ThrottleDelayMs = 0,

    # Hard ceiling on a single SYSVOL file read.
    [int]$FileTimeoutSec = 20,

    # Skip the DC probe entirely (assume all reachable).
    [switch]$NoProbe,

    # Do not contact these DCs at all.
    [string[]]$ExcludeDC,

    # Metadata-only fast pass: no SYSVOL parsing.
    [switch]$SkipSysvol,

    # Include site-linked GPOs. On by default.
    [bool]$IncludeSites = $true,

    # Resolve ADMX/ADML friendly names. On by default.
    [bool]$ResolveAdmx = $true,

    # Report the work list and estimated cost, then stop before SYSVOL.
    [switch]$WhatIfScope,

    # Re-render a previously saved state file without touching the directory.
    [string]$FromState,

    # Collect and write state only; skip HTML generation.
    [switch]$NoHtml,

    # Do not write a state JSON file.
    [switch]$NoState,

    # Do not embed the raw dataset in the HTML. Smaller file, no GPOLens seed.
    [switch]$NoEmbeddedJson,

    # Explicit log file path. Defaults to the output directory.
    [string]$LogPath,

    # Echo every detail to the console as well as the log.
    [switch]$ShowDetail,

    # Cap on registry values decoded per policy file.
    [int]$MaxValuesPerFile = 20000
)

$script:WarnCount    = 0
$script:Observations = New-Object System.Collections.Generic.List[string]

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Bump on every change. Printed in the banner so the running copy is always
# identifiable from the console output alone.
$script:BuildStamp = '2026-08-16.01'

# Initialised here, not lazily. Under StrictMode a read of a never-assigned
# $script: variable throws, so a run in which nothing failed quietly would be
# the one guaranteed to crash.
$script:QuietFailures = @{}
$script:QuietAbsences = @{}

# Domains whose OU sweep failed, keyed by DNS root. Tracked separately from the
# general warning list because these specifically invalidate the link,
# precedence, conflict and OU tree sections for that domain -- losing the
# containers makes every GPO in it look unlinked. The report must say that
# rather than present the gutted dataset as a fact about the environment.
$script:ContainerReadFailures = @{}

# ---- Scale caps ----
# These bound the SIZE OF THE REPORT, not the accuracy of the counts. Every
# counter is computed over the whole estate; only per-object detail retained
# for tables and diagrams is capped, and any truncation is stated in the report.
$script:MaxOuNodes        = 4000     # OU tree nodes retained for the hierarchy diagram
$script:MaxSettingIndex   = 60000    # rows in the searchable settings index
# Above this many identical delegation/filtering rows for one principal, the set
# folds to a single summary line. 175 rows saying the same thing hide the shape
# of the delegation rather than showing it.
$script:PrincipalFoldAt   = 15       # identical principal-usage rows before folding
$script:MaxPerGpoSettings = 2500     # settings rendered per GPO before truncation notice
$script:MaxMatrixCells    = 40000    # GPO/OU matrix cells before falling back to a list

Add-Type -AssemblyName System.DirectoryServices.Protocols

# ==============================================================================
# CONSOLE
# ==============================================================================

Write-Host ""
Write-Host " +==============================================================+" -ForegroundColor Cyan
Write-Host " |                                                              |" -ForegroundColor Cyan
Write-Host " |   GPOOutline -- The Shape of Your Group Policy                |" -ForegroundColor Cyan
Write-Host " |   Version 1.0                                                |" -ForegroundColor Cyan
Write-Host " |                                                              |" -ForegroundColor Cyan
Write-Host " |   Author   : Santhosh Sivarajan, Microsoft MVP               |" -ForegroundColor Cyan
Write-Host " |   LinkedIn : https://www.linkedin.com/in/sivarajan/          |" -ForegroundColor Cyan
Write-Host " |   GitHub   : https://github.com/SanthoshSivarajan/GPOOutline  |" -ForegroundColor Cyan
Write-Host " |                                                              |" -ForegroundColor Cyan
Write-Host " +==============================================================+" -ForegroundColor Cyan
Write-Host " |   Deeper analysis, custom reporting or an assessment?        |" -ForegroundColor DarkCyan
Write-Host " |   Contact santhosh@sivarajan.com                             |" -ForegroundColor DarkCyan
Write-Host " +==============================================================+" -ForegroundColor DarkCyan
Write-Host ""
# Identity of the collecting account, resolved once and reused everywhere it is
# reported. The environment variables are the natural source on Windows, but a
# blank "Running as" line in a document an auditor may read is worse than a
# slightly less specific one, so fall back to the .NET values rather than
# printing an empty domain\user pair.
$script:RunAsUser    = if ($env:USERNAME) { $env:USERNAME } else { [Environment]::UserName }
$script:RunAsDomain  = if ($env:USERDOMAIN) { $env:USERDOMAIN } else { $null }
$script:RunAsAccount = if ($script:RunAsDomain) { "$($script:RunAsDomain)\$($script:RunAsUser)" } else { $script:RunAsUser }
$script:RunOnHost    = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [Environment]::MachineName }

Write-Host (" Build {0}   |   {1}   |   {2}" -f $script:BuildStamp, $script:RunAsAccount, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -ForegroundColor DarkGray
Write-Host " Read-only. No AD object, SYSVOL file, registry value, or GPO is modified." -ForegroundColor DarkGray
Write-Host ""

# ==============================================================================
# LOGGING AND PROGRESS
#
# The console shows progress only. Every detail -- tables, values, warnings,
# errors, timings -- goes to the log file, which is the troubleshooting record
# and the source for the "Collection coverage & gaps" section.
# ==============================================================================

$script:LogFile    = $null
$script:LogBuffer  = New-Object System.Collections.Generic.List[string]
$script:TaskTotal  = 0
$script:TaskIndex  = 0
$script:TaskName   = $null
$script:TaskWatch  = $null
$script:ShowDetail = $false

function Initialize-OutlineLog {
    param([Parameter(Mandatory)][string]$Path, [int]$TaskCount)
    $script:LogFile   = $Path
    $script:TaskTotal = $TaskCount
    $script:TaskIndex = 0
    $header = @(
        "================================================================================",
        " GPOOutline -- The Shape of Your Group Policy",
        " Build      : $script:BuildStamp",
        " Started    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
        " Running as : $($script:RunAsAccount)",
        " Host       : $($script:RunOnHost)",
        " PowerShell : $($PSVersionTable.PSVersion)",
        " Read-only  : no directory object, SYSVOL file, registry value or GPO is modified",
        "================================================================================",
        ""
    )
    try { $header | Out-File -FilePath $Path -Encoding UTF8 -Force } catch { $script:LogFile = $null }
}

function Write-OutlineLog {
    param([string]$Level = 'INFO', [Parameter(Mandatory)][AllowEmptyString()][string]$Message)
    if ($null -eq $script:LogBuffer) { $script:LogBuffer = New-Object System.Collections.Generic.List[string] }
    $line = "{0}  {1,-5}  {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Level, $Message
    $script:LogBuffer.Add($line)
    if ($script:LogBuffer.Count -ge 40) { Save-OutlineLog }
}

function Save-OutlineLog {
    if (-not $script:LogFile -or $script:LogBuffer.Count -eq 0) { return }
    try {
        $script:LogBuffer | Out-File -FilePath $script:LogFile -Encoding UTF8 -Append
        $script:LogBuffer.Clear()
    } catch { }   # logging must never call the quiet logger: it logs
}

function Write-OutlineInfo { param([string]$Message) Write-OutlineLog 'INFO'  $Message; if ($script:ShowDetail) { Write-Host "   $Message" -ForegroundColor DarkGray } }
function Write-OutlineOk   { param([string]$Message) Write-OutlineLog 'OK'    $Message; if ($script:ShowDetail) { Write-Host "   $Message" -ForegroundColor DarkGreen } }
function Write-OutlineSkip { param([string]$Message) Write-OutlineLog 'SKIP'  $Message; if ($script:ShowDetail) { Write-Host "   $Message" -ForegroundColor DarkGray } }
function Write-OutlineErr  { param([string]$Message) Write-OutlineLog 'ERROR' $Message; Write-Host "   [!] $Message" -ForegroundColor Red }

function Write-OutlineWarn {
    <#
      A WARNING means collection was impaired: a host did not answer, a right
      was missing, a file could not be read. It is about the run, not about the
      environment.
    #>
    param([string]$Message)
    Write-OutlineLog 'WARN' $Message
    $script:WarnCount++
    if ($script:ShowDetail) { Write-Host "   [!] $Message" -ForegroundColor Yellow }
}

function Write-OutlineNote {
    <#
      An OBSERVATION is a factual statement about the environment that a reader
      may want to look at. It is deliberately NOT a warning: this tool records
      what is configured, not what should be, so observations describe rather
      than judge and carry no score.
    #>
    param([string]$Message)
    Write-OutlineLog 'NOTE' $Message
    if ($null -eq $script:Observations) {
        $script:Observations = New-Object System.Collections.Generic.List[string]
    }
    $script:Observations.Add($Message)
    if ($script:ShowDetail) { Write-Host "   [i] $Message" -ForegroundColor Cyan }
}

function Write-OutlineQuiet {
    <#
      Records a non-fatal failure that would otherwise vanish into an empty
      catch block. Not a warning -- collection was not impaired -- but no
      longer invisible either.
    #>
    param($ErrorRecord, [string]$Site)
    if ($null -eq $script:QuietFailures) { $script:QuietFailures = @{} }
    if (-not $script:QuietFailures.ContainsKey($Site)) { $script:QuietFailures[$Site] = 0 }
    $script:QuietFailures[$Site]++
    $msg = if ($ErrorRecord) { "$($ErrorRecord.Exception.Message)" } else { 'unspecified' }
    Write-OutlineLog 'INFO' "non-fatal [$Site]: $msg"
}

function Write-OutlineAbsence {
    <# An object queried and legitimately not present. Expected, not a failure. #>
    param([string]$Site)
    if ($null -eq $script:QuietAbsences) { $script:QuietAbsences = @{} }
    if (-not $script:QuietAbsences.ContainsKey($Site)) { $script:QuietAbsences[$Site] = 0 }
    $script:QuietAbsences[$Site]++
}

function Out-OutlineLine {
    <#
      Replacement for Write-Host inside the summary builders. Multi-line input
      (Format-Table output) is split so the log stays one record per line.
    #>
    param(
        [Parameter(ValueFromPipeline = $true, Position = 0)][AllowEmptyString()][AllowNull()]$Text,
        [string]$ForegroundColor
    )
    process {
        if ($null -eq $Text) { $Text = '' }
        foreach ($l in ([string]$Text -split "`r?`n")) {
            Write-OutlineLog 'DATA' ($l -replace '\s+$', '')
        }
        if ($script:ShowDetail) {
            if ($ForegroundColor) { Write-Host $Text -ForegroundColor $ForegroundColor } else { Write-Host $Text }
        }
    }
}

function Start-OutlineTask {
    param([Parameter(Mandatory)][string]$Name)
    $script:TaskIndex++
    $script:TaskName  = $Name
    $script:TaskWatch = [System.Diagnostics.Stopwatch]::StartNew()

    $pct = if ($script:TaskTotal -gt 0) { [int](100 * $script:TaskIndex / $script:TaskTotal) } else { 0 }
    Write-OutlineLog 'TASK' ">>> $Name"

    $label = $Name
    if ($label.Length -gt 44) { $label = $label.Substring(0, 41) + '...' }
    $dots = '.' * [math]::Max(1, 46 - $label.Length)
    Write-Host (" [{0,3}%] {1} {2} " -f $pct, $label, $dots) -NoNewline -ForegroundColor Gray
    Write-Progress -Activity 'GPOOutline' -Status $Name -PercentComplete $pct
}

function Complete-OutlineTask {
    param([string]$Result = '', [switch]$Failed)
    $secs = 0.0
    if ($script:TaskWatch) { $script:TaskWatch.Stop(); $secs = $script:TaskWatch.Elapsed.TotalSeconds }

    $tag = if ($Failed) { 'FAILED' } else { 'done' }
    $col = if ($Failed) { 'Red' } else { 'Green' }
    Write-Host ("{0} ({1:0.0}s)" -f $tag, $secs) -NoNewline -ForegroundColor $col
    if ($Result) { Write-Host ("  {0}" -f $Result) -ForegroundColor DarkGray } else { Write-Host '' }

    Write-OutlineLog 'TASK' ("<<< {0} -- {1} in {2:0.00}s {3}" -f $script:TaskName, $tag, $secs, $Result)
    Save-OutlineLog
}

# ==============================================================================
# SHARED STATE
#
# Collection owns the state; display only reads it. Everything collected lands
# here, the HTML renderer consumes only this, and -FromState re-renders from it
# with zero directory access.
# ==============================================================================

# Real DateTime kept out of the state object: ConvertTo-Json serialises a
# DateTime as a {value=/Date(...)/; DisplayHint; DateTime} wrapper, which is
# culture-dependent and useless to a reader of the state file.
$script:StartedAt = Get-Date

$script:Outline = [ordered]@{
    Version          = '1.0'
    Build            = $script:BuildStamp
    Tool             = 'GPOOutline'
    StartTime        = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    GeneratedBy      = $script:RunAsAccount
    GeneratedOn      = $script:RunOnHost
    GeneratedAt      = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    PowerShell       = "$($PSVersionTable.PSVersion)"

    # --- environment context ---
    RootDse          = $null
    ConfigDN         = $null
    SchemaDN         = $null
    RootDomainDN     = $null
    DefaultDN        = $null
    ForestName       = $null
    BootstrapServer  = $null
    CollectionMode   = 'Raw'
    Domains          = @()      # per-domain context records
    DCs              = [ordered]@{}
    Sites            = @()      # forest-wide, from the config partition
    Trusts           = @()

    # --- group policy core ---
    Gpos             = @()      # one record per GPO
    Links            = @()      # every gPLink entry, parsed
    Containers       = @()      # OUs / domain heads / sites carrying links
    OuTree           = @()      # flat OU list with parent refs
    WmiFilters       = @()
    CentralStore     = @()      # per-domain ADMX central store status

    # --- computed views ---
    Precedence       = @()      # resultant GPO order per container
    Loopback         = @()      # GPOs enabling loopback, with mode and scope
    Conflicts        = @()      # same setting defined by more than one applying GPO
    Anomalies        = $null    # orphans, version mismatches, empty GPOs
    SettingIndex     = @()      # searchable index of every discrete setting
    Matrices         = $null    # GPO->OU, OU->GPO, group->GPO, WMI->GPO, CSE->GPO
    Behavior         = $null    # processing flags, slow-processing, tattooing, footprint

    # --- run quality ---
    Rights           = $null
    Coverage         = $null    # what was read, skipped, unreadable
    UnreachableCount = 0
    Warnings         = New-Object System.Collections.Generic.List[string]
    Observations     = @()
    QuietFailures    = $null
    ContainerReadFailures = @()
    StarterGpos      = @()      # SYSVOL-only, no directory object exists
    AdmxMap          = $null    # persisted so -FromState keeps friendly names
    AdmxSource       = $null
    Stats            = $null    # headline counts used by cards and charts
    Duration         = $null
}

# Rights each report section depends on, and which runtime capability check
# proves whether that right was actually available. Rendered as the
# "Permissions Required by Section" table so a reader can tell a section
# emptied by insufficient rights from one that is genuinely empty.
$script:PermMatrix = @(
    @{ Section='AD Domain Summary';          Tier='A'; Rights='Domain User';               Capability='CanReadConfigNC' }
    @{ Section='GPO Inventory';               Tier='A'; Rights='Domain User';               Capability='CanReadDomainNC' }
    @{ Section='Scope of Management';         Tier='A'; Rights='Domain User';               Capability='CanReadDomainNC' }
    @{ Section='GPO Links & Precedence';      Tier='A'; Rights='Domain User';               Capability='CanReadDomainNC' }
    @{ Section='Site-Linked GPOs';            Tier='A'; Rights='Domain User';               Capability='CanReadConfigNC' }
    @{ Section='Security Filtering';          Tier='A'; Rights='Domain User';               Capability='CanReadGpoAcl' }
    @{ Section='Delegation';                  Tier='A'; Rights='Domain User';               Capability='CanReadGpoAcl' }
    @{ Section='WMI Filters';                 Tier='A'; Rights='Domain User';               Capability='CanReadWmiFilters' }
    @{ Section='Client-Side Extensions';      Tier='A'; Rights='Domain User';               Capability='CanReadDomainNC' }
    @{ Section='Trusts';                      Tier='A'; Rights='Domain User';               Capability='CanReadDomainNC' }
    @{ Section='Administrative Templates';    Tier='B'; Rights='Domain User (SYSVOL read)'; Capability='CanReadSysvol' }
    @{ Section='Security Settings';           Tier='B'; Rights='Domain User (SYSVOL read)'; Capability='CanReadSysvol' }
    @{ Section='Scripts';                     Tier='B'; Rights='Domain User (SYSVOL read)'; Capability='CanReadSysvol' }
    @{ Section='Group Policy Preferences';    Tier='B'; Rights='Domain User (SYSVOL read)'; Capability='CanReadSysvol' }
    @{ Section='Folder Redirection';          Tier='B'; Rights='Domain User (SYSVOL read)'; Capability='CanReadSysvol' }
    @{ Section='Software Installation';       Tier='B'; Rights='Domain User (SYSVOL read)'; Capability='CanReadSysvol' }
    @{ Section='Effective Settings';          Tier='B'; Rights='Domain User (SYSVOL read)'; Capability='CanReadSysvol' }
    @{ Section='Conflict & Override Map';     Tier='B'; Rights='Domain User (SYSVOL read)'; Capability='CanReadSysvol' }
    @{ Section='Setting Search Index';        Tier='B'; Rights='Domain User (SYSVOL read)'; Capability='CanReadSysvol' }
    @{ Section='ADMX Friendly Names';         Tier='B'; Rights='Domain User (SYSVOL read)'; Capability='CanReadCentralStore' }
    @{ Section='Native Cross-Check';          Tier='C'; Rights='RSAT/GPMC on the collecting machine'; Capability='HasGpmc' }
)

function Add-OutlineWarning {
    param([Parameter(Mandatory)][string]$Message)
    $script:Outline.Warnings.Add($Message)
    Write-OutlineWarn $Message
}

# ==============================================================================
# OUTPUT PATH
# ==============================================================================

function Resolve-OutlinePath {
    param([string]$Requested)

    $candidates = New-Object System.Collections.Generic.List[string]
    if ($Requested)    { $candidates.Add($Requested) }
    if ($PSScriptRoot) { $candidates.Add($PSScriptRoot) }
    # Guarded: Join-Path throws on a null Path, which would discard the
    # perfectly good $Requested candidate before the loop ever ran.
    if ($env:TEMP)     { $candidates.Add((Join-Path $env:TEMP 'GPOOutline')) }

    foreach ($c in $candidates) {
        try {
            if (-not (Test-Path -LiteralPath $c)) {
                New-Item -Path $c -ItemType Directory -Force | Out-Null
            }
            $probe = Join-Path $c ".gpoutline_write_test_$PID"
            [System.IO.File]::WriteAllText($probe, 'x')
            Remove-Item -LiteralPath $probe -Force
            return (Resolve-Path -LiteralPath $c).Path
        }
        catch {
            Write-OutlineSkip "Output path not usable: $c"
        }
    }
    throw "No writable output directory found."
}

# ==============================================================================
# LDAP TRANSPORT
#
# Lifted from ADOutline so the two tools behave identically on the wire:
# System.DirectoryServices.Protocols, referral chasing off, hard timeouts,
# server-side paging, attribute-scoped requests.
# ==============================================================================

function New-OutlineLdapConnection {
    <#
      Builds a bound LdapConnection with referral chasing disabled and a hard
      timeout. Referral chasing is the classic multi-domain hang -- it is off
      here and suppressed again per-search via the DomainScope control.
    #>
    param(
        [Parameter(Mandatory)][string]$Target,
        [int]$Port = 389,
        [System.Management.Automation.PSCredential]$Cred,
        [int]$TimeoutSec = 30
    )

    $ident = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier(
        $Target, $Port, $false, $false)

    $conn = New-Object System.DirectoryServices.Protocols.LdapConnection($ident)
    $conn.SessionOptions.ProtocolVersion = 3
    $conn.SessionOptions.ReferralChasing = [System.DirectoryServices.Protocols.ReferralChasingOptions]::None
    $conn.Timeout   = [TimeSpan]::FromSeconds($TimeoutSec)
    $conn.AuthType  = [System.DirectoryServices.Protocols.AuthType]::Negotiate

    # Most current DCs require LDAP signing. Sealing implies signing.
    # Not supported on every path, so failure here is not fatal.
    try {
        $conn.SessionOptions.Sealing = $true
        $conn.SessionOptions.Signing = $true
    } catch {
        Write-OutlineSkip "LDAP sealing unavailable on $Target -- continuing unsealed."
    }

    if ($Cred) { $conn.Bind($Cred.GetNetworkCredential()) } else { $conn.Bind() }
    return $conn
}

function Invoke-OutlineLdapSearch {
    <#
      Paged, timed LDAP search.

      NOTE ON LOCAL NAMES
      A -Process scriptblock supplied by the caller resolves its variables from
      THIS function's scope, not the caller's. A local called $c or $a here
      would silently shadow a caller variable of the same name -- and $c in
      particular is assigned at the end of every page, so a collision would
      only appear once a result set exceeded one page. Every local is therefore
      prefixed __ldap to keep the caller's namespace clear.

      -Process runs once per entry and the entry is then discarded, so memory
      stays flat regardless of result set size.
    #>
    param(
        [Parameter(Mandatory)]$Connection,
        [Parameter(Mandatory)][AllowEmptyString()][string]$BaseDN,
        [Parameter(Mandatory)][string]$Filter,
        [string[]]$Attributes = @('distinguishedName'),
        [ValidateSet('Base','OneLevel','Subtree')][string]$Scope = 'Subtree',
        [int]$PageSize = 1000,
        [int]$TimeoutSec = 30,
        [scriptblock]$Process,
        [switch]$NoPaging,
        # Request only Owner/Group/DACL when reading nTSecurityDescriptor.
        # Without this the server also returns the SACL, which requires
        # SeSecurityPrivilege -- so an ACL read succeeds for an administrator
        # and silently returns nothing for a delegated read-only account.
        [switch]$DaclOnly
    )

    $__ldapReq = New-Object System.DirectoryServices.Protocols.SearchRequest
    $__ldapReq.DistinguishedName = $BaseDN
    $__ldapReq.Filter = $Filter
    $__ldapReq.Scope  = [System.DirectoryServices.Protocols.SearchScope]::$Scope
    foreach ($__ldapAttr in $Attributes) { [void]$__ldapReq.Attributes.Add($__ldapAttr) }

    # Suppress referral generation server-side.
    try {
        $__ldapSo = New-Object System.DirectoryServices.Protocols.SearchOptionsControl(
            [System.DirectoryServices.Protocols.SearchOption]::DomainScope)
        [void]$__ldapReq.Controls.Add($__ldapSo)
    } catch { Write-OutlineQuiet $_ 'LdapSearch:DomainScope' }

    if ($DaclOnly) {
        try {
            $__ldapSd = New-Object System.DirectoryServices.Protocols.SecurityDescriptorFlagControl(
                ([System.DirectoryServices.Protocols.SecurityMasks]::Owner -bor
                 [System.DirectoryServices.Protocols.SecurityMasks]::Group -bor
                 [System.DirectoryServices.Protocols.SecurityMasks]::Dacl))
            [void]$__ldapReq.Controls.Add($__ldapSd)
        } catch {
            Write-OutlineLog 'WARN' "SecurityDescriptorFlagControl unavailable: $($_.Exception.Message)"
        }
    }

    $__ldapPage = $null
    if (-not $NoPaging) {
        $__ldapPage = New-Object System.DirectoryServices.Protocols.PageResultRequestControl($PageSize)
        $__ldapPage.IsCritical = $false
        [void]$__ldapReq.Controls.Add($__ldapPage)
    }

    $__ldapTs    = [TimeSpan]::FromSeconds($TimeoutSec)
    $__ldapCount = 0

    while ($true) {
        $__ldapResp = $Connection.SendRequest($__ldapReq, $__ldapTs)

        if ($__ldapResp.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success -and
            $__ldapResp.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Referral) {
            throw "LDAP search failed on '$BaseDN': $($__ldapResp.ResultCode) $($__ldapResp.ErrorMessage)"
        }

        foreach ($__ldapEntry in $__ldapResp.Entries) {
            $__ldapCount++
            if ($Process) { & $Process $__ldapEntry } else { $__ldapEntry }
        }

        if (-not $__ldapPage) { break }

        $__ldapPrc = $null
        foreach ($__ldapCtrl in $__ldapResp.Controls) {
            if ($__ldapCtrl -is [System.DirectoryServices.Protocols.PageResultResponseControl]) { $__ldapPrc = $__ldapCtrl; break }
        }
        if (-not $__ldapPrc -or $__ldapPrc.Cookie.Length -eq 0) { break }
        $__ldapPage.Cookie = $__ldapPrc.Cookie
    }

    Write-Verbose "LDAP '$Filter' under '$BaseDN' returned $__ldapCount entries."
}

# ==============================================================================
# ATTRIBUTE ACCESSORS
# ==============================================================================

function Get-LdapStr {
    param($Entry, [Parameter(Mandatory)][string]$Name)
    if (-not $Entry.Attributes.Contains($Name)) { return $null }
    $v = $Entry.Attributes[$Name].GetValues([string])
    if ($v -and $v.Count -gt 0) { return [string]$v[0] }
    return $null
}

function Get-LdapStrArray {
    param($Entry, [Parameter(Mandatory)][string]$Name)
    if (-not $Entry.Attributes.Contains($Name)) { return @() }
    $v = $Entry.Attributes[$Name].GetValues([string])
    if ($v) { return @($v) }
    return @()
}

function Get-LdapInt {
    param($Entry, [Parameter(Mandatory)][string]$Name)
    $s = Get-LdapStr -Entry $Entry -Name $Name
    if ($null -eq $s -or $s -eq '') { return $null }
    $out = 0L
    if ([int64]::TryParse($s, [ref]$out)) { return $out }
    return $null
}

function Get-LdapByteArray {
    param($Entry, [Parameter(Mandatory)][string]$Name)
    if (-not $Entry.Attributes.Contains($Name)) { return $null }
    $v = $Entry.Attributes[$Name].GetValues([byte[]])
    # A bare "return $v[0]" UNROLLS the byte[] into the pipeline and the caller
    # receives object[] instead of byte[], which then fails every constructor
    # that expects byte[]. The comma operator preserves the array type.
    if ($v -and $v.Count -gt 0) { return ,([byte[]]$v[0]) }
    return $null
}

function Get-LdapSid {
    param($Entry, [Parameter(Mandatory)][string]$Name)
    $b = Get-LdapByteArray -Entry $Entry -Name $Name
    if (-not $b) { return $null }
    try { return (New-Object System.Security.Principal.SecurityIdentifier($b, 0)).Value }
    catch { return $null }
}

function ConvertFrom-AdGeneralizedTime {
    <# yyyyMMddHHmmss.0Z as used by whenCreated / whenChanged. #>
    param([string]$Value)
    if (-not $Value) { return $null }
    try {
        $t = $Value -replace '\.0Z$', '' -replace 'Z$', ''
        if ($t.Length -lt 14) { return $null }
        $dt = [datetime]::ParseExact($t.Substring(0, 14), 'yyyyMMddHHmmss',
                [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
                [System.Globalization.DateTimeStyles]::AdjustToUniversal)
        return $dt.ToLocalTime()
    } catch { return $null }
}

function Format-OutlineDate {
    <# Dates are stored as strings: ConvertTo-Json mangles DateTime. #>
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-dd HH:mm:ss') }
    return "$Value"
}

function Get-DnComponent {
    <# Returns the value of the Nth RDN of a DN, zero-based from the left. #>
    param([Parameter(Mandatory)][string]$DN, [Parameter(Mandatory)][int]$Index)
    $parts = $DN -split '(?<!\\),'
    if ($Index -lt 0 -or $Index -ge $parts.Count) { return $null }
    return ($parts[$Index] -replace '^[A-Za-z]+=', '')
}

function Get-DnParent {
    <# The parent DN, or $null at the top. #>
    param([string]$DN)
    if (-not $DN) { return $null }
    $parts = $DN -split '(?<!\\),'
    if ($parts.Count -le 1) { return $null }
    return ($parts[1..($parts.Count - 1)] -join ',')
}

function Get-DnLeaf {
    <# The leftmost RDN value -- an OU or GPO display name. #>
    param([string]$DN)
    if (-not $DN) { return '' }
    return (Get-DnComponent -DN $DN -Index 0)
}

function ConvertFrom-DnToDomain {
    <# DC=corp,DC=contoso,DC=com -> corp.contoso.com #>
    param([string]$DN)
    if (-not $DN) { return $null }
    $dcs = @([regex]::Matches($DN, '(?i)DC=([^,]+)') | ForEach-Object { $_.Groups[1].Value })
    if ($dcs.Count -eq 0) { return $null }
    return ($dcs -join '.')
}

# ==============================================================================
# BOOTSTRAP
# ==============================================================================

function Connect-OutlineDirectory {
    param([string]$Target, [System.Management.Automation.PSCredential]$Cred, [int]$TimeoutSec)

    $targets = New-Object System.Collections.Generic.List[string]
    if ($Target)            { $targets.Add($Target) }
    if ($env:USERDNSDOMAIN) { $targets.Add($env:USERDNSDOMAIN) }
    if ($env:LOGONSERVER)   { $targets.Add(($env:LOGONSERVER -replace '^\\\\','')) }

    if ($targets.Count -eq 0) {
        throw "No directory target. This machine does not appear to be domain-joined -- supply -Server."
    }

    foreach ($t in $targets) {
        try {
            Write-OutlineInfo "Binding to $t ..."
            $conn = New-OutlineLdapConnection -Target $t -Cred $Cred -TimeoutSec $TimeoutSec

            $rootAttrs = @(
                'defaultNamingContext','configurationNamingContext','schemaNamingContext',
                'rootDomainNamingContext','dnsHostName','serverName','namingContexts',
                'domainFunctionality','forestFunctionality','domainControllerFunctionality',
                'isGlobalCatalogReady','currentTime','highestCommittedUSN'
            )

            $script:__root = $null
            Invoke-OutlineLdapSearch -Connection $conn -BaseDN '' -Filter '(objectClass=*)' `
                -Attributes $rootAttrs -Scope Base -NoPaging -TimeoutSec $TimeoutSec `
                -Process { param($e) $script:__root = $e } | Out-Null
            $root = $script:__root
            Remove-Variable -Name __root -Scope Script -ErrorAction SilentlyContinue

            if (-not $root) { throw "RootDSE returned no entry." }

            $script:Outline.BootstrapServer = $t
            $script:Outline.DefaultDN    = Get-LdapStr $root 'defaultNamingContext'
            $script:Outline.ConfigDN     = Get-LdapStr $root 'configurationNamingContext'
            $script:Outline.SchemaDN     = Get-LdapStr $root 'schemaNamingContext'
            # objectVersion on the schema head names the OS generation the schema
            # was last prepared for -- useful orientation at the top of a
            # multi-domain report, and cheap since we are already bound.
            $script:Outline.SchemaVersion = $null
            $script:Outline.RootDomainDN = Get-LdapStr $root 'rootDomainNamingContext'
            $script:Outline.ForestName   = ConvertFrom-DnToDomain $script:Outline.RootDomainDN
            $script:Outline.RootDse      = [ordered]@{
                DnsHostName         = Get-LdapStr $root 'dnsHostName'
                ServerName          = Get-LdapStr $root 'serverName'
                DomainFunctional    = Get-LdapInt $root 'domainFunctionality'
                ForestFunctional    = Get-LdapInt $root 'forestFunctionality'
                DcFunctional        = Get-LdapInt $root 'domainControllerFunctionality'
                NamingContexts      = Get-LdapStrArray $root 'namingContexts'
                HighestCommittedUsn = Get-LdapStr $root 'highestCommittedUSN'
                CurrentTime         = Get-LdapStr $root 'currentTime'
            }

            Write-OutlineOk "Bound to $($script:Outline.RootDse.DnsHostName)"
            return $conn
        }
        catch {
            Write-OutlineSkip "Bind failed on ${t}: $($_.Exception.Message)"
        }
    }

    throw "Unable to bind to any directory server. Tried: $($targets -join ', ')"
}

# ==============================================================================
# FUNCTIONAL LEVELS AND PARTITIONS
# ==============================================================================

$script:FuncLevelMap = @{
    0 = 'Windows 2000';                 1 = 'Windows Server 2003 Interim'
    2 = 'Windows Server 2003';          3 = 'Windows Server 2008'
    4 = 'Windows Server 2008 R2';       5 = 'Windows Server 2012'
    6 = 'Windows Server 2012 R2';       7 = 'Windows Server 2016'
   10 = 'Windows Server 2025'
}

function Get-FuncLevelName {
    param([Nullable[int64]]$Value)
    if ($null -eq $Value) { return 'Unknown' }
    $k = [int]$Value
    if ($script:FuncLevelMap.ContainsKey($k)) { return $script:FuncLevelMap[$k] }
    return "Level $k"
}

function Get-OutlinePartition {
    <#
      Reads crossRef objects from CN=Partitions. systemFlags bit 0
      (FLAG_CR_NTDS_NC) marks a directory partition; bit 1
      (FLAG_CR_NTDS_DOMAIN) marks it as a domain.

      This is the authoritative domain list and satisfies the blueprint's
      "auto-discover all domains from the config partition" requirement -- more
      reliable than inferring it from DC records, since a domain with no
      reachable DC still appears.
    #>
    param($Connection, [int]$TimeoutSec, [int]$PageSize = 1000)

    $partDN  = "CN=Partitions,$($script:Outline.ConfigDN)"
    $domains = New-Object System.Collections.Generic.List[object]

    Invoke-OutlineLdapSearch -Connection $Connection -BaseDN $partDN `
        -Filter '(&(objectCategory=crossRef)(systemFlags:1.2.840.113556.1.4.803:=1))' `
        -Attributes @('nCName','dnsRoot','nETBIOSName','systemFlags','distinguishedName') `
        -Scope OneLevel -TimeoutSec $TimeoutSec -PageSize $PageSize -Process {
            param($e)
            $nc    = Get-LdapStr $e 'nCName'
            $dns   = Get-LdapStr $e 'dnsRoot'
            $flags = Get-LdapInt $e 'systemFlags'
            if (-not $nc) { return }
            $isDomain = ($null -ne $flags) -and (($flags -band 2) -eq 2)
            if (-not $isDomain) { return }

            $domains.Add([pscustomobject][ordered]@{
                DnsRoot         = $dns
                NetBIOS         = Get-LdapStr $e 'nETBIOSName'
                NCName          = $nc
                IsRoot          = ($nc -eq $script:Outline.RootDomainDN)
                FunctionalLevel = 'Unknown'
                DcCount         = 0
                DcNames         = @()
                PdcEmulator     = $null
                SysvolReplica   = 'Unknown'
                GpoCount        = 0
                OuCount         = 0
                WmiFilterCount  = 0
                LinkedGpoCount  = 0
                CentralStore    = 'Unknown'
                BoundDc         = $null
                Collected       = $false
                SkipReason      = $null
            })
        }

    # Root domain first, then alphabetically -- a deterministic order matters
    # for a report that is meant to diff cleanly against the next run.
    $script:Outline.Domains = @($domains.ToArray() |
        Sort-Object -Property @{ Expression = { if ($_.IsRoot) { 0 } else { 1 } } }, DnsRoot)
}

# ==============================================================================
# DOMAIN CONTROLLER DISCOVERY  (Configuration NC -- pure LDAP)
# ==============================================================================

function Get-OutlineDomainController {
    <#
      Enumerates nTDSDSA objects under CN=Sites and derives the server host,
      domain, and site for each. No DNS SRV lookups, no RSAT.
    #>
    param($Connection, [int]$TimeoutSec, [int]$PageSize = 1000)

    $map      = [ordered]@{}
    $sitesDN  = "CN=Sites,$($script:Outline.ConfigDN)"
    $servers  = New-Object System.Collections.Generic.List[object]

    Invoke-OutlineLdapSearch -Connection $Connection -BaseDN $sitesDN `
        -Filter '(objectClass=nTDSDSA)' `
        -Attributes @('distinguishedName','options','msDS-Behavior-Version','objectCategory') `
        -Scope Subtree -TimeoutSec $TimeoutSec -PageSize $PageSize -Process {
            param($e)
            $dn = Get-LdapStr $e 'distinguishedName'
            if (-not $dn) { return }
            $opts = Get-LdapInt $e 'options'
            $servers.Add([pscustomobject]@{
                NtdsDN  = $dn
                IsGC    = (($null -ne $opts) -and (($opts -band 1) -eq 1))
                SrvDN   = Get-DnParent $dn
                Site    = Get-DnComponent -DN $dn -Index 3
            })
        }

    foreach ($s in $servers) {
        if (-not $s.SrvDN) { continue }
        try {
            $script:__srv = $null
            Invoke-OutlineLdapSearch -Connection $Connection -BaseDN $s.SrvDN `
                -Filter '(objectClass=server)' `
                -Attributes @('dNSHostName','serverReference','cn') `
                -Scope Base -NoPaging -TimeoutSec $TimeoutSec `
                -Process { param($e) $script:__srv = $e } | Out-Null
            $srv = $script:__srv
            Remove-Variable -Name __srv -Scope Script -ErrorAction SilentlyContinue
            if (-not $srv) { continue }

            $host_ = Get-LdapStr $srv 'dNSHostName'
            $ref   = Get-LdapStr $srv 'serverReference'
            if (-not $host_) { continue }

            # serverReference points at the DC's computer object, whose DN
            # carries the domain the controller actually belongs to.
            $dom = if ($ref) { ConvertFrom-DnToDomain $ref } else { $null }

            $map[$host_] = [ordered]@{
                Name    = $host_
                Site    = $s.Site
                Domain  = $dom
                IsGC    = $s.IsGC
                IsRODC  = $false
                Ldap    = $true
                Smb     = $true
                ProbeMs = 0
                Status  = 'not probed'
                Reasons = @{}
            }
        }
        catch { Write-OutlineQuiet $_ 'DcDiscovery' }
    }

    return $map
}

function Test-TcpPortSet {
    <# Parallel TCP connect probe with a hard timeout per port. #>
    param([string]$HostName, [int[]]$Ports, [int]$TimeoutMs = 1500)

    $result = @{}
    foreach ($p in $Ports) {
        $client = $null
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $iar = $client.BeginConnect($HostName, $p, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false) -and $client.Connected) {
                $client.EndConnect($iar)
                $result[$p] = @{ Open = $true; Reason = 'open' }
            }
            else {
                $result[$p] = @{ Open = $false; Reason = "no answer in ${TimeoutMs}ms" }
            }
        }
        catch {
            $result[$p] = @{ Open = $false; Reason = $_.Exception.Message }
        }
        finally { if ($client) { try { $client.Close() } catch { } } }
    }
    return $result
}

function Invoke-OutlineDCProbe {
    <#
      Marks each discovered controller reachable or not on LDAP and SMB.
      A controller that does not answer is recorded, and every section that
      depended on it says so, rather than reporting an empty result.
    #>
    param([Parameter(Mandatory)]$Map, [int]$TimeoutMs = 1500, [int]$Throttle = 32)

    foreach ($k in @($Map.PSBase.Keys)) {
        $rec = $Map[$k]
        $sw  = [System.Diagnostics.Stopwatch]::StartNew()
        $r   = Test-TcpPortSet -HostName $k -Ports @(389, 445) -TimeoutMs $TimeoutMs
        $sw.Stop()

        $rec.Ldap    = $r[389].Open
        $rec.Smb     = $r[445].Open
        $rec.ProbeMs = [int]$sw.Elapsed.TotalMilliseconds
        $rec.Reasons = @{ Ldap = $r[389].Reason; Smb = $r[445].Reason }
        $rec.Status  = if ($rec.Ldap) { 'reachable' } else { 'no LDAP' }
    }
}

function Get-OutlineResponsiveDC {
    <# Controllers that answered, optionally filtered to one domain. #>
    param([ValidateSet('Ldap','Smb')][string]$Capability = 'Ldap', [string]$DomainName)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($k in @($script:Outline.DCs.PSBase.Keys)) {
        $r = $script:Outline.DCs[$k]
        if ($DomainName -and $r.Domain -ne $DomainName) { continue }
        if (-not $r[$Capability]) { continue }
        $out.Add([pscustomobject]@{ Name = $r.Name; Site = $r.Site; Domain = $r.Domain })
    }
    return ,$out.ToArray()
}

function Set-DCCapability {
    param([string]$Name, [string]$Capability, [string]$Reason)
    if (-not $script:Outline.DCs.Contains($Name)) { return }
    $script:Outline.DCs[$Name][$Capability] = $false
    $script:Outline.DCs[$Name].Reasons[$Capability] = $Reason
    Write-OutlineLog 'WARN' "$Name demoted on ${Capability}: $Reason"
}

# ==============================================================================
# PER-DOMAIN CONNECTIONS
#
# Referral chasing is off, so a connection to one domain cannot read another
# domain's NC -- each domain needs its own bind. One DC is bound per domain and
# reused for the whole run, so the report is a coherent point-in-time view
# rather than a blend of differently-replicated controllers. The DC used is
# recorded per domain for evidence integrity.
# ==============================================================================

$script:DomainConnections = @{}

function Get-OutlineDomainConnection {
    param([Parameter(Mandatory)][string]$DnsRoot)

    if ($script:DomainConnections.ContainsKey($DnsRoot)) {
        return $script:DomainConnections[$DnsRoot]
    }

    foreach ($dc in (Get-OutlineResponsiveDC -Capability Ldap -DomainName $DnsRoot)) {
        try {
            $c = New-OutlineLdapConnection -Target $dc.Name -Cred $script:BoundCredential `
                    -TimeoutSec $script:LdapTimeout
            $script:DomainConnections[$DnsRoot] = $c

            foreach ($d in $script:Outline.Domains) {
                if ($d.DnsRoot -eq $DnsRoot) { $d.BoundDc = $dc.Name }
            }
            Write-OutlineInfo "Bound to $($dc.Name) for domain $DnsRoot."
            return $c
        }
        catch {
            Set-DCCapability -Name $dc.Name -Capability Ldap `
                -Reason "LDAP bind failed: $($_.Exception.Message)"
        }
    }

    $script:DomainConnections[$DnsRoot] = $null
    Add-OutlineWarning "No bindable DC in $DnsRoot -- that domain's Group Policy cannot be collected."
    foreach ($d in $script:Outline.Domains) {
        if ($d.DnsRoot -eq $DnsRoot) { $d.SkipReason = 'No bindable domain controller' }
    }
    return $null
}

function Update-OutlineDomainDetail {
    <#
      Per-domain facts for the AD Domain Summary block: functional level, PDC
      emulator, and SYSVOL replication engine (FRS vs DFSR), each read from
      that domain's own connection.
    #>
    param([int]$TimeoutSec = 30)

    # ---- forest-wide: schema objectVersion ----
    # One read against the schema head. Names the OS generation the schema was
    # last prepared for, which orients a reader at the top of a multi-domain
    # report. Non-fatal: an unreadable schema head costs one line, not the run.
    if ($script:Outline.SchemaDN) {
        try {
            $conn0 = Get-OutlineDomainConnection -DnsRoot $script:Outline.ForestName
            if ($conn0) {
                Invoke-OutlineLdapSearch -Connection $conn0 -BaseDN $script:Outline.SchemaDN `
                    -Filter '(objectClass=*)' -Attributes @('objectVersion') `
                    -Scope Base -NoPaging -TimeoutSec $TimeoutSec -Process {
                        param($e)
                        $script:Outline.SchemaVersion = Get-LdapInt $e 'objectVersion'
                    } | Out-Null
            }
        }
        catch { Write-OutlineQuiet $_ 'SchemaVersion' }
    }

    foreach ($d in $script:Outline.Domains) {
        $conn = Get-OutlineDomainConnection -DnsRoot $d.DnsRoot
        if (-not $conn) { $d.FunctionalLevel = 'Unavailable'; continue }

        # --- functional level + PDC ---
        try {
            Invoke-OutlineLdapSearch -Connection $conn -BaseDN $d.NCName `
                -Filter '(objectClass=*)' -Attributes @('msDS-Behavior-Version','fSMORoleOwner') `
                -Scope Base -NoPaging -TimeoutSec $TimeoutSec -Process {
                    param($e)
                    $d.FunctionalLevel = Get-FuncLevelName (Get-LdapInt $e 'msDS-Behavior-Version')
                    $owner = Get-LdapStr $e 'fSMORoleOwner'
                    if ($owner) {
                        # fSMORoleOwner points at the NTDS Settings object;
                        # the server CN sits two RDNs up.
                        $d.PdcEmulator = Get-DnComponent -DN $owner -Index 1
                    }
                } | Out-Null
        }
        catch {
            $d.FunctionalLevel = 'Unavailable'
            Add-OutlineWarning "Functional level unreadable for $($d.DnsRoot): $($_.Exception.Message)"
        }

        # --- SYSVOL replication engine ---
        # DFSR migration state lives under the DFSR-GlobalSettings container.
        # Absence of that container means the domain never migrated off FRS.
        # This is documented as a fact; it is not graded.
        try {
            $dfsrDN = "CN=DFSR-GlobalSettings,CN=System,$($d.NCName)"
            $script:__dfsr = $null
            Invoke-OutlineLdapSearch -Connection $conn -BaseDN $dfsrDN `
                -Filter '(objectClass=*)' -Attributes @('msDFSR-Flags') `
                -Scope Base -NoPaging -TimeoutSec $TimeoutSec `
                -Process { param($e) $script:__dfsr = $e } | Out-Null
            $g = $script:__dfsr
            Remove-Variable -Name __dfsr -Scope Script -ErrorAction SilentlyContinue

            if ($g) {
                $flags = Get-LdapInt $g 'msDFSR-Flags'
                # 48 = Eliminated: migration complete, FRS no longer used.
                $d.SysvolReplica = if ($null -eq $flags) { 'DFSR' }
                                   elseif ($flags -ge 48) { 'DFSR' }
                                   else { "DFSR (migration state $flags)" }
            }
            else { $d.SysvolReplica = 'FRS' }
        }
        catch {
            $d.SysvolReplica = 'Unknown'
            Write-OutlineQuiet $_ "SysvolReplica:$($d.DnsRoot)"
        }
    }
}

function Invoke-OutlineTrustSweep {
    <#
      Trusts are collected because Group Policy does NOT cross them. The map
      exists so a reader understands why the scope of this report stops at each
      domain edge -- not as a judgement about the trust itself.
    #>
    param([int]$TimeoutSec = 30, [int]$PageSize = 1000)

    $rows = New-Object System.Collections.Generic.List[object]
    $dirMap = @{ 0 = 'Disabled'; 1 = 'Inbound'; 2 = 'Outbound'; 3 = 'Bidirectional' }
    $typMap = @{ 1 = 'Windows NT (downlevel)'; 2 = 'Active Directory'; 3 = 'Kerberos realm'; 4 = 'DCE' }

    foreach ($d in $script:Outline.Domains) {
        $conn = Get-OutlineDomainConnection -DnsRoot $d.DnsRoot
        if (-not $conn) { continue }
        try {
            Invoke-OutlineLdapSearch -Connection $conn -BaseDN "CN=System,$($d.NCName)" `
                -Filter '(objectClass=trustedDomain)' `
                -Attributes @('trustPartner','trustDirection','trustType','trustAttributes','flatName','whenCreated') `
                -Scope OneLevel -TimeoutSec $TimeoutSec -PageSize $PageSize -Process {
                    param($e)
                    $dir = [int](Get-LdapInt $e 'trustDirection')
                    $typ = [int](Get-LdapInt $e 'trustType')
                    $att = [int](Get-LdapInt $e 'trustAttributes')
                    $notes = New-Object System.Collections.Generic.List[string]
                    if (($att -band 0x1)  -ne 0) { $notes.Add('Non-transitive') }
                    if (($att -band 0x8)  -ne 0) { $notes.Add('Forest trust') }
                    if (($att -band 0x20) -ne 0) { $notes.Add('Within forest') }
                    if (($att -band 0x40) -ne 0) { $notes.Add('Treat as external') }
                    if (($att -band 0x4)  -ne 0) { $notes.Add('Quarantined (SID filtering)') }

                    $rows.Add([pscustomobject]@{
                        Domain      = $d.DnsRoot
                        Partner     = Get-LdapStr $e 'trustPartner'
                        FlatName    = Get-LdapStr $e 'flatName'
                        Direction   = $(if ($dirMap.ContainsKey($dir)) { $dirMap[$dir] } else { "Direction $dir" })
                        Type        = $(if ($typMap.ContainsKey($typ)) { $typMap[$typ] } else { "Type $typ" })
                        Attributes  = ($notes -join ', ')
                        Created     = Format-OutlineDate (ConvertFrom-AdGeneralizedTime (Get-LdapStr $e 'whenCreated'))
                    })
                }
        }
        catch { Write-OutlineQuiet $_ "Trusts:$($d.DnsRoot)" }
    }

    $script:Outline.Trusts = $rows.ToArray()
}

function Invoke-OutlineSiteSweep {
    <#
      Sites live in the configuration partition and are therefore forest-wide:
      collected once, then cross-referenced against each domain's GPO links.
      Site links are easy to miss in GPMC, which is why they get their own
      section in the report.
    #>
    param($Connection, [int]$TimeoutSec = 30, [int]$PageSize = 1000)

    $rows    = New-Object System.Collections.Generic.List[object]
    $sitesDN = "CN=Sites,$($script:Outline.ConfigDN)"

    try {
        Invoke-OutlineLdapSearch -Connection $Connection -BaseDN $sitesDN `
            -Filter '(objectClass=site)' `
            -Attributes @('distinguishedName','cn','gPLink','gPOptions','description','whenChanged') `
            -Scope OneLevel -TimeoutSec $TimeoutSec -PageSize $PageSize -Process {
                param($e)
                $rows.Add([pscustomobject]@{
                    Name        = Get-LdapStr $e 'cn'
                    DN          = Get-LdapStr $e 'distinguishedName'
                    GpLink      = Get-LdapStr $e 'gPLink'
                    GpOptions   = [int](Get-LdapInt $e 'gPOptions')
                    Description = Get-LdapStr $e 'description'
                    Changed     = Format-OutlineDate (ConvertFrom-AdGeneralizedTime (Get-LdapStr $e 'whenChanged'))
                })
            }
    }
    catch { Add-OutlineWarning "Sites unreadable: $($_.Exception.Message)" }

    $script:Outline.Sites = $rows.ToArray()
}

# ==============================================================================
# REFERENCE DATA
#
# Everything in this block is static lookup data, versioned with the script so
# the report resolves names and links with no network call at open time. That
# is what keeps the HTML self-contained and readable offline years later.
# ==============================================================================

# ---- Client-Side Extension GUIDs -------------------------------------------
# gPCMachineExtensionNames / gPCUserExtensionNames carry [CSE GUID][tool GUID]
# pairs. The CSE GUID says which client-side extension processes the GPO, which
# is how the report can state what a GPO actually does before any file is read.
$script:CseNames = @{
    '{00000000-0000-0000-0000-000000000000}' = 'Core Group Policy'
    '{0ACDD40C-75AC-47AB-BAA0-BF6DE7E7FE63}' = 'Wireless Network (802.11) Policies'
    '{0E28E245-9368-4853-AD84-6DA3BA35BB75}' = 'Group Policy Environment'
    '{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}' = 'Computer Policy Setting'
    '{0F6B957D-509E-11D1-A7CC-0000F87571E3}' = 'Tool Extension GUID (Computer)'
    '{0F6B957E-509E-11D1-A7CC-0000F87571E3}' = 'Tool Extension GUID (User)'
    '{16be69fa-4209-4ff4-b3f7-a0a62ef1c6c6}' = 'Group Policy Regional Options'
    '{17D89FEC-5C44-4972-B12D-241CAEF74509}' = 'Group Policy Local Users and Groups'
    '{1A6364EB-776B-4120-ADE1-B63A406A76B5}' = 'Group Policy Device Settings'
    '{25537BA6-77A8-11D2-9B6C-0000F8080861}' = 'Folder Redirection'
    '{2A8FDC61-2347-4C87-92F6-B05EB91A201A}' = 'MitigationOptions'
    '{2EA1A81B-48E5-45E9-8BB7-A6E3AC170006}' = 'Group Policy Drives'
    '{3060E8D0-7020-11D2-842D-00C04FA372D4}' = 'Remote Installation Services'
    '{3610eda5-77ef-11d2-8dc5-00c04fa31a66}' = 'Microsoft Disk Quota'
    '{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' = 'Registry Policy (Administrative Templates)'
    '{3A0DBA37-F8B2-4356-83DE-3E90BD5C261F}' = 'Group Policy Network Options'
    '{3BAE7E51-E3F4-41D0-853D-9BB9FD47605F}' = 'Group Policy Files'
    '{3BFAE46A-7F3A-467B-8CEA-6AA34DC71F53}' = 'Group Policy Folder Options'
    '{3EC4E9D3-714D-471F-88DC-4DD4471AAB47}' = 'Group Policy Folders'
    '{40B6664F-4972-11D1-A7CA-0000F87571E3}' = 'Scripts (Startup/Shutdown)'
    '{4283DDA1-8AAA-4F70-A0C0-F6D8C24BEB8B}' = 'Group Policy Ini Files'
    '{42B5FAAE-6536-11D2-AE5A-0000F87571E3}' = 'Scripts (Logon/Logoff)'
    '{4B7C3B0F-E993-4E06-A241-3FBE06943684}' = 'Group Policy Power Options'
    '{4CFB60C1-FAA6-47F1-89AA-0B18730C9FD3}' = 'Internet Explorer Zonemapping'
    '{4D2F9B6F-1E52-4711-A382-6A8B1A003DE6}' = 'RADCProcessGroupPolicy'
    '{5794DAFD-BE60-433f-88A2-1A31939AC01F}' = 'Group Policy Scheduled Tasks'
    '{53D6AB1B-2488-11D1-A28C-00C04FB94F17}' = 'Certificates (EFS Recovery)'
    '{53D6AB1D-2488-11D1-A28C-00C04FB94F17}' = 'Certificates Run Restriction'
    '{6232C319-91AC-4931-9385-E70C2B099F0E}' = 'Group Policy Shortcuts'
    '{6A4C88C6-C502-4f74-8F60-2CB23EDC24E2}' = 'Group Policy Network Shares'
    '{7150F9BF-48AD-4DA4-A49C-29EF4A8369BA}' = 'Group Policy Internet Settings'
    '{728EE579-943C-4519-9EF7-AB56765798ED}' = 'Group Policy Data Sources'
    '{74EE6C03-5363-4554-B161-627540339CAB}' = 'Group Policy Ini Files (User)'
    '{7933F41E-56F8-41d6-A31C-4148A711EE93}' = 'Windows Search'
    '{7B849a69-220F-451E-B3FE-2CB811AF94AE}' = 'Internet Explorer User Accelerators'
    '{827D319E-6EAC-11D2-A4EA-00C04F79F83A}' = 'Security Settings'
    '{88E729D6-BDC1-11D1-BD2A-00C04FB9603F}' = 'Folder Redirection Policy'
    '{8A28E2C5-8D06-49A4-A08C-632DAA493E17}' = 'Deployed Printer Connections'
    '{91FBB303-0CD5-4055-BF42-E512A681B325}' = 'Group Policy Services'
    '{9AD2BAFE-63B4-4883-A08C-C3C6196BCAFD}' = 'Group Policy Power Options (User)'
    '{A2E30F80-D7DE-11d2-BBDE-00C04F86AE3B}' = 'Internet Explorer Maintenance'
    '{A3F3E39B-5D83-4940-B954-28315B82F0A8}' = 'Group Policy Folder Options (User)'
    '{A8C42CEA-CDB8-4388-97F4-5831F933DA84}' = 'Group Policy Printers'
    '{AADCED64-746C-4633-A97C-D61349046527}' = 'Group Policy Scheduled Tasks (User)'
    '{B087BE9D-ED37-454f-AF9C-04291E351182}' = 'Group Policy Registry'
    '{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}' = 'EFS Recovery'
    '{B587E2B1-4D59-4e7e-AED9-22B9DF11D053}' = '802.3 Group Policy'
    '{BA649533-0AAC-4E04-B9BC-4DBAE0325B12}' = 'Windows To Go Startup Options'
    '{BC75B1ED-5833-4858-9BB8-CBF0B166DF9D}' = 'Group Policy Printers (Deployed)'
    '{BEE07A6A-EC9F-4659-B8C9-0B1937907C83}' = 'Certificates (Autoenrollment)'
    '{BFCBBEB0-9DF4-4c0c-A728-434EA66A0373}' = 'Network Access Protection'
    '{C34B2751-1CF4-44F5-9262-C3FC39666591}' = 'Windows To Go Hibernate Options'
    '{C418DD9D-0D14-4efb-8FBF-CFE535C8FAC7}' = 'Group Policy Shortcuts (User)'
    '{C6DC5466-785A-11D2-84D0-00C04FB169F7}' = 'Software Installation'
    '{CDEAFC3D-948D-49dd-AB12-E578BA4AF7AA}' = 'TCPIP Configuration'
    '{CF7639F3-ABA2-41DB-97F2-81E2C5DBFC5D}' = 'Internet Explorer Machine Accelerators'
    '{CRT-NOT-A-GUID}'                        = 'Unknown'
    '{D02B1F72-3407-48AE-BA88-E8213C6761F1}' = 'Tool Extension GUID (Computer, MMC)'
    '{D02B1F73-3407-48AE-BA88-E8213C6761F1}' = 'Tool Extension GUID (User, MMC)'
    '{E437BC1C-AA7D-11D2-A382-00C04F991E27}' = 'IP Security Policy'
    '{E47248BA-94CC-49c4-BBB5-9EB7F05183D0}' = 'Group Policy Internet Settings (User)'
    '{E4F48E54-F38D-4884-BFB9-D4D2E5729C18}' = 'Group Policy Start Menu Settings'
    '{E5094040-C46C-4115-B030-04FB2E545B00}' = 'Group Policy Regional Options (User)'
    '{E5E2C6C0-5B7F-4B0B-B15D-5E6E1B7C8D1B}' = 'Group Policy Local Users and Groups (User)'
    '{E62688F0-25FD-4c90-BFF5-F508B9D2E31F}' = 'Group Policy Power Options (Machine)'
    '{F0DB2806-FD46-45B7-81BD-AA3744B32765}' = 'Policy Maker'
    '{F17E8B5B-78F2-49A6-8933-7B767EDA5B41}' = 'Policy Maker (Machine)'
    '{F27A6DA8-D22B-4179-A042-3D715F9E75B5}' = 'Policy Maker (User)'
    '{F3CCC681-B74C-4060-9F26-CD84525DCA2A}' = 'Audit Policy Configuration'
    '{F581DAE7-8064-444A-AEB3-1875662A61CE}' = 'Group Policy Applications'
    '{F9C77450-3A41-477E-9310-9ACD617BD9E3}' = 'Group Policy Applications (User)'
    '{FB2CA36D-0B40-4307-821B-A13B252DE56C}' = 'Administrative Templates (Policy Definitions)'
    '{FC491EF1-C4AA-41CE-9C4B-BB1B1C0E4EAF}' = 'Group Policy Devices'
    '{FD2D917B-6519-4BF7-8403-456C0C64312F}' = 'Group Policy Devices (User)'
}

# Which CSEs indicate a setting area, for the "setting footprint" section.
$script:CseArea = @{
    '{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' = 'Administrative Templates'
    '{827D319E-6EAC-11D2-A4EA-00C04F79F83A}' = 'Security Settings'
    '{40B6664F-4972-11D1-A7CA-0000F87571E3}' = 'Scripts'
    '{42B5FAAE-6536-11D2-AE5A-0000F87571E3}' = 'Scripts'
    '{25537BA6-77A8-11D2-9B6C-0000F8080861}' = 'Folder Redirection'
    '{C6DC5466-785A-11D2-84D0-00C04FB169F7}' = 'Software Installation'
    '{B087BE9D-ED37-454f-AF9C-04291E351182}' = 'Preferences'
    '{2EA1A81B-48E5-45E9-8BB7-A6E3AC170006}' = 'Preferences'
    '{17D89FEC-5C44-4972-B12D-241CAEF74509}' = 'Preferences'
    '{5794DAFD-BE60-433f-88A2-1A31939AC01F}' = 'Preferences'
    '{91FBB303-0CD5-4055-BF42-E512A681B325}' = 'Preferences'
    '{A8C42CEA-CDB8-4388-97F4-5831F933DA84}' = 'Preferences'
    '{3BAE7E51-E3F4-41D0-853D-9BB9FD47605F}' = 'Preferences'
    '{6232C319-91AC-4931-9385-E70C2B099F0E}' = 'Preferences'
    '{0E28E245-9368-4853-AD84-6DA3BA35BB75}' = 'Preferences'
    '{BEE07A6A-EC9F-4659-B8C9-0B1937907C83}' = 'Public Key Policies'
    '{E437BC1C-AA7D-11D2-A382-00C04F991E27}' = 'IP Security'
    '{0ACDD40C-75AC-47AB-BAA0-BF6DE7E7FE63}' = 'Wireless Policy'
    '{B587E2B1-4D59-4e7e-AED9-22B9DF11D053}' = 'Wired Policy'
    '{8A28E2C5-8D06-49A4-A08C-632DAA493E17}' = 'Deployed Printers'
    '{A2E30F80-D7DE-11d2-BBDE-00C04F86AE3B}' = 'Internet Explorer Maintenance'
    '{F3CCC681-B74C-4060-9F26-CD84525DCA2A}' = 'Advanced Audit Policy'
}

# CSEs whose presence changes logon/boot behaviour. Documented as a factual
# "this affects logon experience" surface -- not scored, not graded.
$script:CseSynchronous = @{
    '{25537BA6-77A8-11D2-9B6C-0000F8080861}' = 'Folder redirection is applied during synchronous foreground processing.'
    '{C6DC5466-785A-11D2-84D0-00C04FB169F7}' = 'Software installation is applied during synchronous foreground processing.'
    '{40B6664F-4972-11D1-A7CA-0000F87571E3}' = 'Startup scripts run before the logon screen is presented.'
    '{42B5FAAE-6536-11D2-AE5A-0000F87571E3}' = 'Logon scripts run before the desktop is presented.'
    '{2EA1A81B-48E5-45E9-8BB7-A6E3AC170006}' = 'Drive maps are processed at logon.'
    '{A8C42CEA-CDB8-4388-97F4-5831F933DA84}' = 'Printer connections are processed at logon.'
    '{8A28E2C5-8D06-49A4-A08C-632DAA493E17}' = 'Deployed printer connections are processed at logon.'
}

function Get-CseName {
    param([string]$Guid)
    if (-not $Guid) { return $null }
    $g = $Guid.Trim()
    if ($script:CseNames.ContainsKey($g)) { return $script:CseNames[$g] }
    # GUID case varies between GPOs written by different tooling.
    foreach ($k in $script:CseNames.Keys) {
        if ($k -ieq $g) { return $script:CseNames[$k] }
    }
    return $null
}

function Get-CseArea {
    param([string]$Guid)
    if (-not $Guid) { return $null }
    foreach ($k in $script:CseArea.Keys) { if ($k -ieq $Guid.Trim()) { return $script:CseArea[$k] } }
    return $null
}

function ConvertFrom-CseList {
    <#
      Parses gPCMachineExtensionNames / gPCUserExtensionNames.
      Format: [{CSE GUID}{tool GUID}{tool GUID}...][{CSE GUID}{tool GUID}]...
      Only the FIRST GUID in each bracketed group is the CSE; the rest are the
      MMC snap-in extensions that authored it, which are not interesting here.
    #>
    param([string]$Value)
    $out = New-Object System.Collections.Generic.List[object]
    if (-not $Value) { return ,$out.ToArray() }

    foreach ($m in [regex]::Matches($Value, '\[(.*?)\]')) {
        $inner = $m.Groups[1].Value
        $guids = [regex]::Matches($inner, '\{[0-9A-Fa-f\-]{36}\}')
        if ($guids.Count -eq 0) { continue }
        $cse  = $guids[0].Value
        $name = Get-CseName $cse
        $out.Add([pscustomobject]@{
            Guid     = $cse
            Name     = $(if ($name) { $name } else { 'Unrecognised extension' })
            Resolved = [bool]$name
            Area     = Get-CseArea $cse
            ToolCount = [Math]::Max(0, $guids.Count - 1)
        })
    }
    return ,$out.ToArray()
}

# ---- Well-known SIDs --------------------------------------------------------
$script:WellKnownSids = @{
    'S-1-0-0'      = 'Nobody';                          'S-1-1-0'      = 'Everyone'
    'S-1-2-0'      = 'Local';                           'S-1-3-0'      = 'Creator Owner'
    'S-1-3-1'      = 'Creator Group';                   'S-1-5-2'      = 'NETWORK'
    'S-1-5-4'      = 'INTERACTIVE';                     'S-1-5-6'      = 'SERVICE'
    'S-1-5-7'      = 'ANONYMOUS LOGON';                 'S-1-5-9'      = 'Enterprise Domain Controllers'
    'S-1-5-10'     = 'SELF';                            'S-1-5-11'     = 'Authenticated Users'
    'S-1-5-12'     = 'RESTRICTED';                      'S-1-5-13'     = 'Terminal Server User'
    'S-1-5-14'     = 'Remote Interactive Logon';        'S-1-5-15'     = 'This Organization'
    'S-1-5-17'     = 'IUSR';                            'S-1-5-18'     = 'SYSTEM'
    'S-1-5-19'     = 'LOCAL SERVICE';                   'S-1-5-20'     = 'NETWORK SERVICE'
    'S-1-5-32-544' = 'Administrators';                  'S-1-5-32-545' = 'Users'
    'S-1-5-32-546' = 'Guests';                          'S-1-5-32-547' = 'Power Users'
    'S-1-5-32-548' = 'Account Operators';               'S-1-5-32-549' = 'Server Operators'
    'S-1-5-32-550' = 'Print Operators';                 'S-1-5-32-551' = 'Backup Operators'
    'S-1-5-32-552' = 'Replicator';                      'S-1-5-32-554' = 'Pre-Windows 2000 Compatible Access'
    'S-1-5-32-555' = 'Remote Desktop Users';            'S-1-5-32-556' = 'Network Configuration Operators'
    'S-1-5-32-557' = 'Incoming Forest Trust Builders';  'S-1-5-32-558' = 'Performance Monitor Users'
    'S-1-5-32-559' = 'Performance Log Users';           'S-1-5-32-560' = 'Windows Authorization Access Group'
    'S-1-5-32-561' = 'Terminal Server License Servers'; 'S-1-5-32-562' = 'Distributed COM Users'
    'S-1-5-32-568' = 'IIS_IUSRS';                       'S-1-5-32-569' = 'Cryptographic Operators'
    'S-1-5-32-573' = 'Event Log Readers';               'S-1-5-32-574' = 'Certificate Service DCOM Access'
    'S-1-5-32-578' = 'Hyper-V Administrators';          'S-1-5-32-579' = 'Access Control Assistance Operators'
    'S-1-5-32-580' = 'Remote Management Users';         'S-1-5-80-0'   = 'All Services'
    'S-1-5-64-10'  = 'NTLM Authentication';             'S-1-5-64-14'  = 'SChannel Authentication'
    'S-1-5-64-21'  = 'Digest Authentication'
}

# RID suffixes on a domain SID.
$script:WellKnownRids = @{
    '500' = 'Administrator';        '501' = 'Guest';                 '502' = 'krbtgt'
    '512' = 'Domain Admins';        '513' = 'Domain Users';          '514' = 'Domain Guests'
    '515' = 'Domain Computers';     '516' = 'Domain Controllers';    '517' = 'Cert Publishers'
    '518' = 'Schema Admins';        '519' = 'Enterprise Admins';     '520' = 'Group Policy Creator Owners'
    '521' = 'Read-only Domain Controllers'
    '522' = 'Cloneable Domain Controllers'
    '525' = 'Protected Users';      '526' = 'Key Admins';            '527' = 'Enterprise Key Admins'
    '553' = 'RAS and IAS Servers';  '571' = 'Allowed RODC Password Replication Group'
    '572' = 'Denied RODC Password Replication Group'
    '498' = 'Enterprise Read-only Domain Controllers'
}

$script:SidNameCache = @{}

function Resolve-OutlineSid {
    <#
      SID -> readable name, cached. GPO security filtering and delegation are
      full of repeated principals, so every translation is memoised: on a large
      estate this is the difference between hundreds of lookups and tens of
      thousands.

      Resolution order: cache, well-known table, RID table, then a live
      translate attempt. A SID that cannot be resolved is returned as-is and
      marked unresolved rather than guessed at -- an unresolvable principal is
      usually a deleted account or one from an untrusted domain, and that is
      itself worth showing the reader.
    #>
    param([string]$Sid)
    if (-not $Sid) { return $null }
    $s = $Sid.Trim().TrimStart('*')

    if ($script:SidNameCache.ContainsKey($s)) { return $script:SidNameCache[$s] }

    $result = $null
    if ($script:WellKnownSids.ContainsKey($s)) {
        $result = [pscustomobject]@{ Sid = $s; Name = $script:WellKnownSids[$s]; Resolved = $true; Source = 'Well-known SID' }
    }
    elseif ($s -match '^S-1-5-21-\d+-\d+-\d+-(\d+)$' -and $script:WellKnownRids.ContainsKey($Matches[1])) {
        $result = [pscustomobject]@{ Sid = $s; Name = $script:WellKnownRids[$Matches[1]]; Resolved = $true; Source = 'Well-known RID' }
    }
    else {
        try {
            $obj = New-Object System.Security.Principal.SecurityIdentifier($s)
            $nt  = $obj.Translate([System.Security.Principal.NTAccount])
            $result = [pscustomobject]@{ Sid = $s; Name = $nt.Value; Resolved = $true; Source = 'Directory' }
        }
        catch {
            Write-OutlineAbsence 'SidTranslate'
            $result = [pscustomobject]@{ Sid = $s; Name = $s; Resolved = $false; Source = 'Unresolved' }
        }
    }

    $script:SidNameCache[$s] = $result
    return $result
}

# ---- Group Policy Preferences extension folders ----------------------------
# Directory name under Preferences\ -> readable category and the XML element
# that carries individual items.
$script:GppExtensions = [ordered]@{
    'Drives'            = @{ Label = 'Drive Maps';          Item = 'Drive' }
    'EnvironmentVariables' = @{ Label = 'Environment';      Item = 'EnvironmentVariable' }
    'Files'             = @{ Label = 'Files';               Item = 'File' }
    'Folders'           = @{ Label = 'Folders';             Item = 'Folder' }
    'IniFiles'          = @{ Label = 'Ini Files';           Item = 'Ini' }
    'Registry'          = @{ Label = 'Registry';            Item = 'Registry' }
    'NetworkShares'     = @{ Label = 'Network Shares';      Item = 'NetShare' }
    'Shortcuts'         = @{ Label = 'Shortcuts';           Item = 'Shortcut' }
    'DataSources'       = @{ Label = 'Data Sources';        Item = 'DataSource' }
    'Devices'           = @{ Label = 'Devices';             Item = 'Device' }
    'FolderOptions'     = @{ Label = 'Folder Options';      Item = 'GlobalFolderOptions' }
    'Groups'            = @{ Label = 'Local Users and Groups'; Item = 'Group' }
    'InternetSettings'  = @{ Label = 'Internet Settings';   Item = 'InternetExplorer' }
    'NetworkOptions'    = @{ Label = 'Network Options';     Item = 'VPN' }
    'PowerOptions'      = @{ Label = 'Power Options';       Item = 'GlobalPowerOptions' }
    'Printers'          = @{ Label = 'Printers';            Item = 'SharedPrinter' }
    'RegionalOptions'   = @{ Label = 'Regional Options';    Item = 'RegionalOptions' }
    'ScheduledTasks'    = @{ Label = 'Scheduled Tasks';     Item = 'Task' }
    'Services'          = @{ Label = 'Services';            Item = 'NTService' }
    'StartMenu'         = @{ Label = 'Start Menu';          Item = 'StartMenu' }
    'Applications'      = @{ Label = 'Applications';        Item = 'Application' }
}

# GPP action codes on the <Properties action="..."> attribute.
$script:GppAction = @{ 'C' = 'Create'; 'R' = 'Replace'; 'U' = 'Update'; 'D' = 'Delete' }

# ---- Microsoft reference map ------------------------------------------------
# Registry key prefix -> Microsoft Learn documentation. Resolution is by
# longest-prefix match, so a specific key beats a general one. Shipped inline
# so links work with no network access when the report is opened.
$script:MsReferenceMap = @(
    @{ Prefix = 'Software\Policies\Microsoft\Windows\System';            Url = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-grouppolicy'; Label = 'Group Policy (Policy CSP)' }
    @{ Prefix = 'Software\Policies\Microsoft\Windows\WindowsUpdate';     Url = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-update'; Label = 'Windows Update (Policy CSP)' }
    @{ Prefix = 'Software\Policies\Microsoft\Windows Defender';          Url = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-defender'; Label = 'Microsoft Defender (Policy CSP)' }
    @{ Prefix = 'Software\Policies\Microsoft\Windows\WindowsFirewall';   Url = 'https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/'; Label = 'Windows Firewall' }
    @{ Prefix = 'Software\Policies\Microsoft\Windows\BITS';              Url = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-bits'; Label = 'BITS (Policy CSP)' }
    @{ Prefix = 'Software\Policies\Microsoft\Windows\Explorer';          Url = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-explorer'; Label = 'File Explorer (Policy CSP)' }
    @{ Prefix = 'Software\Policies\Microsoft\Windows\Personalization';   Url = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-controlpanel'; Label = 'Personalization (Policy CSP)' }
    @{ Prefix = 'Software\Policies\Microsoft\Windows\Installer';         Url = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-msi'; Label = 'Windows Installer (Policy CSP)' }
    @{ Prefix = 'Software\Policies\Microsoft\Windows\PowerShell';        Url = 'https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_group_policy_settings'; Label = 'PowerShell policy settings' }
    @{ Prefix = 'Software\Policies\Microsoft\Windows\WinRM';             Url = 'https://learn.microsoft.com/windows/win32/winrm/installation-and-configuration-for-windows-remote-management'; Label = 'Windows Remote Management' }
    @{ Prefix = 'Software\Policies\Microsoft\Windows\RemoteDesktop';     Url = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-terminalserver'; Label = 'Remote Desktop (Policy CSP)' }
    @{ Prefix = 'Software\Policies\Microsoft\Windows NT\Terminal Services'; Url = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-terminalserver'; Label = 'Terminal Services (Policy CSP)' }
    @{ Prefix = 'Software\Policies\Microsoft\Windows NT\DNSClient';      Url = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-dnsclient'; Label = 'DNS Client (Policy CSP)' }
    @{ Prefix = 'Software\Policies\Microsoft\Windows NT\Rpc';            Url = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-rpc'; Label = 'RPC (Policy CSP)' }
    @{ Prefix = 'Software\Policies\Microsoft\Internet Explorer';         Url = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-internetexplorer'; Label = 'Internet Explorer (Policy CSP)' }
    @{ Prefix = 'Software\Policies\Microsoft\Edge';                      Url = 'https://learn.microsoft.com/deployedge/microsoft-edge-policies'; Label = 'Microsoft Edge policies' }
    @{ Prefix = 'Software\Policies\Google\Chrome';                       Url = 'https://chromeenterprise.google/policies/'; Label = 'Chrome Enterprise policies' }
    @{ Prefix = 'Software\Policies\Microsoft\Office';                    Url = 'https://learn.microsoft.com/deployoffice/admincenter/overview-cloud-policy'; Label = 'Microsoft 365 Apps policies' }
    @{ Prefix = 'Software\Policies\Microsoft\Cryptography';              Url = 'https://learn.microsoft.com/windows/security/identity-protection/'; Label = 'Cryptography and certificates' }
    @{ Prefix = 'Software\Policies\Microsoft\SystemCertificates';        Url = 'https://learn.microsoft.com/windows-server/identity/ad-cs/'; Label = 'Certificate policies' }
    @{ Prefix = 'Software\Policies\Microsoft\WindowsStore';              Url = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-windowsstore'; Label = 'Microsoft Store (Policy CSP)' }
    @{ Prefix = 'Software\Microsoft\Windows\CurrentVersion\Policies';    Url = 'https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn265983(v=ws.11)'; Label = 'Group Policy settings reference' }
    @{ Prefix = 'System\CurrentControlSet\Services\LanmanServer';        Url = 'https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3'; Label = 'SMB server configuration' }
    @{ Prefix = 'System\CurrentControlSet\Services\LanmanWorkstation';   Url = 'https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3'; Label = 'SMB client configuration' }
    @{ Prefix = 'System\CurrentControlSet\Control\Lsa';                  Url = 'https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/security-options'; Label = 'Security Options (LSA)' }
    @{ Prefix = 'System\CurrentControlSet\Control\SecurityProviders';    Url = 'https://learn.microsoft.com/windows/win32/secauthn/schannel'; Label = 'Schannel / TLS' }
    @{ Prefix = 'System\CurrentControlSet\Services';                     Url = 'https://learn.microsoft.com/windows-server/administration/'; Label = 'Windows service configuration' }
    @{ Prefix = 'Software\Policies';                                     Url = 'https://learn.microsoft.com/windows/client-management/mdm/policy-configuration-service-provider'; Label = 'Policy CSP reference' }
)

$script:MsReferenceGeneric = @{
    Url   = 'https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn265983(v=ws.11)'
    Label = 'Group Policy settings reference'
}

function Get-MsReference {
    <#
      Longest-prefix match against the shipped reference table. Every result
      carries its source so the reader can judge the linkage:
        ADMX      -- friendly name came from the central store
        CSP map   -- matched a known Policy CSP area
        Generic   -- fell back to the general settings reference
    #>
    param([string]$Key)
    if (-not $Key) { return $null }
    $best = $null; $bestLen = -1
    foreach ($r in $script:MsReferenceMap) {
        if ($Key.StartsWith($r.Prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            if ($r.Prefix.Length -gt $bestLen) { $best = $r; $bestLen = $r.Prefix.Length }
        }
    }
    if ($best) {
        return [pscustomobject]@{ Url = $best.Url; Label = $best.Label; Source = 'CSP map'; Confidence = 'Known area' }
    }
    return [pscustomobject]@{
        Url = $script:MsReferenceGeneric.Url; Label = $script:MsReferenceGeneric.Label
        Source = 'Generic'; Confidence = 'Fallback'
    }
}

# ---- User rights descriptions ----------------------------------------------
# Used to render GptTmpl.inf [Privilege Rights] in language a non-specialist
# can follow, which is the whole point of the Outline series.
$script:PrivilegeNames = @{
    'SeTrustedCredManAccessPrivilege'      = 'Access Credential Manager as a trusted caller'
    'SeNetworkLogonRight'                  = 'Access this computer from the network'
    'SeTcbPrivilege'                       = 'Act as part of the operating system'
    'SeMachineAccountPrivilege'            = 'Add workstations to domain'
    'SeIncreaseQuotaPrivilege'             = 'Adjust memory quotas for a process'
    'SeInteractiveLogonRight'              = 'Allow log on locally'
    'SeRemoteInteractiveLogonRight'        = 'Allow log on through Remote Desktop Services'
    'SeBackupPrivilege'                    = 'Back up files and directories'
    'SeChangeNotifyPrivilege'              = 'Bypass traverse checking'
    'SeSystemtimePrivilege'                = 'Change the system time'
    'SeTimeZonePrivilege'                  = 'Change the time zone'
    'SeCreatePagefilePrivilege'            = 'Create a pagefile'
    'SeCreateTokenPrivilege'               = 'Create a token object'
    'SeCreateGlobalPrivilege'              = 'Create global objects'
    'SeCreatePermanentPrivilege'           = 'Create permanent shared objects'
    'SeCreateSymbolicLinkPrivilege'        = 'Create symbolic links'
    'SeDebugPrivilege'                     = 'Debug programs'
    'SeDenyNetworkLogonRight'              = 'Deny access to this computer from the network'
    'SeDenyBatchLogonRight'                = 'Deny log on as a batch job'
    'SeDenyServiceLogonRight'              = 'Deny log on as a service'
    'SeDenyInteractiveLogonRight'          = 'Deny log on locally'
    'SeDenyRemoteInteractiveLogonRight'    = 'Deny log on through Remote Desktop Services'
    'SeEnableDelegationPrivilege'          = 'Enable computer and user accounts to be trusted for delegation'
    'SeRemoteShutdownPrivilege'            = 'Force shutdown from a remote system'
    'SeAuditPrivilege'                     = 'Generate security audits'
    'SeImpersonatePrivilege'               = 'Impersonate a client after authentication'
    'SeIncreaseWorkingSetPrivilege'        = 'Increase a process working set'
    'SeIncreaseBasePriorityPrivilege'      = 'Increase scheduling priority'
    'SeLoadDriverPrivilege'                = 'Load and unload device drivers'
    'SeLockMemoryPrivilege'                = 'Lock pages in memory'
    'SeBatchLogonRight'                    = 'Log on as a batch job'
    'SeServiceLogonRight'                  = 'Log on as a service'
    'SeSecurityPrivilege'                  = 'Manage auditing and security log'
    'SeRelabelPrivilege'                   = 'Modify an object label'
    'SeSystemEnvironmentPrivilege'         = 'Modify firmware environment values'
    'SeDelegateSessionUserImpersonatePrivilege' = 'Obtain an impersonation token for another user'
    'SeManageVolumePrivilege'              = 'Perform volume maintenance tasks'
    'SeProfileSingleProcessPrivilege'      = 'Profile single process'
    'SeSystemProfilePrivilege'             = 'Profile system performance'
    'SeUndockPrivilege'                    = 'Remove computer from docking station'
    'SeAssignPrimaryTokenPrivilege'        = 'Replace a process level token'
    'SeRestorePrivilege'                   = 'Restore files and directories'
    'SeShutdownPrivilege'                  = 'Shut down the system'
    'SeSyncAgentPrivilege'                 = 'Synchronize directory service data'
    'SeTakeOwnershipPrivilege'             = 'Take ownership of files or other objects'
}

# ---- Glossary ---------------------------------------------------------------
# Rendered as a report section. The Outline series is written for a reader who
# is not a Group Policy specialist, so the vocabulary is defined in the document
# rather than assumed.
# ---- Group Policy Preferences item-level targeting ---------------------------
# Item-level targeting (the "Common" tab, stored as <Filters> under each
# preference item) decides whether an individual item applies. It is as decisive
# as a WMI filter and far more common, so it is rendered in plain English rather
# than left as raw XML.
#
# Element name -> a function of the node's attributes producing a readable
# clause. Anything not listed still renders, using its attributes verbatim, so
# an unrecognised filter type is never silently dropped.
# ---- Schema objectVersion -> OS generation -----------------------------------
# Stated as a fact about what the schema currently is. No upgrade advice: what
# an estate should run is an assessment question, not a documentation one.
$script:SchemaVersionName = @{
    13 = 'Windows 2000 Server'; 30 = 'Windows Server 2003'; 31 = 'Windows Server 2003 R2'
    44 = 'Windows Server 2008'; 47 = 'Windows Server 2008 R2'; 56 = 'Windows Server 2012'
    69 = 'Windows Server 2012 R2'; 87 = 'Windows Server 2016'; 88 = 'Windows Server 2019 / 2022'
    91 = 'Windows Server 2025'
}
function Get-SchemaVersionName {
    param($Version)
    if ($null -eq $Version -or "$Version" -eq '') { return 'not read' }
    $v = 0
    if (-not [int]::TryParse("$Version", [ref]$v)) { return "$Version" }
    if ($script:SchemaVersionName.ContainsKey($v)) { return "$v ($($script:SchemaVersionName[$v]))" }
    return "$v (generation not in this script's table)"
}

$script:GppFilterLabel = @{
    'FilterGroup'         = 'Security group'
    'FilterUser'          = 'User'
    'FilterComputer'      = 'Computer name'
    'FilterOs'            = 'Operating system'
    'FilterOrgUnit'       = 'Organizational unit'
    'FilterSite'          = 'AD site'
    'FilterDomain'        = 'Domain'
    'FilterIpRange'       = 'IP address range'
    'FilterMacRange'      = 'MAC address range'
    'FilterPortable'      = 'Portable computer'
    'FilterTerminal'      = 'Terminal session'
    'FilterWmi'           = 'WMI query'
    'FilterLdap'          = 'LDAP query'
    'FilterRegistry'      = 'Registry match'
    'FilterFile'          = 'File match'
    'FilterEnvironment'   = 'Environment variable'
    'FilterLanguage'      = 'Language'
    'FilterTime'          = 'Time range'
    'FilterDate'          = 'Date range'
    'FilterProcessing'    = 'Processing mode'
    'FilterRunOnce'       = 'Run once'
    'FilterCollection'    = 'Group of conditions'
    'FilterBattery'       = 'Battery present'
    'FilterCpuSpeed'      = 'CPU speed'
    'FilterDiskSpace'     = 'Free disk space'
    'FilterDialUp'        = 'Dial-up connection'
    'FilterPcmcia'        = 'PCMCIA present'
    'FilterRam'           = 'RAM'
    'FilterOperatingSystem' = 'Operating system'
    'FilterSecurityGroup' = 'Security group'
}

function ConvertTo-GppFilterText {
    <#
      Renders one <Filters> child as a readable clause.

      Two attributes are common to every filter type and both invert meaning, so
      they are handled generically rather than per type:
        not="1"  -> the condition is negated
        bool     -> AND / OR joining it to the previous condition
    #>
    param($Node)
    if (-not $Node) { return $null }

    $label = $script:GppFilterLabel[$Node.LocalName]
    if (-not $label) { $label = ($Node.LocalName -replace '^Filter', '') }

    $neg  = $false
    $join = $null
    $parts = New-Object System.Collections.Generic.List[string]

    if ($Node.Attributes) {
        foreach ($a in $Node.Attributes) {
            switch ($a.Name) {
                'not'  { if ($a.Value -eq '1' -or $a.Value -eq 'true') { $neg = $true }; continue }
                'bool' { $join = $a.Value.ToUpperInvariant(); continue }
                'hidden' { continue }
                default {
                    if ([string]::IsNullOrEmpty($a.Value)) { continue }
                    if ($a.Value.Length -gt 300) { continue }
                    $parts.Add("$($a.Name)=$($a.Value)")
                }
            }
        }
    }

    $text = $label
    if ($parts.Count -gt 0) { $text += ' (' + ($parts.ToArray() -join ', ') + ')' }
    if ($neg) { $text = "NOT $text" }
    return [pscustomobject]@{ Text = $text; Join = $join; Type = $Node.LocalName }
}

function ConvertFrom-GppFilters {
    <#
      Walks the <Filters> block of one preference item and returns both the
      readable clause list and a single joined sentence.

      The join operator lives on the FOLLOWING sibling in GPP's schema, not the
      preceding one, which is why the operator is read from each node and
      applied before it rather than after.
    #>
    param($ItemNode)
    if (-not $ItemNode) { return ,@() }

    $filtersNode = $null
    try {
        $filtersNode = $ItemNode.SelectSingleNode('./Filters')
        if (-not $filtersNode) { $filtersNode = $ItemNode.SelectSingleNode('./*[local-name()="Filters"]') }
    } catch { }
    if (-not $filtersNode) { return ,@() }

    $out = New-Object System.Collections.Generic.List[object]
    foreach ($child in @($filtersNode.ChildNodes)) {
        if (-not $child -or $child.NodeType -ne 'Element') { continue }
        $f = ConvertTo-GppFilterText -Node $child
        if ($f) { $out.Add($f) }
    }
    return ,$out.ToArray()
}

function Format-GppFilterSentence {
    <# Joins the clause list into one line, honouring each clause's AND/OR. #>
    param($Filters)
    $f = @($Filters)
    if ($f.Count -eq 0) { return $null }
    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $f.Count; $i++) {
        if ($i -gt 0) {
            $op = if ($f[$i].Join) { $f[$i].Join } else { 'AND' }
            [void]$sb.Append(" $op ")
        }
        [void]$sb.Append($f[$i].Text)
    }
    return $sb.ToString()
}

$script:Glossary = [ordered]@{
    'Block Inheritance' = 'A setting on an OU (or domain) that stops policies from higher containers being inherited. Enforced links are the exception and still apply.'
    'Client-Side Extension (CSE)' = 'The component on a Windows machine that actually applies one category of policy -- registry settings, security settings, drive maps and so on. The list of CSEs recorded on a GPO tells you which categories it contains.'
    'cpassword' = 'An obfuscated password that could be stored in a Group Policy Preferences item. The key used to obfuscate it was published by Microsoft, so any stored value is recoverable by anyone who can read SYSVOL. GPOOutline records only that one is present, never the value.'
    'Enforced' = 'A link setting (formerly "No Override") that makes a GPO win over policies applied later in the order, and makes it immune to Block Inheritance.'
    'GPC' = 'Group Policy Container -- the directory half of a GPO, holding its name, version, links, filtering and permissions.'
    'GPT' = 'Group Policy Template -- the SYSVOL half of a GPO, holding the actual settings as files.'
    'Group Policy Preferences (GPP)' = 'A second settings mechanism alongside policy proper. Preference items are generally not reverted when the GPO stops applying.'
    'Link Order' = 'The order of GPOs linked to one container. A lower number wins: link order 1 is applied last and therefore takes precedence.'
    'Loopback' = 'A mode where a user''s settings are taken from the computer''s policies instead of (Replace) or in addition to (Merge) the user''s own. It is the most common reason a policy appears to apply where a reader does not expect it.'
    'LSDOU' = 'The order policies are applied: Local, then Site, then Domain, then each OU from the top down. Later application wins, so the closest OU normally has the final say.'
    'Orphaned GPO' = 'A GPO that exists but is not linked to any site, domain or OU, so it does not apply anywhere.'
    'Security Filtering' = 'Restricting a GPO to particular users, computers or groups by granting them both Read and Apply Group Policy.'
    'SOM' = 'Scope of Management -- the set of containers a GPO is linked to.'
    'SYSVOL' = 'The replicated share on every domain controller that holds policy files. Replicated by DFSR on current domains, or by the older FRS on ones that never migrated.'
    'Tattooing' = 'When a setting written by a GPO stays behind after the GPO no longer applies, because nothing reverts it. Preference items and non-managed registry writes behave this way.'
    'Version Mismatch' = 'The GPO version recorded in the directory and the version recorded in SYSVOL disagree, which normally means replication has not finished converging.'
    'WMI Filter' = 'A query evaluated on the target machine. If it returns nothing, the GPO does not apply to that machine, whatever the links and filtering say.'
}

# ==============================================================================
# PARSERS
#
# Everything below reads bytes and text that Windows already exposes. No parser
# writes anything, and every one of them reports failure rather than throwing:
# a single corrupt policy file in one GPO must never end a forest-wide run.
# ==============================================================================

# ------------------------------------------------------------------------------
# registry.pol  (PReg binary format, MS-GPREG)
#
# This is the one component the GroupPolicy module was hiding, so it was built
# and unit-tested standalone before anything else depended on it.
#
#   "PReg" (4 bytes) + version 1 (4 bytes, little-endian)
#   then records: [ key\0 ; value\0 ; type(4 LE) ; size(4 LE) ; data(size) ]
#   where [ ; ] are literal UTF-16LE characters and strings are UTF-16LE,
#   null-terminated.
#
# The size field is authoritative. Data may legitimately contain the code units
# for ';' and ']', so a parser that splits on delimiters corrupts those records
# -- every read here is length-driven.
# ------------------------------------------------------------------------------

$script:PRegTypeName = @{
    0  = 'REG_NONE';               1  = 'REG_SZ';        2  = 'REG_EXPAND_SZ'
    3  = 'REG_BINARY';             4  = 'REG_DWORD';     5  = 'REG_DWORD_BIG_ENDIAN'
    6  = 'REG_LINK';               7  = 'REG_MULTI_SZ'; 11 = 'REG_QWORD'
}

function Get-PRegTypeName {
    param([int]$Type)
    if ($script:PRegTypeName.ContainsKey($Type)) { return $script:PRegTypeName[$Type] }
    return "REG_TYPE_$Type"
}

function Read-PRegString {
    <#
      Reference implementation of the null-terminated UTF-16LE string read.
      Exercised directly by the unit tests. The hot loop in
      ConvertFrom-PRegBytes inlines this same logic for speed; the two must
      stay in agreement.
    #>
    param(
        [Parameter(Mandatory)][byte[]]$B,
        [Parameter(Mandatory)][int]$Start,
        [Parameter(Mandatory)][ref]$Next
    )
    $i = $Start
    $end = $B.Length - 1
    while ($i -lt $end) {
        if ($B[$i] -eq 0 -and $B[$i + 1] -eq 0) {
            $len = $i - $Start
            $Next.Value = $i + 2
            if ($len -le 0) { return '' }
            return [System.Text.Encoding]::Unicode.GetString($B, $Start, $len)
        }
        $i += 2
    }
    $Next.Value = $B.Length
    return $null
}

function Test-PRegDelimiter {
    param([byte[]]$B, [int]$Pos, [char]$Char)
    if ($Pos + 1 -ge $B.Length) { return $false }
    return ($B[$Pos] -eq [byte][int]$Char -and $B[$Pos + 1] -eq 0)
}

function ConvertTo-PRegData {
    <#
      Renders raw data bytes per the registry type. Binary output is capped so
      a single large blob cannot dominate the report; truncation is stated.
    #>
    param([byte[]]$B, [int]$Start, [int]$Size, [int]$Type, [int]$MaxBinaryBytes = 64)

    if ($Size -le 0) { return [pscustomobject]@{ Display = ''; Native = $null } }

    switch ($Type) {
        1 {
            $s = [System.Text.Encoding]::Unicode.GetString($B, $Start, $Size).TrimEnd([char]0)
            return [pscustomobject]@{ Display = $s; Native = $s }
        }
        2 {
            $s = [System.Text.Encoding]::Unicode.GetString($B, $Start, $Size).TrimEnd([char]0)
            return [pscustomobject]@{ Display = $s; Native = $s }
        }
        7 {   # REG_MULTI_SZ -- double-null terminated block of null-terminated strings
            $s = [System.Text.Encoding]::Unicode.GetString($B, $Start, $Size)
            $parts = @($s -split "`0" | Where-Object { $_ -ne '' })
            return [pscustomobject]@{ Display = ($parts -join '; '); Native = $parts }
        }
        4 {
            if ($Size -lt 4) { return [pscustomobject]@{ Display = '(short DWORD)'; Native = $null } }
            $v = [System.BitConverter]::ToUInt32($B, $Start)
            return [pscustomobject]@{ Display = "$v"; Native = $v }
        }
        5 {   # big-endian DWORD
            if ($Size -lt 4) { return [pscustomobject]@{ Display = '(short DWORD)'; Native = $null } }
            $v = ([uint32]$B[$Start] -shl 24) -bor ([uint32]$B[$Start + 1] -shl 16) -bor
                 ([uint32]$B[$Start + 2] -shl 8) -bor [uint32]$B[$Start + 3]
            return [pscustomobject]@{ Display = "$v"; Native = $v }
        }
        11 {
            if ($Size -lt 8) { return [pscustomobject]@{ Display = '(short QWORD)'; Native = $null } }
            $v = [System.BitConverter]::ToUInt64($B, $Start)
            return [pscustomobject]@{ Display = "$v"; Native = $v }
        }
        default {
            $take = [Math]::Min($Size, $MaxBinaryBytes)
            $sb = New-Object System.Text.StringBuilder
            for ($i = 0; $i -lt $take; $i++) {
                if ($i -gt 0) { [void]$sb.Append(' ') }
                [void]$sb.Append($B[$Start + $i].ToString('x2'))
            }
            if ($take -lt $Size) { [void]$sb.Append(" ... ($Size bytes)") }
            return [pscustomobject]@{ Display = $sb.ToString(); Native = $null }
        }
    }
}

function Resolve-PRegDirective {
    <#
      Normalises the documented **directives into a target plus a plain-English
      description, so the report never shows a reader a literal "**del.Foo" and
      calls it a setting. Returns $null for an ordinary value.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$ValueName, $DataDisplay)

    if (-not $ValueName.StartsWith('**')) { return $null }

    # Order matters: **delvals must be tested before **del.
    if ($ValueName -match '^\*\*delvals\.?$')  { return [pscustomobject]@{ Target = '';            Directive = 'Delete all values in key' } }
    if ($ValueName -match '^\*\*del\.(.*)$')   { return [pscustomobject]@{ Target = $Matches[1];   Directive = 'Delete value' } }
    if ($ValueName -match '^\*\*soft\.(.*)$')  { return [pscustomobject]@{ Target = $Matches[1];   Directive = 'Set only if not already present' } }
    if ($ValueName -match '^\*\*DeleteValues$'){ return [pscustomobject]@{ Target = "$DataDisplay"; Directive = 'Delete listed values' } }
    if ($ValueName -match '^\*\*DeleteKeys$')  { return [pscustomobject]@{ Target = "$DataDisplay"; Directive = 'Delete subkeys' } }
    if ($ValueName -match '^\*\*SecureKey$')   { return [pscustomobject]@{ Target = $ValueName;    Directive = 'Key security' } }
    if ($ValueName -match '^\*\*DeletePolicy$'){ return [pscustomobject]@{ Target = $ValueName;    Directive = 'Delete policy' } }
    return [pscustomobject]@{ Target = $ValueName; Directive = 'Directive' }
}

function ConvertFrom-PRegBytes {
    <#
      Decodes a registry.pol byte array into setting records. Never throws on
      malformed input.

      Returns: Valid, Records, Truncated, Reason, ByteCount, Capped.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes,
        [ValidateSet('HKLM', 'HKCU')][string]$Hive = 'HKLM',
        [int]$MaxRecords = 20000
    )

    $out = [ordered]@{
        Valid = $false; Records = @(); Truncated = $false
        Reason = $null; ByteCount = $Bytes.Length; Capped = $false
    }

    if ($Bytes.Length -lt 8) {
        $out.Reason = 'File is shorter than the 8-byte PReg header.'
        return [pscustomobject]$out
    }
    if (-not ($Bytes[0] -eq 0x50 -and $Bytes[1] -eq 0x52 -and $Bytes[2] -eq 0x65 -and $Bytes[3] -eq 0x67)) {
        $out.Reason = 'Signature is not "PReg" -- not a registry.pol file.'
        return [pscustomobject]$out
    }
    $ver = [System.BitConverter]::ToUInt32($Bytes, 4)
    if ($ver -ne 1) {
        $out.Reason = "Unexpected PReg version $ver (expected 1)."
        return [pscustomobject]$out
    }

    $out.Valid = $true
    $recs = New-Object System.Collections.Generic.List[object]
    $pos  = 8
    $len  = $Bytes.Length

    # ------------------------------------------------------------------
    # HOT LOOP -- deliberately inlined.
    #
    # The helpers above are the readable reference implementation and are
    # exercised directly by the unit tests. They are NOT called per record:
    # measured on PowerShell 7, the call layer alone cost ~1 ms per value,
    # which is 5.4 s for one 5,000-value GPO and hours across a large forest.
    # Inlined byte arithmetic decodes the same file in 0.3 s. Any change here
    # must keep the two implementations in agreement.
    # ------------------------------------------------------------------
    while ($pos -lt $len) {

        if ($recs.Count -ge $MaxRecords) {
            $out.Capped = $true
            $out.Reason = "Stopped after $MaxRecords values (cap reached)."
            break
        }

        # '[' 0x5B
        if ($pos + 1 -ge $len -or $Bytes[$pos] -ne 0x5B -or $Bytes[$pos + 1] -ne 0) {
            # Trailing null padding is common and benign; anything else is a
            # real malformation and is reported rather than swallowed.
            $allZero = $true
            for ($z = $pos; $z -lt $len; $z++) { if ($Bytes[$z] -ne 0) { $allZero = $false; break } }
            if (-not $allZero) {
                $out.Truncated = $true
                $out.Reason = "Record does not begin with '[' at byte $pos ($($len - $pos) bytes remaining)."
            }
            break
        }
        $pos += 2

        # ---- key ----
        $s = $pos
        while ($pos + 1 -lt $len -and -not ($Bytes[$pos] -eq 0 -and $Bytes[$pos + 1] -eq 0)) { $pos += 2 }
        if ($pos + 1 -ge $len) { $out.Truncated = $true; $out.Reason = "Unterminated key at byte $s."; break }
        $key = if ($pos -gt $s) { [System.Text.Encoding]::Unicode.GetString($Bytes, $s, $pos - $s) } else { '' }
        $pos += 2
        if ($pos + 1 -ge $len -or $Bytes[$pos] -ne 0x3B -or $Bytes[$pos + 1] -ne 0) { $out.Truncated = $true; $out.Reason = "Missing ';' after key at byte $pos."; break }
        $pos += 2

        # ---- value name ----
        $s = $pos
        while ($pos + 1 -lt $len -and -not ($Bytes[$pos] -eq 0 -and $Bytes[$pos + 1] -eq 0)) { $pos += 2 }
        if ($pos + 1 -ge $len) { $out.Truncated = $true; $out.Reason = "Unterminated value name at byte $s."; break }
        $valueName = if ($pos -gt $s) { [System.Text.Encoding]::Unicode.GetString($Bytes, $s, $pos - $s) } else { '' }
        $pos += 2
        if ($pos + 1 -ge $len -or $Bytes[$pos] -ne 0x3B -or $Bytes[$pos + 1] -ne 0) { $out.Truncated = $true; $out.Reason = "Missing ';' after value name at byte $pos."; break }
        $pos += 2

        # ---- type ----
        if ($pos + 4 -gt $len) { $out.Truncated = $true; $out.Reason = "Type field runs past end of file at byte $pos."; break }
        $type = [int][System.BitConverter]::ToUInt32($Bytes, $pos)
        $pos += 4
        if ($pos + 1 -ge $len -or $Bytes[$pos] -ne 0x3B -or $Bytes[$pos + 1] -ne 0) { $out.Truncated = $true; $out.Reason = "Missing ';' after type at byte $pos."; break }
        $pos += 2

        # ---- size ----
        if ($pos + 4 -gt $len) { $out.Truncated = $true; $out.Reason = "Size field runs past end of file at byte $pos."; break }
        $size = [int][System.BitConverter]::ToUInt32($Bytes, $pos)
        $pos += 4
        if ($pos + 1 -ge $len -or $Bytes[$pos] -ne 0x3B -or $Bytes[$pos + 1] -ne 0) { $out.Truncated = $true; $out.Reason = "Missing ';' after size at byte $pos."; break }
        $pos += 2

        if ($size -lt 0 -or $pos + $size -gt $len) {
            $out.Truncated = $true
            $out.Reason = "Declared data size $size at byte $pos runs past end of file."
            break
        }

        # ---- data: the two dominant types inline, the rest via the helper ----
        $disp = ''; $native = $null
        if ($size -gt 0) {
            if ($type -eq 4 -and $size -ge 4) {
                $native = [System.BitConverter]::ToUInt32($Bytes, $pos)
                $disp   = "$native"
            }
            elseif ($type -eq 1 -or $type -eq 2) {
                $disp   = [System.Text.Encoding]::Unicode.GetString($Bytes, $pos, $size).TrimEnd([char]0)
                $native = $disp
            }
            else {
                $d = ConvertTo-PRegData -B $Bytes -Start $pos -Size $size -Type $type
                $disp = $d.Display; $native = $d.Native
            }
        }
        $pos += $size

        # ']' 0x5D
        if ($pos + 1 -ge $len -or $Bytes[$pos] -ne 0x5D -or $Bytes[$pos + 1] -ne 0) { $out.Truncated = $true; $out.Reason = "Missing ']' closing record at byte $pos."; break }
        $pos += 2

        $tn = if ($script:PRegTypeName.ContainsKey($type)) { $script:PRegTypeName[$type] } else { "REG_TYPE_$type" }

        # A two-character test keeps the regex-based directive resolver off the
        # path for ordinary values, which are the overwhelming majority.
        if ($valueName.Length -gt 1 -and $valueName[0] -eq '*' -and $valueName[1] -eq '*') {
            $dir = Resolve-PRegDirective -ValueName $valueName -DataDisplay $disp
            $recs.Add([pscustomobject]@{
                Hive = $Hive; Key = $key; Value = $dir.Target; Type = $tn; TypeId = $type
                Data = ''; Native = $null; Directive = $dir.Directive; RawValue = $valueName
            })
        }
        else {
            $recs.Add([pscustomobject]@{
                Hive = $Hive; Key = $key; Value = $valueName; Type = $tn; TypeId = $type
                Data = $disp; Native = $native; Directive = $null; RawValue = $valueName
            })
        }
    }

    $out.Records = $recs.ToArray()
    return [pscustomobject]$out
}

function ConvertFrom-PRegFile {
    <# File wrapper. Read-only; failure is reported, never thrown. #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateSet('HKLM', 'HKCU')][string]$Hive = 'HKLM',
        [int]$MaxRecords = 20000
    )
    try { $bytes = [System.IO.File]::ReadAllBytes($Path) }
    catch {
        return [pscustomobject]@{
            Valid = $false; Records = @(); Truncated = $false
            Reason = "Unreadable: $($_.Exception.Message)"; ByteCount = 0; Capped = $false
        }
    }
    return ConvertFrom-PRegBytes -Bytes $bytes -Hive $Hive -MaxRecords $MaxRecords
}

# ------------------------------------------------------------------------------
# INI files: GPT.INI, GptTmpl.inf, scripts.ini, psscripts.ini, fdeploy.ini
# ------------------------------------------------------------------------------

function ConvertFrom-OutlineIni {
    <#
      Section -> key -> value.

      Duplicate keys within a section are kept by appending an index, because
      GptTmpl.inf legitimately repeats keys in some sections and a naive
      last-one-wins read silently discards real configuration.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Content)

    $out = [ordered]@{}
    $section = $null
    foreach ($line in ($Content -split "`r?`n")) {
        $t = $line.Trim()
        if (-not $t -or $t.StartsWith(';') -or $t.StartsWith('#')) { continue }
        if ($t -match '^\[(.+)\]$') {
            $section = $Matches[1]
            if (-not $out.Contains($section)) { $out[$section] = [ordered]@{} }
            continue
        }
        if (-not $section) { continue }
        $eq = $t.IndexOf('=')
        if ($eq -lt 1) { continue }
        $k = $t.Substring(0, $eq).Trim()
        $v = $t.Substring($eq + 1).Trim()
        if ($out[$section].Contains($k)) {
            $n = 2
            while ($out[$section].Contains("$k~$n")) { $n++ }
            $out[$section]["$k~$n"] = $v
        }
        else { $out[$section][$k] = $v }
    }
    return $out
}

function Get-IniBaseKey {
    <# Strips the ~N suffix added for duplicate keys. #>
    param([string]$Key)
    if ($Key -match '^(.*)~\d+$') { return $Matches[1] }
    return $Key
}

# ------------------------------------------------------------------------------
# GptTmpl.inf -- the security half of a GPO
# ------------------------------------------------------------------------------

# Section -> reportable area. Anything not listed is still captured, under a
# generic label, so a section this table does not know about is never lost.
$script:GptTmplAreas = [ordered]@{
    'System Access'          = 'Account Policy'
    'Kerberos Policy'        = 'Account Policy'
    'Privilege Rights'       = 'User Rights Assignment'
    'Registry Values'        = 'Security Options'
    'Event Audit'            = 'Audit Policy'
    'Group Membership'       = 'Restricted Groups'
    'Service General Setting'= 'System Services'
    'Registry Keys'          = 'Registry ACLs'
    'File Security'          = 'File System ACLs'
    'Version'                = 'Template Metadata'
    'Unicode'                = 'Template Metadata'
}

# [System Access] keys rendered in plain English.
$script:SystemAccessNames = @{
    'MinimumPasswordAge'      = 'Minimum password age (days)'
    'MaximumPasswordAge'      = 'Maximum password age (days)'
    'MinimumPasswordLength'   = 'Minimum password length'
    'PasswordComplexity'      = 'Password must meet complexity requirements'
    'PasswordHistorySize'     = 'Enforce password history (passwords remembered)'
    'LockoutBadCount'         = 'Account lockout threshold (invalid attempts)'
    'ResetLockoutCount'       = 'Reset account lockout counter after (minutes)'
    'LockoutDuration'         = 'Account lockout duration (minutes)'
    'RequireLogonToChangePassword' = 'Require logon to change password'
    'ForceLogoffWhenHourExpire'    = 'Force logoff when logon hours expire'
    'ClearTextPassword'       = 'Store passwords using reversible encryption'
    'NewAdministratorName'    = 'Rename administrator account'
    'NewGuestName'            = 'Rename guest account'
    'EnableAdminAccount'      = 'Administrator account status'
    'EnableGuestAccount'      = 'Guest account status'
    'LSAAnonymousNameLookup'  = 'Allow anonymous SID/name translation'
}

$script:KerberosNames = @{
    'MaxTicketAge'        = 'Maximum lifetime for user ticket (hours)'
    'MaxRenewAge'         = 'Maximum lifetime for user ticket renewal (days)'
    'MaxServiceAge'       = 'Maximum lifetime for service ticket (minutes)'
    'MaxClockSkew'        = 'Maximum tolerance for computer clock synchronization (minutes)'
    'TicketValidateClient'= 'Enforce user logon restrictions'
}

$script:EventAuditNames = @{
    'AuditSystemEvents'     = 'Audit system events'
    'AuditLogonEvents'      = 'Audit logon events'
    'AuditObjectAccess'     = 'Audit object access'
    'AuditPrivilegeUse'     = 'Audit privilege use'
    'AuditPolicyChange'     = 'Audit policy change'
    'AuditAccountManage'    = 'Audit account management'
    'AuditProcessTracking'  = 'Audit process tracking'
    'AuditDSAccess'         = 'Audit directory service access'
    'AuditAccountLogon'     = 'Audit account logon events'
}

function ConvertFrom-AuditValue {
    param($Value)
    switch ("$Value") {
        '0' { return 'No auditing' }
        '1' { return 'Success' }
        '2' { return 'Failure' }
        '3' { return 'Success and Failure' }
        default { return "$Value" }
    }
}

function ConvertFrom-GptTmpl {
    <#
      Turns GptTmpl.inf into a flat list of readable settings, each tagged with
      the area it belongs to. Values are rendered in plain English where the
      meaning is otherwise unrecoverable by a non-specialist -- "-1" for a
      lockout duration means "until an administrator unlocks it", and a reader
      should not have to know that.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Content)

    $ini  = ConvertFrom-OutlineIni -Content $Content
    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($sec in $ini.PSBase.Keys) {
        $area = if ($script:GptTmplAreas.Contains($sec)) { $script:GptTmplAreas[$sec] } else { "Security Settings ($sec)" }
        if ($area -eq 'Template Metadata') { continue }

        foreach ($rawKey in $ini[$sec].PSBase.Keys) {
            $key = Get-IniBaseKey $rawKey
            $val = $ini[$sec][$rawKey]

            switch ($sec) {

                'System Access' {
                    $name = if ($script:SystemAccessNames.ContainsKey($key)) { $script:SystemAccessNames[$key] } else { $key }
                    $disp = "$val"
                    # Account policy encodes "never" and "forever" as sentinels.
                    if ($key -eq 'MaximumPasswordAge' -and "$val" -eq '-1') { $disp = 'Never expires' }
                    if ($key -eq 'LockoutDuration'   -and "$val" -eq '-1') { $disp = 'Until an administrator unlocks the account' }
                    if ($key -in @('PasswordComplexity','ClearTextPassword','RequireLogonToChangePassword','ForceLogoffWhenHourExpire','LSAAnonymousNameLookup')) {
                        $disp = if ("$val" -eq '1') { 'Enabled' } elseif ("$val" -eq '0') { 'Disabled' } else { "$val" }
                    }
                    if ($key -in @('EnableAdminAccount','EnableGuestAccount')) {
                        $disp = if ("$val" -eq '1') { 'Enabled' } elseif ("$val" -eq '0') { 'Disabled' } else { "$val" }
                    }
                    $rows.Add([pscustomobject]@{ Area = $area; Section = $sec; Name = $name; Setting = $key; Value = $disp; Raw = "$val" })
                }

                'Kerberos Policy' {
                    $name = if ($script:KerberosNames.ContainsKey($key)) { $script:KerberosNames[$key] } else { $key }
                    $rows.Add([pscustomobject]@{ Area = $area; Section = $sec; Name = $name; Setting = $key; Value = "$val"; Raw = "$val" })
                }

                'Event Audit' {
                    $name = if ($script:EventAuditNames.ContainsKey($key)) { $script:EventAuditNames[$key] } else { $key }
                    $rows.Add([pscustomobject]@{ Area = $area; Section = $sec; Name = $name; Setting = $key; Value = (ConvertFrom-AuditValue $val); Raw = "$val" })
                }

                'Privilege Rights' {
                    $name = if ($script:PrivilegeNames.ContainsKey($key)) { $script:PrivilegeNames[$key] } else { $key }
                    $members = @(($val -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                    $named = @($members | ForEach-Object {
                        $r = Resolve-OutlineSid $_
                        if ($r) { $r.Name } else { $_ }
                    })
                    $rows.Add([pscustomobject]@{
                        Area = $area; Section = $sec; Name = $name; Setting = $key
                        Value = $(if ($named.Count -eq 0) { '(no one)' } else { $named -join ', ' })
                        Raw = "$val"; MemberCount = $named.Count
                    })
                }

                'Registry Values' {
                    # Format: <registry path>=<type>,<value>
                    $parts = "$val" -split ',', 2
                    $disp  = if ($parts.Count -eq 2) { $parts[1] } else { "$val" }
                    $rows.Add([pscustomobject]@{
                        Area = 'Security Options'; Section = $sec
                        Name = $key; Setting = $key; Value = $disp; Raw = "$val"
                    })
                }

                'Group Membership' {
                    # <group>__Members / <group>__Memberof
                    $g = $key -replace '__(Members|Memberof)$', ''
                    $kind = if ($key -match '__Memberof$') { 'is a member of' } else { 'members' }
                    $gn = (Resolve-OutlineSid $g)
                    $gname = if ($gn) { $gn.Name } else { $g }
                    $members = @(($val -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ } |
                                 ForEach-Object { $r = Resolve-OutlineSid $_; if ($r) { $r.Name } else { $_ } })
                    $rows.Add([pscustomobject]@{
                        Area = $area; Section = $sec
                        Name = "$gname -- $kind"; Setting = $key
                        Value = $(if ($members.Count -eq 0) { '(none -- membership is emptied)' } else { $members -join ', ' })
                        Raw = "$val"
                    })
                }

                'Service General Setting' {
                    # <service>,<startup>,<sddl>
                    $parts = "$val" -split ',', 3
                    $mode  = switch ("$($parts[0])") { '2' { 'Automatic' } '3' { 'Manual' } '4' { 'Disabled' } default { "$($parts[0])" } }
                    $rows.Add([pscustomobject]@{
                        Area = $area; Section = $sec; Name = $key; Setting = $key
                        Value = "Startup: $mode"; Raw = "$val"
                    })
                }

                default {
                    $rows.Add([pscustomobject]@{ Area = $area; Section = $sec; Name = $key; Setting = $key; Value = "$val"; Raw = "$val" })
                }
            }
        }
    }

    return ,$rows.ToArray()
}

# ------------------------------------------------------------------------------
# scripts.ini / psscripts.ini
# ------------------------------------------------------------------------------

function ConvertFrom-ScriptsIni {
    <#
      [Startup] / [Shutdown] / [Logon] / [Logoff] sections with indexed
      CmdLine/Parameters pairs:  0CmdLine=..., 0Parameters=...
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Content, [string]$Engine = 'Command')

    $ini  = ConvertFrom-OutlineIni -Content $Content
    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($sec in $ini.PSBase.Keys) {
        $bag = @{}
        foreach ($rawKey in $ini[$sec].PSBase.Keys) {
            $k = Get-IniBaseKey $rawKey
            if ($k -match '^(\d+)(CmdLine|Parameters)$') {
                $idx = [int]$Matches[1]; $which = $Matches[2]
                if (-not $bag.ContainsKey($idx)) { $bag[$idx] = @{ CmdLine = ''; Parameters = '' } }
                $bag[$idx][$which] = $ini[$sec][$rawKey]
            }
        }
        foreach ($idx in ($bag.Keys | Sort-Object)) {
            if (-not $bag[$idx].CmdLine) { continue }
            $rows.Add([pscustomobject]@{
                Trigger    = $sec
                Order      = $idx
                Engine     = $Engine
                Script     = $bag[$idx].CmdLine
                Parameters = $bag[$idx].Parameters
            })
        }
    }
    return ,$rows.ToArray()
}

# ------------------------------------------------------------------------------
# fdeploy.ini -- folder redirection
# ------------------------------------------------------------------------------

$script:FolderRedirectionGuids = @{
    '{FDD39AD0-238F-46AF-ADB4-6C85480369C7}' = 'Documents'
    '{33E28130-4E1E-4676-835A-98395C3BC3BB}' = 'Pictures'
    '{4BD8D571-6D19-48D3-BE97-422220080E43}' = 'Music'
    '{18989B1D-99B5-455B-841C-AB7C74E4DDFC}' = 'Videos'
    '{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}' = 'Desktop'
    '{1777F761-68AD-4D8A-87BD-30B759FA33DD}' = 'Favorites'
    '{56784854-C6CB-462B-8169-88E350ACB882}' = 'Contacts'
    '{374DE290-123F-4565-9164-39C4925E467B}' = 'Downloads'
    '{BFB9D5E0-C6A9-404C-B2B2-AE6DB6AF4968}' = 'Links'
    '{4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4}' = 'Saved Games'
    '{7D1D3A04-DEBB-4115-95CF-2F29DA2920DA}' = 'Searches'
    '{A63293E8-664E-48DB-A079-DF759E0509F7}' = 'Templates'
    '{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}' = 'Start Menu'
    '{AE50C081-EBD2-438A-8655-8A092E34987A}' = 'Recent'
    '{9E52AB10-F80D-49DF-ACB8-4330F5687855}' = 'AppData'
}

function ConvertFrom-FdeployIni {
    <# Folder redirection targets, one row per redirected folder. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Content)

    $ini  = ConvertFrom-OutlineIni -Content $Content
    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($sec in $ini.PSBase.Keys) {
        if ($sec -notmatch '^\{[0-9A-Fa-f\-]{36}\}$') { continue }
        $folder = if ($script:FolderRedirectionGuids.ContainsKey($sec.ToUpper())) {
            $script:FolderRedirectionGuids[$sec.ToUpper()]
        } else { $sec }

        $targets = New-Object System.Collections.Generic.List[string]
        $flags = $null; $policy = $null
        foreach ($rawKey in $ini[$sec].PSBase.Keys) {
            $k = Get-IniBaseKey $rawKey
            $v = $ini[$sec][$rawKey]
            if ($k -match '^S-1-') {
                # <SID>=<flags>;<path>
                $p = "$v" -split ';', 2
                $sid = Resolve-OutlineSid $k
                $who = if ($sid) { $sid.Name } else { $k }
                $path = if ($p.Count -eq 2) { $p[1] } else { "$v" }
                $targets.Add("$who -> $path")
            }
            elseif ($k -eq 'p_Flags')      { $flags = $v }
            elseif ($k -eq 'p_Redirection'){ $policy = $v }
        }

        $mode = switch ("$policy") {
            '1' { 'Basic -- redirect everyone to the same location' }
            '2' { 'Advanced -- redirect by security group' }
            default { $(if ($policy) { "Mode $policy" } else { 'Not stated' }) }
        }

        $rows.Add([pscustomobject]@{
            Folder  = $folder
            Mode    = $mode
            Targets = $targets.ToArray()
            Flags   = "$flags"
        })
    }
    return ,$rows.ToArray()
}

# ------------------------------------------------------------------------------
# Group Policy Preferences XML
#
# cpassword: presence is recorded as a fact, with the item and file it appears
# in. The value is never decrypted, never printed, never stored, and the
# published AES key is not shipped with this tool. "A credential is present
# here" is the documentation-worthy fact; the credential itself is not.
# ------------------------------------------------------------------------------

function ConvertFrom-GppXml {
    <#
      Parses one Preferences XML file into item rows. Attribute names differ
      per extension, so the common identifying attributes are probed in order
      and the rest are captured generically -- that way an extension this code
      has never seen still produces readable rows instead of nothing.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Category,
        [string]$ItemElement
    )

    $result = [ordered]@{
        Category = $Category; Items = @(); CPasswordItems = @()
        Readable = $false; Reason = $null
    }

    try {
        [xml]$xml = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    }
    catch {
        $result.Reason = "Unreadable: $($_.Exception.Message)"
        return [pscustomobject]$result
    }

    $result.Readable = $true
    $items = New-Object System.Collections.Generic.List[object]
    $cpw   = New-Object System.Collections.Generic.List[object]

    # Every GPP item carries a <Properties> child; walking those covers all
    # extensions without a per-extension element list.
    $nodes = $xml.SelectNodes('//*[Properties]')
    if (-not $nodes -or $nodes.Count -eq 0) { $nodes = @() }

    foreach ($n in $nodes) {
        $props = $n.SelectSingleNode('Properties')
        if (-not $props) { continue }

        $name = $null
        foreach ($a in @('name','Name','desc')) {
            if ($n.Attributes -and $n.Attributes[$a]) { $name = $n.Attributes[$a].Value; break }
        }
        if (-not $name) {
            foreach ($a in @('name','path','key','targetPath','userName','serviceName','taskName','shareName','letter')) {
                if ($props.Attributes -and $props.Attributes[$a]) { $name = $props.Attributes[$a].Value; break }
            }
        }
        if (-not $name) { $name = $n.LocalName }

        $actionCode = if ($props.Attributes -and $props.Attributes['action']) { $props.Attributes['action'].Value } else { $null }
        $action = if ($actionCode -and $script:GppAction.ContainsKey($actionCode)) { $script:GppAction[$actionCode] } else { $actionCode }

        # Detail: every property attribute except the credential ones.
        $detail = New-Object System.Collections.Generic.List[string]
        $hasCpassword = $false
        if ($props.Attributes) {
            foreach ($a in $props.Attributes) {
                if ($a.Name -eq 'cpassword') {
                    # Recorded as presence only. The value is deliberately not
                    # read into any variable that reaches the report or state.
                    if ($a.Value) { $hasCpassword = $true }
                    continue
                }
                if ($a.Name -in @('action')) { continue }
                if ([string]::IsNullOrEmpty($a.Value)) { continue }
                if ($a.Value.Length -gt 200) { continue }
                $detail.Add("$($a.Name)=$($a.Value)")
            }
        }

        # Item-level targeting (the Common tab) decides whether this individual
        # item applies, independently of the GPO's own scope. It is as decisive
        # as a WMI filter and much more common, so the conditions themselves are
        # extracted rather than merely flagged as present.
        $filters = ConvertFrom-GppFilters -ItemNode $n
        $targeted = (@($filters).Count -gt 0)
        $targetText = Format-GppFilterSentence -Filters $filters

        $row = [pscustomobject]@{
            Category   = $Category
            Element    = $n.LocalName
            Name       = $name
            Action     = $action
            Detail     = ($detail.ToArray() -join '; ')
            Targeted   = $targeted
            TargetText = $targetText
            Filters    = $filters
            CPassword  = $hasCpassword
        }
        $items.Add($row)

        if ($hasCpassword) {
            $cpw.Add([pscustomobject]@{
                Category = $Category; Element = $n.LocalName; Name = $name
                File     = (Split-Path -Leaf $Path)
            })
        }
    }

    $result.Items          = $items.ToArray()
    $result.CPasswordItems = $cpw.ToArray()
    return [pscustomobject]$result
}

# ------------------------------------------------------------------------------
# ADMX / ADML friendly-name resolution
#
# Builds registry key+value -> friendly policy name from the central store when
# present, or the local PolicyDefinitions folder otherwise. Parsed once per run
# and cached: thousands of registry values resolve against one map, and this is
# the single largest CPU saving available in the whole collection.
# ------------------------------------------------------------------------------

$script:AdmxMap        = $null
$script:AdmxSourcePath = $null
$script:AdmxStats      = $null

function Import-OutlineAdmx {
    <#
      Returns a hashtable keyed "key\value" (lower-case) -> friendly name.

      ADMX declares the registry key and value for each policy; ADML supplies
      the display strings for the current language. Both are needed, so a
      central store with no matching ADML resolves nothing and says so.
    #>
    param([string[]]$SearchPaths, [string]$Language = 'en-US')

    $map = @{}
    $stats = [ordered]@{
        Source = $null; AdmxFiles = 0; AdmlFiles = 0; Policies = 0
        Strings = 0; Failed = 0; Reason = $null
    }

    $root = $null
    foreach ($p in $SearchPaths) {
        if (-not $p) { continue }
        try { if (Test-Path -LiteralPath $p) { $root = $p; break } }
        catch { Write-OutlineQuiet $_ 'AdmxProbe' }
    }
    if (-not $root) {
        $stats.Reason = 'No ADMX source found (no central store and no local PolicyDefinitions).'
        $script:AdmxStats = [pscustomobject]$stats
        return $map
    }
    $stats.Source = $root

    # ---- ADML strings first: policy display names live there ----
    $strings = @{}
    $admlDir = Join-Path $root $Language
    if (-not (Test-Path -LiteralPath $admlDir)) {
        # Fall back to any language folder present, and say which was used.
        try {
            $alt = @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction Stop |
                     Where-Object { $_.Name -match '^[a-z]{2}-[A-Z]{2}$' } | Select-Object -First 1)
            if ($alt.Count -gt 0) { $admlDir = $alt[0].FullName; $Language = $alt[0].Name }
        } catch { Write-OutlineQuiet $_ 'AdmlLanguageProbe' }
    }

    if (Test-Path -LiteralPath $admlDir) {
        foreach ($f in @(Get-ChildItem -LiteralPath $admlDir -Filter '*.adml' -File -ErrorAction SilentlyContinue)) {
            try {
                [xml]$x = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop
                $stats.AdmlFiles++
                $nodes = $x.SelectNodes("//*[local-name()='string']")
                foreach ($s in $nodes) {
                    $id = $s.GetAttribute('id')
                    if ($id) { $strings["$($f.BaseName)|$id"] = $s.InnerText; $stats.Strings++ }
                }
            }
            catch { $stats.Failed++; Write-OutlineQuiet $_ "Adml:$($f.Name)" }
        }
    }
    else { $stats.Reason = "No ADML language folder under $root -- friendly names unavailable." }

    # ---- ADMX definitions ----
    foreach ($f in @(Get-ChildItem -LiteralPath $root -Filter '*.admx' -File -ErrorAction SilentlyContinue)) {
        try {
            [xml]$x = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop
            $stats.AdmxFiles++
            $base = $f.BaseName

            foreach ($pol in @($x.SelectNodes("//*[local-name()='policy']"))) {
                $pKey  = $pol.GetAttribute('key')
                $pVal  = $pol.GetAttribute('valueName')
                $disp  = $pol.GetAttribute('displayName')
                $cls   = $pol.GetAttribute('class')
                if (-not $pKey) { continue }
                $stats.Policies++

                # displayName is "$(string.SomeId)"
                $friendly = $null
                if ($disp -match '\$\(string\.(.+)\)$') {
                    $sid = $Matches[1]
                    if ($strings.ContainsKey("$base|$sid")) { $friendly = $strings["$base|$sid"] }
                }
                if (-not $friendly) { $friendly = $pol.GetAttribute('name') }
                if (-not $friendly) { continue }

                $rec = [pscustomobject]@{ Name = $friendly; Class = $cls; Admx = $f.Name }

                if ($pVal) {
                    $k = "$pKey\$pVal".ToLowerInvariant()
                    if (-not $map.ContainsKey($k)) { $map[$k] = $rec }
                }

                # Elements carry their own valueName; each maps to the same policy.
                foreach ($el in @($pol.SelectNodes(".//*[local-name()='elements']/*"))) {
                    $eVal = $el.GetAttribute('valueName')
                    $eKey = $el.GetAttribute('key')
                    if (-not $eKey) { $eKey = $pKey }
                    if ($eVal) {
                        $k2 = "$eKey\$eVal".ToLowerInvariant()
                        if (-not $map.ContainsKey($k2)) { $map[$k2] = $rec }
                    }
                }

                # Key-only fallback so a value the ADMX does not name still
                # resolves to the policy that owns its key.
                $kk = "$pKey\*".ToLowerInvariant()
                if (-not $map.ContainsKey($kk)) { $map[$kk] = $rec }
            }
        }
        catch { $stats.Failed++; Write-OutlineQuiet $_ "Admx:$($f.Name)" }
    }

    $stats.Language = $Language
    $script:AdmxStats = [pscustomobject]$stats
    return $map
}

function Resolve-AdmxName {
    <#
      key+value -> friendly policy name.
      Exact match first, then the key-only fallback. The result carries how it
      was resolved so the report can state which rows are raw registry and why.
    #>
    param([string]$Key, [string]$Value)
    if (-not $script:AdmxMap -or $script:AdmxMap.Count -eq 0) { return $null }
    if (-not $Key) { return $null }

    $k = "$Key\$Value".ToLowerInvariant()
    if ($script:AdmxMap.ContainsKey($k)) {
        return [pscustomobject]@{ Name = $script:AdmxMap[$k].Name; Match = 'Exact'; Admx = $script:AdmxMap[$k].Admx }
    }
    $kk = "$Key\*".ToLowerInvariant()
    if ($script:AdmxMap.ContainsKey($kk)) {
        return [pscustomobject]@{ Name = $script:AdmxMap[$kk].Name; Match = 'Key'; Admx = $script:AdmxMap[$kk].Admx }
    }
    return $null
}

# ------------------------------------------------------------------------------
# gPLink / gPOptions
# ------------------------------------------------------------------------------

function ConvertFrom-GpLink {
    <#
      gPLink is a concatenation of [LDAP://<GPO DN>;<flags>] entries.

      Two behaviours matter and are easy to get wrong:
        * The string is processed in REVERSE for precedence -- the LAST entry
          in the string has the LOWEST precedence. Link order 1, the highest
          precedence, is the last entry written.
        * Flags are a bitmask: 1 = link disabled, 2 = enforced. So 3 is both,
          and a disabled link is ignored regardless of enforcement.

      Returns entries in link-order (1 = highest precedence).
    #>
    param([string]$Value, [string]$ContainerDN)

    $out = New-Object System.Collections.Generic.List[object]
    if (-not $Value) { return ,$out.ToArray() }

    $matches_ = [regex]::Matches($Value, '\[LDAP://(?<dn>[^;\]]+);(?<flags>\d+)\]')
    if ($matches_.Count -eq 0) { return ,$out.ToArray() }

    # Reverse the string order to get precedence order.
    $entries = New-Object System.Collections.Generic.List[object]
    foreach ($m in $matches_) { $entries.Add($m) }
    $entries.Reverse()

    $order = 1
    foreach ($m in $entries) {
        $dn    = $m.Groups['dn'].Value.Trim()
        $flags = [int]$m.Groups['flags'].Value
        $gpoIdVal = $(if ($dn -match '(?i)\{[0-9A-F\-]{36}\}') { $Matches[0].ToUpper() } else { $null })
        $out.Add([pscustomobject]@{
            GpoDN       = $dn
            GpoId       = $gpoIdVal
            # The link DN names the domain the target GPO lives in. Resolving on
            # this rather than on the GUID alone is what keeps a link from
            # binding to another domain's GPO -- every domain has a Default
            # Domain Policy carrying the identical GUID.
            GpoKey      = $(if ($gpoIdVal) { "$(ConvertFrom-DnToDomain $dn)|$gpoIdVal".ToUpperInvariant() } else { $null })
            ContainerDN = $ContainerDN
            LinkOrder   = $order
            Enabled     = (($flags -band 1) -eq 0)
            Enforced    = (($flags -band 2) -eq 2)
            Flags       = $flags
        })
        $order++
    }
    return ,$out.ToArray()
}

function Test-BlockInheritance {
    <# gPOptions bit 0 set = Block Inheritance on this container. #>
    param($GpOptions)
    if ($null -eq $GpOptions) { return $false }
    return (([int]$GpOptions -band 1) -eq 1)
}

# ------------------------------------------------------------------------------
# Security descriptors -- security filtering and delegation
# ------------------------------------------------------------------------------

# Extended right GUID for "Apply Group Policy". A GPO applies to a principal
# only when that principal holds BOTH Read and Apply Group Policy.
$script:ApplyGroupPolicyGuid = 'edacfd8f-ffb3-11d1-b41d-00a0c968f939'

# Generic access mask bits that matter when reading a GPC ACL.
$script:AdsRight = @{
    ReadProperty        = 0x00000010
    WriteProperty       = 0x00000020
    CreateChild         = 0x00000001
    DeleteChild         = 0x00000002
    DeleteTree          = 0x00000040
    Delete              = 0x00010000
    WriteDacl           = 0x00040000
    WriteOwner          = 0x00080000
    ExtendedRight       = 0x00000100
    GenericAll          = 0x10000000
}

function ConvertFrom-GpoSecurityDescriptor {
    <#
      Turns a GPC nTSecurityDescriptor into two readable views:

        Filtering  -- who the GPO actually applies to (Read + Apply Group Policy)
        Delegation -- who can read, edit, or take control of the GPO

      Both are facts as recorded. The absence of Authenticated Users from
      filtering is noted because it changes who the GPO reaches, not because it
      is being judged: since MS16-072 that pattern is a normal and deliberate
      delegation choice in many estates.
    #>
    param([byte[]]$Descriptor)

    $res = [ordered]@{
        Filtering = @(); Delegation = @(); Owner = $null
        Readable = $false; Reason = $null
        AuthenticatedUsersApply = $false
        AuthenticatedUsersRead  = $false
    }

    if (-not $Descriptor -or $Descriptor.Length -eq 0) {
        $res.Reason = 'Security descriptor not returned -- the collecting account may lack read on it.'
        return [pscustomobject]$res
    }

    try {
        $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $sd.SetSecurityDescriptorBinaryForm($Descriptor)
        $res.Readable = $true

        try {
            $own = $sd.GetOwner([System.Security.Principal.SecurityIdentifier])
            if ($own) { $r = Resolve-OutlineSid $own.Value; $res.Owner = $(if ($r) { $r.Name } else { $own.Value }) }
        } catch { Write-OutlineQuiet $_ 'SdOwner' }

        # principal -> accumulated rights
        $acc = [ordered]@{}

        foreach ($ace in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            $sidStr = "$($ace.IdentityReference)"
            if (-not $acc.Contains($sidStr)) {
                $acc[$sidStr] = [ordered]@{
                    Sid = $sidStr; Read = $false; Apply = $false; Write = $false
                    Delete = $false; ModifySecurity = $false; FullControl = $false
                    Denied = $false
                }
            }
            $e = $acc[$sidStr]
            $mask = [int]$ace.ActiveDirectoryRights
            $deny = ($ace.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny)
            $objGuid = "$($ace.ObjectType)"

            if ($deny) {
                # A deny on Apply Group Policy is how "exclude this group" is
                # expressed, and it must not be reported as an allow.
                if ($objGuid -eq $script:ApplyGroupPolicyGuid) { $e.Denied = $true }
                continue
            }

            if (($mask -band $script:AdsRight.GenericAll) -ne 0) {
                $e.FullControl = $true; $e.Read = $true; $e.Write = $true
                $e.Delete = $true; $e.ModifySecurity = $true; $e.Apply = $true
            }
            if (($mask -band $script:AdsRight.ReadProperty)  -ne 0) { $e.Read = $true }
            if (($mask -band $script:AdsRight.WriteProperty) -ne 0) { $e.Write = $true }
            if (($mask -band $script:AdsRight.Delete) -ne 0 -or ($mask -band $script:AdsRight.DeleteTree) -ne 0) { $e.Delete = $true }
            if (($mask -band $script:AdsRight.WriteDacl) -ne 0 -or ($mask -band $script:AdsRight.WriteOwner) -ne 0) { $e.ModifySecurity = $true }

            if (($mask -band $script:AdsRight.ExtendedRight) -ne 0 -and $objGuid -eq $script:ApplyGroupPolicyGuid) {
                $e.Apply = $true
            }
        }

        $filter = New-Object System.Collections.Generic.List[object]
        $deleg  = New-Object System.Collections.Generic.List[object]

        foreach ($sidStr in $acc.PSBase.Keys) {
            $e = $acc[$sidStr]
            $r = Resolve-OutlineSid $sidStr
            $name = if ($r) { $r.Name } else { $sidStr }
            $resolved = if ($r) { $r.Resolved } else { $false }

            # --- filtering: the GPO applies where Read AND Apply are both held
            if ($e.Apply -and $e.Read -and -not $e.Denied) {
                $filter.Add([pscustomobject]@{
                    Name = $name; Sid = $sidStr; Resolved = $resolved; Access = 'Read, Apply Group Policy'
                })
                if ($sidStr -eq 'S-1-5-11') { $res.AuthenticatedUsersApply = $true }
            }
            elseif ($e.Denied) {
                $filter.Add([pscustomobject]@{
                    Name = $name; Sid = $sidStr; Resolved = $resolved; Access = 'Apply Group Policy denied'
                })
            }

            if ($sidStr -eq 'S-1-5-11' -and $e.Read) { $res.AuthenticatedUsersRead = $true }

            # --- delegation: anything beyond plain read
            $rights = New-Object System.Collections.Generic.List[string]
            if ($e.FullControl)    { $rights.Add('Full control') }
            else {
                if ($e.Write)          { $rights.Add('Edit settings') }
                if ($e.Delete)         { $rights.Add('Delete') }
                if ($e.ModifySecurity) { $rights.Add('Modify security') }
            }
            if ($rights.Count -gt 0) {
                $deleg.Add([pscustomobject]@{
                    Name = $name; Sid = $sidStr; Resolved = $resolved
                    Rights = ($rights.ToArray() -join ', ')
                    CanEdit = $true
                })
            }
        }

        $res.Filtering  = @($filter.ToArray() | Sort-Object Name)
        $res.Delegation = @($deleg.ToArray()  | Sort-Object Name)
    }
    catch {
        $res.Reason = "Security descriptor could not be decoded: $($_.Exception.Message)"
    }

    return [pscustomobject]$res
}

# ------------------------------------------------------------------------------
# WMI filter text
# ------------------------------------------------------------------------------

function ConvertFrom-WmiFilterExpression {
    <#
      msWMI-Parm2 packs one or more WQL queries:
        <count>;<ns len>;<namespace>;<query len>;<query>;...
      Returns the namespace/query pairs. On any unexpected shape the raw value
      is returned rather than a guess.
    #>
    param([string]$Parm2)

    $out = New-Object System.Collections.Generic.List[object]
    if (-not $Parm2) { return ,$out.ToArray() }

    $parts = $Parm2 -split ';'
    if ($parts.Count -lt 5) {
        $out.Add([pscustomobject]@{ Namespace = ''; Query = $Parm2; Parsed = $false })
        return ,$out.ToArray()
    }

    try {
        $i = 1   # parts[0] is the count
        while ($i + 3 -lt $parts.Count) {
            $ns = $parts[$i + 1]
            $q  = $parts[$i + 3]
            if ($q) { $out.Add([pscustomobject]@{ Namespace = $ns; Query = $q; Parsed = $true }) }
            $i += 4
        }
    }
    catch { Write-OutlineQuiet $_ 'WmiFilterParse' }

    if ($out.Count -eq 0) {
        $out.Add([pscustomobject]@{ Namespace = ''; Query = $Parm2; Parsed = $false })
    }
    return ,$out.ToArray()
}

function ConvertTo-PlainEnglishWql {
    <#
      Best-effort plain-English rendering of the WQL shapes that appear in
      practice. Anything not recognised keeps its raw query and is marked as
      not translated -- a wrong paraphrase would be worse than none.
    #>
    param([string]$Query)
    if (-not $Query) { return $null }
    $q = $Query -replace '\s+', ' '

    $notes = New-Object System.Collections.Generic.List[string]

    if ($q -match '(?i)from\s+Win32_OperatingSystem') {
        if ($q -match '(?i)ProductType\s*=\s*"?1"?') { $notes.Add('the machine is a workstation') }
        if ($q -match '(?i)ProductType\s*=\s*"?2"?') { $notes.Add('the machine is a domain controller') }
        if ($q -match '(?i)ProductType\s*=\s*"?3"?') { $notes.Add('the machine is a member server') }
        if ($q -match '(?i)Version\s+like\s+"([^"]+)"') { $notes.Add("the OS version matches $($Matches[1])") }
        if ($q -match '(?i)Version\s*>=\s*"([^"]+)"')   { $notes.Add("the OS version is $($Matches[1]) or later") }
        if ($q -match '(?i)Caption\s+like\s+"([^"]+)"') { $notes.Add("the OS name matches $($Matches[1])") }
        if ($q -match '(?i)OSArchitecture\s*=\s*"([^"]+)"') { $notes.Add("the architecture is $($Matches[1])") }
    }
    if ($q -match '(?i)from\s+Win32_ComputerSystem') {
        if ($q -match '(?i)Model\s+like\s+"([^"]+)"')        { $notes.Add("the hardware model matches $($Matches[1])") }
        if ($q -match '(?i)Manufacturer\s+like\s+"([^"]+)"') { $notes.Add("the manufacturer matches $($Matches[1])") }
        if ($q -match '(?i)DomainRole\s*=\s*"?(\d)"?')       { $notes.Add("the domain role is $($Matches[1])") }
    }
    if ($q -match '(?i)from\s+Win32_Product')       { $notes.Add('a specific installed product is present') }
    if ($q -match '(?i)from\s+Win32_LogicalDisk')   { $notes.Add('a disk matching the stated criteria is present') }
    if ($q -match '(?i)from\s+Win32_NetworkAdapterConfiguration') { $notes.Add('a network adapter matching the stated criteria is present') }
    if ($q -match '(?i)from\s+Win32_Battery')       { $notes.Add('the machine has a battery (typically a laptop)') }

    if ($notes.Count -eq 0) { return $null }
    return "Applies only where " + ($notes.ToArray() -join ', and ') + "."
}

# ==============================================================================
# COLLECTION -- PHASE 1 (cheap, LDAP only)
#
# Discovery-then-collect: one paged LDAP sweep per domain enumerates every GPC,
# every container carrying a link, and every WMI filter. That builds the work
# list, gives the progress bar a real denominator, and lets the expensive
# SYSVOL phase be throttled independently.
#
# Attributes are always scoped -- never '*'. On a 5,000-GPO forest the
# difference in payload is the difference between a fast run and a slow one.
# ==============================================================================

$script:GpoAttributes = @(
    'distinguishedName','displayName','cn','gPCFileSysPath','versionNumber','flags',
    'gPCWQLFilter','gPCMachineExtensionNames','gPCUserExtensionNames','gPCFunctionalityVersion',
    'whenCreated','whenChanged','nTSecurityDescriptor','objectGUID'
)

function Get-GpoStatusText {
    <#
      GPC 'flags': bit 0 disables the User half, bit 1 disables the Computer
      half. A GPO with both halves disabled has no runtime effect at all,
      which is a fact worth stating plainly next to it.
    #>
    param([Nullable[int64]]$Flags)
    if ($null -eq $Flags) { return 'Unknown' }
    $f = [int]$Flags
    $userOff = (($f -band 1) -eq 1)
    $compOff = (($f -band 2) -eq 2)
    if ($userOff -and $compOff) { return 'All settings disabled' }
    if ($userOff)  { return 'User settings disabled' }
    if ($compOff)  { return 'Computer settings disabled' }
    return 'Enabled'
}

function Split-GpoVersion {
    <#
      versionNumber packs both halves into one integer:
      low word = User version, high word = Computer version.
    #>
    param([Nullable[int64]]$Version)
    if ($null -eq $Version) { return [pscustomobject]@{ User = $null; Computer = $null; Raw = $null } }
    $v = [int64]$Version
    return [pscustomobject]@{
        User     = [int]($v -band 0xFFFF)
        Computer = [int](($v -shr 16) -band 0xFFFF)
        Raw      = $v
    }
}

function Invoke-OutlineGpoSweep {
    <#
      Reads every Group Policy Container in one domain.

      The GPC is the directory half of a GPO: name, version, status, WMI
      filter, CSE lists, and the security descriptor that drives both filtering
      and delegation. No SYSVOL is touched here.
    #>
    param(
        [Parameter(Mandatory)]$DomainRec,
        [int]$TimeoutSec = 30,
        [int]$PageSize = 1000
    )

    $conn = Get-OutlineDomainConnection -DnsRoot $DomainRec.DnsRoot
    if (-not $conn) { return @() }

    $baseDN = "CN=Policies,CN=System,$($DomainRec.NCName)"
    $rows   = New-Object System.Collections.Generic.List[object]
    $aclFail = 0

    try {
        Invoke-OutlineLdapSearch -Connection $conn -BaseDN $baseDN `
            -Filter '(objectClass=groupPolicyContainer)' `
            -Attributes $script:GpoAttributes -Scope OneLevel `
            -TimeoutSec $TimeoutSec -PageSize $PageSize -DaclOnly -Process {
                param($e)

                $dn   = Get-LdapStr $e 'distinguishedName'
                $cn   = Get-LdapStr $e 'cn'
                $name = Get-LdapStr $e 'displayName'
                if (-not $name) { $name = $cn }

                $ver    = Split-GpoVersion (Get-LdapInt $e 'versionNumber')
                $flags  = Get-LdapInt $e 'flags'
                $wmiRaw = Get-LdapStr $e 'gPCWQLFilter'

                # gPCWQLFilter is "[domain;{GUID};0]" -- only the GUID matters.
                $wmiId = $null
                if ($wmiRaw -and $wmiRaw -match '\{[0-9A-Fa-f\-]{36}\}') { $wmiId = $Matches[0].ToUpper() }

                $mCse = ConvertFrom-CseList (Get-LdapStr $e 'gPCMachineExtensionNames')
                $uCse = ConvertFrom-CseList (Get-LdapStr $e 'gPCUserExtensionNames')

                # An unreadable security descriptor is recorded on the GPO row
                # itself (AclReadable / AclReason) and surfaced per-GPO in the
                # report. No separate counter is kept here: a $script: counter
                # incremented from inside this callback without being assigned
                # first throws under StrictMode, which would abort the whole GPO
                # sweep for the domain on the first GPO whose ACL is hidden --
                # turning a per-GPO gap into total data loss.
                $sd = ConvertFrom-GpoSecurityDescriptor (Get-LdapByteArray $e 'nTSecurityDescriptor')

                $gid = if ($cn -match '\{[0-9A-Fa-f\-]{36}\}') { $Matches[0].ToUpper() } else { $cn }

                $rows.Add([pscustomobject][ordered]@{
                    Id            = $gid
                    # A GPO GUID is unique WITHIN a domain, not across a forest:
                    # every domain has a Default Domain Policy with the same
                    # {31B2F340-...} GUID. Anything that indexes GPOs by GUID
                    # alone will silently collapse them and attribute one
                    # domain's settings to another. Key on this instead.
                    Key           = "$($DomainRec.DnsRoot)|$gid".ToUpperInvariant()
                    Name          = $name
                    Domain        = $DomainRec.DnsRoot
                    DN            = $dn
                    SysvolPath    = Get-LdapStr $e 'gPCFileSysPath'
                    Status        = Get-GpoStatusText $flags
                    Flags         = [int]$flags
                    UserEnabled   = (($flags -band 1) -eq 0)
                    ComputerEnabled = (($flags -band 2) -eq 0)
                    AdVersionUser     = $ver.User
                    AdVersionComputer = $ver.Computer
                    SysvolVersionUser     = $null   # filled by the SYSVOL phase
                    SysvolVersionComputer = $null
                    VersionMismatch   = $false
                    Created       = Format-OutlineDate (ConvertFrom-AdGeneralizedTime (Get-LdapStr $e 'whenCreated'))
                    Changed       = Format-OutlineDate (ConvertFrom-AdGeneralizedTime (Get-LdapStr $e 'whenChanged'))
                    WmiFilterId   = $wmiId
                    WmiFilterName = $null
                    MachineCse    = $mCse
                    UserCse       = $uCse
                    Filtering     = $sd.Filtering
                    Delegation    = $sd.Delegation
                    Owner         = $sd.Owner
                    # SYSVOL-side (file system) rights, filled by the SYSVOL pass.
                    GptAcl        = @()
                    GptAclReadable = $false
                    GptAclReason  = $null
                    GptOwner      = $null
                    AclReadable   = $sd.Readable
                    AclReason     = $sd.Reason
                    AuthUsersApply= $sd.AuthenticatedUsersApply
                    AuthUsersRead = $sd.AuthenticatedUsersRead
                    Comment       = $null    # from SYSVOL comment.cmtx
                    LinkCount     = 0
                    Links         = @()
                    Settings      = $null    # filled by the SYSVOL phase
                    SettingCount  = 0
                    SysvolReadable= $false
                    SysvolReason  = $null
                    IsEmpty       = $false
                    Loopback      = $null
                })
            }
    }
    catch {
        Add-OutlineWarning "GPO container read failed in $($DomainRec.DnsRoot): $($_.Exception.Message)"
        return @()
    }

    return ,$rows.ToArray()
}

function Invoke-OutlineContainerSweep {
    <#
      Every container that can carry a GPO link: the domain head, and every OU.
      Sites are collected separately at forest level because they live in the
      configuration partition.

      gPLink and gPOptions are read raw and parsed here -- this is the
      module-free replacement for Get-GPInheritance.
    #>
    param(
        [Parameter(Mandatory)]$DomainRec,
        [string]$SearchBase,
        [int]$TimeoutSec = 30,
        [int]$PageSize = 1000
    )

    $conn = Get-OutlineDomainConnection -DnsRoot $DomainRec.DnsRoot
    if (-not $conn) { return @() }

    $rows = New-Object System.Collections.Generic.List[object]

    # ---- the domain head itself ----
    try {
        Invoke-OutlineLdapSearch -Connection $conn -BaseDN $DomainRec.NCName `
            -Filter '(objectClass=*)' -Attributes @('distinguishedName','gPLink','gPOptions') `
            -Scope Base -NoPaging -TimeoutSec $TimeoutSec -Process {
                param($e)
                $dn = Get-LdapStr $e 'distinguishedName'
                $rows.Add([pscustomobject][ordered]@{
                    Type       = 'Domain'
                    Name       = $DomainRec.DnsRoot
                    DN         = $dn
                    ParentDN   = $null
                    Domain     = $DomainRec.DnsRoot
                    Depth      = 0
                    GpLink     = Get-LdapStr $e 'gPLink'
                    GpOptions  = [int](Get-LdapInt $e 'gPOptions')
                    BlockInheritance = (Test-BlockInheritance (Get-LdapInt $e 'gPOptions'))
                    Links      = @()
                })
            }
    }
    catch { Add-OutlineWarning "Domain head unreadable in $($DomainRec.DnsRoot): $($_.Exception.Message)" }

    # ---- organizational units ----
    $base = if ($SearchBase) { $SearchBase } else { $DomainRec.NCName }
    try {
        Invoke-OutlineLdapSearch -Connection $conn -BaseDN $base `
            -Filter '(objectCategory=organizationalUnit)' `
            -Attributes @('distinguishedName','ou','name','gPLink','gPOptions','whenChanged') `
            -Scope Subtree -TimeoutSec $TimeoutSec -PageSize $PageSize -Process {
                param($e)
                $dn = Get-LdapStr $e 'distinguishedName'
                if (-not $dn) { return }

                # Depth is the count of OU= components: it drives both the tree
                # rendering and the precedence layering.
                $depth = @([regex]::Matches($dn, '(?i)OU=')).Count
                $opts  = Get-LdapInt $e 'gPOptions'

                $rows.Add([pscustomobject][ordered]@{
                    Type       = 'OU'
                    Name       = Get-DnLeaf $dn
                    DN         = $dn
                    ParentDN   = Get-DnParent $dn
                    Domain     = $DomainRec.DnsRoot
                    Depth      = $depth
                    GpLink     = Get-LdapStr $e 'gPLink'
                    GpOptions  = [int]$opts
                    BlockInheritance = (Test-BlockInheritance $opts)
                    Links      = @()
                })
            }
    }
    catch {
        # An OU sweep failure is not a cosmetic gap: links live on containers,
        # so losing the OUs makes every GPO look unlinked and the precedence,
        # OU tree and conflict sections silently wrong rather than merely empty.
        # Record it against the domain so the report can say so instead of
        # presenting a gutted dataset as a finding about the environment.
        $script:ContainerReadFailures[$DomainRec.DnsRoot] = $_.Exception.Message
        Add-OutlineWarning "OU read failed in $($DomainRec.DnsRoot): $($_.Exception.Message) -- link, precedence and OU tree data for this domain is incomplete."
    }

    # Parse the raw gPLink on every container into structured link records.
    foreach ($c in $rows) {
        $c.Links = ConvertFrom-GpLink -Value $c.GpLink -ContainerDN $c.DN
    }

    return ,$rows.ToArray()
}

function Invoke-OutlineWmiFilterSweep {
    <#
      WMI filters live in CN=SOM,CN=WMIPolicy,CN=System. Each is parsed once and
      keyed by ID: a single filter is typically referenced by many GPOs, so
      re-parsing per GPO would be wasted work.
    #>
    param([Parameter(Mandatory)]$DomainRec, [int]$TimeoutSec = 30, [int]$PageSize = 1000)

    $conn = Get-OutlineDomainConnection -DnsRoot $DomainRec.DnsRoot
    if (-not $conn) { return @() }

    $baseDN = "CN=SOM,CN=WMIPolicy,CN=System,$($DomainRec.NCName)"
    $rows   = New-Object System.Collections.Generic.List[object]

    try {
        Invoke-OutlineLdapSearch -Connection $conn -BaseDN $baseDN `
            -Filter '(objectClass=msWMI-Som)' `
            -Attributes @('msWMI-Name','msWMI-Parm1','msWMI-Parm2','msWMI-ID','whenCreated','whenChanged','distinguishedName') `
            -Scope OneLevel -TimeoutSec $TimeoutSec -PageSize $PageSize -Process {
                param($e)
                $id = Get-LdapStr $e 'msWMI-ID'
                $queries = ConvertFrom-WmiFilterExpression (Get-LdapStr $e 'msWMI-Parm2')

                $plain = New-Object System.Collections.Generic.List[string]
                foreach ($q in $queries) {
                    $t = ConvertTo-PlainEnglishWql $q.Query
                    if ($t) { $plain.Add($t) }
                }

                $rows.Add([pscustomobject][ordered]@{
                    Id          = $(if ($id) { $id.ToUpper() } else { $null })
                    # Domain-qualified for the same reason as GPOs: a WMI filter
                    # ID is unique within its domain, not across the forest.
                    Key         = "$($DomainRec.DnsRoot)|$(if ($id) { $id.ToUpper() } else { '' })".ToUpperInvariant()
                    Name        = Get-LdapStr $e 'msWMI-Name'
                    Description = Get-LdapStr $e 'msWMI-Parm1'
                    Domain      = $DomainRec.DnsRoot
                    DN          = Get-LdapStr $e 'distinguishedName'
                    Queries     = $queries
                    PlainEnglish= $(if ($plain.Count -gt 0) { $plain.ToArray() -join ' ' } else { $null })
                    Created     = Format-OutlineDate (ConvertFrom-AdGeneralizedTime (Get-LdapStr $e 'whenCreated'))
                    Changed     = Format-OutlineDate (ConvertFrom-AdGeneralizedTime (Get-LdapStr $e 'whenChanged'))
                    UsedBy      = @()
                })
            }
    }
    catch {
        Write-OutlineQuiet $_ "WmiFilters:$($DomainRec.DnsRoot)"
        Write-OutlineLog 'INFO' "No WMI filter container readable in $($DomainRec.DnsRoot) -- none defined, or not readable."
    }

    return ,$rows.ToArray()
}

# ==============================================================================
# RIGHTS SELF-CHECK
#
# Every capability the report depends on is proven at run time, so a section
# that came back empty can always be attributed correctly: "not readable" is
# never presented as "not present".
# ==============================================================================

function Test-OutlineAccess {
    param($Connection, [int]$TimeoutSec = 30)

    $r = [ordered]@{
        Identity            = $script:RunAsAccount
        CanReadDomainNC     = $false
        CanReadConfigNC     = $false
        CanReadGpoAcl       = $false
        CanReadWmiFilters   = $false
        CanReadSysvol       = $false
        CanReadCentralStore = $false
        HasGpmc             = $false
        IsDomainAdmin       = $false
        Notes               = New-Object System.Collections.Generic.List[string]
    }

    if ($script:BoundCredential) { $r.Identity = $script:BoundCredential.UserName }

    # ---- Configuration NC ----
    try {
        Invoke-OutlineLdapSearch -Connection $Connection -BaseDN "CN=Sites,$($script:Outline.ConfigDN)" `
            -Filter '(objectClass=site)' -Attributes @('cn') -Scope OneLevel `
            -NoPaging -TimeoutSec $TimeoutSec -Process { param($e) } | Out-Null
        $r.CanReadConfigNC = $true
    }
    catch { $r.Notes.Add("Configuration partition not readable: $($_.Exception.Message)") }

    # ---- Domain NC + GPC ACL in one probe ----
    try {
        $script:__probeGpo = 0; $script:__probeAcl = 0
        Invoke-OutlineLdapSearch -Connection $Connection -BaseDN "CN=Policies,CN=System,$($script:Outline.DefaultDN)" `
            -Filter '(objectClass=groupPolicyContainer)' `
            -Attributes @('displayName','nTSecurityDescriptor') -Scope OneLevel `
            -TimeoutSec $TimeoutSec -PageSize 10 -DaclOnly -Process {
                param($e)
                $script:__probeGpo++
                if ((Get-LdapByteArray $e 'nTSecurityDescriptor')) { $script:__probeAcl++ }
            } | Out-Null
        $r.CanReadDomainNC = $true
        $r.CanReadGpoAcl   = ($script:__probeAcl -gt 0)
        if ($script:__probeGpo -gt 0 -and $script:__probeAcl -eq 0) {
            $r.Notes.Add('GPO objects are readable but their security descriptors are not -- security filtering and delegation will be incomplete.')
        }
        Remove-Variable -Name __probeGpo, __probeAcl -Scope Script -ErrorAction SilentlyContinue
    }
    catch { $r.Notes.Add("Group Policy container not readable: $($_.Exception.Message)") }

    # ---- WMI filters ----
    try {
        Invoke-OutlineLdapSearch -Connection $Connection -BaseDN "CN=SOM,CN=WMIPolicy,CN=System,$($script:Outline.DefaultDN)" `
            -Filter '(objectClass=msWMI-Som)' -Attributes @('msWMI-Name') -Scope OneLevel `
            -NoPaging -TimeoutSec $TimeoutSec -Process { param($e) } | Out-Null
        $r.CanReadWmiFilters = $true
    }
    catch {
        # An empty or absent container is not a rights failure. It is only
        # recorded as unavailable when the read itself was refused.
        if ("$($_.Exception.Message)" -match '(?i)access|denied|insufficient') {
            $r.Notes.Add('WMI filter container not readable.')
        } else {
            $r.CanReadWmiFilters = $true
        }
    }

    # ---- SYSVOL ----
    $dom = ConvertFrom-DnToDomain $script:Outline.DefaultDN
    if ($dom) {
        $polPath = "\\$dom\SYSVOL\$dom\Policies"
        try {
            if (Test-Path -LiteralPath $polPath) {
                $null = @(Get-ChildItem -LiteralPath $polPath -Directory -ErrorAction Stop | Select-Object -First 1)
                $r.CanReadSysvol = $true
            }
            else { $r.Notes.Add("SYSVOL policy path not reachable: $polPath") }
        }
        catch { $r.Notes.Add("SYSVOL not readable: $($_.Exception.Message)") }

        try {
            $cs = "\\$dom\SYSVOL\$dom\Policies\PolicyDefinitions"
            if (Test-Path -LiteralPath $cs) { $r.CanReadCentralStore = $true }
        }
        catch { Write-OutlineQuiet $_ 'CentralStoreProbe' }
    }

    # ---- optional GPMC cross-check ----
    # Presence only. GPOOutline never requires it and never falls back to it.
    try {
        $m = Get-Module -ListAvailable -Name GroupPolicy -ErrorAction SilentlyContinue
        $r.HasGpmc = [bool]$m
    }
    catch { Write-OutlineQuiet $_ 'GpmcProbe' }

    # ---- privilege hint (best effort, never required) ----
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
        $r.IsDomainAdmin = $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { Write-OutlineQuiet $_ 'PrivilegeProbe' }

    return $r
}

function Write-OutlineRightsSummary {
    param($Rights)
    Write-OutlineLog 'DATA' '--- Collection rights ---'
    foreach ($k in @('CanReadDomainNC','CanReadConfigNC','CanReadGpoAcl','CanReadWmiFilters','CanReadSysvol','CanReadCentralStore','HasGpmc')) {
        Write-OutlineLog 'DATA' ("  {0,-22} {1}" -f $k, $Rights[$k])
    }
    foreach ($n in $Rights.Notes) { Write-OutlineLog 'DATA' "  note: $n" }
}

function Invoke-OutlineStarterGpoSweep {
    <#
      Starter GPOs live only on SYSVOL -- they have no directory object -- so they
      are invisible to every LDAP sweep in this script and would otherwise be
      absent from a document claiming to describe the estate.

      Layout: \\<domain>\SYSVOL\<domain>\StarterGPOs\{GUID}\ with the same
      Machine\registry.pol and User\registry.pol a normal GPO uses, plus a
      manifest.xml at the StarterGPOs root naming them. The PReg decoder already
      built for GPOs is reused unchanged.

      Read-only, capability-gated on SYSVOL access, and non-fatal throughout: a
      missing StarterGPOs folder is the normal case in most estates and is
      reported as such rather than as a failure.
    #>
    param([Parameter(Mandatory)]$DomainRec, [int]$MaxValues = 20000)

    $rows = New-Object System.Collections.Generic.List[object]
    $root = "\\$($DomainRec.DnsRoot)\SYSVOL\$($DomainRec.DnsRoot)\StarterGPOs"

    try { if (-not (Test-Path -LiteralPath $root)) { return ,$rows.ToArray() } }
    catch { Write-OutlineQuiet $_ "StarterGpos:$($DomainRec.DnsRoot)"; return ,$rows.ToArray() }

    # manifest.xml names them; without it the GUID is all we have, which is still
    # worth reporting rather than dropping.
    $names = @{}
    try {
        $mf = Join-Path $root 'manifest.xml'
        if (Test-Path -LiteralPath $mf) {
            $xml = New-Object System.Xml.XmlDocument
            $xml.XmlResolver = $null
            $xml.Load($mf)
            foreach ($n in @($xml.SelectNodes('//*[local-name()="Instance"]'))) {
                $gid = $null; $nm = $null
                foreach ($a in @('ID','id','GUID')) { if ($n.Attributes -and $n.Attributes[$a]) { $gid = $n.Attributes[$a].Value; break } }
                foreach ($a in @('Name','name','DisplayName')) { if ($n.Attributes -and $n.Attributes[$a]) { $nm = $n.Attributes[$a].Value; break } }
                if (-not $gid) { $gid = ($n.SelectSingleNode('.//*[local-name()="ID"]')).InnerText }
                if (-not $nm)  { $nm  = ($n.SelectSingleNode('.//*[local-name()="Name"]')).InnerText }
                if ($gid) {
                    if ($gid -match '\{[0-9A-Fa-f\-]{36}\}') { $gid = $Matches[0].ToUpper() }
                    $names[$gid] = $nm
                }
            }
        }
    }
    catch { Write-OutlineQuiet $_ "StarterManifest:$($DomainRec.DnsRoot)" }

    try {
        foreach ($dir in @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction Stop)) {
            if ($dir.Name -notmatch '^\{[0-9A-Fa-f\-]{36}\}$') { continue }
            $gid = $dir.Name.ToUpper()

            $cCount = 0; $uCount = 0
            $areas = New-Object System.Collections.Generic.List[string]
            foreach ($pair in @(@('Machine','HKLM'), @('User','HKCU'))) {
                $pol = [System.IO.Path]::Combine($dir.FullName, $pair[0], 'registry.pol')
                try {
                    if (-not (Test-Path -LiteralPath $pol)) { continue }
                    $dec = ConvertFrom-PRegFile -Path $pol -MaxRecords $MaxValues -Hive $pair[1]
                    if (-not $dec.Valid) { continue }
                    $n = @($dec.Records).Count
                    if ($pair[0] -eq 'Machine') { $cCount = $n } else { $uCount = $n }
                    if ($n -gt 0 -and -not $areas.Contains('Administrative Templates')) { $areas.Add('Administrative Templates') }
                }
                catch { Write-OutlineQuiet $_ "StarterPol:$gid" }
            }

            # The system Starter GPOs shipped by Microsoft are read-only and are
            # distinguished so a reader does not mistake them for local authoring.
            $isSystem = ($names.ContainsKey($gid) -and $names[$gid] -match '(?i)^(Windows|MSFT)')

            $rows.Add([pscustomobject][ordered]@{
                Id       = $gid
                Name     = $(if ($names.ContainsKey($gid) -and $names[$gid]) { $names[$gid] } else { "(unnamed -- $gid)" })
                Domain   = $DomainRec.DnsRoot
                Kind     = $(if ($isSystem) { 'System (read-only, shipped by Microsoft)' } else { 'Custom' })
                Path     = $dir.FullName
                Modified = Format-OutlineDate $dir.LastWriteTime
                'Computer settings' = $cCount
                'User settings'     = $uCount
                Areas    = $(if ($areas.Count -gt 0) { $areas.ToArray() -join ', ' } else { 'None recorded' })
            })
        }
    }
    catch { Add-OutlineWarning "Starter GPO folder unreadable in $($DomainRec.DnsRoot): $($_.Exception.Message)" }

    return ,$rows.ToArray()
}

# ==============================================================================
# COLLECTION -- PHASE 2 (expensive: SYSVOL file parsing)
#
# SYSVOL parsing is I/O bound and parallelises well. PowerShell 7 gets
# ForEach-Object -Parallel; Windows PowerShell 5.1 gets a runspace pool. The
# parsing itself is identical in both -- the work is a self-contained
# scriptblock with no dependency on the parent session state, which is what
# makes the two paths interchangeable.
# ==============================================================================

function Get-OutlineConcurrency {
    param([int]$Requested)
    if ($Requested -gt 0) { return [Math]::Min($Requested, 64) }
    $cpu = 4
    try { $cpu = [Environment]::ProcessorCount } catch { Write-OutlineQuiet $_ 'ProcessorCount' }
    return [Math]::Max(1, [Math]::Min($cpu, 16))
}

function Read-OutlineTextFile {
    <#
      Bounded text read. A hung share must not stall the run, so the read is
      size-capped and any failure is returned rather than thrown.
    #>
    param([string]$Path, [int]$MaxBytes = 8MB)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $null }
        $fi = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($fi.Length -gt $MaxBytes) { return $null }
        return [System.IO.File]::ReadAllText($Path)
    }
    catch { return $null }
}

# The GPO settings parser, as a standalone scriptblock.
#
# It is defined once and used by BOTH the PS7 parallel path and the 5.1
# runspace path. It closes over nothing: every lookup table it needs is passed
# in. That is deliberate -- a scriptblock that captured parent state would work
# in-process and fail silently inside a runspace.
$script:GpoSysvolWorker = {
    param($Job)

    # ---- the job carries everything the worker needs ----
    $gpoId      = $Job.Id
    $gpoKey     = $Job.Key
    $gpoName    = $Job.Name
    $sysvolPath = $Job.SysvolPath
    $maxValues  = $Job.MaxValues
    $gppExt     = $Job.GppExtensions

    $result = [ordered]@{
        Key = $gpoKey; Id = $gpoId; Readable = $false; Reason = $null
        SysvolVersionUser = $null; SysvolVersionComputer = $null
        Comment = $null
        Computer = [ordered]@{ Registry = @(); Security = @(); Scripts = @(); Preferences = @(); SoftwareInstall = @(); Other = @() }
        User     = [ordered]@{ Registry = @(); Security = @(); Scripts = @(); Preferences = @(); FolderRedirection = @(); SoftwareInstall = @(); Other = @() }
        CPassword = @()
        Areas    = @()
        Truncations = @()
        FileCount = 0
        # C3: the SYSVOL-side counterpart to the AD delegation already reported.
        # AD-side and SYSVOL-side rights drift apart in real estates, and that
        # drift is a common cause of "I have Edit rights but cannot save".
        GptAcl = @()
        GptAclReadable = $false
        GptAclReason = $null
    }

    if (-not $sysvolPath) {
        $result.Reason = 'No gPCFileSysPath recorded on the GPO container.'
        return [pscustomobject]$result
    }

    try { if (-not (Test-Path -LiteralPath $sysvolPath)) {
            $result.Reason = "SYSVOL path not found: $sysvolPath"
            return [pscustomobject]$result
        } }
    catch {
        $result.Reason = "SYSVOL path not reachable: $($_.Exception.Message)"
        return [pscustomobject]$result
    }

    $result.Readable = $true

    # Read here rather than in a separate pass: this worker is already at this
    # path with the share open, so the ACL costs one metadata call instead of a
    # second sweep across every GPO folder. Failure is recorded, never fatal --
    # an unreadable ACL is a fact about rights, not a reason to lose the settings.
    try {
        $sd = Get-Acl -LiteralPath $sysvolPath -ErrorAction Stop
        $aclRows = New-Object System.Collections.Generic.List[object]
        foreach ($ace in @($sd.Access)) {
            if (-not $ace) { continue }

            # FileSystemRights.ToString() returns a bare NUMBER when the ACE uses
            # generic rights bits, because the enum has no name for them --
            # SYSVOL ACEs routinely do. Printing 268435456 in a permissions table
            # is useless, so the generic bits are decoded by hand and the specific
            # rights left to the enum.
            $rightsVal = [int]$ace.FileSystemRights
            $rightsText = [string]$ace.FileSystemRights
            $canWrite = $false

            if ($rightsText -match '^-?\d+$') {
                $parts = New-Object System.Collections.Generic.List[string]
                if ($rightsVal -band 0x10000000) { $parts.Add('Full control (generic)'); $canWrite = $true }
                if ($rightsVal -band 0x40000000) { $parts.Add('Write (generic)'); $canWrite = $true }
                if ($rightsVal -band 0x80000000) { $parts.Add('Read (generic)') }
                if ($rightsVal -band 0x20000000) { $parts.Add('Execute (generic)') }
                if ($parts.Count -gt 0) { $rightsText = $parts.ToArray() -join ', ' }
                else { $rightsText = "Rights mask 0x$($rightsVal.ToString('X8'))" }
            }
            else {
                $canWrite = ($rightsText -match '(?i)Write|Modify|FullControl|CreateFiles|TakeOwnership|ChangePermissions')
            }
            if ($ace.AccessControlType -match '(?i)deny') { $canWrite = $false }

            $aclRows.Add([pscustomobject]@{
                Identity  = [string]$ace.IdentityReference
                Rights    = $rightsText
                RightsMask = $rightsVal
                CanWrite  = $canWrite
                Type      = [string]$ace.AccessControlType
                Inherited = [bool]$ace.IsInherited
                Applies   = [string]$ace.InheritanceFlags
            })
        }
        $result.GptAcl = $aclRows.ToArray()
        $result.GptAclReadable = $true
        $result.Owner = [string]$sd.Owner
    }
    catch {
        $result.GptAclReason = "SYSVOL folder permissions were not readable: $($_.Exception.Message)"
    }

    $areas = New-Object System.Collections.Generic.List[string]

    # ---------------- GPT.INI: the SYSVOL-side version ----------------
    try {
        $gptIni = Join-Path $sysvolPath 'GPT.INI'
        if (Test-Path -LiteralPath $gptIni) {
            $result.FileCount++
            $txt = [System.IO.File]::ReadAllText($gptIni)
            foreach ($line in ($txt -split "`r?`n")) {
                if ($line -match '(?i)^\s*Version\s*=\s*(\d+)') {
                    $v = [int64]$Matches[1]
                    $result.SysvolVersionUser     = [int]($v -band 0xFFFF)
                    $result.SysvolVersionComputer = [int](($v -shr 16) -band 0xFFFF)
                }
            }
        }
    } catch { }

    # ---------------- comment.cmtx: the author's stated intent ----------------
    foreach ($half in @('Machine','User')) {
        try {
            $cmt = Join-Path (Join-Path $sysvolPath $half) 'comment.cmtx'
            if (Test-Path -LiteralPath $cmt) {
                $result.FileCount++
                [xml]$cx = [System.IO.File]::ReadAllText($cmt)
                $n = $cx.SelectSingleNode("//*[local-name()='resourceString']")
                if ($n -and $n.InnerText -and -not $result.Comment) { $result.Comment = $n.InnerText.Trim() }
            }
        } catch { }
    }

    # ---------------- per-half parsing ----------------
    foreach ($half in @('Machine','User')) {
        $root = Join-Path $sysvolPath $half
        try { if (-not (Test-Path -LiteralPath $root)) { continue } } catch { continue }

        $bucket = if ($half -eq 'Machine') { $result.Computer } else { $result.User }
        $hive   = if ($half -eq 'Machine') { 'HKLM' } else { 'HKCU' }

        # --- registry.pol (Administrative Templates) ---
        try {
            $pol = Join-Path $root 'registry.pol'
            if (Test-Path -LiteralPath $pol) {
                $result.FileCount++
                $decoded = & $Job.PRegDecoder $pol $hive $maxValues
                if ($decoded.Valid) {
                    $bucket.Registry = $decoded.Records
                    if ($decoded.Records.Count -gt 0) { $areas.Add('Administrative Templates') }
                    if ($decoded.Truncated) { $result.Truncations += "registry.pol ($half): $($decoded.Reason)" }
                    if ($decoded.Capped)    { $result.Truncations += "registry.pol ($half): $($decoded.Reason)" }
                }
                elseif ($decoded.Reason) { $result.Truncations += "registry.pol ($half): $($decoded.Reason)" }
            }
        } catch { $result.Truncations += "registry.pol ($half): $($_.Exception.Message)" }

        # --- GptTmpl.inf (security settings) ---
        try {
            # Segment-wise join rather than an embedded-separator string, so the
            # path is built by the platform instead of being hard-coded.
            $inf = [System.IO.Path]::Combine($root, 'Microsoft', 'Windows NT', 'SecEdit', 'GptTmpl.inf')
            if (Test-Path -LiteralPath $inf) {
                $result.FileCount++
                $txt = [System.IO.File]::ReadAllText($inf)
                $rows = & $Job.GptTmplParser $txt
                if ($rows.Count -gt 0) { $bucket.Security = $rows; $areas.Add('Security Settings') }
            }
        } catch { $result.Truncations += "GptTmpl.inf ($half): $($_.Exception.Message)" }

        # --- Advanced Audit Policy ---
        # [Event Audit] in GptTmpl.inf is the legacy nine-category policy. On a
        # current domain the real configuration lives in a separate CSV, so a
        # report reading only the INF shows an empty audit policy on an estate
        # that has a full one.
        try {
            $csv = [System.IO.Path]::Combine($root, 'Microsoft', 'Windows NT', 'Audit', 'audit.csv')
            if (Test-Path -LiteralPath $csv) {
                $result.FileCount++
                $rows = @(Import-Csv -LiteralPath $csv -ErrorAction Stop)
                $out = New-Object System.Collections.Generic.List[object]
                foreach ($r in $rows) {
                    $sub = $r.Subcategory
                    if (-not $sub) { continue }
                    $sv = "$($r.'Setting Value')"
                    $label = switch ($sv) {
                        '0' { 'No auditing' } '1' { 'Success' } '2' { 'Failure' } '3' { 'Success and Failure' }
                        default { if ($r.'Inclusion Setting') { "$($r.'Inclusion Setting')" } else { $sv } }
                    }
                    $out.Add([pscustomobject]@{
                        Area = 'Advanced Audit Policy'; Section = 'Audit'; Name = $sub
                        Setting = $sub; Value = $label; Raw = $sv
                    })
                }
                if ($out.Count -gt 0) {
                    $bucket.Security = @($bucket.Security) + $out.ToArray()
                    $areas.Add('Advanced Audit Policy')
                }
            }
        } catch { $result.Truncations += "audit.csv ($half): $($_.Exception.Message)" }

        # --- scripts.ini / psscripts.ini ---
        foreach ($pair in @(@('scripts.ini','Command'), @('psscripts.ini','PowerShell'))) {
            try {
                $sp = [System.IO.Path]::Combine($root, 'Scripts', $pair[0])
                if (Test-Path -LiteralPath $sp) {
                    $result.FileCount++
                    $txt = [System.IO.File]::ReadAllText($sp)
                    $rows = & $Job.ScriptsParser $txt $pair[1]
                    if ($rows.Count -gt 0) {
                        $bucket.Scripts = @($bucket.Scripts) + $rows
                        $areas.Add('Scripts')
                    }
                }
            } catch { $result.Truncations += "$($pair[0]) ($half): $($_.Exception.Message)" }
        }

        # --- folder redirection (User half only) ---
        if ($half -eq 'User') {
            try {
                $fd = [System.IO.Path]::Combine($root, 'Documents & Settings', 'fdeploy.ini')
                if (Test-Path -LiteralPath $fd) {
                    $result.FileCount++
                    $txt = [System.IO.File]::ReadAllText($fd)
                    $rows = & $Job.FdeployParser $txt
                    if ($rows.Count -gt 0) { $bucket.FolderRedirection = $rows; $areas.Add('Folder Redirection') }
                }
            } catch { $result.Truncations += "fdeploy.ini: $($_.Exception.Message)" }
        }

        # --- software installation (.aas packages) ---
        try {
            $appDir = Join-Path $root 'Applications'
            if (Test-Path -LiteralPath $appDir) {
                $aas = @(Get-ChildItem -LiteralPath $appDir -Filter '*.aas' -File -ErrorAction SilentlyContinue)
                if ($aas.Count -gt 0) {
                    $result.FileCount += $aas.Count
                    # The .aas format is an undocumented binary. Rather than
                    # guess at its internals, the package files are recorded as
                    # evidence that software installation is configured, with
                    # the MSI paths recovered from the readable strings inside.
                    $pkgs = New-Object System.Collections.Generic.List[object]
                    foreach ($a in $aas) {
                        $msi = $null
                        try {
                            $raw = [System.IO.File]::ReadAllBytes($a.FullName)
                            $txt = [System.Text.Encoding]::Unicode.GetString($raw)
                            $m = [regex]::Match($txt, '\\\\[^\x00]{4,240}?\.msi')
                            if ($m.Success) { $msi = $m.Value }
                        } catch { }
                        $pkgs.Add([pscustomobject]@{
                            Package = $a.BaseName
                            File    = $a.Name
                            MsiPath = $msi
                            Size    = $a.Length
                        })
                    }
                    $bucket.SoftwareInstall = $pkgs.ToArray()
                    $areas.Add('Software Installation')
                }
            }
        } catch { $result.Truncations += "Applications ($half): $($_.Exception.Message)" }

        # --- Group Policy Preferences ---
        try {
            $prefRoot = Join-Path $root 'Preferences'
            if (Test-Path -LiteralPath $prefRoot) {
                $prefs = New-Object System.Collections.Generic.List[object]
                foreach ($extDir in @(Get-ChildItem -LiteralPath $prefRoot -Directory -ErrorAction SilentlyContinue)) {
                    $label = $extDir.Name
                    if ($gppExt.Contains($extDir.Name)) { $label = $gppExt[$extDir.Name].Label }

                    foreach ($xf in @(Get-ChildItem -LiteralPath $extDir.FullName -Filter '*.xml' -File -ErrorAction SilentlyContinue)) {
                        $result.FileCount++
                        $parsed = & $Job.GppParser $xf.FullName $label
                        if (-not $parsed.Readable) {
                            $result.Truncations += "$($extDir.Name)\$($xf.Name): $($parsed.Reason)"
                            continue
                        }
                        if ($parsed.Items.Count -gt 0) { $prefs.Add($parsed) }
                        foreach ($c in $parsed.CPasswordItems) {
                            $result.CPassword += [pscustomobject]@{
                                Category = $c.Category; Name = $c.Name
                                Element = $c.Element; Half = $half; File = $c.File
                            }
                        }
                    }
                }
                if ($prefs.Count -gt 0) { $bucket.Preferences = $prefs.ToArray(); $areas.Add('Preferences') }
            }
        } catch { $result.Truncations += "Preferences ($half): $($_.Exception.Message)" }
    }

    $result.Areas = @($areas | Sort-Object -Unique)
    return [pscustomobject]$result
}

function Invoke-OutlineSysvolPhase {
    <#
      Runs the SYSVOL worker across every GPO, in parallel where the host
      supports it.

      Adaptive throttle: the elapsed time per batch is measured and concurrency
      is reduced when it climbs (multiplicative decrease) and eased back up when
      it settles (additive increase). The point is to stay off the back of a
      production DC rather than to finish a few seconds sooner.
    #>
    param(
        [Parameter(Mandatory)][object[]]$Gpos,
        [int]$MaxConcurrency = 0,
        [int]$ThrottleDelayMs = 0,
        [int]$MaxValues = 20000
    )

    if ($Gpos.Count -eq 0) { return @{} }

    $conc = Get-OutlineConcurrency -Requested $MaxConcurrency
    $isPs7 = $PSVersionTable.PSVersion.Major -ge 7
    Write-OutlineInfo "SYSVOL phase: $($Gpos.Count) GPO(s), concurrency $conc, engine $(if ($isPs7) { 'ForEach-Object -Parallel' } else { 'runspace pool' })"

    # Function bodies are passed as text and rebuilt inside each worker. A
    # runspace does not inherit the parent's function table, and PS7's
    # -Parallel runs in a fresh session state, so this is what makes one
    # scriptblock work identically on both.
    $fnPReg    = ${function:ConvertFrom-PRegFile}.ToString()
    $fnPRegB   = ${function:ConvertFrom-PRegBytes}.ToString()
    $fnPRegD   = ${function:ConvertTo-PRegData}.ToString()
    $fnPRegDir = ${function:Resolve-PRegDirective}.ToString()
    $fnIni     = ${function:ConvertFrom-OutlineIni}.ToString()
    $fnIniBase = ${function:Get-IniBaseKey}.ToString()
    $fnGpt     = ${function:ConvertFrom-GptTmpl}.ToString()
    $fnScripts = ${function:ConvertFrom-ScriptsIni}.ToString()
    $fnFdeploy = ${function:ConvertFrom-FdeployIni}.ToString()
    $fnGpp     = ${function:ConvertFrom-GppXml}.ToString()
    # Item-level targeting is parsed inside the worker alongside the GPP XML, so
    # its helpers have to travel with it -- the worker runspace shares no state
    # with the caller.
    $fnGppFilt = ${function:ConvertFrom-GppFilters}.ToString()
    $fnGppFTxt = ${function:ConvertTo-GppFilterText}.ToString()
    $fnGppFSen = ${function:Format-GppFilterSentence}.ToString()
    $fnSid     = ${function:Resolve-OutlineSid}.ToString()
    $fnAudit   = ${function:ConvertFrom-AuditValue}.ToString()

    $tables = @{
        PRegTypeName        = $script:PRegTypeName
        GppFilterLabel      = $script:GppFilterLabel
        WellKnownSids       = $script:WellKnownSids
        WellKnownRids       = $script:WellKnownRids
        PrivilegeNames      = $script:PrivilegeNames
        GptTmplAreas        = $script:GptTmplAreas
        SystemAccessNames   = $script:SystemAccessNames
        KerberosNames       = $script:KerberosNames
        EventAuditNames     = $script:EventAuditNames
        FolderRedirectionGuids = $script:FolderRedirectionGuids
        GppAction           = $script:GppAction
        GppExtensions       = $script:GppExtensions
    }

    $results = @{}
    $jobs = New-Object System.Collections.Generic.List[object]
    foreach ($g in $Gpos) {
        $jobs.Add([pscustomobject]@{
            # Key, not Id. GPO GUIDs repeat across domains (every domain has a
            # Default Domain Policy with the same GUID), so a results hashtable
            # keyed on Id alone silently collapses them and hands one domain's
            # settings to another domain's GPO.
            Key = $g.Key; Id = $g.Id; Name = $g.Name; SysvolPath = $g.SysvolPath; MaxValues = $MaxValues
        })
    }

    # The bootstrap rebuilds the parsers inside the worker, then runs the
    # shared worker scriptblock against one GPO.
    $bootstrap = {
        param($Job, $Fn, $Tab, $WorkerText)

        Set-StrictMode -Version 2.0
        $script:PRegTypeName           = $Tab.PRegTypeName
        $script:WellKnownSids          = $Tab.WellKnownSids
        $script:WellKnownRids          = $Tab.WellKnownRids
        $script:PrivilegeNames         = $Tab.PrivilegeNames
        $script:GptTmplAreas           = $Tab.GptTmplAreas
        $script:SystemAccessNames      = $Tab.SystemAccessNames
        $script:KerberosNames          = $Tab.KerberosNames
        $script:EventAuditNames        = $Tab.EventAuditNames
        $script:FolderRedirectionGuids = $Tab.FolderRedirectionGuids
        $script:GppAction              = $Tab.GppAction
        $script:GppFilterLabel         = $Tab.GppFilterLabel
        $script:SidNameCache           = @{}

        # Logging is a no-op inside a worker: the parent owns the log file and
        # concurrent appends from N runspaces would interleave and corrupt it.
        function Write-OutlineQuiet { param($ErrorRecord, [string]$Site) }
        function Write-OutlineAbsence { param([string]$Site) }
        function Write-OutlineLog { param($Level, $Message) }

        Set-Item -Path function:ConvertFrom-PRegBytes    -Value $Fn.PRegB
        Set-Item -Path function:ConvertTo-PRegData       -Value $Fn.PRegD
        Set-Item -Path function:Resolve-PRegDirective    -Value $Fn.PRegDir
        Set-Item -Path function:ConvertFrom-PRegFile     -Value $Fn.PReg
        Set-Item -Path function:ConvertFrom-OutlineIni   -Value $Fn.Ini
        Set-Item -Path function:Get-IniBaseKey           -Value $Fn.IniBase
        Set-Item -Path function:Resolve-OutlineSid       -Value $Fn.Sid
        Set-Item -Path function:ConvertFrom-AuditValue   -Value $Fn.Audit
        Set-Item -Path function:ConvertFrom-GptTmpl      -Value $Fn.Gpt
        Set-Item -Path function:ConvertFrom-ScriptsIni   -Value $Fn.Scripts
        Set-Item -Path function:ConvertFrom-FdeployIni   -Value $Fn.Fdeploy
        Set-Item -Path function:ConvertTo-GppFilterText   -Value $Fn.GppFTxt
        Set-Item -Path function:ConvertFrom-GppFilters    -Value $Fn.GppFilt
        Set-Item -Path function:Format-GppFilterSentence  -Value $Fn.GppFSen
        Set-Item -Path function:ConvertFrom-GppXml        -Value $Fn.Gpp

        $Job | Add-Member -NotePropertyName PRegDecoder  -NotePropertyValue { param($p, $h, $m) ConvertFrom-PRegFile -Path $p -Hive $h -MaxRecords $m } -Force
        $Job | Add-Member -NotePropertyName GptTmplParser -NotePropertyValue { param($t) ConvertFrom-GptTmpl -Content $t } -Force
        $Job | Add-Member -NotePropertyName ScriptsParser -NotePropertyValue { param($t, $e) ConvertFrom-ScriptsIni -Content $t -Engine $e } -Force
        $Job | Add-Member -NotePropertyName FdeployParser -NotePropertyValue { param($t) ConvertFrom-FdeployIni -Content $t } -Force
        $Job | Add-Member -NotePropertyName GppParser     -NotePropertyValue { param($p, $c) ConvertFrom-GppXml -Path $p -Category $c } -Force
        $Job | Add-Member -NotePropertyName GppExtensions -NotePropertyValue $Tab.GppExtensions -Force

        $worker = [scriptblock]::Create($WorkerText)
        return (& $worker $Job)
    }

    # A scriptblock cannot cross the -Parallel boundary as a live object: it
    # carries its originating session state and PS7 rejects it. Both engines
    # therefore receive the source text and rebuild it on the far side.
    $workerText    = $script:GpoSysvolWorker.ToString()
    $bootstrapText = $bootstrap.ToString()
    $fnBag = @{
        PReg = $fnPReg; PRegB = $fnPRegB; PRegD = $fnPRegD; PRegDir = $fnPRegDir
        Ini = $fnIni; IniBase = $fnIniBase; Gpt = $fnGpt; Scripts = $fnScripts
        Fdeploy = $fnFdeploy; Gpp = $fnGpp; Sid = $fnSid; Audit = $fnAudit
        GppFilt = $fnGppFilt; GppFTxt = $fnGppFTxt; GppFSen = $fnGppFSen
    }

    $done = 0
    $total = $jobs.Count
    $batchSize = [Math]::Max($conc, 1)
    $lastAvg = 0.0

    for ($i = 0; $i -lt $total; $i += $batchSize) {
        $slice = @($jobs[$i..([Math]::Min($i + $batchSize - 1, $total - 1))])
        $sw = [System.Diagnostics.Stopwatch]::StartNew()

        if ($isPs7) {
            # PS7: -Parallel. Variables must be marshalled with $using:.
            $out = $slice | ForEach-Object -ThrottleLimit $conc -Parallel {
                $bs = [scriptblock]::Create($using:bootstrapText)
                & $bs $_ $using:fnBag $using:tables $using:workerText
            }
            foreach ($o in $out) { if ($o) { $results[$o.Key] = $o } }
        }
        else {
            # 5.1: runspace pool. Every runspace is disposed after use.
            $pool = [runspacefactory]::CreateRunspacePool(1, $conc)
            $pool.Open()
            $handles = New-Object System.Collections.Generic.List[object]
            try {
                foreach ($j in $slice) {
                    $ps = [powershell]::Create()
                    $ps.RunspacePool = $pool
                    [void]$ps.AddScript($bootstrap).AddArgument($j).AddArgument($fnBag).AddArgument($tables).AddArgument($workerText)
                    $handles.Add([pscustomobject]@{ Ps = $ps; Handle = $ps.BeginInvoke() })
                }
                foreach ($h in $handles) {
                    try {
                        $o = $h.Ps.EndInvoke($h.Handle)
                        foreach ($r in $o) { if ($r) { $results[$r.Key] = $r } }
                    }
                    catch { Write-OutlineQuiet $_ 'SysvolRunspace' }
                    finally { $h.Ps.Dispose() }
                }
            }
            finally { $pool.Close(); $pool.Dispose() }
        }

        $sw.Stop()
        $done += $slice.Count
        $avg = if ($slice.Count -gt 0) { $sw.Elapsed.TotalMilliseconds / $slice.Count } else { 0 }

        # ---- adaptive throttle (AIMD) ----
        # Rising per-GPO latency means the share or the DC is under load. Back
        # off hard and recover slowly.
        if ($lastAvg -gt 0 -and $avg -gt ($lastAvg * 1.75) -and $conc -gt 2) {
            $conc = [Math]::Max(2, [int]($conc / 2))
            Write-OutlineLog 'INFO' ("SYSVOL latency rose to {0:0}ms/GPO -- concurrency reduced to {1}." -f $avg, $conc)
        }
        elseif ($lastAvg -gt 0 -and $avg -lt ($lastAvg * 1.1)) {
            $ceiling = Get-OutlineConcurrency -Requested $MaxConcurrency
            if ($conc -lt $ceiling) { $conc++ }
        }
        $lastAvg = $avg
        $batchSize = [Math]::Max($conc, 1)

        $pct = [int](100 * $done / $total)
        Write-Progress -Activity 'GPOOutline' -Status "Parsing SYSVOL: $done of $total GPO(s)" -PercentComplete $pct

        if ($ThrottleDelayMs -gt 0) { Start-Sleep -Milliseconds $ThrottleDelayMs }
    }

    Write-OutlineInfo "SYSVOL phase complete: $($results.Count) of $total GPO(s) returned a result."
    return $results
}

function Merge-OutlineSysvolResult {
    <#
      Folds the SYSVOL results back onto the GPO records and derives the facts
      that only become visible once both halves are known: version mismatch,
      emptiness, loopback mode, and total setting count.
    #>
    param([Parameter(Mandatory)]$Gpos, [Parameter(Mandatory)]$Results)

    foreach ($g in $Gpos) {
        if (-not $Results.ContainsKey($g.Key)) {
            $g.SysvolReadable = $false
            $g.SysvolReason   = 'No result was returned by the SYSVOL collection worker for this GPO.'
            continue
        }
        $r = $Results[$g.Key]

        $g.SysvolReadable = $r.Readable
        $g.SysvolReason   = $r.Reason

        # SYSVOL-side rights, kept distinct from the AD-side delegation already on
        # the record so the report can show the two side by side and let a reader
        # see where they disagree.
        $g.GptAcl          = @($r.GptAcl)
        $g.GptAclReadable  = [bool]$r.GptAclReadable
        $g.GptAclReason    = $r.GptAclReason
        $g.GptOwner        = $(if ($r.PSObject.Properties['Owner']) { $r.Owner } else { $null })
        $g.SysvolVersionUser     = $r.SysvolVersionUser
        $g.SysvolVersionComputer = $r.SysvolVersionComputer
        if ($r.Comment) { $g.Comment = $r.Comment }

        # ---- version mismatch ----
        # AD and SYSVOL versions disagreeing normally means replication has not
        # converged. Documented as a fact; the report does not diagnose it.
        if ($r.Readable -and $null -ne $r.SysvolVersionUser) {
            $g.VersionMismatch = (
                ($g.AdVersionUser     -ne $r.SysvolVersionUser) -or
                ($g.AdVersionComputer -ne $r.SysvolVersionComputer)
            )
        }

        $g.Settings = [ordered]@{
            Computer    = $r.Computer
            User        = $r.User
            CPassword   = $r.CPassword
            Areas       = $r.Areas
            Truncations = $r.Truncations
            FileCount   = $r.FileCount
        }

        # ---- total discrete settings ----
        $n = 0
        foreach ($halfName in @('Computer','User')) {
            $half = $r.$halfName
            if (-not $half) { continue }
            foreach ($k in $half.PSBase.Keys) {
                $v = $half[$k]
                if ($null -eq $v) { continue }
                if ($k -eq 'Preferences') {
                    foreach ($p in @($v)) { $n += @($p.Items).Count }
                }
                else { $n += @($v).Count }
            }
        }
        $g.SettingCount = $n
        $g.IsEmpty = ($n -eq 0 -and $r.Readable)

        # ---- loopback ----
        # Computer-side registry setting: HKLM\Software\Policies\Microsoft\
        # Windows\System, UserPolicyMode. 1 = Replace, 2 = Merge.
        foreach ($rec in @($r.Computer.Registry)) {
            if ($rec.Value -eq 'UserPolicyMode' -and
                $rec.Key -match '(?i)Software\\Policies\\Microsoft\\Windows\\System') {
                $mode = switch ("$($rec.Data)") {
                    '1' { 'Replace' }
                    '2' { 'Merge' }
                    default { "Mode $($rec.Data)" }
                }
                $g.Loopback = $mode
                break
            }
        }
    }
}

# ==============================================================================
# SCOPE, INHERITANCE AND PRECEDENCE ENGINE
#
# This is the module-free replacement for Get-GPInheritance, implemented from
# the documented rules rather than inferred:
#
#   * Application order is Local -> Site -> Domain -> OU, each deeper OU last.
#     Later application wins, so the closest OU normally has the final say.
#   * Within one container, a LOWER link order number means HIGHER precedence:
#     link order 1 is applied last and therefore wins.
#   * Block Inheritance on a container stops inheritance from above -- except
#     for enforced links, which it cannot stop.
#   * Enforced links are applied after everything else and cannot be blocked.
#     Where several are enforced, the one linked HIGHEST in the hierarchy wins.
#   * A disabled link is ignored entirely, enforced or not.
#
# The engine is deterministic and is unit-tested against synthetic trees
# covering enforced-over-block, block-stops-inheritance, link-order ties,
# and cross-domain links.
#
# Output is ordered with index 0 = highest precedence ("what wins here").
# ==============================================================================

function Get-OutlineContainerChain {
    <#
      The container chain from a target container up to its domain head,
      ordered ROOT FIRST (domain, then each OU top-down to the target). That is
      application order, which is the order precedence is computed in.
    #>
    param([Parameter(Mandatory)]$Container, [Parameter(Mandatory)]$ContainerIndex)

    $chain = New-Object System.Collections.Generic.List[object]
    $cur   = $Container
    $guard = 0

    while ($cur -and $guard -lt 256) {
        $chain.Add($cur)
        $guard++
        if ($cur.Type -eq 'Domain') { break }
        $p = $cur.ParentDN
        if (-not $p -or -not $ContainerIndex.ContainsKey($p)) { break }
        $cur = $ContainerIndex[$p]
    }

    $chain.Reverse()   # root first
    return ,$chain.ToArray()
}

function Resolve-OutlinePrecedence {
    <#
      Computes the resultant GPO order for one container.

      -SiteContainer is optional: site links apply to a machine by virtue of
      where it sits on the network, not where its object sits in the tree, so
      the caller supplies the site when it wants a machine-accurate view.

      Every returned row carries WHY it is where it is, because "what wins
      here" is only useful to a reader who can see the reason.
    #>
    param(
        [Parameter(Mandatory)]$Container,
        [Parameter(Mandatory)]$ContainerIndex,
        [Parameter(Mandatory)]$GpoIndex,
        $SiteContainer
    )

    $chain = Get-OutlineContainerChain -Container $Container -ContainerIndex $ContainerIndex

    # Application order: site first, then the domain-to-OU chain.
    $ordered = New-Object System.Collections.Generic.List[object]
    if ($SiteContainer) { $ordered.Add($SiteContainer) }
    foreach ($c in $chain) { $ordered.Add($c) }

    # Block Inheritance on any container discards non-enforced policy from
    # every container ABOVE it. The deepest blocking container is the one that
    # matters, so find it and cut there.
    $cutIndex = 0
    for ($i = 0; $i -lt $ordered.Count; $i++) {
        if ($ordered[$i].BlockInheritance) { $cutIndex = $i }
    }

    $normal   = New-Object System.Collections.Generic.List[object]
    $enforced = New-Object System.Collections.Generic.List[object]

    for ($i = 0; $i -lt $ordered.Count; $i++) {
        $c = $ordered[$i]
        $blockedHere = ($i -lt $cutIndex)

        # Within a container, link order 1 is applied LAST, so applying in
        # descending link order leaves link order 1 with the final say.
        $links = @($c.Links | Sort-Object -Property LinkOrder -Descending)

        foreach ($lk in $links) {
            if (-not $lk.Enabled) { continue }         # a disabled link never applies
            if (-not $lk.GpoId) { continue }

            # Resolved via the link's own DN, so a GUID shared across domains
            # cannot bind to the wrong domain's GPO.
            $gpo = $null
            $lkKey = $lk.GpoKey
            $lkDomain = ConvertFrom-DnToDomain $lk.GpoDN
            if ($lkKey -and $GpoIndex.ContainsKey($lkKey)) { $gpo = $GpoIndex[$lkKey] }

            $row = [pscustomobject]@{
                GpoKey      = $lkKey
                GpoId       = $lk.GpoId
                GpoName     = $(if ($gpo) { $gpo.Name } else { '(GPO not found in this forest)' })
                GpoDomain   = $(if ($gpo) { $gpo.Domain } else { $lkDomain })
                Container   = $c.Name
                ContainerDN = $c.DN
                ContainerType = $c.Type
                LinkOrder   = $lk.LinkOrder
                Enforced    = $lk.Enforced
                Blocked     = ($blockedHere -and -not $lk.Enforced)
                Reason      = $null
                GpoStatus   = $(if ($gpo) { $gpo.Status } else { 'Unknown' })
                WmiFilter   = $(if ($gpo) { $gpo.WmiFilterName } else { $null })
                Missing     = (-not $gpo)
            }

            if ($blockedHere -and -not $lk.Enforced) {
                # Recorded, not silently dropped: a reader looking for a policy
                # that "should" apply needs to see that it was blocked.
                $row.Reason = "Not applied -- inheritance is blocked at $($ordered[$cutIndex].Name)."
                $normal.Add($row)
                continue
            }

            if ($lk.Enforced) {
                $row.Reason = "Enforced at $($c.Name) -- applied last and cannot be blocked."
                $enforced.Add($row)
            }
            else {
                $row.Reason = "Linked at $($c.Name), link order $($lk.LinkOrder)."
                $normal.Add($row)
            }
        }
    }

    # ---- assemble final precedence, index 0 = wins ----
    #
    # Applied-last wins, so precedence is application order reversed.
    #
    # Enforced links outrank everything. Among them the one linked highest in
    # the hierarchy wins, and $enforced was built root-first, so it already
    # reads highest-first: it needs no reversal.
    $applied = @($normal | Where-Object { -not $_.Blocked })
    [array]::Reverse($applied)

    $final = New-Object System.Collections.Generic.List[object]
    foreach ($e in $enforced) { $final.Add($e) }
    foreach ($a in $applied)  { $final.Add($a) }

    $rank = 1
    foreach ($f in $final) {
        $f | Add-Member -NotePropertyName Precedence -NotePropertyValue $rank -Force
        $rank++
    }

    $blocked = @($normal | Where-Object { $_.Blocked })
    foreach ($b in $blocked) {
        $b | Add-Member -NotePropertyName Precedence -NotePropertyValue $null -Force
    }

    return [pscustomobject]@{
        Container        = $Container.Name
        ContainerDN      = $Container.DN
        ContainerType    = $Container.Type
        Domain           = $Container.Domain
        BlockInheritance = [bool]$Container.BlockInheritance
        BlockedAt        = $(if ($cutIndex -gt 0) { $ordered[$cutIndex].Name } else { $null })
        Applied          = $final.ToArray()
        NotApplied       = $blocked
        AppliedCount     = $final.Count
    }
}

function Build-OutlineScopeModel {
    <#
      Cross-links the three collections so every later section can be computed
      from memory rather than from LDAP:

        GPO   -> the containers it is linked to
        WMI   -> the GPOs that reference it
        Sites -> parsed as containers so site links join the same model
    #>
    param()

    $O = $script:Outline

    $gpoIndex = @{}
    # Indexed by domain-qualified Key, never by GUID alone: the same GUID exists
    # in every domain for the default policies, so a GUID-keyed index attributes
    # one domain's GPO to another's links.
    foreach ($g in $O.Gpos) { if ($g.Key) { $gpoIndex[$g.Key] = $g } }

    $containers = New-Object System.Collections.Generic.List[object]
    foreach ($c in $O.Containers) { $containers.Add($c) }

    # ---- sites become containers so the precedence engine sees one model ----
    foreach ($s in $O.Sites) {
        $links = ConvertFrom-GpLink -Value $s.GpLink -ContainerDN $s.DN
        $containers.Add([pscustomobject][ordered]@{
            Type             = 'Site'
            Name             = $s.Name
            DN               = $s.DN
            ParentDN         = $null
            Domain           = '(forest-wide)'
            Depth            = 0
            GpLink           = $s.GpLink
            GpOptions        = $s.GpOptions
            BlockInheritance = (Test-BlockInheritance $s.GpOptions)
            Links            = $links
        })
    }
    $O.Containers = $containers.ToArray()

    $containerIndex = @{}
    foreach ($c in $O.Containers) { if ($c.DN) { $containerIndex[$c.DN] = $c } }

    # ---- flatten every link, and attach links back to their GPO ----
    $allLinks = New-Object System.Collections.Generic.List[object]
    foreach ($c in $O.Containers) {
        foreach ($lk in $c.Links) {
            # The link's own DN names the domain the GPO lives in, which is what
            # disambiguates a GUID shared across domains -- and is also what makes
            # a genuine cross-domain link resolve to the right object.
            $gpo = $null
            $lkKey = $lk.GpoKey
            $lkDomain = ConvertFrom-DnToDomain $lk.GpoDN
            if ($lkKey -and $gpoIndex.ContainsKey($lkKey)) { $gpo = $gpoIndex[$lkKey] }

            # A GPO in one domain linked to a container in another is legal but
            # rare, and it is a fragility fact worth surfacing: the link
            # depends on cross-domain SYSVOL reads at every policy refresh.
            $gpoDomain = if ($gpo) { $gpo.Domain } else { $lkDomain }
            $crossDomain = ($gpoDomain -and $c.Domain -ne '(forest-wide)' -and $gpoDomain -ne $c.Domain)

            $rec = [pscustomobject][ordered]@{
                GpoKey        = $lkKey
                GpoId         = $lk.GpoId
                GpoName       = $(if ($gpo) { $gpo.Name } else { '(not found)' })
                GpoDomain     = $gpoDomain
                ContainerName = $c.Name
                ContainerDN   = $c.DN
                ContainerType = $c.Type
                ContainerDomain = $c.Domain
                LinkOrder     = $lk.LinkOrder
                Enabled       = $lk.Enabled
                Enforced      = $lk.Enforced
                BlockInheritance = $c.BlockInheritance
                CrossDomain   = $crossDomain
                Orphaned      = (-not $gpo)
            }
            $allLinks.Add($rec)

            if ($gpo) {
                $gpo.Links = @($gpo.Links) + $rec
                $gpo.LinkCount = @($gpo.Links).Count
            }
        }
    }
    $O.Links = $allLinks.ToArray()

    # ---- WMI filter names onto GPOs, and usage back onto filters ----
    $wmiIndex = @{}
    foreach ($w in $O.WmiFilters) { if ($w.Key) { $wmiIndex[$w.Key] = $w } }
    foreach ($g in $O.Gpos) {
        if (-not $g.WmiFilterId) { continue }
        # A WMI filter is always in the GPO's own domain.
        $wKey = "$($g.Domain)|$($g.WmiFilterId)".ToUpperInvariant()
        if ($wmiIndex.ContainsKey($wKey)) {
            $w = $wmiIndex[$wKey]
            $g.WmiFilterName = $w.Name
            $w.UsedBy = @($w.UsedBy) + [pscustomobject]@{ GpoKey = $g.Key; GpoId = $g.Id; GpoName = $g.Name; Domain = $g.Domain }
        }
        else { $g.WmiFilterName = '(filter not found)' }
    }

    # ---- per-domain counters for the summary block ----
    foreach ($d in $O.Domains) {
        $d.GpoCount = @($O.Gpos | Where-Object { $_.Domain -eq $d.DnsRoot }).Count
        $d.OuCount  = @($O.Containers | Where-Object { $_.Type -eq 'OU' -and $_.Domain -eq $d.DnsRoot }).Count
        $d.WmiFilterCount = @($O.WmiFilters | Where-Object { $_.Domain -eq $d.DnsRoot }).Count
        $d.LinkedGpoCount = @($O.Gpos | Where-Object { $_.Domain -eq $d.DnsRoot -and $_.LinkCount -gt 0 }).Count
    }

    return [pscustomobject]@{ GpoIndex = $gpoIndex; ContainerIndex = $containerIndex }
}

function Build-OutlinePrecedence {
    <#
      Resultant precedence for every container that has policy reaching it.
      Computed entirely from the in-memory model -- no further LDAP.
    #>
    param([Parameter(Mandatory)]$Model)

    $O = $script:Outline
    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($c in $O.Containers) {
        if ($c.Type -eq 'Site') { continue }   # sites are reported separately
        $p = Resolve-OutlinePrecedence -Container $c -ContainerIndex $Model.ContainerIndex -GpoIndex $Model.GpoIndex
        # Containers with nothing reaching them are omitted from the table but
        # still counted, so the report is readable without becoming misleading.
        if ($p.AppliedCount -eq 0 -and @($p.NotApplied).Count -eq 0) { continue }
        $rows.Add($p)
    }

    $O.Precedence = $rows.ToArray()
}

function Build-OutlineLoopbackMap {
    <#
      Loopback is a first-class section because it is the single most common
      reason a reader cannot explain why a policy applied.

      For each GPO that enables it: the mode, where the GPO is linked, and
      therefore which computers fall under it.
    #>
    param()

    $O = $script:Outline
    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($g in $O.Gpos) {
        if (-not $g.Loopback) { continue }

        $scopes = @($g.Links | ForEach-Object { "$($_.ContainerType): $($_.ContainerName)" })
        $explain = if ($g.Loopback -eq 'Replace') {
            'User settings are taken only from the GPOs that apply to the computer. The settings from the user''s own location are not applied.'
        } elseif ($g.Loopback -eq 'Merge') {
            'User settings from the user''s own location are applied first, then the user settings from the GPOs that apply to the computer. Where both set the same thing, the computer''s side wins.'
        } else {
            'The loopback value recorded is not one of the two documented modes.'
        }

        $rows.Add([pscustomobject]@{
            GpoKey   = $g.Key
            GpoId    = $g.Id
            GpoName  = $g.Name
            Domain   = $g.Domain
            Mode     = $g.Loopback
            LinkCount = $g.LinkCount
            Scopes   = $scopes
            ScopeText = $(if ($scopes.Count -gt 0) { $scopes -join '; ' } else { 'Not linked -- has no effect' })
            Explanation = $explain
        })
    }

    $O.Loopback = $rows.ToArray()

    if ($rows.Count -gt 0) {
        Write-OutlineNote ("{0} GPO(s) enable user Group Policy loopback processing." -f $rows.Count)
    }
}

# ==============================================================================
# SETTING INDEX, CONFLICTS AND BEHAVIOUR
# ==============================================================================

function Get-OutlineSettingRows {
    <#
      Flattens one GPO's settings into uniform rows so every downstream view --
      the search index and the conflict map -- works from one
      shape instead of five.

      A setting's IDENTITY (what makes two settings "the same setting" for
      conflict purposes) is deliberately the area plus the key plus the name,
      not the value. Two GPOs setting the same key to the same value still
      overlap; a reader wants to see that.

      NOTE ON THE COMMA OPERATOR
      Every return here is `return ,$rows.ToArray()`. Without the comma,
      PowerShell unrolls an empty array to $null on return, so a GPO with no
      settings -- an empty GPO, a both-halves-disabled GPO, or any GPO whose
      SYSVOL was unreadable -- makes the caller's `.Count` throw under
      StrictMode. Empty GPOs are common in real estates, so this is a crash on
      the ordinary case, not an edge case. The same applies to every
      `.ToArray()` return in this script.
    #>
    param([Parameter(Mandatory)]$Gpo)

    $rows = New-Object System.Collections.Generic.List[object]
    if (-not $Gpo.Settings) { return ,$rows.ToArray() }

    foreach ($halfName in @('Computer','User')) {
        $half = $Gpo.Settings[$halfName]
        if (-not $half) { continue }
        $scope = if ($halfName -eq 'Computer') { 'Computer Configuration' } else { 'User Configuration' }

        # --- Administrative Templates ---
        foreach ($r in @($half['Registry'])) {
            if (-not $r) { continue }
            $friendly = Resolve-AdmxName -Key $r.Key -Value $r.Value
            # A registry value name may legitimately be empty -- that is the
            # key's default value. Falling straight through to $r.Value then
            # produces a nameless row, which is worse than useless in a table
            # whose whole purpose is answering "who sets this?". Fall back to
            # something a reader can actually search for.
            $name = if ($friendly) { $friendly.Name }
                    elseif ($r.Value) { $r.Value }
                    else {
                        $leaf = ($r.Key -split '\\')[-1]
                        if ($leaf) { "(default value of $leaf)" } else { '(default value)' }
                    }
            $rows.Add([pscustomobject]@{
                GpoKey = $Gpo.Key; GpoId = $Gpo.Id; GpoName = $Gpo.Name; Domain = $Gpo.Domain
                Scope = $scope; Area = 'Administrative Templates'
                Name  = $name
                Key   = "$($r.Hive)\$($r.Key)"
                Value = $r.Value
                Data  = $(if ($r.Directive) { "[$($r.Directive)]" } else { $r.Data })
                Type  = $r.Type
                Identity = "AT|$scope|$($r.Key)\$($r.Value)".ToLowerInvariant()
                Resolved = [bool]$friendly
                AdmxMatch = $(if ($friendly) { $friendly.Match } else { $null })
            })
        }

        # --- Security settings ---
        foreach ($r in @($half['Security'])) {
            if (-not $r) { continue }
            $rows.Add([pscustomobject]@{
                GpoKey = $Gpo.Key; GpoId = $Gpo.Id; GpoName = $Gpo.Name; Domain = $Gpo.Domain
                Scope = $scope; Area = $r.Area
                Name  = $r.Name; Key = $r.Section; Value = $r.Setting
                Data  = $r.Value; Type = 'Security'
                Identity = "SEC|$scope|$($r.Section)|$($r.Setting)".ToLowerInvariant()
                Resolved = $true; AdmxMatch = $null
            })
        }

        # --- Scripts ---
        foreach ($r in @($half['Scripts'])) {
            if (-not $r) { continue }
            $rows.Add([pscustomobject]@{
                GpoKey = $Gpo.Key; GpoId = $Gpo.Id; GpoName = $Gpo.Name; Domain = $Gpo.Domain
                Scope = $scope; Area = 'Scripts'
                Name  = "$($r.Trigger) script ($($r.Engine))"
                Key   = $r.Trigger; Value = $r.Script
                Data  = $(if ($r.Parameters) { "$($r.Script) $($r.Parameters)" } else { $r.Script })
                Type  = $r.Engine
                Identity = "SCR|$scope|$($r.Trigger)|$($r.Script)".ToLowerInvariant()
                Resolved = $true; AdmxMatch = $null
            })
        }

        # --- Folder redirection ---
        if ($half.Contains('FolderRedirection')) {
            foreach ($r in @($half['FolderRedirection'])) {
                if (-not $r) { continue }
                $rows.Add([pscustomobject]@{
                    GpoKey = $Gpo.Key; GpoId = $Gpo.Id; GpoName = $Gpo.Name; Domain = $Gpo.Domain
                    Scope = $scope; Area = 'Folder Redirection'
                    Name  = "Redirect $($r.Folder)"; Key = $r.Folder; Value = $r.Mode
                    Data  = (@($r.Targets) -join '; '); Type = 'Redirection'
                    Identity = "FR|$scope|$($r.Folder)".ToLowerInvariant()
                    Resolved = $true; AdmxMatch = $null
                })
            }
        }

        # --- Software installation ---
        foreach ($r in @($half['SoftwareInstall'])) {
            if (-not $r) { continue }
            $rows.Add([pscustomobject]@{
                GpoKey = $Gpo.Key; GpoId = $Gpo.Id; GpoName = $Gpo.Name; Domain = $Gpo.Domain
                Scope = $scope; Area = 'Software Installation'
                Name  = $r.Package; Key = 'Applications'; Value = $r.Package
                Data  = $(if ($r.MsiPath) { $r.MsiPath } else { $r.File }); Type = 'MSI package'
                Identity = "SI|$scope|$($r.Package)".ToLowerInvariant()
                Resolved = $true; AdmxMatch = $null
            })
        }

        # --- Preferences ---
        foreach ($p in @($half['Preferences'])) {
            if (-not $p) { continue }
            foreach ($it in @($p.Items)) {
                if (-not $it) { continue }
                $rows.Add([pscustomobject]@{
                    GpoKey = $Gpo.Key; GpoId = $Gpo.Id; GpoName = $Gpo.Name; Domain = $Gpo.Domain
                    Scope = $scope; Area = $p.Category
                    Name  = $it.Name
                    Key   = $p.Category; Value = $it.Action
                    Data  = $it.Detail; Type = 'Preference'
                    Identity = "GPP|$scope|$($p.Category)|$($it.Name)".ToLowerInvariant()
                    Resolved = $true; AdmxMatch = $null
                    Targeted = $it.Targeted
                    # Get-PropValue, not PSObject.Properties. After -FromState the
                    # items are OrderedDictionary rather than PSCustomObject, and
                    # PSObject.Properties on a dictionary reports the dictionary's
                    # own members (Count, Keys) -- never its entries. The check
                    # therefore silently failed on every re-render, and the
                    # targeting conditions were replaced by "could not be read"
                    # even though they were sitting in the state file.
                    TargetText = (Get-PropValue $it 'TargetText')
                    CPassword = $it.CPassword
                })
            }
        }
    }

    return ,$rows.ToArray()
}

function Build-OutlineSettingIndex {
    <#
      The searchable index of every discrete setting across every GPO -- the
      section that lets an auditor answer "who sets this?" in one place.

      Capped for report size only. The cap is stated in the report when hit;
      counts elsewhere are still computed over everything.
    #>
    param()

    $O = $script:Outline
    $rows = New-Object System.Collections.Generic.List[object]
    $capped = $false
    $total = 0

    foreach ($g in $O.Gpos) {
        $settings = Get-OutlineSettingRows -Gpo $g
        $total += $settings.Count
        foreach ($s in $settings) {
            if ($rows.Count -ge $script:MaxSettingIndex) { $capped = $true; continue }
            $rows.Add($s)
        }
    }

    $O.SettingIndex = $rows.ToArray()
    return [pscustomobject]@{ Total = $total; Indexed = $rows.Count; Capped = $capped }
}

function Build-OutlineConflictMap {
    <#
      Where the same setting is defined by more than one GPO that applies to
      the same container, this shows which GPO wins and which are overridden.

      "Wins" is decided purely by the precedence already computed for that
      container -- the report never guesses. Where two GPOs set the same thing
      to the same value that is stated too, since it is a maintenance fact even
      though nothing actually conflicts at runtime.
    #>
    param()

    $O = $script:Outline
    if (@($O.SettingIndex).Count -eq 0) { $O.Conflicts = @(); return }

    # setting identity -> the GPOs that define it
    $byIdentity = @{}
    foreach ($s in $O.SettingIndex) {
        if (-not $byIdentity.ContainsKey($s.Identity)) {
            $byIdentity[$s.Identity] = New-Object System.Collections.Generic.List[object]
        }
        $byIdentity[$s.Identity].Add($s)
    }

    # Only identities touched by more than one GPO can conflict.
    $contested = @{}
    foreach ($k in $byIdentity.Keys) {
        $gpos = @($byIdentity[$k] | ForEach-Object { $_.GpoKey } | Sort-Object -Unique)
        if ($gpos.Count -gt 1) { $contested[$k] = $byIdentity[$k] }
    }
    if ($contested.Count -eq 0) { $O.Conflicts = @(); return }

    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($p in $O.Precedence) {
        if ($p.AppliedCount -lt 2) { continue }

        # rank lookup for the GPOs applying here (1 = wins)
        $rank = @{}
        foreach ($a in $p.Applied) { if (-not $rank.ContainsKey($a.GpoKey)) { $rank[$a.GpoKey] = $a.Precedence } }

        foreach ($k in $contested.Keys) {
            $defs = @($contested[$k] | Where-Object { $rank.ContainsKey($_.GpoKey) })
            $ids = @($defs | ForEach-Object { $_.GpoKey } | Sort-Object -Unique)
            if ($ids.Count -lt 2) { continue }

            $sorted = @($defs | Sort-Object -Property @{ Expression = { $rank[$_.GpoKey] } })
            $winner = $sorted[0]
            $losers = @($sorted | Select-Object -Skip 1)

            $sameValue = $true
            foreach ($l in $losers) { if ("$($l.Data)" -ne "$($winner.Data)") { $sameValue = $false; break } }

            $rows.Add([pscustomobject]@{
                Container   = $p.Container
                ContainerType = $p.ContainerType
                Domain      = $p.Domain
                Area        = $winner.Area
                Scope       = $winner.Scope
                Setting     = $winner.Name
                WinningGpo  = $winner.GpoName
                WinningValue= $winner.Data
                WinningRank = $rank[$winner.GpoKey]
                OverriddenBy = @($losers | ForEach-Object { "$($_.GpoName) = $($_.Data)" }) -join '; '
                OverriddenCount = $losers.Count
                SameValue   = $sameValue
            })
        }
    }

    # Deterministic order so two runs of the same estate diff cleanly.
    $O.Conflicts = @($rows.ToArray() | Sort-Object Container, Area, Setting)

    if ($O.Conflicts.Count -gt 0) {
        Write-OutlineNote ("{0} setting(s) are defined by more than one GPO applying to the same container." -f $O.Conflicts.Count)
    }
}

function Build-OutlineAnomalies {
    <#
      The factual inventory of things that are structurally notable: orphans,
      version mismatches, empty GPOs, disabled links, SYSVOL/GPC mismatches.

      Every one is documented as a fact. None is scored, and none is presented
      as a fault -- an unlinked GPO may be a staging copy kept deliberately.
    #>
    param()

    $O = $script:Outline

    $unlinked   = @($O.Gpos | Where-Object { $_.LinkCount -eq 0 })
    $emptyGpos  = @($O.Gpos | Where-Object { $_.IsEmpty })
    $allDisabled= @($O.Gpos | Where-Object { $_.Status -eq 'All settings disabled' })
    $mismatch   = @($O.Gpos | Where-Object { $_.VersionMismatch })
    $noSysvol   = @($O.Gpos | Where-Object { -not $_.SysvolReadable -and $_.SysvolReason -and $_.SysvolReason -match '(?i)not found' })
    $disabledLinks = @($O.Links | Where-Object { -not $_.Enabled })
    $orphanLinks   = @($O.Links | Where-Object { $_.Orphaned })
    $crossDomain   = @($O.Links | Where-Object { $_.CrossDomain })
    $noFiltering   = @($O.Gpos | Where-Object { $_.AclReadable -and @($_.Filtering | Where-Object { $_.Access -notmatch 'denied' }).Count -eq 0 })
    $authRemoved   = @($O.Gpos | Where-Object { $_.AclReadable -and -not $_.AuthUsersApply -and $_.LinkCount -gt 0 })
    $cpasswordGpos = @($O.Gpos | Where-Object { $_.Settings -and @($_.Settings.CPassword).Count -gt 0 })

    # SYSVOL folders with no matching GPC. Read once per domain: a folder here
    # with no directory object is a leftover that nothing can apply.
    $strayFolders = New-Object System.Collections.Generic.List[object]
    if (-not $script:SkipSysvolFlag) {
        foreach ($d in $O.Domains) {
            if (-not $d.Collected) { continue }
            $polRoot = "\\$($d.DnsRoot)\SYSVOL\$($d.DnsRoot)\Policies"
            try {
                if (-not (Test-Path -LiteralPath $polRoot)) { continue }
                $known = @{}
                foreach ($g in $O.Gpos) { if ($g.Domain -eq $d.DnsRoot -and $g.Id) { $known[$g.Id] = $true } }
                foreach ($dir in @(Get-ChildItem -LiteralPath $polRoot -Directory -ErrorAction SilentlyContinue)) {
                    if ($dir.Name -notmatch '^\{[0-9A-Fa-f\-]{36}\}$') { continue }
                    if (-not $known.ContainsKey($dir.Name.ToUpper())) {
                        $strayFolders.Add([pscustomobject]@{
                            Domain = $d.DnsRoot; Folder = $dir.Name
                            Modified = Format-OutlineDate $dir.LastWriteTime
                        })
                    }
                }
            }
            catch { Write-OutlineQuiet $_ "StraySysvol:$($d.DnsRoot)" }
        }
    }

    $O.Anomalies = [ordered]@{
        UnlinkedGpos      = @($unlinked    | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Domain = $_.Domain; Id = $_.Id; Status = $_.Status; Settings = $_.SettingCount; Created = $_.Created } })
        EmptyGpos         = @($emptyGpos   | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Domain = $_.Domain; Id = $_.Id; Links = $_.LinkCount } })
        AllDisabledGpos   = @($allDisabled | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Domain = $_.Domain; Id = $_.Id; Links = $_.LinkCount } })
        VersionMismatches = @($mismatch    | ForEach-Object { [pscustomobject]@{
                                Name = $_.Name; Domain = $_.Domain
                                'AD (User/Computer)'     = "$($_.AdVersionUser) / $($_.AdVersionComputer)"
                                'SYSVOL (User/Computer)' = "$($_.SysvolVersionUser) / $($_.SysvolVersionComputer)" } })
        MissingSysvol     = @($noSysvol    | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Domain = $_.Domain; Reason = $_.SysvolReason } })
        StraySysvolFolders= $strayFolders.ToArray()
        DisabledLinks     = @($disabledLinks | ForEach-Object { [pscustomobject]@{ Gpo = $_.GpoName; Container = $_.ContainerName; Type = $_.ContainerType; Domain = $_.ContainerDomain } })
        OrphanedLinks     = @($orphanLinks   | ForEach-Object { [pscustomobject]@{ Container = $_.ContainerName; Type = $_.ContainerType; GpoId = $_.GpoId; Domain = $_.ContainerDomain } })
        CrossDomainLinks  = @($crossDomain   | ForEach-Object { [pscustomobject]@{ Gpo = $_.GpoName; 'GPO domain' = $_.GpoDomain; Container = $_.ContainerName; 'Container domain' = $_.ContainerDomain } })
        NoApplyPrincipal  = @($noFiltering   | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Domain = $_.Domain; Links = $_.LinkCount } })
        AuthUsersRemoved  = @($authRemoved   | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Domain = $_.Domain; 'Applies to' = (@($_.Filtering | Where-Object { $_.Access -notmatch 'denied' } | ForEach-Object { $_.Name }) -join ', ') } })
        CPasswordGpos     = @($cpasswordGpos | ForEach-Object {
                                $g = $_
                                [pscustomobject]@{
                                    Name = $g.Name; Domain = $g.Domain
                                    Items = (@($g.Settings.CPassword | ForEach-Object { "$($_.Category): $($_.Name)" }) -join '; ')
                                    Count = @($g.Settings.CPassword).Count } })
    }

    # ---- observations: factual notes, never findings ----
    if ($unlinked.Count -gt 0)    { Write-OutlineNote ("{0} GPO(s) are not linked to any site, domain or OU." -f $unlinked.Count) }
    if ($emptyGpos.Count -gt 0)   { Write-OutlineNote ("{0} GPO(s) contain no settings." -f $emptyGpos.Count) }
    if ($mismatch.Count -gt 0)    { Write-OutlineNote ("{0} GPO(s) record a different version in the directory than in SYSVOL." -f $mismatch.Count) }
    if ($crossDomain.Count -gt 0) { Write-OutlineNote ("{0} link(s) point at a GPO in a different domain." -f $crossDomain.Count) }
    if ($cpasswordGpos.Count -gt 0) { Write-OutlineNote ("{0} GPO(s) contain a Group Policy Preferences item with a cpassword attribute present." -f $cpasswordGpos.Count) }
    if ($strayFolders.Count -gt 0) { Write-OutlineNote ("{0} SYSVOL policy folder(s) have no matching Group Policy object in the directory." -f $strayFolders.Count) }
}

function Build-OutlineMatrices {
    <#
      The cross-reference views: GPO->OU, OU->GPO, security group usage,
      WMI filter usage, and CSE usage. All computed from memory.
    #>
    param()

    $O = $script:Outline

    # ---- GPO -> containers ----
    $gpoToOu = @($O.Gpos | ForEach-Object {
        $g = $_
        [pscustomobject]@{
            GPO = $g.Name; Domain = $g.Domain; Status = $g.Status
            'Linked to' = $(if ($g.LinkCount -eq 0) { '(not linked)' } else { (@($g.Links | ForEach-Object { "$($_.ContainerName)$(if ($_.Enforced) { ' [enforced]' })$(if (-not $_.Enabled) { ' [link disabled]' })" }) -join '; ') })
            Links = $g.LinkCount
            Settings = $g.SettingCount
        }
    })

    # ---- container -> GPOs in precedence order ----
    $ouToGpo = @($O.Precedence | ForEach-Object {
        $p = $_
        [pscustomobject]@{
            Container = $p.Container; Type = $p.ContainerType; Domain = $p.Domain
            'Block inheritance' = $(if ($p.BlockInheritance) { 'Yes' } else { '' })
            'Applies in order (1 wins)' = (@($p.Applied | ForEach-Object { "$($_.Precedence). $($_.GpoName)$(if ($_.Enforced) { ' [enforced]' })" }) -join '; ')
            Count = $p.AppliedCount
        }
    })

    # ---- security groups used in filtering and delegation ----
    # Counts alone are a dead end: "Enterprise Admins -- used in delegation 175"
    # tells a reader nothing they can act on. Every use is therefore recorded
    # individually as well, so the count can be backed by the list behind it.
    $groupUse = @{}
    $groupWhere = @{}

    foreach ($g in $O.Gpos) {
        foreach ($f in @($g.Filtering)) {
            if (-not $f) { continue }
            $k = $f.Name
            if (-not $groupUse.ContainsKey($k)) {
                $groupUse[$k] = [ordered]@{ Name = $k; Sid = $f.Sid; Filtering = 0; Delegation = 0; Resolved = $f.Resolved }
                $groupWhere[$k] = New-Object System.Collections.Generic.List[object]
            }
            $groupUse[$k].Filtering++
            $groupWhere[$k].Add([pscustomobject]@{
                Usage = 'Security filtering'; GpoKey = $g.Key; GPO = $g.Name; Domain = $g.Domain
                Rights = $f.Access
                Effect = $(if ($f.Access -match '(?i)denied') { 'Explicitly denied -- this GPO does not apply to this principal' }
                           elseif ($f.Access -match '(?i)apply') { 'This GPO applies to this principal' }
                           else { 'Can read the GPO but it does not apply' })
            })
        }
        foreach ($d in @($g.Delegation)) {
            if (-not $d) { continue }
            $k = $d.Name
            if (-not $groupUse.ContainsKey($k)) {
                $groupUse[$k] = [ordered]@{ Name = $k; Sid = $d.Sid; Filtering = 0; Delegation = 0; Resolved = $d.Resolved }
                $groupWhere[$k] = New-Object System.Collections.Generic.List[object]
            }
            $groupUse[$k].Delegation++
            $groupWhere[$k].Add([pscustomobject]@{
                Usage = 'Delegation'; GpoKey = $g.Key; GPO = $g.Name; Domain = $g.Domain
                Rights = $d.Rights
                Effect = $(if ($d.CanEdit) { 'Can change the settings in this GPO' } else { 'Holds rights on this GPO short of editing settings' })
            })
        }
    }

    # Per-principal detail, ordered so the editing rights a reader most wants to
    # see come first.
    $principalDetail = @($groupUse.Keys | ForEach-Object {
        $k = $_
        $uses = @($groupWhere[$k].ToArray() | Sort-Object @{ Expression = { $_.Usage } }, Domain, GPO)
        [pscustomobject]@{
            Principal  = $k
            Sid        = $groupUse[$k].Sid
            Resolved   = $groupUse[$k].Resolved
            Slug       = (Get-OutlineSlug $k)
            Filtering  = $groupUse[$k].Filtering
            Delegation = $groupUse[$k].Delegation
            Total      = $groupUse[$k].Filtering + $groupUse[$k].Delegation
            CanEditCount = @($uses | Where-Object { $_.Effect -like 'Can change*' }).Count
            Uses       = $uses
        }
    } | Sort-Object Total -Descending)
    $groupRows = @($principalDetail | ForEach-Object {
        [pscustomobject]@{
            Principal = $_.Principal
            'Used in filtering' = $_.Filtering
            'Used in delegation' = $_.Delegation
            'Can edit' = $_.CanEditCount
            Resolved = $(if ($_.Resolved) { 'Yes' } else { 'No -- SID could not be translated' })
            Slug = $_.Slug
        }
    })

    # ---- WMI filter usage ----
    $wmiRows = @($O.WmiFilters | ForEach-Object {
        [pscustomobject]@{
            Filter = $_.Name; Domain = $_.Domain
            'Used by' = $(if (@($_.UsedBy).Count -eq 0) { '(not used)' } else { (@($_.UsedBy | ForEach-Object { $_.GpoName }) -join '; ') })
            Count = @($_.UsedBy).Count
            Query = (@($_.Queries | ForEach-Object { $_.Query }) -join ' | ')
        }
    })

    # ---- CSE usage across the estate ----
    $cseUse = @{}
    foreach ($g in $O.Gpos) {
        foreach ($half in @(@('Computer', $g.MachineCse), @('User', $g.UserCse))) {
            foreach ($c in @($half[1])) {
                if (-not $c) { continue }
                $k = $c.Name
                if (-not $cseUse.ContainsKey($k)) {
                    $cseUse[$k] = [ordered]@{ Name = $k; Guid = $c.Guid; Area = $c.Area; Computer = 0; User = 0; Resolved = $c.Resolved }
                }
                $cseUse[$k][$half[0]]++
            }
        }
    }
    $cseRows = @($cseUse.Keys | ForEach-Object {
        $v = $cseUse[$_]
        [pscustomobject]@{
            Extension = $v.Name; Area = $v.Area
            'Computer half' = $v.Computer; 'User half' = $v.User
            Total = $v.Computer + $v.User
            GUID = $v.Guid
        }
    } | Sort-Object Total -Descending)

    $O.Matrices = [ordered]@{
        GpoToContainer = $gpoToOu
        ContainerToGpo = $ouToGpo
        GroupUsage     = $groupRows
        PrincipalDetail = $principalDetail
        WmiUsage       = $wmiRows
        CseUsage       = $cseRows
    }
}

function Build-OutlineBehavior {
    <#
      The "how does this policy layer actually behave" views: processing flags,
      slow/synchronous indicators, setting footprint, tattooing, and GPOs with
      no runtime effect.

      All documentary. "This adds logon cost" is a statement about mechanics,
      not a grade -- an estate may accept that cost knowingly.
    #>
    param()

    $O = $script:Outline

    # ---- per-GPO processing flags ----
    $flags = @($O.Gpos | ForEach-Object {
        $g = $_
        $notes = New-Object System.Collections.Generic.List[string]
        if ($g.Loopback) { $notes.Add("Loopback: $($g.Loopback)") }
        if ($g.WmiFilterName) { $notes.Add("WMI filtered: $($g.WmiFilterName)") }
        if (-not $g.UserEnabled) { $notes.Add('User half disabled') }
        if (-not $g.ComputerEnabled) { $notes.Add('Computer half disabled') }
        if (@($g.Links | Where-Object { $_.Enforced }).Count -gt 0) { $notes.Add('Enforced on at least one link') }
        if ($g.AclReadable -and -not $g.AuthUsersApply) { $notes.Add('Authenticated Users does not have Apply') }

        [pscustomobject]@{
            GPO = $g.Name; Domain = $g.Domain
            'Client-side extensions' = (@(@($g.MachineCse) + @($g.UserCse) | Where-Object { $_ } | ForEach-Object { $_.Name } | Sort-Object -Unique) -join ', ')
            'Processing notes' = $(if ($notes.Count -gt 0) { $notes.ToArray() -join '; ' } else { 'Standard processing' })
        }
    })

    # ---- slow / synchronous processing indicators ----
    $slow = New-Object System.Collections.Generic.List[object]
    foreach ($g in $O.Gpos) {
        $hits = New-Object System.Collections.Generic.List[string]
        foreach ($c in @(@($g.MachineCse) + @($g.UserCse))) {
            if (-not $c) { continue }
            foreach ($k in $script:CseSynchronous.Keys) {
                if ($k -ieq $c.Guid) { $hits.Add($script:CseSynchronous[$k]) }
            }
        }
        # AlwaysWaitForNetwork forces synchronous foreground policy at boot.
        if ($g.Settings) {
            foreach ($r in @($g.Settings.Computer.Registry)) {
                if ($r -and $r.Value -eq 'SyncForegroundPolicy') { $hits.Add('Always wait for the network at computer startup and logon is configured, which forces synchronous foreground processing.') }
            }
        }
        if ($hits.Count -eq 0) { continue }
        $slow.Add([pscustomobject]@{
            GPO = $g.Name; Domain = $g.Domain; Links = $g.LinkCount
            'Why it affects logon or boot' = (@($hits.ToArray() | Sort-Object -Unique) -join ' ')
        })
    }

    # ---- setting footprint by area ----
    $areaCount = @{}
    $areaGpos  = @{}
    foreach ($s in $O.SettingIndex) {
        if (-not $areaCount.ContainsKey($s.Area)) { $areaCount[$s.Area] = 0; $areaGpos[$s.Area] = @{} }
        $areaCount[$s.Area]++
        $areaGpos[$s.Area][$s.GpoKey] = $true
    }
    $footprint = @($areaCount.Keys | ForEach-Object {
        [pscustomobject]@{
            Area = $_; Settings = $areaCount[$_]; 'GPOs touching it' = $areaGpos[$_].Count
        }
    } | Sort-Object Settings -Descending)

    # ---- tattooing ----
    # Preference items and registry writes outside the four managed policy
    # branches are not reverted when the GPO stops applying.
    $managedRoots = @(
        'software\policies', 'software\microsoft\windows\currentversion\policies'
    )
    $tattoo = New-Object System.Collections.Generic.List[object]
    foreach ($g in $O.Gpos) {
        $prefCount = 0; $unmanaged = 0
        if ($g.Settings) {
            foreach ($halfName in @('Computer','User')) {
                $half = $g.Settings[$halfName]
                if (-not $half) { continue }
                foreach ($p in @($half['Preferences'])) { if ($p) { $prefCount += @($p.Items).Count } }
                foreach ($r in @($half['Registry'])) {
                    if (-not $r) { continue }
                    $k = "$($r.Key)".ToLowerInvariant()
                    $isManaged = $false
                    foreach ($m in $managedRoots) { if ($k.StartsWith($m)) { $isManaged = $true; break } }
                    if (-not $isManaged) { $unmanaged++ }
                }
            }
        }
        if ($prefCount -eq 0 -and $unmanaged -eq 0) { continue }
        $tattoo.Add([pscustomobject]@{
            GPO = $g.Name; Domain = $g.Domain
            'Preference items' = $prefCount
            'Registry writes outside the managed policy branches' = $unmanaged
            'Effect' = 'These values are not removed when the GPO stops applying.'
        })
    }

    # ---- GPOs with no runtime effect ----
    $noEffect = New-Object System.Collections.Generic.List[object]
    foreach ($g in $O.Gpos) {
        $why = New-Object System.Collections.Generic.List[string]
        if ($g.LinkCount -eq 0) { $why.Add('not linked anywhere') }
        elseif (@($g.Links | Where-Object { $_.Enabled }).Count -eq 0) { $why.Add('every link is disabled') }
        if ($g.Status -eq 'All settings disabled') { $why.Add('both halves are disabled') }
        if ($g.IsEmpty) { $why.Add('contains no settings') }
        if ($g.AclReadable -and @($g.Filtering | Where-Object { $_.Access -notmatch 'denied' }).Count -eq 0) { $why.Add('no principal has both Read and Apply') }
        if ($why.Count -eq 0) { continue }
        $noEffect.Add([pscustomobject]@{
            GPO = $g.Name; Domain = $g.Domain
            'Why it has no runtime effect' = ($why.ToArray() -join '; ')
        })
    }

    $O.Behavior = [ordered]@{
        ProcessingFlags = $flags
        SlowProcessing  = $slow.ToArray()
        Footprint       = $footprint
        Tattooing       = $tattoo.ToArray()
        NoEffect        = $noEffect.ToArray()
    }
}

function Build-OutlineStats {
    <# Headline counters used by the summary cards and the charts. #>
    param()

    $O = $script:Outline
    $g = @($O.Gpos)

    $O.Stats = [ordered]@{
        Domains        = @($O.Domains).Count
        DomainControllers = @($O.DCs.PSBase.Keys).Count
        Gpos           = $g.Count
        LinkedGpos     = @($g | Where-Object { $_.LinkCount -gt 0 }).Count
        UnlinkedGpos   = @($g | Where-Object { $_.LinkCount -eq 0 }).Count
        EmptyGpos      = @($g | Where-Object { $_.IsEmpty }).Count
        DisabledGpos   = @($g | Where-Object { $_.Status -eq 'All settings disabled' }).Count
        PartlyDisabled = @($g | Where-Object { $_.Status -like '*settings disabled' -and $_.Status -ne 'All settings disabled' }).Count
        Ous            = @($O.Containers | Where-Object { $_.Type -eq 'OU' }).Count
        OusWithLinks   = @($O.Containers | Where-Object { $_.Type -eq 'OU' -and @($_.Links).Count -gt 0 }).Count
        OusBlocking    = @($O.Containers | Where-Object { $_.Type -eq 'OU' -and $_.BlockInheritance }).Count
        Sites          = @($O.Sites).Count
        SiteLinkedGpos = @($O.Links | Where-Object { $_.ContainerType -eq 'Site' }).Count
        TotalLinks     = @($O.Links).Count
        EnforcedLinks  = @($O.Links | Where-Object { $_.Enforced }).Count
        DisabledLinks  = @($O.Links | Where-Object { -not $_.Enabled }).Count
        WmiFilters     = @($O.WmiFilters).Count
        WmiFilteredGpos= @($g | Where-Object { $_.WmiFilterId }).Count
        LoopbackGpos   = @($O.Loopback).Count
        Settings       = @($O.SettingIndex).Count
        Conflicts      = @($O.Conflicts).Count
        Trusts         = @($O.Trusts).Count
        VersionMismatch= @($g | Where-Object { $_.VersionMismatch }).Count
        CPasswordGpos  = @($g | Where-Object { $_.Settings -and @($_.Settings.CPassword).Count -gt 0 }).Count
    }
}

# ==============================================================================
# HTML HELPERS
# ==============================================================================

function Get-OutlineSlug {
    <#
      A stable, HTML-safe anchor id for an arbitrary name.

      Principal names contain backslashes and spaces, and GPO names contain
      almost anything, so neither can be used as a fragment id directly. A short
      hash is appended because slugging alone collides -- "CONTOSO\Admins" and
      "CONTOSO-Admins" would otherwise produce the same anchor and the wrong
      target would open.
    #>
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return 'x' }

    $slug = ($Text.ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-')
    if ($slug.Length -gt 40) { $slug = $slug.Substring(0, 40).Trim('-') }

    $md5 = [System.Security.Cryptography.MD5]::Create()
    try {
        $h = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))
        $suffix = -join ($h[0..3] | ForEach-Object { $_.ToString('x2') })
    }
    finally { $md5.Dispose() }

    if (-not $slug) { return "x-$suffix" }
    return "$slug-$suffix"
}

function ConvertTo-OutlineHtmlText {
    param($Value)
    if ($null -eq $Value) { return '' }
    $s = [string]$Value
    $s = $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;'
    return $s
}

function Format-OutlineCellValue {
    <#
      Binary policy values -- EFS blobs, CRLs, certificate stores -- run to
      hundreds of bytes of hex. Printing them inline is factually correct but
      makes the setting index unscannable and inflates the report substantially,
      so anything past the threshold collapses to a byte count with the hex
      behind a disclosure. Nothing is discarded: it is one click away, and the
      full value is always in the state file.

      Only hex dumps collapse. Long prose is left alone, because truncating a
      readable value would cost the reader something.
    #>
    param($Value, [int]$Threshold = 96)

    $s = [string]$Value
    if ([string]::IsNullOrEmpty($s) -or $s.Length -le $Threshold) { return ConvertTo-OutlineHtmlText $s }
    if ($s -notmatch '^(?:[0-9a-fA-F]{2}[ ,]){8,}') { return ConvertTo-OutlineHtmlText $s }

    $bytes = if ($s -match '\((\d+) bytes\)') { "$($Matches[1]) bytes" }
             else { "$([math]::Floor((($s -replace '[^0-9a-fA-F]','').Length) / 2)) bytes" }

    return "<details class='blob'><summary>binary, $(ConvertTo-OutlineHtmlText $bytes)</summary><code>$(ConvertTo-OutlineHtmlText $s)</code></details>"
}

function New-HtmlTable {
    # -RawColumns names columns whose values are already rendered HTML (a count
    # link, a badge) and must not be escaped again. Everything else is escaped,
    # so the default stays safe and only deliberate exceptions bypass it.
    param([object[]]$Rows, [string[]]$Columns, [string]$Empty = 'No data collected.',
          [int]$MaxRows = 0, [string[]]$RawColumns = @())
    if (-not $Rows -or $Rows.Count -eq 0) { return "<p class='muted'>$(ConvertTo-OutlineHtmlText $Empty)</p>" }

    $note = ''
    $use = $Rows
    if ($MaxRows -gt 0 -and $Rows.Count -gt $MaxRows) {
        $use = $Rows[0..($MaxRows - 1)]
        $note = "<p class='muted'>Showing the first $MaxRows of $($Rows.Count) rows. The full set is in the state file and the embedded data.</p>"
    }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<div class='tw'><table><thead><tr>")
    foreach ($c in $Columns) { [void]$sb.Append("<th>$(ConvertTo-OutlineHtmlText $c)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in $use) {
        [void]$sb.Append('<tr>')
        foreach ($c in $Columns) {
            $v = $null
            try { $v = $r.$c } catch { $v = $null }
            if ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) {
                $v = (@($v) | ForEach-Object { [string]$_ }) -join ', '
            }
            # The length test is inline and the helper is called only when it can
            # possibly matter. PowerShell function-call overhead is ~80us, and a
            # 5,000-setting estate renders ~50,000 cells, so calling a helper
            # unconditionally per cell cost ~6s of pure dispatch. Same lesson as
            # the PReg hot loop: at this cardinality the call is the cost, not
            # the work inside it.
            $vs = [string]$v
            if ($RawColumns -contains $c) { [void]$sb.Append("<td>$vs</td>") }
            elseif ($vs.Length -gt 96)    { [void]$sb.Append("<td>$(Format-OutlineCellValue $vs)</td>") }
            else                          { [void]$sb.Append("<td>$(ConvertTo-OutlineHtmlText $vs)</td>") }
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    [void]$sb.Append($note)
    return $sb.ToString()
}

function New-CountLink {
    <#
      Renders a count as a link to the detail behind it, or as plain text when
      there is nothing to link to.

      A bare "175" in a usage table is a dead end: it tells a reader the scale of
      something without letting them see what it consists of. Zero stays plain --
      linking to an empty list wastes a click.
    #>
    param($Count, [string]$Target, [string]$Title)
    $n = 0
    if (-not [int]::TryParse("$Count", [ref]$n)) { return ConvertTo-OutlineHtmlText $Count }
    if ($n -le 0 -or -not $Target) { return "<span class='cz'>0</span>" }
    $t = if ($Title) { " title=`"$(ConvertTo-OutlineHtmlText $Title)`"" } else { '' }
    return "<a class='cl-link' href='#$Target'$t>$n</a>"
}

function New-StatCard {
    param([string]$Value, [string]$Label, [string]$Color = 'var(--accent)')
    return "<div class='card'><div class='cv' style='color:$Color'>$(ConvertTo-OutlineHtmlText $Value)</div><div class='cl'>$(ConvertTo-OutlineHtmlText $Label)</div></div>"
}

function New-InfoRow {
    param([string]$Label, [string]$Value, [switch]$Raw)
    $v = if ($Raw) { $Value } else { ConvertTo-OutlineHtmlText $Value }
    return "<div class='ic'><span class='il'>$(ConvertTo-OutlineHtmlText $Label)</span><span class='iv'>$v</span></div>"
}

function Get-PropValue {
    <# Safe property read across both hashtable and PSCustomObject state shapes. #>
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Get-PropArray {
    param($Object, [string]$Name)
    $v = Get-PropValue $Object $Name
    if ($null -eq $v) { return @() }
    return @($v)
}

# ==============================================================================
# THEME
#
# The :root block, component classes, chart palette and print stylesheet are
# taken from ADOutline unchanged. GPOOutline is a sibling in the Outline series
# and must be visually indistinguishable as one -- this is deliberate reuse,
# not duplication.
# ==============================================================================

$script:OutlineCss = @'
*{box-sizing:border-box;margin:0;padding:0}
:root{
/* True navy base with a royal-blue accent, tuned for long reading on screen. */
--bg:#070f1f;--bg2:#0b172c;--surface:#111f38;--surface2:#1a2c4a;--border:#27405f;
--border-soft:#1e3350;--text:#e8eefb;--text-dim:#a3b5d0;--text-mute:#6b83a3;
--accent:#4d8dfa;--accent-deep:#1d4ed8;--accent2:#38bdf8;--green:#34d399;
--amber:#fbbf24;--red:#f87171;--purple:#a78bfa;--orange:#fb923c;--pink:#f472b6;
--radius:10px;--radius-sm:6px;
--shadow:0 1px 2px rgba(0,0,0,.45),0 6px 22px rgba(0,0,0,.32);
--mono:"Cascadia Code",ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;
--sans:"Segoe UI Variable Display","Segoe UI",Inter,Roboto,-apple-system,Helvetica,Arial,sans-serif}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:14px;
line-height:1.6;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
::selection{background:rgba(77,141,250,.32)}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:#27405f;border-radius:5px;border:2px solid var(--bg)}
::-webkit-scrollbar-thumb:hover{background:#3a5a80}

/* ---------- top bar ---------- */
.topbar{position:sticky;top:0;z-index:50;height:54px;display:flex;align-items:center;
gap:16px;padding:0 22px 0 272px;background:rgba(7,15,31,.86);
backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
border-bottom:1px solid var(--border-soft)}
.topbar .tb-title{font-size:.88rem;font-weight:700;color:#fff;letter-spacing:-.01em;
white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.topbar .tb-title em{font-style:normal;color:var(--accent)}
.topbar .tb-title span{color:var(--text-mute);font-weight:400;letter-spacing:0}
.topbar .tb-meta{margin-left:auto;font-size:.72rem;color:var(--text-mute);
white-space:nowrap;display:flex;align-items:center;gap:14px}
.tb-btn{border:1px solid var(--border);background:var(--surface);color:var(--text-dim);
font:inherit;font-size:.72rem;padding:5px 12px;border-radius:99px;cursor:pointer;
transition:all .15s ease;white-space:nowrap}
.tb-btn:hover{border-color:var(--accent);color:var(--accent);background:rgba(77,141,250,.1)}
.tb-btn:focus-visible{outline:2px solid var(--accent);outline-offset:2px}

.wrapper{display:flex;min-height:100vh}

/* ---------- sidebar ---------- */
.sidebar{width:250px;background:#050b17;border-right:1px solid var(--border-soft);
padding:0 0 28px;position:fixed;top:0;height:100vh;overflow-y:auto;z-index:60}
.logo{padding:20px 18px 15px;border-bottom:1px solid var(--border-soft)}
.logo h2{font-size:1.2rem;color:#fff;letter-spacing:-.02em;font-weight:700}
.logo h2 em{font-style:normal;color:var(--accent)}
.logo p{font-size:.7rem;color:var(--text-mute);margin-top:3px;letter-spacing:.01em}
.byline{margin-top:13px;padding-top:11px;border-top:1px solid var(--border-soft)}
.byline p{font-size:.68rem;line-height:1.55;margin-top:2px;color:var(--text-mute)}
.byline strong{color:var(--text-dim);font-weight:600}
.byline .links{margin-top:7px;display:flex;gap:9px}
.byline a{color:var(--accent);text-decoration:none;font-size:.68rem}
.byline a:hover{text-decoration:underline}
.logo .forest{margin-top:12px;padding:9px 11px;border-radius:var(--radius-sm);
background:rgba(77,141,250,.09);border:1px solid rgba(77,141,250,.2);font-size:.72rem;color:var(--text-mute)}
.logo .forest strong{color:var(--accent2);display:block;font-size:.82rem;margin-top:1px;word-break:break-all}
nav{padding-top:6px}
nav a{display:block;padding:6px 18px 6px 17px;color:var(--text-mute);text-decoration:none;
font-size:.785rem;border-left:3px solid transparent;transition:all .13s ease}
nav a:hover{background:rgba(77,141,250,.07);color:var(--text)}
nav a.active{color:var(--accent);border-left-color:var(--accent);
background:linear-gradient(90deg,rgba(77,141,250,.15),transparent)}
.ng{display:flex;align-items:center;gap:7px;padding:14px 16px 6px 17px;margin-top:2px;
font-size:.66rem;text-transform:uppercase;letter-spacing:.15em;color:var(--accent2);
font-weight:800;cursor:pointer;user-select:none;transition:color .13s ease}
.ng:hover{color:#7dd3fc}
.ng .chev{margin-left:auto;flex-shrink:0;width:9px;height:9px;
border-right:2px solid currentColor;border-bottom:2px solid currentColor;
transform:rotate(45deg) translate(-1px,-1px);transition:transform .18s ease;opacity:.75}
.ng.collapsed .chev{transform:rotate(-45deg) translate(-1px,1px)}
.ng:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
.nav-group{overflow:hidden;transition:max-height .22s ease}
.nav-group.collapsed{max-height:0!important}

/* ---------- main ---------- */
.main{margin-left:250px;padding:0 34px 40px;flex:1;min-width:0}
.hero{background:
radial-gradient(900px 230px at 10% -12%,rgba(77,141,250,.20),transparent 68%),
radial-gradient(620px 200px at 90% 0%,rgba(56,189,248,.10),transparent 70%),
linear-gradient(160deg,#132747,#08152b);
border:1px solid var(--border-soft);border-radius:14px;padding:28px 30px;
margin:0 0 26px;box-shadow:var(--shadow);position:relative;overflow:hidden}
.hero h1{font-size:1.95rem;font-weight:700;color:#fff;letter-spacing:-.03em;line-height:1.12}
.hero h1 em{font-style:normal;color:var(--accent)}
.hero .sub{font-size:.84rem;color:var(--accent2);margin-top:5px;
letter-spacing:.06em;text-transform:uppercase;font-weight:600}
.hero .meta{margin-top:14px;display:flex;flex-wrap:wrap;gap:9px;
font-size:.74rem;color:var(--text-mute)}
.hero .meta b{color:var(--text-dim);font-weight:600}
.section{background:linear-gradient(160deg,var(--surface),#0d1c33);
border:1px solid var(--border-soft);border-radius:12px;padding:22px 24px;
margin-bottom:20px;box-shadow:var(--shadow);scroll-margin-top:70px}
.sec-eyebrow{font-size:.62rem;text-transform:uppercase;letter-spacing:.14em;
color:var(--accent2);font-weight:700;margin-bottom:7px;display:flex;align-items:center;gap:9px}
.sec-eyebrow::before{content:"";width:16px;height:2px;background:var(--accent);border-radius:1px;flex-shrink:0}
.st{font-size:1.22rem;margin-bottom:6px;display:flex;align-items:center;gap:11px;
color:#fff;font-weight:650;letter-spacing:-.015em}
.st .ico{width:29px;height:29px;border-radius:8px;display:inline-flex;align-items:center;
justify-content:center;font-size:.85rem;flex-shrink:0}
.sd{color:var(--text-mute);font-size:.79rem;margin-bottom:15px;max-width:96ch}
.sub-h{font-size:.7rem;color:var(--accent2);margin:20px 0 9px;font-weight:700;
text-transform:uppercase;letter-spacing:.1em;display:flex;align-items:center;gap:9px}
.sub-h::after{content:"";flex:1;height:1px;background:var(--border-soft)}

/* ---------- cards ---------- */
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:16px}
.card{background:linear-gradient(160deg,var(--surface),#0d1c33);border:1px solid var(--border-soft);
border-radius:var(--radius);padding:16px 13px;text-align:center;transition:transform .15s ease,border-color .15s ease}
.card:hover{transform:translateY(-2px);border-color:#3a5a86;box-shadow:var(--shadow)}
.cv{font-size:1.7rem;font-weight:700;letter-spacing:-.03em;line-height:1.1;font-variant-numeric:tabular-nums}
.cl{font-size:.65rem;color:var(--text-mute);text-transform:uppercase;letter-spacing:.09em;margin-top:5px;font-weight:600}
.ig{display:grid;grid-template-columns:repeat(auto-fit,minmax(258px,1fr));gap:10px;margin-bottom:15px}
.ic{background:var(--surface);border:1px solid var(--border-soft);border-radius:var(--radius);
padding:11px 14px;border-left:3px solid var(--accent)}
.il{display:block;font-size:.63rem;text-transform:uppercase;letter-spacing:.09em;
color:var(--text-mute);font-weight:600}
.iv{display:block;font-size:.86rem;margin-top:3px;word-break:break-word;color:var(--text)}

/* ---------- tables ---------- */
.tw{overflow:auto;max-height:660px;border:1px solid var(--border-soft);
border-radius:var(--radius);margin-bottom:15px;background:var(--surface)}
table{border-collapse:separate;border-spacing:0;width:100%;font-size:.785rem}
th{position:sticky;top:0;z-index:2;background:#172c4c;color:var(--text);text-align:left;
padding:10px 13px;font-weight:650;white-space:nowrap;font-size:.7rem;
text-transform:uppercase;letter-spacing:.055em;border-bottom:1px solid var(--border)}
td{padding:8px 13px;border-bottom:1px solid rgba(51,65,85,.42);color:var(--text-dim);vertical-align:top}
tr:last-child td{border-bottom:none}
tbody tr{transition:background .1s ease}
tbody tr:nth-child(even) td{background:rgba(255,255,255,.014)}
tbody tr:hover td{background:rgba(77,141,250,.08);color:var(--text)}
td:first-child{color:var(--text);font-weight:500}
.muted{color:var(--text-mute);font-size:.79rem;font-style:italic;padding:11px 13px;
background:var(--surface);border:1px dashed var(--border);border-radius:var(--radius);margin-bottom:14px}
.b{display:inline-block;padding:1px 8px;border-radius:99px;font-size:.66rem;
font-weight:650;letter-spacing:.02em}
.b-ok{background:rgba(52,211,153,.14);color:var(--green);border:1px solid rgba(52,211,153,.28)}
.b-w{background:rgba(251,191,36,.14);color:var(--amber);border:1px solid rgba(251,191,36,.28)}
.b-e{background:rgba(248,113,113,.14);color:var(--red);border:1px solid rgba(248,113,113,.28)}
.b-i{background:rgba(77,141,250,.15);color:var(--accent);border:1px solid rgba(77,141,250,.3)}
.tools{display:flex;gap:8px;margin-bottom:8px;align-items:center}
.tsearch{background:var(--surface);border:1px solid var(--border);color:var(--text);
font:inherit;font-size:.74rem;padding:5px 11px;border-radius:99px;width:210px}
.tsearch:focus{outline:none;border-color:var(--accent)}
.tcount{font-size:.7rem;color:var(--text-mute)}

/* ---------- purpose / disclaimer ---------- */
.about{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:14px;margin-bottom:26px}
.ac{background:var(--surface);border:1px solid var(--border-soft);border-radius:var(--radius);
padding:17px 19px;border-top:3px solid var(--accent)}
.ac.d{border-top-color:var(--amber)}
.ac h3{font-size:.7rem;text-transform:uppercase;letter-spacing:.11em;margin-bottom:10px;font-weight:700}
.ac.p h3{color:var(--accent)}
.ac.d h3{color:var(--amber)}
.ac p{margin-bottom:8px;font-size:.785rem;line-height:1.68;color:var(--text-mute)}
.ac p:last-child{margin-bottom:0}
.ac strong{color:var(--text-dim);font-weight:600}
.ac a{color:var(--accent);text-decoration:none;border-bottom:1px dotted rgba(96,165,250,.5)}
.ac a:hover{border-bottom-style:solid}
.ft-services{margin:16px auto 0;max-width:760px;padding:12px 16px;border-radius:9px;
background:rgba(96,165,250,.07);border:1px solid rgba(96,165,250,.22);
font-size:.78rem;line-height:1.6;color:var(--text-mute);text-align:left}
.ft-services strong{color:var(--text-dim)}
.ft-services a{color:var(--accent);text-decoration:none}
.ft-services a:hover{text-decoration:underline}
.section::after{content:'Group Policy current-state documentation generated by GPOOutline \2014 developed by Santhosh Sivarajan, Microsoft MVP';
display:block;margin-top:15px;padding-top:9px;border-top:1px solid var(--border-soft);
font-size:.64rem;letter-spacing:.02em;color:var(--text-mute);opacity:.6}
.section:hover::after{opacity:.85}
@media print{.section::after{opacity:1;color:#555}}
.series{margin-top:11px;padding-top:10px;border-top:1px solid var(--border-soft)}
.series-row{display:flex;align-items:baseline;gap:8px;padding:3px 0;font-size:.755rem;
line-height:1.5;color:var(--text-mute)}
.series-row .sn{flex:0 0 78px;font-weight:700;color:var(--accent)}
.series-row.self{color:var(--text-dim)}
.series-row.self .sn{color:var(--text)}
.series-row .sv{flex:1}
.series-row .self-tag{font-size:.62rem;text-transform:uppercase;letter-spacing:.09em;
color:var(--text-mute);background:rgba(96,165,250,.12);border-radius:99px;padding:1px 7px;
margin-left:6px}
.obs-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:13px;margin-bottom:16px}
.obs-col{background:var(--surface);border:1px solid var(--border-soft);border-radius:var(--radius);
padding:13px 16px;border-left:3px solid var(--accent2)}
.obs-col h5{font-size:.68rem;text-transform:uppercase;letter-spacing:.1em;color:var(--accent2);
font-weight:700;margin-bottom:8px;display:flex;align-items:center;gap:8px}
.obs-col h5 span{background:rgba(56,189,248,.15);color:var(--accent2);border-radius:99px;
padding:1px 8px;font-size:.66rem}
.obs-col ul{list-style:none;margin:0;padding:0}
.obs-col li{font-size:.76rem;line-height:1.6;color:var(--text-dim);padding:4px 0 4px 13px;
position:relative;border-bottom:1px solid rgba(51,65,85,.4)}
.obs-col li:last-child{border-bottom:none}
.obs-col li::before{content:"";position:absolute;left:0;top:11px;width:4px;height:4px;
border-radius:50%;background:var(--accent2);opacity:.6}
.warn{background:linear-gradient(90deg,rgba(251,191,36,.1),rgba(251,191,36,.02));
border-left:3px solid var(--amber);border-radius:var(--radius-sm);
padding:10px 14px;margin-bottom:8px;font-size:.79rem;color:var(--text-dim)}

/* ---------- charts ---------- */
.chart-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(360px,1fr));gap:14px;margin-bottom:18px}
.cbox{background:var(--surface);border:1px solid var(--border-soft);border-radius:var(--radius);
padding:17px;box-shadow:var(--shadow)}
.cbox h4{font-size:.7rem;margin-bottom:13px;color:var(--text);font-weight:700;
text-transform:uppercase;letter-spacing:.09em}
.legend{font-size:.71rem;color:var(--text-mute);margin-top:10px}
.legend div{display:flex;align-items:center;gap:7px;margin-bottom:4px}
.sw{width:9px;height:9px;border-radius:3px;flex-shrink:0}
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:7px;font-size:.735rem}
.bar-lbl{width:190px;text-align:right;color:var(--text-mute);flex-shrink:0;
overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar-track{flex:1;background:#0a1730;border-radius:99px;height:15px;overflow:hidden}
.bar-fill{height:100%;border-radius:99px;transition:width .5s cubic-bezier(.4,0,.2,1)}
.bar-val{width:60px;color:var(--text);flex-shrink:0;font-variant-numeric:tabular-nums;font-weight:600}

/* ---------- diagrams ---------- */
.dwrap{display:flex;gap:15px;align-items:flex-start;background:var(--surface);
border:1px solid var(--border-soft);border-radius:var(--radius);padding:16px;
margin-bottom:10px;overflow-x:auto;box-shadow:var(--shadow)}
.dwrap>svg{flex:1 1 auto;min-width:0;max-width:100%}
.dpanel{width:258px;flex:0 0 258px;background:#0e1e38;
border:1px solid var(--border-soft);border-radius:var(--radius-sm);padding:13px;
font-size:.75rem;max-height:470px;overflow-y:auto}
.dpanel h4{color:var(--accent);font-size:.85rem;margin-bottom:10px;word-break:break-all}
.dpanel h5{color:var(--accent2);font-size:.65rem;text-transform:uppercase;
letter-spacing:.09em;margin:12px 0 6px;font-weight:700}
.dpanel .kv{display:flex;justify-content:space-between;gap:10px;padding:4px 0;
border-bottom:1px solid rgba(51,65,85,.5)}
.dpanel .kv span{color:var(--text-mute);flex-shrink:0}
.dpanel .kv b{color:var(--text);font-weight:600;text-align:right;word-break:break-word}
.dlegend{display:flex;flex-wrap:wrap;gap:15px;font-size:.71rem;color:var(--text-mute);
margin-bottom:20px;padding-left:3px}
.dlegend span{display:flex;align-items:center;gap:6px}
.dlegend i{width:11px;height:11px;border-radius:3px;display:inline-block}
.outree{background:var(--surface);border:1px solid var(--border-soft);
border-radius:var(--radius);padding:12px 15px;margin-bottom:10px;max-height:700px;overflow:auto}
.outree summary{cursor:pointer;font-size:.81rem;color:var(--accent);font-weight:650;padding:2px 0}
.outree summary:hover{color:var(--accent2)}
.outree ul{list-style:none;margin:8px 0 0 4px;padding-left:15px;border-left:1px solid var(--border-soft)}
.outree li{padding:2px 0;font-size:.76rem;color:var(--text-mute)}
.outree .ouname{color:var(--text-dim)}
.outree .gpl{color:var(--accent2);font-size:.72rem}
.outree .bi{color:var(--amber);font-size:.68rem}
.outree .enf{color:var(--green);font-size:.68rem}

/* ---------- clickable counts and cross-links ---------- */
.cl-link{color:var(--accent);text-decoration:none;font-weight:650;
border-bottom:1px dotted rgba(77,141,250,.45);cursor:pointer}
.cl-link:hover{color:var(--accent2);border-bottom-style:solid}
.cl-link:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
td .cz{color:var(--text-mute)}
/* Brief highlight on the element a link just opened, so the reader can see
   where they landed in a long page. */
@keyframes clFlash{0%{background:rgba(77,141,250,.28)}100%{background:transparent}}
.cl-target{animation:clFlash 1.6s ease-out}
@media(prefers-reduced-motion:reduce){.cl-target{animation:none;outline:2px solid var(--accent)}}
@media print{.cl-link{color:#111!important;border-bottom:none!important}}

/* ---------- collapsed binary values ---------- */
details.blob{display:inline-block;max-width:100%}
details.blob>summary{cursor:pointer;color:var(--text-mute);font-size:.72rem;
font-style:italic;list-style:none}
details.blob>summary::-webkit-details-marker{display:none}
details.blob>summary::before{content:'\25B8 ';color:var(--accent)}
details.blob[open]>summary::before{content:'\25BE '}
details.blob>summary:hover{color:var(--accent)}
details.blob code{display:block;margin-top:5px;font-family:var(--mono);font-size:.68rem;
color:var(--text-mute);word-break:break-all;max-height:170px;overflow:auto;
background:#0a1730;border:1px solid var(--border-soft);border-radius:var(--radius-sm);padding:7px 9px}
@media print{details.blob>summary::before{content:''}details.blob code{display:none}}

/* ---------- GPO detail: domain rail + card pane ---------- */
.gpo-layout{display:flex;gap:16px;align-items:flex-start}
.gpo-domains{flex:0 0 216px;position:sticky;top:66px;display:flex;flex-direction:column;gap:4px;
max-height:calc(100vh - 90px);overflow-y:auto;padding-right:2px}
.gpo-domain{display:flex;align-items:center;gap:8px;width:100%;text-align:left;
background:var(--surface);border:1px solid var(--border-soft);border-left:3px solid transparent;
border-radius:var(--radius-sm);color:var(--text-dim);font:inherit;font-size:.76rem;
padding:8px 11px;cursor:pointer;transition:all .13s ease;word-break:break-all;line-height:1.35}
.gpo-domain:hover{background:rgba(77,141,250,.08);color:var(--text);border-color:#3a5a86}
.gpo-domain.active{border-left-color:var(--accent);color:var(--accent);
background:linear-gradient(90deg,rgba(77,141,250,.15),transparent)}
.gpo-domain span{margin-left:auto;flex-shrink:0;font-size:.66rem;font-weight:700;
background:rgba(77,141,250,.14);color:var(--accent);border-radius:99px;padding:1px 8px}
.gpo-domain.active span{background:rgba(77,141,250,.28)}
.gpo-domain:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.gpo-main{flex:1;min-width:0}
.gpo-dh{margin-top:4px}
.gpo-dh:first-child{margin-top:0}
@media(max-width:900px){
.gpo-layout{flex-direction:column}
.gpo-domains{position:static;flex:1 1 auto;width:100%;flex-direction:row;flex-wrap:wrap;max-height:none}
.gpo-domain{width:auto}}
@media print{
.gpo-domains{display:none}
.gpo-layout{display:block}}

/* ---------- GPO cards ---------- */
.gpo{border:1px solid var(--border-soft);border-radius:var(--radius);
background:var(--surface);margin-bottom:9px;overflow:hidden}
.gpo>summary{cursor:pointer;padding:11px 15px;font-size:.83rem;color:var(--text);
font-weight:600;list-style:none;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.gpo>summary::-webkit-details-marker{display:none}
.gpo>summary::before{content:'\25B8';color:var(--accent);flex-shrink:0}
.gpo[open]>summary::before{content:'\25BE'}
.gpo>summary:hover{background:rgba(77,141,250,.06)}
.gpo .gname{flex:1;min-width:200px}
.gpo .gplain{width:100%;font-weight:400;font-size:.75rem;color:var(--text-mute);
padding-left:18px;line-height:1.55}
.gpo .gbody{padding:4px 15px 15px;border-top:1px solid var(--border-soft)}
.gpo .gbody h5{font-size:.66rem;text-transform:uppercase;letter-spacing:.1em;
color:var(--accent2);font-weight:700;margin:14px 0 7px}
.ref{font-size:.7rem}
.ref a{color:var(--accent);text-decoration:none}
.ref a:hover{text-decoration:underline}

/* ---------- standard masthead / footer band ---------- */
.masthead{background:linear-gradient(160deg,#0e1d38,#08132a);
border:1px solid var(--border-soft);border-left:4px solid var(--accent);
border-radius:12px;padding:24px 28px;margin:24px 0 18px;box-shadow:var(--shadow)}
.mh-title{font-size:1.65rem;font-weight:700;color:#fff;letter-spacing:-.025em;line-height:1.1}
.mh-title em{font-style:normal;color:var(--accent)}
.mh-tagline{font-size:.82rem;color:var(--accent2);margin-top:3px;
letter-spacing:.06em;text-transform:uppercase;font-weight:600}
.mh-about{font-size:.83rem;line-height:1.75;color:var(--text-dim);margin:14px 0 0;max-width:104ch}
.mh-author{margin-top:15px;padding-top:13px;border-top:1px solid rgba(148,163,184,.16);
font-size:.85rem;color:var(--text-dim)}
.mh-author strong{color:#fff;font-weight:650}
.mh-contact{margin-top:6px;font-size:.78rem;color:var(--text-mute);
display:flex;flex-wrap:wrap;gap:9px;align-items:center}
.mh-contact a{color:var(--accent);text-decoration:none}
.mh-contact a:hover{text-decoration:underline}
.mh-contact span{color:#3a5170}
.mh-lic{color:var(--text-mute)!important}

.ft-band{background:linear-gradient(160deg,#0e1d38,#08132a);
border:1px solid var(--border-soft);border-left:4px solid var(--accent);
border-radius:12px;padding:22px 26px;margin-bottom:24px}
.ft-title{font-size:1.3rem;font-weight:700;color:#fff;letter-spacing:-.02em}
.ft-title em{font-style:normal;color:var(--accent)}
.ft-tagline{font-size:.72rem;color:var(--accent2);margin-top:2px;
letter-spacing:.07em;text-transform:uppercase;font-weight:600}
.ft-about{font-size:.79rem;line-height:1.7;color:var(--text-mute);margin:12px 0 0;max-width:104ch}
.ft-author{margin-top:13px;padding-top:11px;border-top:1px solid rgba(148,163,184,.14);
font-size:.8rem;color:var(--text-dim)}
.ft-author strong{color:#fff;font-weight:650}
.ft-contact{margin-top:5px;font-size:.76rem;color:var(--text-mute);
display:flex;flex-wrap:wrap;gap:9px;align-items:center}
.ft-contact a{color:var(--accent);text-decoration:none}
.ft-contact a:hover{text-decoration:underline}
.ft-contact span{color:#3a5170}

/* ---------- footer ---------- */
.footer{margin-top:52px;border-top:1px solid var(--border-soft);padding-top:26px}
.fgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:26px;margin-bottom:24px}
.fcol h5{font-size:.63rem;text-transform:uppercase;letter-spacing:.13em;
color:var(--accent2);font-weight:700;margin-bottom:9px}
.fcol p{font-size:.75rem;color:var(--text-mute);line-height:1.7;margin-bottom:3px}
.fcol strong{color:var(--text-dim);font-weight:600}
.fcol a{color:var(--accent);text-decoration:none}
.fcol a:hover{text-decoration:underline}
.fbar{border-top:1px solid var(--border-soft);padding:16px 0 26px;display:flex;
gap:14px;flex-wrap:wrap;align-items:center;justify-content:space-between;
font-size:.72rem;color:var(--text-mute)}
.fbar .brand{font-weight:700;color:var(--accent);font-size:.82rem}
.fbar .stamp{font-family:var(--mono);font-size:.68rem}

@media(max-width:1000px){
.sidebar{display:none}.main{margin-left:0;padding:0 15px 30px}
.topbar{padding-left:20px}.hero h1{font-size:1.6rem}}
@media print{
.sidebar,.topbar,.tools,.tb-btn{display:none!important}
.main{margin-left:0;max-width:100%;padding:0}
body{background:#fff;color:#111;font-size:10.5pt}
.card,.ic,.cbox,.ac,.hero,.dwrap,.tw,.outree,.masthead,.ft-band,.gpo{background:#fff!important;
border-color:#ccc!important;box-shadow:none!important;break-inside:avoid}
.hero{border-radius:0}
.cv,.iv,.st,.hero h1,.dpanel h4,.mh-title,.ft-title{color:#111!important}
.mh-about,.ft-about,.mh-author,.ft-author{color:#333!important}
.masthead,.ft-band{border-left:4px solid #333!important;break-inside:avoid}
td{color:#333!important}th{background:#eee!important;color:#111!important;position:static}
.tw{max-height:none;overflow:visible}
.outree{max-height:none;overflow:visible}
.gpo>summary::before{content:''}
.section{break-inside:avoid-page;margin-bottom:18px}
.footer,.fbar{color:#555}}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}
html{scroll-behavior:auto}}
'@

$script:OutlineJs = @'
var COLORS=['#60a5fa','#34d399','#f87171','#fbbf24','#a78bfa','#f472b6','#22d3ee','#fb923c','#a3e635','#e879f9','#facc15','#94a3b8'];
function esc(s){var d=document.createElement('div');d.textContent=s==null?'':String(s);return d.innerHTML;}

function donut(host,title,pairs){
  var total=0,i;for(i=0;i<pairs.length;i++){total+=pairs[i][1];}
  var box=document.createElement('div');box.className='cbox';
  var h=document.createElement('h4');h.textContent=title;box.appendChild(h);
  if(!total){var m=document.createElement('p');m.className='muted';m.textContent='Nothing to chart.';box.appendChild(m);host.appendChild(box);return;}
  var size=170,r=68,cx=size/2,cy=size/2,circ=2*Math.PI*r,off=0,svg='';
  svg+='<svg viewBox="0 0 '+size+' '+size+'" style="max-width:170px;display:block;margin:0 auto">';
  svg+='<circle cx="'+cx+'" cy="'+cy+'" r="'+r+'" fill="none" stroke="#0a1730" stroke-width="22"/>';
  for(i=0;i<pairs.length;i++){
    var v=pairs[i][1];if(!v)continue;
    var len=(v/total)*circ;
    svg+='<circle cx="'+cx+'" cy="'+cy+'" r="'+r+'" fill="none" stroke="'+COLORS[i%COLORS.length]+
         '" stroke-width="22" stroke-dasharray="'+len+' '+(circ-len)+'" stroke-dashoffset="'+(-off)+
         '" transform="rotate(-90 '+cx+' '+cy+')"><title>'+esc(pairs[i][0]+': '+v)+'</title></circle>';
    off+=len;
  }
  svg+='<text x="'+cx+'" y="'+(cy+6)+'" text-anchor="middle" fill="#e8eefb" font-size="24" font-weight="700">'+total.toLocaleString()+'</text>';
  svg+='</svg>';
  box.innerHTML+=svg;
  var lg='<div class="legend">';
  for(i=0;i<pairs.length;i++){
    if(!pairs[i][1])continue;
    lg+='<div><span class="sw" style="background:'+COLORS[i%COLORS.length]+'"></span>'+
        esc(pairs[i][0])+' &mdash; '+pairs[i][1].toLocaleString()+'</div>';
  }
  lg+='</div>';box.innerHTML+=lg;host.appendChild(box);
}

function bars(host,title,pairs,note){
  var box=document.createElement('div');box.className='cbox';
  var h=document.createElement('h4');h.textContent=title;box.appendChild(h);
  var max=0,i;for(i=0;i<pairs.length;i++){if(pairs[i][1]>max)max=pairs[i][1];}
  if(!max){var m=document.createElement('p');m.className='muted';m.textContent='Nothing to chart.';box.appendChild(m);host.appendChild(box);return;}
  var html='';
  for(i=0;i<pairs.length;i++){
    var pct=(pairs[i][1]/max)*100;
    html+='<div class="bar-row"><div class="bar-lbl" title="'+esc(pairs[i][0])+'">'+esc(pairs[i][0])+
          '</div><div class="bar-track"><div class="bar-fill" style="width:'+pct+'%;background:'+
          COLORS[i%COLORS.length]+'"></div></div><div class="bar-val">'+pairs[i][1].toLocaleString()+'</div></div>';
  }
  box.innerHTML+=html;
  if(note){box.innerHTML+='<p class="muted" style="margin:9px 0 0;padding:0;background:none;border:none">'+esc(note)+'</p>';}
  host.appendChild(box);
}

try {

/* ---------- active nav link on scroll ---------- */
(function(){
  var links=[].slice.call(document.querySelectorAll('nav a[href^="#"]'));
  if(!links.length)return;
  var secs=links.map(function(a){return document.getElementById(a.getAttribute('href').slice(1));});
  function upd(){
    var best=-1,bestTop=-1e9;
    for(var i=0;i<secs.length;i++){
      if(!secs[i])continue;
      var t=secs[i].getBoundingClientRect().top-90;
      if(t<=0&&t>bestTop){bestTop=t;best=i;}
    }
    links.forEach(function(a){a.classList.remove('active');});
    if(best>=0)links[best].classList.add('active');
  }
  window.addEventListener('scroll',upd,{passive:true});upd();
})();

/* ---------- Top button ---------- */
(function(){
  var b=document.getElementById('tocTop');
  if(b)b.addEventListener('click',function(){window.scrollTo({top:0,behavior:'smooth'});});
})();

/* ---------- per-table filter ---------- */
(function(){
  [].slice.call(document.querySelectorAll('.tw')).forEach(function(w){
    var tb=w.querySelector('tbody');
    if(!tb||tb.rows.length<9)return;
    var bar=document.createElement('div');bar.className='tools';
    var inp=document.createElement('input');
    inp.className='tsearch';inp.type='search';inp.placeholder='Filter '+tb.rows.length+' rows...';
    var cnt=document.createElement('span');cnt.className='tcount';cnt.textContent=tb.rows.length+' rows';
    bar.appendChild(inp);bar.appendChild(cnt);
    w.parentNode.insertBefore(bar,w);
    inp.addEventListener('input',function(){
      var q=inp.value.toLowerCase(),shown=0;
      for(var i=0;i<tb.rows.length;i++){
        var hit=!q||tb.rows[i].textContent.toLowerCase().indexOf(q)>-1;
        tb.rows[i].style.display=hit?'':'none';
        if(hit)shown++;
      }
      cnt.textContent=shown+' of '+tb.rows.length+' rows';
    });
  });
})();

/* ---------- cross-link navigation ----------
   A link to a collapsed <details> would otherwise scroll to a closed block and
   look like nothing happened. Open the target (and any collapsed ancestor),
   clear a domain filter that would hide it, then scroll and flash it. */
(function(){
  function reveal(el){
    if(!el)return;
    var n=el;
    while(n&&n!==document.body){
      if(n.tagName==='DETAILS')n.open=true;
      /* A card hidden by the domain filter must be shown, or the link lands on
         a display:none element and appears to do nothing. */
      if(n.style&&n.style.display==='none')n.style.display='';
      n=n.parentNode;
    }
    var grp=el.closest?el.closest('.nav-group'):null;
    if(grp)grp.classList.remove('collapsed');
  }
  function go(id){
    var el=document.getElementById(id);
    if(!el)return false;
    reveal(el);
    /* Two frames: the first lets the opened <details> lay out so the scroll
       target is measured at its real position, not its collapsed one. */
    requestAnimationFrame(function(){
      requestAnimationFrame(function(){
        el.scrollIntoView({behavior:'smooth',block:'center'});
        el.classList.remove('cl-target');
        void el.offsetWidth;
        el.classList.add('cl-target');
        setTimeout(function(){el.classList.remove('cl-target');},1800);
      });
    });
    return true;
  }
  document.addEventListener('click',function(e){
    var a=e.target&&e.target.closest?e.target.closest('a.cl-link'):null;
    if(!a)return;
    var href=a.getAttribute('href')||'';
    if(href.charAt(0)!=='#')return;
    if(go(href.slice(1)))e.preventDefault();
  });
  /* Same treatment when the page is opened at a fragment directly. */
  if(location.hash&&location.hash.length>1){
    setTimeout(function(){go(location.hash.slice(1));},220);
  }
})();

/* ---------- GPO domain filter + card search ---------- */
(function(){
  var host=document.getElementById('gpoSearch');
  var list=document.getElementById('gpoList');
  var rail=document.getElementById('gpoDomains');
  if(!host||!list)return;

  var cards=[].slice.call(list.querySelectorAll('details.gpo'));
  var heads=[].slice.call(list.querySelectorAll('.gpo-dh'));
  var domain='__all';

  var inp=document.createElement('input');
  inp.className='tsearch';inp.type='search';inp.style.width='320px';
  inp.placeholder='Search '+cards.length+' GPOs by name, setting or value...';
  var cnt=document.createElement('span');cnt.className='tcount';
  host.appendChild(inp);host.appendChild(cnt);

  function apply(){
    var q=inp.value.toLowerCase(),shown=0,pool=0;
    cards.forEach(function(c){
      var inDomain=(domain==='__all'||c.getAttribute('data-domain')===domain);
      if(inDomain)pool++;
      var hit=inDomain&&(!q||c.textContent.toLowerCase().indexOf(q)>-1);
      c.style.display=hit?'':'none';
      if(hit)shown++;
      /* Opening on a hit puts the matched text on screen rather than leaving
         the reader to expand every card by hand. */
      if(q&&hit&&shown<=12)c.open=true; else if(!q)c.open=false;
    });
    /* A heading with nothing under it is noise, so hide it with its group. */
    heads.forEach(function(h){
      var d=h.getAttribute('data-domain');
      var any=cards.some(function(c){
        return c.getAttribute('data-domain')===d&&c.style.display!=='none';
      });
      h.style.display=any?'':'none';
    });
    cnt.textContent=(shown===pool?shown+' GPOs':shown+' of '+pool+' GPOs')+
                    (domain==='__all'?'':' in '+domain);
  }

  inp.addEventListener('input',apply);

  if(rail){
    var btns=[].slice.call(rail.querySelectorAll('.gpo-domain'));
    btns.forEach(function(b){
      b.addEventListener('click',function(){
        btns.forEach(function(x){x.classList.remove('active');});
        b.classList.add('active');
        domain=b.getAttribute('data-domain');
        apply();
        list.scrollIntoView({behavior:'smooth',block:'start'});
      });
    });
  }
  apply();
})();

/* ---------- collapsible sidebar groups ---------- */
(function(){
  var nav=document.querySelector('nav');if(!nav)return;
  var kids=[].slice.call(nav.children),i,cur=null;
  for(i=0;i<kids.length;i++){
    var el=kids[i];
    if(el.className==='ng'){
      var chev=document.createElement('span');chev.className='chev';el.appendChild(chev);
      el.setAttribute('role','button');el.setAttribute('tabindex','0');
      el.setAttribute('aria-expanded','true');
      cur=document.createElement('div');cur.className='nav-group';
      nav.insertBefore(cur,el.nextSibling);
      (function(head,body){
        function toggle(){
          var open=!head.classList.contains('collapsed');
          if(open){ body.style.maxHeight=body.scrollHeight+'px';
                    requestAnimationFrame(function(){body.classList.add('collapsed');}); }
          else { body.classList.remove('collapsed');
                 body.style.maxHeight=body.scrollHeight+'px'; }
          head.classList.toggle('collapsed');
          head.setAttribute('aria-expanded',String(open?false:true));
        }
        head.addEventListener('click',toggle);
        head.addEventListener('keydown',function(e){
          if(e.key==='Enter'||e.key===' '){e.preventDefault();toggle();}
        });
      })(el,cur);
    } else if(cur&&el.tagName==='A'){
      cur.appendChild(el);
    }
  }
  [].slice.call(nav.querySelectorAll('.nav-group')).forEach(function(g){
    g.style.maxHeight=g.scrollHeight+'px';
    setTimeout(function(){ if(!g.classList.contains('collapsed'))g.style.maxHeight='none'; },300);
  });
})();

/* ---------- section eyebrows, derived from the nav grouping ---------- */
(function(){
  var nav=document.querySelector('nav');if(!nav)return;
  var group=null,map={};
  [].slice.call(nav.children).forEach(function(el){
    if(el.classList&&el.classList.contains('ng')){
      group=el.textContent.replace(/\s+/g,' ').trim();
    } else if(group){
      var links=el.tagName==='A'?[el]:[].slice.call(el.querySelectorAll('a[href^="#"]'));
      links.forEach(function(a){ map[a.getAttribute('href').slice(1)]=group; });
    }
  });
  [].slice.call(document.querySelectorAll('.section')).forEach(function(sec){
    var g=map[sec.id];if(!g)return;
    var h=sec.querySelector('.st');if(!h)return;
    var eb=document.createElement('div');
    eb.className='sec-eyebrow';eb.textContent=g;
    sec.insertBefore(eb,h);
  });
})();

/* ---------- charts, driven from the embedded dataset ---------- */
(function(){
  var D=window.GPOOutlineData;if(!D||!D.Stats)return;
  var S=D.Stats;

  var h=document.getElementById('chartInventory');
  if(h){
    donut(h,'GPOs by link state',[
      ['Linked',S.LinkedGpos||0],['Not linked',S.UnlinkedGpos||0]]);
    donut(h,'GPOs by settings state',[
      ['With settings',(S.Gpos||0)-(S.EmptyGpos||0)],['Empty',S.EmptyGpos||0]]);
    donut(h,'GPO status',[
      ['Fully enabled',(S.Gpos||0)-(S.DisabledGpos||0)-(S.PartlyDisabled||0)],
      ['One half disabled',S.PartlyDisabled||0],
      ['All settings disabled',S.DisabledGpos||0]]);
    donut(h,'Links by kind',[
      ['Normal',(S.TotalLinks||0)-(S.EnforcedLinks||0)-(S.DisabledLinks||0)],
      ['Enforced',S.EnforcedLinks||0],['Disabled',S.DisabledLinks||0]]);
  }

  var f=document.getElementById('chartFootprint');
  if(f&&D.Behavior&&D.Behavior.Footprint){
    var fp=D.Behavior.Footprint.slice(0,12).map(function(r){return [r.Area,r.Settings];});
    bars(f,'Where the policy weight sits',fp,
      'Number of discrete settings recorded in each area, across every GPO.');
    var fg=D.Behavior.Footprint.slice(0,12).map(function(r){return [r.Area,r['GPOs touching it']];});
    bars(f,'GPOs touching each area',fg,null);
  }

  var c=document.getElementById('chartCse');
  if(c&&D.Matrices&&D.Matrices.CseUsage){
    var cu=D.Matrices.CseUsage.slice(0,12).map(function(r){return [r.Extension,r.Total];});
    bars(c,'Client-side extensions in use',cu,
      'How many GPO halves invoke each extension. This is what the client actually has to process.');
  }

  var d=document.getElementById('chartDomains');
  if(d&&D.Domains&&D.Domains.length){
    bars(d,'GPOs per domain',D.Domains.map(function(x){return [x.DnsRoot,x.GpoCount||0];}),null);
    bars(d,'OUs per domain',D.Domains.map(function(x){return [x.DnsRoot,x.OuCount||0];}),null);
  }
})();

} catch (e) { if (window.console) console.warn('GPOOutline UI layer:', e); }
'@

# ==============================================================================
# REPORT BUILDER
#
# Consumes $script:Outline and nothing else. Collection owns the state; display
# only reads it -- which is what makes -FromState a complete re-render with no
# directory access at all.
#
# Voice: documentary throughout. Sections state what is configured and what
# that means mechanically. Nothing is scored, graded or recommended.
# ==============================================================================

function New-OutlineGpoSummaryLine {
    <#
      The plain-English line a non-specialist reads before any detail.

      Written as a sentence about what the GPO IS and DOES, not as a verdict on
      it. "Applies to Authenticated Users" is a fact; "correctly scoped" would
      be a judgement and does not belong here.
    #>
    param($Gpo)

    $bits = New-Object System.Collections.Generic.List[string]

    if ($Gpo.LinkCount -eq 0) { $bits.Add('Not linked to any site, domain or OU, so it does not apply anywhere') }
    else {
        $enf = @($Gpo.Links | Where-Object { $_.Enforced }).Count
        $t = "Linked to $($Gpo.LinkCount) container$(if ($Gpo.LinkCount -ne 1) { 's' })"
        if ($enf -gt 0) { $t += ", enforced on $enf of them" }
        $bits.Add($t)
    }

    if ($Gpo.SettingCount -gt 0) {
        $areas = @()
        if ($Gpo.Settings -and $Gpo.Settings.Areas) { $areas = @($Gpo.Settings.Areas) }
        $t = "contains $($Gpo.SettingCount) setting$(if ($Gpo.SettingCount -ne 1) { 's' })"
        if ($areas.Count -gt 0) { $t += " covering $($areas -join ', ')" }
        $bits.Add($t)
    }
    elseif ($Gpo.SysvolReadable) { $bits.Add('contains no settings') }
    else { $bits.Add('its settings could not be read') }

    if ($Gpo.Status -ne 'Enabled') { $bits.Add($Gpo.Status.ToLower()) }
    if ($Gpo.Loopback) { $bits.Add("enables user Group Policy loopback in $($Gpo.Loopback) mode") }
    if ($Gpo.WmiFilterName) { $bits.Add("gated by the WMI filter '$($Gpo.WmiFilterName)'") }

    if ($Gpo.AclReadable) {
        $applies = @($Gpo.Filtering | Where-Object { $_.Access -notmatch 'denied' })
        if ($applies.Count -eq 0) { $bits.Add('no principal holds both Read and Apply, so it reaches no one') }
        elseif ($Gpo.AuthUsersApply -and $applies.Count -eq 1) { $bits.Add('applies to Authenticated Users') }
        else { $bits.Add("applies to $((@($applies | ForEach-Object { $_.Name }) | Select-Object -First 4) -join ', ')") }
    }

    return ((($bits -join '; ') -replace '^\s*', '') + '.')
}

function New-OutlineGpoCard {
    <# One collapsible block per GPO: plain-English summary, then raw detail. #>
    param($Gpo)

    $sb = New-Object System.Text.StringBuilder
    $badge = switch ($Gpo.Status) {
        'Enabled' { "<span class='b b-ok'>enabled</span>" }
        'All settings disabled' { "<span class='b b-w'>all settings disabled</span>" }
        default { "<span class='b b-i'>$(ConvertTo-OutlineHtmlText $Gpo.Status)</span>" }
    }
    $linkBadge = if ($Gpo.LinkCount -eq 0) { "<span class='b b-w'>not linked</span>" } else { "<span class='b b-i'>$($Gpo.LinkCount) link(s)</span>" }
    $lbBadge = if ($Gpo.Loopback) { "<span class='b b-i'>loopback: $(ConvertTo-OutlineHtmlText $Gpo.Loopback)</span>" } else { '' }
    $vmBadge = if ($Gpo.VersionMismatch) { "<span class='b b-w'>version mismatch</span>" } else { '' }
    $cpBadge = if ($Gpo.Settings -and @($Gpo.Settings.CPassword).Count -gt 0) { "<span class='b b-e'>cpassword present</span>" } else { '' }

    # data-domain drives the domain rail filter. It matters more than it looks:
    # Default Domain Policy exists once per domain with an identical name AND an
    # identical GUID, so without the domain attached a reader cannot tell four
    # cards apart.
    # A stable id makes the card a link target, so a GPO named anywhere else in
    # the report can jump straight to its detail instead of leaving the reader to
    # scroll or search for it.
    $gpoAnchor = "gpo-$(Get-OutlineSlug $Gpo.Key)"
    [void]$sb.Append("<details class='gpo' id='$gpoAnchor' data-domain=`"$(ConvertTo-OutlineHtmlText $Gpo.Domain)`"><summary>")
    [void]$sb.Append("<span class='gname'>$(ConvertTo-OutlineHtmlText $Gpo.Name)</span>")
    [void]$sb.Append("$badge $linkBadge $lbBadge $vmBadge $cpBadge")
    [void]$sb.Append("<span class='gplain'>$(ConvertTo-OutlineHtmlText (New-OutlineGpoSummaryLine $Gpo))</span>")
    [void]$sb.Append("</summary><div class='gbody'>")

    # ---- identity ----
    [void]$sb.Append("<h5>Identity</h5><div class='ig'>")
    [void]$sb.Append((New-InfoRow 'Domain' $Gpo.Domain))
    [void]$sb.Append((New-InfoRow 'GUID' $Gpo.Id))
    [void]$sb.Append((New-InfoRow 'Created' $Gpo.Created))
    [void]$sb.Append((New-InfoRow 'Modified' $Gpo.Changed))
    [void]$sb.Append((New-InfoRow 'Status' $Gpo.Status))
    [void]$sb.Append((New-InfoRow 'Version (AD user/computer)' "$($Gpo.AdVersionUser) / $($Gpo.AdVersionComputer)"))
    [void]$sb.Append((New-InfoRow 'Version (SYSVOL user/computer)' "$($Gpo.SysvolVersionUser) / $($Gpo.SysvolVersionComputer)"))
    if ($Gpo.Owner) { [void]$sb.Append((New-InfoRow 'Owner' $Gpo.Owner)) }
    [void]$sb.Append('</div>')

    if ($Gpo.VersionMismatch) {
        [void]$sb.Append("<p class='muted'>The version recorded in the directory and the version recorded in SYSVOL do not match. This normally means replication of one half has not yet caught up with the other.</p>")
    }
    if ($Gpo.Comment) {
        [void]$sb.Append("<h5>Comment recorded by the author</h5><p class='sd'>$(ConvertTo-OutlineHtmlText $Gpo.Comment)</p>")
    }

    # ---- evidence paths ----
    [void]$sb.Append("<h5>Evidence paths</h5><div class='ig'>")
    [void]$sb.Append((New-InfoRow 'Directory object (GPC)' $Gpo.DN))
    [void]$sb.Append((New-InfoRow 'SYSVOL path (GPT)' $Gpo.SysvolPath))
    [void]$sb.Append('</div>')

    # ---- links ----
    [void]$sb.Append('<h5>Links</h5>')
    if ($Gpo.LinkCount -eq 0) {
        [void]$sb.Append("<p class='muted'>This GPO is not linked to any container.</p>")
    }
    else {
        $lr = @($Gpo.Links | ForEach-Object {
            [pscustomobject]@{
                Container = $_.ContainerName; Type = $_.ContainerType; Domain = $_.ContainerDomain
                'Link order' = $_.LinkOrder
                'Link enabled' = $(if ($_.Enabled) { 'Yes' } else { 'No' })
                Enforced = $(if ($_.Enforced) { 'Yes' } else { '' })
                'Container blocks inheritance' = $(if ($_.BlockInheritance) { 'Yes' } else { '' })
                'Cross-domain' = $(if ($_.CrossDomain) { 'Yes' } else { '' })
            }
        })
        [void]$sb.Append((New-HtmlTable -Rows $lr -Columns @('Container','Type','Domain','Link order','Link enabled','Enforced','Container blocks inheritance','Cross-domain')))
    }

    # ---- filtering ----
    [void]$sb.Append('<h5>Security filtering &mdash; who this GPO applies to</h5>')
    if (-not $Gpo.AclReadable) {
        [void]$sb.Append("<p class='muted'>$(ConvertTo-OutlineHtmlText $(if ($Gpo.AclReason) { $Gpo.AclReason } else { 'The security descriptor was not readable by the collecting account.' }))</p>")
    }
    elseif (@($Gpo.Filtering).Count -eq 0) {
        [void]$sb.Append("<p class='muted'>No principal holds both Read and Apply Group Policy, so this GPO does not apply to anyone as recorded.</p>")
    }
    else {
        [void]$sb.Append((New-HtmlTable -Rows @($Gpo.Filtering | ForEach-Object {
            [pscustomobject]@{ Principal = $_.Name; Access = $_.Access; 'SID resolved' = $(if ($_.Resolved) { 'Yes' } else { 'No' }); SID = $_.Sid } }) `
            -Columns @('Principal','Access','SID resolved','SID')))
        if (-not $Gpo.AuthUsersApply) {
            [void]$sb.Append("<p class='muted'>Authenticated Users does not hold Apply Group Policy on this GPO. Scope is therefore set by the principals listed above rather than by the links alone.</p>")
        }
    }

    # ---- delegation ----
    [void]$sb.Append('<h5>Delegation &mdash; who can change this GPO</h5>')
    if (@($Gpo.Delegation).Count -eq 0) {
        [void]$sb.Append("<p class='muted'>No principal beyond the defaults holds edit, delete or modify-security rights, as recorded.</p>")
    }
    else {
        [void]$sb.Append((New-HtmlTable -Rows @($Gpo.Delegation | ForEach-Object {
            [pscustomobject]@{ Principal = $_.Name; Rights = $_.Rights; 'SID resolved' = $(if ($_.Resolved) { 'Yes' } else { 'No' }) } }) `
            -Columns @('Principal','Rights','SID resolved')))
    }

    # ---- SYSVOL-side permissions ----
    # Shown immediately after the AD delegation so the two can be read together.
    # A principal with Edit rights in AD but no write access to the GPT folder
    # cannot actually save a change, and that mismatch is invisible from either
    # side alone.
    [void]$sb.Append('<h5>SYSVOL folder permissions &mdash; who can write the policy files</h5>')
    $gptAcl = @(Get-PropArray $Gpo 'GptAcl')
    if (-not (Get-PropValue $Gpo 'GptAclReadable')) {
        $reason = Get-PropValue $Gpo 'GptAclReason'
        [void]$sb.Append("<p class='muted'>$(ConvertTo-OutlineHtmlText $(if ($reason) { $reason } else { 'The SYSVOL folder permissions were not read for this GPO.' }))</p>")
    }
    elseif ($gptAcl.Count -eq 0) {
        [void]$sb.Append("<p class='muted'>No access control entries were returned for this GPO's SYSVOL folder.</p>")
    }
    else {
        $gptOwner = Get-PropValue $Gpo 'GptOwner'
        if ($gptOwner) { [void]$sb.Append("<div class='ig'>$(New-InfoRow 'SYSVOL folder owner' $gptOwner)</div>") }

        # Writers are what matter here, so they are named rather than left for the
        # reader to infer from a rights string.
        # CanWrite is computed where the ACE is read, because deciding it from the
        # rendered rights string cannot see generic-rights bits.
        $writers = @($gptAcl | Where-Object { Get-PropValue $_ 'CanWrite' })
        [void]$sb.Append((New-HtmlTable -Rows @($gptAcl | ForEach-Object {
            [pscustomobject][ordered]@{
                Principal = $_.Identity
                Rights = $_.Rights
                Type = $_.Type
                Inherited = $(if ($_.Inherited) { 'Yes' } else { 'No -- set on this folder' })
                'Can write policy files' = $(if (Get-PropValue $_ 'CanWrite') { 'Yes' } else { '' })
            } }) -Columns @('Principal','Rights','Type','Inherited','Can write policy files')))

        # Cross-check the two sides. Stated as an observation, not a fault: a
        # delegation may be intentional and unused.
        # Built-in administrative principals are excluded from the comparison.
        # They reach the file system through BUILTIN\Administrators or by holding
        # SeTakeOwnership/SeRestore regardless of the folder ACL, so naming them
        # produces an identical notice on every GPO in the estate -- noise that
        # teaches a reader to skip the one case that matters. Only delegated
        # principals are compared.
        $builtinEditors = @(
            'domain admins','enterprise admins','administrators','system',
            'creator owner','domain controllers','enterprise domain controllers',
            'schema admins','local system')
        $adEditors = @(@(Get-PropArray $Gpo 'Delegation') |
            Where-Object { $_.CanEdit } |
            ForEach-Object { [string]$_.Name } |
            Where-Object { $builtinEditors -notcontains (($_ -split '\\')[-1]).ToLowerInvariant() })

        if ($adEditors.Count -gt 0 -and $writers.Count -gt 0) {
            $writerText = ($writers | ForEach-Object { [string]$_.Identity }) -join ' '
            $noFile = @($adEditors | Where-Object {
                $short = ($_ -split '\\')[-1]
                $writerText -notmatch [regex]::Escape($short) })
            if ($noFile.Count -gt 0) {
                [void]$sb.Append("<p class='muted'>Delegated for editing in the directory but not named in the SYSVOL folder permissions above: <b>$(ConvertTo-OutlineHtmlText ($noFile -join ', '))</b>. Editing a GPO writes to both sides, so a principal present on one side only may be unable to save a change. Built-in administrative groups are excluded from this comparison, and group nesting is not resolved, so the access may be granted indirectly.</p>")
            }
        }
    }

    # ---- WMI filter ----
    if ($Gpo.WmiFilterName) {
        [void]$sb.Append('<h5>WMI filter</h5>')
        # Matched on domain as well as ID: filter IDs, like GPO GUIDs, are only
        # unique within a domain.
        $w = @($script:Outline.WmiFilters | Where-Object { $_.Id -eq $Gpo.WmiFilterId -and $_.Domain -eq $Gpo.Domain })
        [void]$sb.Append("<div class='ig'>")
        [void]$sb.Append((New-InfoRow 'Filter name' $Gpo.WmiFilterName))
        if ($w.Count -gt 0) {
            if ($w[0].Description) { [void]$sb.Append((New-InfoRow 'Description' $w[0].Description)) }
            foreach ($q in @($w[0].Queries)) { [void]$sb.Append((New-InfoRow "Query ($($q.Namespace))" $q.Query)) }
            if ($w[0].PlainEnglish) { [void]$sb.Append((New-InfoRow 'In plain English' $w[0].PlainEnglish)) }
        }
        [void]$sb.Append('</div>')
    }

    # ---- client-side extensions ----
    $cseAll = @(@($Gpo.MachineCse) + @($Gpo.UserCse) | Where-Object { $_ })
    if ($cseAll.Count -gt 0) {
        [void]$sb.Append('<h5>Client-side extensions recorded on this GPO</h5>')
        [void]$sb.Append((New-HtmlTable -Rows @($cseAll | ForEach-Object {
            [pscustomobject]@{ Extension = $_.Name; Area = $_.Area; GUID = $_.Guid } }) `
            -Columns @('Extension','Area','GUID')))
    }

    # ---- settings ----
    if (-not $Gpo.SysvolReadable) {
        [void]$sb.Append("<h5>Settings</h5><p class='muted'>Not readable: $(ConvertTo-OutlineHtmlText $(if ($Gpo.SysvolReason) { $Gpo.SysvolReason } else { 'SYSVOL was not read for this GPO.' }))</p>")
    }
    elseif ($Gpo.SettingCount -eq 0) {
        [void]$sb.Append("<h5>Settings</h5><p class='muted'>This GPO contains no settings in either half.</p>")
    }
    else {
        # No @() wrapper here. Get-OutlineSettingRows returns ,$array -- the
        # comma stops the pipeline unrolling it, which is what keeps an empty
        # result an empty array rather than $null. Wrapping that single emitted
        # object in @() collects it into a NEW one-element array, so every
        # setting in the GPO collapses into one row whose every property is an
        # array. The comma already guarantees an array, so @() is both
        # unnecessary and harmful.
        $rows = Get-OutlineSettingRows -Gpo $Gpo
        $truncated = $false
        if ($rows.Count -gt $script:MaxPerGpoSettings) {
            $rows = $rows[0..($script:MaxPerGpoSettings - 1)]
            $truncated = $true
        }

        foreach ($scope in @('Computer Configuration','User Configuration')) {
            $sr = @($rows | Where-Object { $_.Scope -eq $scope })
            if ($sr.Count -eq 0) { continue }
            [void]$sb.Append("<h5>$scope &mdash; $($sr.Count) setting(s)</h5>")

            # Project then de-duplicate. Select-Object -ExpandProperty combined
            # with -Unique throws under StrictMode when the rows in the set do
            # not all carry an identical property list, which preference rows
            # do not -- they add Targeted and CPassword.
            foreach ($area in @($sr | ForEach-Object { $_.Area } | Sort-Object -Unique)) {
                $ar = @($sr | Where-Object { $_.Area -eq $area })
                [void]$sb.Append("<p class='sd' style='margin:10px 0 5px'><b>$(ConvertTo-OutlineHtmlText $area)</b> &mdash; $($ar.Count) setting(s)</p>")

                if ($area -eq 'Administrative Templates') {
                    [void]$sb.Append((New-HtmlTable -Rows @($ar | ForEach-Object {
                        $ref = Get-MsReference ($_.Key -replace '^HK[LC][MU]\\','')
                        [pscustomobject]@{
                            Setting = $_.Name
                            'Registry key' = $_.Key
                            'Value name' = $_.Value
                            Data = $_.Data
                            Type = $_.Type
                            'Name source' = $(if ($_.Resolved) { "ADMX ($($_.AdmxMatch) match)" } else { 'Not resolved -- raw registry' })
                            Reference = $(if ($ref) { $ref.Label } else { '' })
                        } }) -Columns @('Setting','Registry key','Value name','Data','Type','Name source','Reference')))
                }
                elseif (@($ar | Where-Object { $_.Type -eq 'Preference' }).Count -gt 0) {
                    # Preference rows get a targeting column of their own.
                    # Item-level targeting is frequently the actual reason an
                    # item does or does not apply, and it is invisible from the
                    # GPO's scope, its links, and its security filtering -- so
                    # omitting it leaves a reader unable to explain the outcome.
                    [void]$sb.Append((New-HtmlTable -Rows @($ar | ForEach-Object {
                        $tt = Get-PropValue $_ 'TargetText'
                        [pscustomobject]@{
                            Setting = $_.Name
                            Action  = $_.Value
                            Detail  = $_.Data
                            'Item-level targeting' = $(
                                if ($tt) { $tt }
                                elseif ($_.Targeted) { 'Targeted, but the conditions could not be read' }
                                else { 'None -- applies wherever the GPO applies' })
                        } }) -Columns @('Setting','Action','Detail','Item-level targeting')))
                }
                else {
                    [void]$sb.Append((New-HtmlTable -Rows @($ar | ForEach-Object {
                        [pscustomobject]@{ Setting = $_.Name; Value = $_.Data; Detail = $_.Value; Type = $_.Type } }) `
                        -Columns @('Setting','Value','Detail','Type')))
                }
            }
        }

        if ($truncated) {
            [void]$sb.Append("<p class='muted'>This GPO has more than $($script:MaxPerGpoSettings) settings; the listing above is truncated for readability. Every setting is still counted in the totals and present in the state file.</p>")
        }
    }

    # ---- cpassword ----
    if ($Gpo.Settings -and @($Gpo.Settings.CPassword).Count -gt 0) {
        [void]$sb.Append('<h5>Group Policy Preferences credential</h5>')
        [void]$sb.Append("<p class='sd'>A cpassword attribute is present on the preference item(s) below. The key used to obfuscate this value was published by Microsoft, so a stored value is readable by anyone who can read SYSVOL. GPOOutline records only that one is present &mdash; it does not read, decrypt or store the value.</p>")
        [void]$sb.Append((New-HtmlTable -Rows @($Gpo.Settings.CPassword | ForEach-Object {
            [pscustomobject]@{ Category = $_.Category; Item = $_.Name; Half = $_.Half; File = $_.File } }) `
            -Columns @('Category','Item','Half','File')))
    }

    # ---- collection notes ----
    if ($Gpo.Settings -and @($Gpo.Settings.Truncations).Count -gt 0) {
        [void]$sb.Append('<h5>Collection notes for this GPO</h5>')
        foreach ($t in @($Gpo.Settings.Truncations)) { [void]$sb.Append("<div class='warn'>$(ConvertTo-OutlineHtmlText $t)</div>") }
    }

    [void]$sb.Append('</div></details>')
    return $sb.ToString()
}

function New-OutlineOuTreeHtml {
    <#
      OU hierarchy with the GPOs linked at each node, in precedence order, with
      Block Inheritance and Enforced markers. Rendered as nested <details> so a
      20,000-OU forest still opens.
    #>
    param()

    $O = $script:Outline
    $sb = New-Object System.Text.StringBuilder

    $ous = @($O.Containers | Where-Object { $_.Type -in @('Domain','OU') })
    if ($ous.Count -eq 0) { return "<p class='muted'>No containers collected.</p>" }

    $byParent = @{}
    $roots = New-Object System.Collections.Generic.List[object]
    foreach ($c in $ous) {
        if ($c.Type -eq 'Domain') { $roots.Add($c); continue }
        $p = $c.ParentDN
        if (-not $p) { continue }
        if (-not $byParent.ContainsKey($p)) { $byParent[$p] = New-Object System.Collections.Generic.List[object] }
        $byParent[$p].Add($c)
    }

    $emitted = 0
    $capped = $false

    function Format-Node {
        param($Node, $ByParent, [int]$Depth)
        if ($script:__treeCount -ge $script:MaxOuNodes) { $script:__treeCapped = $true; return '' }
        $script:__treeCount++

        # Sort-Object {$_.X}, never Sort-Object X. After -FromState these records
        # are OrderedDictionary, and Sort-Object resolves a bare property NAME
        # through the PSObject property adapter, which a dictionary does not
        # expose for its entries -- so the sort silently becomes a no-op and the
        # output falls back to insertion order. Nothing errors; the report is just
        # ordered differently on re-render than it was live, which breaks the
        # diffability the state file exists to provide. A scriptblock uses member
        # access, which works for both shapes.
        $links = @($Node.Links | Sort-Object { [int]$_.LinkOrder })
        $lbl = ConvertTo-OutlineHtmlText $Node.Name
        $marks = ''
        if ($Node.BlockInheritance) { $marks += " <span class='bi'>[block inheritance]</span>" }

        $gpoText = ''
        if ($links.Count -gt 0) {
            $parts = @($links | ForEach-Object {
                $n = $_.GpoId
                foreach ($g in $script:Outline.Gpos) { if ($g.Key -eq $_.GpoKey) { $n = $g.Name; break } }
                $t = "$($_.LinkOrder). " + (ConvertTo-OutlineHtmlText $n)
                if ($_.Enforced) { $t += " <span class='enf'>[enforced]</span>" }
                if (-not $_.Enabled) { $t += " <span class='bi'>[link disabled]</span>" }
                $t
            })
            $gpoText = "<div class='gpl'>&#8627; " + ($parts -join ' &middot; ') + "</div>"
        }

        $kids = @()
        if ($ByParent.ContainsKey($Node.DN)) { $kids = @($ByParent[$Node.DN] | Sort-Object { [string]$_.Name }) }

        if ($kids.Count -eq 0) {
            return "<li><span class='ouname'>$lbl</span>$marks$gpoText</li>"
        }

        $inner = ''
        foreach ($k in $kids) { $inner += Format-Node -Node $k -ByParent $ByParent -Depth ($Depth + 1) }
        $open = if ($Depth -lt 1) { ' open' } else { '' }
        return "<li><details$open><summary>$lbl$marks</summary>$gpoText<ul>$inner</ul></details></li>"
    }

    $script:__treeCount = 0
    $script:__treeCapped = $false

    [void]$sb.Append("<div class='outree'><ul>")
    foreach ($r in $roots) { [void]$sb.Append((Format-Node -Node $r -ByParent $byParent -Depth 0)) }
    [void]$sb.Append('</ul></div>')

    if ($script:__treeCapped) {
        [void]$sb.Append("<p class='muted'>The tree is capped at $($script:MaxOuNodes) nodes for readability. Counts elsewhere in this report cover every OU.</p>")
    }
    return $sb.ToString()
}

function New-OutlineHtml {
    <#
      Builds the complete self-contained report from $script:Outline.
      No external CSS, JS, fonts, or images; no web calls at open time.
    #>
    param([Parameter(Mandatory)][string]$OutputPath, [switch]$NoJson)

    $O = $script:Outline
    $Stats = $O.Stats
    $now = $O.GeneratedAt
    $forest = $O.ForestName

    # ---------------- AD domain summary ----------------
    $domRows = @($O.Domains | ForEach-Object {
        [pscustomobject]@{
            Domain = $_.DnsRoot
            NetBIOS = $_.NetBIOS
            Role = $(if ($_.IsRoot) { 'Forest root' } else { 'Child / tree domain' })
            'Functional level' = $_.FunctionalLevel
            'Domain controllers' = $_.DcCount
            'PDC emulator' = $_.PdcEmulator
            GPOs = $_.GpoCount
            OUs = $_.OuCount
            'WMI filters' = $_.WmiFilterCount
            'SYSVOL replication' = $_.SysvolReplica
            'Central ADMX store' = $_.CentralStore
            'DC used for collection' = $_.BoundDc
        }
    })

    $cards  = New-StatCard $Stats.Domains 'Domains' 'var(--accent)'
    $cards += New-StatCard $Stats.DomainControllers 'Domain Controllers' 'var(--accent2)'
    $cards += New-StatCard $Stats.Gpos 'Group Policy Objects' 'var(--green)'
    $cards += New-StatCard $Stats.Ous 'Organizational Units' 'var(--purple)'
    $cards += New-StatCard $Stats.Sites 'Sites' 'var(--orange)'
    $cards += New-StatCard $Stats.WmiFilters 'WMI Filters' 'var(--pink)'
    $cards += New-StatCard $Stats.Settings 'Settings Recorded' 'var(--amber)'

    $invCards  = New-StatCard $Stats.LinkedGpos 'Linked GPOs' 'var(--green)'
    $invCards += New-StatCard $Stats.UnlinkedGpos 'Not Linked' $(if ($Stats.UnlinkedGpos -gt 0) { 'var(--amber)' } else { 'var(--green)' })
    $invCards += New-StatCard $Stats.EmptyGpos 'Empty GPOs' 'var(--text-mute)'
    $invCards += New-StatCard $Stats.DisabledGpos 'All Settings Disabled' 'var(--text-mute)'
    $invCards += New-StatCard $Stats.TotalLinks 'Total Links' 'var(--accent)'
    $invCards += New-StatCard $Stats.EnforcedLinks 'Enforced Links' 'var(--accent2)'
    $invCards += New-StatCard $Stats.OusBlocking 'OUs Blocking Inheritance' 'var(--amber)'
    $invCards += New-StatCard $Stats.LoopbackGpos 'Loopback GPOs' 'var(--purple)'

    # ---------------- trusts ----------------
    $trustTable = New-HtmlTable -Rows @($O.Trusts) -Columns @('Domain','Partner','Direction','Type','Attributes') `
        -Empty 'No trusts are recorded in this forest.'

    # ---------------- rights ----------------
    $rightsHtml = "<p class='muted'>Rights check not run.</p>"
    if ($O.Rights) {
        $r = $O.Rights
        $checks = [ordered]@{
            'Directory (domain partition) read' = $r.CanReadDomainNC
            'Configuration partition read'      = $r.CanReadConfigNC
            'GPO security descriptors'          = $r.CanReadGpoAcl
            'WMI filter container'              = $r.CanReadWmiFilters
            'SYSVOL policy files'               = $r.CanReadSysvol
            'ADMX central store'                = $r.CanReadCentralStore
            'GPMC present (optional cross-check)' = $r.HasGpmc
        }
        $rightsHtml = "<div class='ig'>"
        $rightsHtml += New-InfoRow 'Collected as' $r.Identity
        $rightsHtml += New-InfoRow 'Collection mode' $O.CollectionMode
        $rightsHtml += New-InfoRow 'PowerShell' $O.PowerShell
        $rightsHtml += '</div><div class="tw"><table><thead><tr><th>Capability</th><th>Result</th></tr></thead><tbody>'
        foreach ($k in $checks.PSBase.Keys) {
            $v = $checks[$k]
            $b = if ($v) { "<span class='b b-ok'>available</span>" } else { "<span class='b b-w'>unavailable</span>" }
            $rightsHtml += "<tr><td>$(ConvertTo-OutlineHtmlText $k)</td><td>$b</td></tr>"
        }
        $rightsHtml += '</tbody></table></div>'
        foreach ($n in @($r.Notes)) { $rightsHtml += "<p class='muted'>$(ConvertTo-OutlineHtmlText $n)</p>" }

        # Permissions required by section: so a section left empty by missing
        # rights is never mistaken for an empty environment.
        $permRows = @()
        foreach ($m in $script:PermMatrix) {
            $cap = $m.Capability
            $state = 'Available'
            if ($cap) {
                if ($r.Contains($cap) -and $r[$cap]) { $state = 'Available' }
                elseif ($r.Contains($cap))           { $state = 'Not available' }
                else                                  { $state = 'Not checked' }
            }
            $permRows += [pscustomobject]@{
                Section = $m.Section; Tier = $m.Tier
                'Rights needed' = $m.Rights
                'This run' = $state
            }
        }
        $rightsHtml += '<h3 class="sub-h">Permissions required by section</h3>'
        $rightsHtml += "<p class='sd'>Where a capability was unavailable, the sections that depend on it say so rather than appearing empty. An empty section in this report means the environment is empty, not that the account could not see it.</p>"
        $rightsHtml += New-HtmlTable -Rows $permRows -Columns @('Section','Tier','Rights needed','This run')
    }

    # ---------------- warnings & observations ----------------
    $warnHtml = ''

    # A failed OU sweep invalidates scope entirely for that domain, so it gets
    # its own banner above the ordinary warning list rather than one line inside
    # it. Without the containers, every GPO in the domain reads as unlinked.
    $cf = @(Get-PropArray $O 'ContainerReadFailures')
    if ($cf.Count -gt 0) {
        $warnHtml += '<h3 class="sub-h">Scope data is incomplete</h3>'
        $warnHtml += "<p class='sd'>The organizational unit sweep did not complete in the domain(s) below. Links are stored on containers, so where this happened the GPOs in that domain will appear unlinked and the OU tree, precedence and conflict sections are incomplete for it. <b>Do not read the link and precedence figures for these domains as a description of the environment.</b></p>"
        foreach ($f in $cf) {
            $warnHtml += "<div class='warn'><b>$(ConvertTo-OutlineHtmlText $f.Domain)</b> &mdash; $(ConvertTo-OutlineHtmlText $f.Reason)</div>"
        }
    }

    if (@($O.Warnings).Count -gt 0) {
        $warnHtml = '<h3 class="sub-h">Collection warnings</h3>'
        $warnHtml += "<p class='sd'>These affected the collection itself &mdash; a host that did not answer, a right that was missing, or a query that failed. Sections they touch may be incomplete.</p>"
        foreach ($w in @($O.Warnings)) { $warnHtml += "<div class='warn'>$(ConvertTo-OutlineHtmlText $w)</div>" }
    }

    $obsHtml = ''
    $obsList = @(Get-PropArray $O 'Observations')
    if ($obsList.Count -gt 0) {
        $groups = [ordered]@{
            'Scope and linking'   = @()
            'Settings and content'= @()
            'Replication and structure' = @()
            'Filtering and delegation'  = @()
        }
        foreach ($t in $obsList) {
            # Named, not $s. PowerShell variable names are case-insensitive, so a
            # loop variable called $s silently overwrites $S -- which used to hold
            # the stats object here, producing a failure hundreds of lines later
            # at a line that looked entirely innocent.
            $obsText = [string]$t
            if     ($obsText -match 'linked|link\(s\)|loopback')  { $groups['Scope and linking']   += $obsText }
            elseif ($obsText -match 'setting|cpassword|contain')  { $groups['Settings and content']+= $obsText }
            elseif ($obsText -match 'version|SYSVOL|domain')      { $groups['Replication and structure'] += $obsText }
            else                                                   { $groups['Filtering and delegation']  += $obsText }
        }
        $obsHtml = '<h3 class="sub-h">Observations</h3>'
        $obsHtml += "<p class='sd'>Factual notes about how this environment is configured, drawn from the data above. They are observations, not findings &mdash; nothing here is scored, graded, or presented as a fault. Whether any of them matters is a judgement for an assessment to make.</p>"
        $obsHtml += "<div class='obs-grid'>"
        foreach ($g in $groups.PSBase.Keys) {
            if ($groups[$g].Count -eq 0) { continue }
            $obsHtml += "<div class='obs-col'><h5>$(ConvertTo-OutlineHtmlText $g) <span>$($groups[$g].Count)</span></h5><ul>"
            foreach ($t in $groups[$g]) { $obsHtml += "<li>$(ConvertTo-OutlineHtmlText $t)</li>" }
            $obsHtml += '</ul></div>'
        }
        $obsHtml += '</div>'
    }

    # ---------------- per-GPO cards ----------------
    # Cards are grouped under a per-domain heading and sorted within it. The
    # domain rail on the left filters to one domain at a time; the headings are
    # what keep "All domains" readable.
    $gpoCards = ''
    $railHtml  = ''
    $domainsWithGpos = @($O.Gpos | ForEach-Object { $_.Domain } | Sort-Object -Unique)

    foreach ($dom in $domainsWithGpos) {
        # Name then Key: the key is a deterministic tiebreaker, so two GPOs with
        # the same display name in one domain cannot swap places between runs.
        $inDom = @($O.Gpos | Where-Object { $_.Domain -eq $dom } |
                   Sort-Object { [string]$_.Name }, { [string]$_.Key })
        $gpoCards += "<h3 class='sub-h gpo-dh' data-domain=`"$(ConvertTo-OutlineHtmlText $dom)`">$(ConvertTo-OutlineHtmlText $dom) &mdash; $($inDom.Count) GPO(s)</h3>"
        foreach ($g in $inDom) { $gpoCards += New-OutlineGpoCard -Gpo $g }
    }
    if (-not $gpoCards) { $gpoCards = "<p class='muted'>No Group Policy objects were collected.</p>" }

    $railHtml = "<button class='gpo-domain active' data-domain='__all'>All domains<span>$(@($O.Gpos).Count)</span></button>"
    foreach ($dom in $domainsWithGpos) {
        $n = @($O.Gpos | Where-Object { $_.Domain -eq $dom }).Count
        $linked = @($O.Gpos | Where-Object { $_.Domain -eq $dom -and $_.LinkCount -gt 0 }).Count
        $railHtml += "<button class='gpo-domain' data-domain=`"$(ConvertTo-OutlineHtmlText $dom)`" title='$linked of $n linked'>$(ConvertTo-OutlineHtmlText $dom)<span>$n</span></button>"
    }

    # ---------------- precedence ----------------
    $precRows = @($O.Precedence | Where-Object { $_.AppliedCount -gt 0 } | ForEach-Object {
        [pscustomobject]@{
            Container = $_.Container; Type = $_.ContainerType; Domain = $_.Domain
            'Blocks inheritance' = $(if ($_.BlockInheritance) { 'Yes' } else { '' })
            'What applies here, in order (1 wins)' = (@($_.Applied | ForEach-Object {
                "$($_.Precedence). $($_.GpoName)" + $(if ($_.Enforced) { ' [enforced]' } else { '' })
            }) -join '  |  ')
            'GPOs applying' = $_.AppliedCount
        }
    })

    # ---------------- loopback ----------------
    $loopHtml = if (@($O.Loopback).Count -eq 0) {
        "<p class='muted'>No GPO in this forest enables user Group Policy loopback processing.</p>"
    } else {
        (New-HtmlTable -Rows @($O.Loopback | ForEach-Object {
            [pscustomobject]@{
                GPO = $_.GpoName; Domain = $_.Domain; Mode = $_.Mode
                'Applies at' = $_.ScopeText
                'What that means' = $_.Explanation
            } }) -Columns @('GPO','Domain','Mode','Applies at','What that means'))
    }

    # ---------------- site links ----------------
    $siteRows = @($O.Links | Where-Object { $_.ContainerType -eq 'Site' } | ForEach-Object {
        [pscustomobject]@{
            Site = $_.ContainerName; GPO = $_.GpoName; 'GPO domain' = $_.GpoDomain
            'Link order' = $_.LinkOrder
            Enabled = $(if ($_.Enabled) { 'Yes' } else { 'No' })
            Enforced = $(if ($_.Enforced) { 'Yes' } else { '' })
        }
    })

    # ---------------- starter GPOs ----------------
    $starterRows = @(Get-PropArray $O 'StarterGpos')
    $starterTable = New-HtmlTable -Rows $starterRows `
        -Columns @('Name','Domain','Kind','Computer settings','User settings','Areas','Modified','Path') `
        -Empty $(if ($script:SkipSysvolFlag) { 'SYSVOL was not read, so Starter GPOs were not enumerated.' } else { 'No Starter GPOs exist on SYSVOL in the collected domains. This is the default state -- the StarterGPOs folder is only created when the first Starter GPO is made.' })

    # ---------------- default policies ----------------
    $defaultGuids = @('{31B2F340-016D-11D2-945F-00C04FB984F9}','{6AC1786C-016F-11D2-945F-00C04FB984F9}')
    $defRows = @($O.Gpos | Where-Object { $defaultGuids -contains $_.Id } | ForEach-Object {
        [pscustomobject]@{
            GPO = $_.Name; Domain = $_.Domain
            Which = $(if ($_.Id -eq '{31B2F340-016D-11D2-945F-00C04FB984F9}') { 'Default Domain Policy' } else { 'Default Domain Controllers Policy' })
            Status = $_.Status; Settings = $_.SettingCount; Links = $_.LinkCount
            Modified = $_.Changed
        }
    })

    # ---------------- anomalies ----------------
    $an = $O.Anomalies
    $anomalyHtml = ''
    if ($an) {
        $blocks = [ordered]@{
            'GPOs not linked anywhere' = @{ Rows = @($an.UnlinkedGpos); Cols = @('Name','Domain','Status','Settings','Created'); Note = 'These exist in the directory but are not linked to any site, domain or OU, so they do not apply. This is often deliberate &mdash; a staged or retired policy kept for reference.' }
            'GPOs containing no settings' = @{ Rows = @($an.EmptyGpos); Cols = @('Name','Domain','Links'); Note = 'These contain no settings in either half, so they have no runtime effect even where they are linked.' }
            'GPOs with both halves disabled' = @{ Rows = @($an.AllDisabledGpos); Cols = @('Name','Domain','Links'); Note = 'The User and Computer halves are both switched off, so nothing in them is processed.' }
            'Version mismatches between the directory and SYSVOL' = @{ Rows = @($an.VersionMismatches); Cols = @('Name','Domain','AD (User/Computer)','SYSVOL (User/Computer)'); Note = 'The two halves of the GPO record different version numbers. This normally means replication has not finished converging.' }
            'GPOs with no SYSVOL folder' = @{ Rows = @($an.MissingSysvol); Cols = @('Name','Domain','Reason'); Note = 'A directory object exists but the matching policy folder was not found, so the settings cannot be read or applied.' }
            'SYSVOL folders with no directory object' = @{ Rows = @($an.StraySysvolFolders); Cols = @('Domain','Folder','Modified'); Note = 'A policy folder exists in SYSVOL with no matching Group Policy object in the directory. Nothing can apply it.' }
            'Disabled links' = @{ Rows = @($an.DisabledLinks); Cols = @('Gpo','Container','Type','Domain'); Note = 'The GPO is linked here but the link is switched off, so it does not apply at this container.' }
            'Links pointing at a GPO that was not found' = @{ Rows = @($an.OrphanedLinks); Cols = @('Container','Type','GpoId','Domain'); Note = 'The container references a GPO that could not be found in the collected data &mdash; typically a deleted GPO whose link was left behind, or one in a domain not collected.' }
            'Cross-domain links' = @{ Rows = @($an.CrossDomainLinks); Cols = @('Gpo','GPO domain','Container','Container domain'); Note = 'A GPO in one domain is linked to a container in another. This is legal but means every policy refresh at that container reads SYSVOL across the domain boundary.' }
            'GPOs that reach no one' = @{ Rows = @($an.NoApplyPrincipal); Cols = @('Name','Domain','Links'); Note = 'No principal holds both Read and Apply Group Policy, so these do not apply to any user or computer despite being linked.' }
            'GPOs where Authenticated Users does not have Apply' = @{ Rows = @($an.AuthUsersRemoved); Cols = @('Name','Domain','Applies to'); Note = 'Scope is set by explicit principals rather than by the links alone. Since MS16-072 this is a normal delegation pattern; it is recorded here as a fact about scope, not as a fault.' }
            'GPOs containing a preferences credential' = @{ Rows = @($an.CPasswordGpos); Cols = @('Name','Domain','Items','Count'); Note = 'A cpassword attribute is present. GPOOutline records only that one exists and where; it never reads or stores the value.' }
        }
        foreach ($k in $blocks.PSBase.Keys) {
            $b = $blocks[$k]
            if ($b.Rows.Count -eq 0) { continue }
            $anomalyHtml += "<h3 class='sub-h'>$(ConvertTo-OutlineHtmlText $k) &mdash; $($b.Rows.Count)</h3>"
            $anomalyHtml += "<p class='sd'>$($b.Note)</p>"
            $anomalyHtml += New-HtmlTable -Rows $b.Rows -Columns $b.Cols -MaxRows 500
        }
    }
    if (-not $anomalyHtml) { $anomalyHtml = "<p class='muted'>No structural anomalies were recorded.</p>" }

    # ---------------- matrices ----------------
    $mx = $O.Matrices
    $gpoToOuTable = if ($mx) {
        $keyByName = @{}
        foreach ($g in @($O.Gpos)) { $keyByName["$($g.Domain)|$($g.Name)"] = $g.Key }
        $rowsLinked = @($mx.GpoToContainer | ForEach-Object {
            $k = $keyByName["$($_.Domain)|$($_.GPO)"]
            [pscustomobject][ordered]@{
                GPO = $(if ($k) { "<a class='cl-link' href='#gpo-$(Get-OutlineSlug $k)'>$(ConvertTo-OutlineHtmlText $_.GPO)</a>" } else { ConvertTo-OutlineHtmlText $_.GPO })
                Domain = $_.Domain; Status = $_.Status; 'Linked to' = $_.'Linked to'
                Links = $_.Links; Settings = $_.Settings
            } })
        New-HtmlTable -Rows $rowsLinked -Columns @('GPO','Domain','Status','Linked to','Links','Settings') `
            -RawColumns @('GPO') -MaxRows 2000
    } else { "<p class='muted'>Not computed.</p>" }
    $ouToGpoTable = if ($mx) { New-HtmlTable -Rows @($mx.ContainerToGpo) -Columns @('Container','Type','Domain','Block inheritance','Applies in order (1 wins)','Count') -MaxRows 2000 } else { "<p class='muted'>Not computed.</p>" }
    # Counts link to the principal's own block below, so a reader who sees
    # "delegation 175" can see which 175 without leaving the page.
    $groupTable = ''
    $principalHtml = ''
    if ($mx) {
        # Only the principals that actually get a detail block below may be
        # linked. A state file written before PrincipalDetail existed has no
        # blocks at all, and a link to a missing anchor is worse than a plain
        # number: it looks broken and teaches the reader not to trust the links.
        $pdList = @(Get-PropArray $mx 'PrincipalDetail')
        $linkable = @{}
        foreach ($pd in $pdList) {
            $sl = Get-PropValue $pd 'Slug'
            if (-not $sl) { $sl = Get-OutlineSlug $pd.Principal }
            if (@($pd.Uses).Count -gt 0) { $linkable[[string]$pd.Principal] = $sl }
        }

        $groupRowsLinked = @($mx.GroupUsage | ForEach-Object {
            $name = [string]$_.Principal
            $slug = $(if ($linkable.ContainsKey($name)) { $linkable[$name] } else { $null })
            [pscustomobject][ordered]@{
                Principal = $name
                'Used in filtering'  = $(if ($slug) { New-CountLink $_.'Used in filtering'  "principal-$slug" 'Show where' } else { ConvertTo-OutlineHtmlText $_.'Used in filtering' })
                'Used in delegation' = $(if ($slug) { New-CountLink $_.'Used in delegation' "principal-$slug" 'Show where' } else { ConvertTo-OutlineHtmlText $_.'Used in delegation' })
                'Can edit settings'  = $(if ($slug) { New-CountLink (Get-PropValue $_ 'Can edit') "principal-$slug" 'Show which GPOs' } else { ConvertTo-OutlineHtmlText (Get-PropValue $_ 'Can edit') })
                Resolved = $_.Resolved
            } })
        $groupTable = New-HtmlTable -Rows $groupRowsLinked `
            -Columns @('Principal','Used in filtering','Used in delegation','Can edit settings','Resolved') `
            -RawColumns @('Used in filtering','Used in delegation','Can edit settings') -MaxRows 1000

        foreach ($pd in $pdList) {
            $uses = @($pd.Uses)
            if ($uses.Count -eq 0) { continue }
            $badge = if ($pd.CanEditCount -gt 0) { "<span class='b b-w'>can edit $($pd.CanEditCount)</span>" } else { '' }
            $pdSlug = Get-PropValue $pd 'Slug'
            if (-not $pdSlug) { $pdSlug = Get-OutlineSlug $pd.Principal }
            $principalHtml += "<details class='gpo' id='principal-$pdSlug'><summary>"
            $principalHtml += "<span class='gname'>$(ConvertTo-OutlineHtmlText $pd.Principal)</span>"
            $principalHtml += "<span class='b b-i'>filtering $($pd.Filtering)</span> <span class='b b-i'>delegation $($pd.Delegation)</span> $badge"
            $sidText = if ($pd.Sid) { $pd.Sid } else { 'not recorded' }
            $principalHtml += "<span class='gplain'>SID $(ConvertTo-OutlineHtmlText $sidText) &mdash; used on $($pd.Total) GPO reference(s) across the forest.</span>"
            $principalHtml += "</summary><div class='gbody'>"
            # Uniform groups collapse to one line. "Enterprise Admins, Full
            # control, on all 148 GPOs in this domain" is both smaller and more
            # informative than 148 identical rows -- the repetition actively
            # hides the shape of the delegation. Anything non-uniform, or small
            # enough to read, is still listed GPO by GPO with links.
            $domTotals = @{}
            foreach ($dd in @($O.Domains)) { $domTotals[[string]$dd.DnsRoot] = [int]$dd.GpoCount }

            $grouped = @{}
            foreach ($u in $uses) {
                $gk = "$($u.Usage)|$($u.Domain)|$($u.Rights)|$($u.Effect)"
                if (-not $grouped.ContainsKey($gk)) { $grouped[$gk] = New-Object System.Collections.Generic.List[object] }
                $grouped[$gk].Add($u)
            }

            $detailRows = New-Object System.Collections.Generic.List[object]
            foreach ($gk in @($grouped.Keys | Sort-Object)) {
                $grp = @($grouped[$gk].ToArray())
                $first = $grp[0]
                $dTotal = $(if ($domTotals.ContainsKey([string]$first.Domain)) { $domTotals[[string]$first.Domain] } else { 0 })

                if ($grp.Count -gt $script:PrincipalFoldAt) {
                    $scope = if ($dTotal -gt 0 -and $grp.Count -ge $dTotal) {
                        "Every GPO in this domain ($($grp.Count))"
                    } else { "$($grp.Count) GPOs in this domain" }
                    $detailRows.Add([pscustomobject][ordered]@{
                        Usage = $first.Usage
                        GPO = "<span class='cz'>$(ConvertTo-OutlineHtmlText $scope)</span>"
                        Domain = $first.Domain; Rights = $first.Rights
                        'What that means' = $first.Effect
                    })
                    continue
                }
                foreach ($u in $grp) {
                    $detailRows.Add([pscustomobject][ordered]@{
                        Usage = $u.Usage
                        GPO = "<a class='cl-link' href='#gpo-$(Get-OutlineSlug $u.GpoKey)'>$(ConvertTo-OutlineHtmlText $u.GPO)</a>"
                        Domain = $u.Domain; Rights = $u.Rights
                        'What that means' = $u.Effect
                    })
                }
            }
            $collapsed = @($uses).Count - $detailRows.Count
            $principalHtml += New-HtmlTable -Rows $detailRows.ToArray() `
                -Columns @('Usage','GPO','Domain','Rights','What that means') `
                -RawColumns @('GPO') -MaxRows 600
            if ($collapsed -gt 0) {
                $principalHtml += "<p class='muted'>$collapsed identical row(s) were folded into the summary lines above. The per-GPO detail for every one of them is in the state file, and each GPO's own card lists this principal under delegation.</p>"
            }
            $principalHtml += '</div></details>'
        }
    }
    if (-not $principalHtml) {
        $principalHtml = if ($mx -and @($mx.GroupUsage).Count -gt 0) {
            "<p class='muted'>Per-principal detail is not present in this dataset. It is recorded by collection from v1.0 onwards, so a state file written by an earlier build shows the counts above without the detail behind them. Re-collect to populate this section.</p>"
        } else {
            "<p class='muted'>No principal was recorded in filtering or delegation on any GPO.</p>"
        }
    }
    # 'Used by' becomes links, so a reader can go from a filter straight to the
    # GPOs gated by it.
    $wmiTable = ''
    if ($mx) {
        $wmiIdx = @{}
        foreach ($w in @($O.WmiFilters)) { if ($w.Key) { $wmiIdx[$w.Key] = $w } }
        $wmiRowsLinked = @($mx.WmiUsage | ForEach-Object {
            $row = $_
            $links = '(not used)'
            $match = @($O.WmiFilters | Where-Object { $_.Name -eq $row.Filter -and $_.Domain -eq $row.Domain })
            if ($match.Count -gt 0 -and @($match[0].UsedBy).Count -gt 0) {
                $links = (@($match[0].UsedBy | ForEach-Object {
                    "<a class='cl-link' href='#gpo-$(Get-OutlineSlug $_.GpoKey)'>$(ConvertTo-OutlineHtmlText $_.GpoName)</a>"
                }) -join ', ')
            }
            [pscustomobject][ordered]@{
                Filter = $row.Filter; Domain = $row.Domain
                'Used by' = $links; Count = $row.Count; Query = $row.Query
            } })
        $wmiTable = New-HtmlTable -Rows $wmiRowsLinked -Columns @('Filter','Domain','Used by','Count','Query') `
            -RawColumns @('Used by') -Empty 'No WMI filters are defined in this forest.'
    }
    $cseTable     = if ($mx) { New-HtmlTable -Rows @($mx.CseUsage) -Columns @('Extension','Area','Computer half','User half','Total','GUID') } else { '' }

    # The GPO column links to the card, which is the natural next question after
    # "who sets this?" -- namely "and what else does that GPO do?".
    $settingIndexTable = New-HtmlTable -Rows @($O.SettingIndex | ForEach-Object {
        $k = Get-PropValue $_ 'GpoKey'
        [pscustomobject][ordered]@{
            Setting = $_.Name; Area = $_.Area; Scope = $_.Scope; Value = $_.Data
            GPO = $(if ($k) { "<a class='cl-link' href='#gpo-$(Get-OutlineSlug $k)'>$(ConvertTo-OutlineHtmlText $_.GpoName)</a>" } else { ConvertTo-OutlineHtmlText $_.GpoName })
            Domain = $_.Domain } }) `
        -Columns @('Setting','Area','Scope','Value','GPO','Domain') -RawColumns @('GPO') -MaxRows 3000 `
        -Empty 'No settings were read. This is expected when SYSVOL was skipped or was not readable.'

    # ---------------- behaviour ----------------
    $bh = $O.Behavior
    $flagsTable  = if ($bh) { New-HtmlTable -Rows @($bh.ProcessingFlags) -Columns @('GPO','Domain','Client-side extensions','Processing notes') -MaxRows 2000 } else { '' }
    $slowTable   = if ($bh) { New-HtmlTable -Rows @($bh.SlowProcessing) -Columns @('GPO','Domain','Links','Why it affects logon or boot') -Empty 'No GPO records an extension or setting that forces synchronous foreground processing.' } else { '' }
    $footTable   = if ($bh) { New-HtmlTable -Rows @($bh.Footprint) -Columns @('Area','Settings','GPOs touching it') } else { '' }
    $tattooTable = if ($bh) { New-HtmlTable -Rows @($bh.Tattooing) -Columns @('GPO','Domain','Preference items','Registry writes outside the managed policy branches','Effect') -Empty 'No preference items or unmanaged registry writes were recorded.' -MaxRows 1000 } else { '' }
    $noEffectTable = if ($bh) { New-HtmlTable -Rows @($bh.NoEffect) -Columns @('GPO','Domain','Why it has no runtime effect') -Empty 'Every collected GPO has some runtime effect.' -MaxRows 1000 } else { '' }

    $conflictTable = New-HtmlTable -Rows @($O.Conflicts | ForEach-Object {
        [pscustomobject]@{
            Container = $_.Container; Setting = $_.Setting; Area = $_.Area; Scope = $_.Scope
            'Winning GPO' = $_.WinningGpo; 'Winning value' = $_.WinningValue
            'Overridden' = $_.OverriddenBy
            'Same value' = $(if ($_.SameValue) { 'Yes -- no practical difference' } else { '' })
        } }) -Columns @('Container','Setting','Area','Scope','Winning GPO','Winning value','Overridden','Same value') `
        -MaxRows 2000 -Empty 'No setting is defined by more than one GPO applying to the same container.'

    # ---------------- central store ----------------
    $csRows = @($O.CentralStore)
    $csTable = New-HtmlTable -Rows $csRows -Columns @('Domain','Central store','Path','ADMX files','ADML files','Language','Policies mapped') `
        -Empty 'ADMX resolution was not attempted.'

    $admxNote = ''
    $unresolved = @($O.SettingIndex | Where-Object { $_.Area -eq 'Administrative Templates' -and -not $_.Resolved })
    $atTotal = @($O.SettingIndex | Where-Object { $_.Area -eq 'Administrative Templates' }).Count
    if ($atTotal -gt 0) {
        $pct = [math]::Round(100 * ($atTotal - $unresolved.Count) / $atTotal, 1)
        $admxNote = "<p class='sd'>$($atTotal - $unresolved.Count) of $atTotal Administrative Template values ($pct%) resolved to a friendly policy name. The remainder are shown as raw registry keys, which happens when the ADMX defining them is not in the store that was read, or when the value is written by a policy that does not name it individually.</p>"
    }

    # ---------------- coverage ----------------
    $cov = $O.Coverage
    $covHtml = ''
    if ($cov) {
        $covHtml += "<div class='ig'>"
        $covHtml += New-InfoRow 'GPOs discovered' "$($cov.GposDiscovered)"
        $covHtml += New-InfoRow 'GPO settings read from SYSVOL' "$($cov.SysvolRead)"
        $covHtml += New-InfoRow 'GPOs whose SYSVOL could not be read' "$($cov.SysvolFailed)"
        $covHtml += New-InfoRow 'Domains collected' "$($cov.DomainsCollected) of $($cov.DomainsDiscovered)"
        $covHtml += New-InfoRow 'Collection started' $O.StartTime
        $covHtml += New-InfoRow 'Collection finished' $O.GeneratedAt
        $covHtml += New-InfoRow 'Duration' $O.Duration
        $covHtml += '</div>'
        if (@($cov.Skipped).Count -gt 0) {
            $covHtml += '<h3 class="sub-h">Skipped or unreadable</h3>'
            $covHtml += New-HtmlTable -Rows @($cov.Skipped) -Columns @('What','Why') -MaxRows 500
        }
    }

    # ---------------- glossary ----------------
    $glossRows = @($script:Glossary.PSBase.Keys | ForEach-Object {
        [pscustomobject]@{ Term = $_; Meaning = $script:Glossary[$_] } })
    $glossTable = New-HtmlTable -Rows $glossRows -Columns @('Term','Meaning')

    # ---------------- embedded data ----------------
    $json = '{}'
    if (-not $NoJson) {
        try {
            # Depth 6 keeps the payload bounded: the deep per-GPO settings are
            # already rendered above, and the state file holds the full fidelity.
            $slim = [ordered]@{
                Tool = $O.Tool; Version = $O.Version; Build = $O.Build
                ForestName = $O.ForestName; GeneratedAt = $O.GeneratedAt
                Stats = $O.Stats
                Domains = @($O.Domains | ForEach-Object { [ordered]@{ DnsRoot = $_.DnsRoot; GpoCount = $_.GpoCount; OuCount = $_.OuCount; DcCount = $_.DcCount; SysvolReplica = $_.SysvolReplica } })
                Behavior = [ordered]@{ Footprint = @($O.Behavior.Footprint) }
                Matrices = [ordered]@{ CseUsage = @($O.Matrices.CseUsage) }
            }
            $json = $slim | ConvertTo-Json -Depth 6 -Compress
            # '</' inside a <script> block would end it early.
            $json = $json -replace '</', '<\/'
        }
        catch { Write-OutlineQuiet $_ 'EmbedJson'; $json = '{}' }
    }

    $unreadDomains = @($O.Domains | Where-Object { -not $_.Collected })

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GPOOutline -- $(ConvertTo-OutlineHtmlText $forest)</title>
<style>$($script:OutlineCss)</style>
</head>
<body>
<div class="topbar">
  <div class="tb-title">GPO<em>Outline</em><span> &mdash; $(ConvertTo-OutlineHtmlText $forest)</span></div>
  <div class="tb-meta">
    <span>$(ConvertTo-OutlineHtmlText $now)</span>
    <button class="tb-btn" onclick="window.print()">Print / Save PDF</button>
    <button class="tb-btn" id="tocTop">Top</button>
  </div>
</div>
<div class="wrapper">
<aside class="sidebar">
  <div class="logo">
    <h2>GPO<em>Outline</em></h2>
    <p>The Shape of Your Group Policy</p>
    <div class="byline">
      <p>Report generated using the <strong>GPOOutline</strong> script</p>
      <p>Developed by <strong>Santhosh Sivarajan</strong></p>
      <p>Microsoft MVP</p>
      <p class="links">
        <a href="https://www.linkedin.com/in/sivarajan/" target="_blank">LinkedIn</a> &middot;
        <a href="https://github.com/SanthoshSivarajan/GPOOutline" target="_blank">GitHub</a>
      </p>
    </div>
    <p class="forest">Forest<strong>$(ConvertTo-OutlineHtmlText $forest)</strong></p>
  </div>
  <nav>
    <div class="ng">Overview</div>
    <a href="#about">Purpose &amp; Disclaimer</a>
    <a href="#summary">AD Domain Summary</a>
    <a href="#inventory">GPO Inventory</a>
    <a href="#trusts">Trusts &amp; Scope Boundaries</a>
    <a href="#rights">Collection Rights</a>
    <div class="ng">Group Policy</div>
    <a href="#gpos">Every GPO in Detail</a>
    <a href="#defaults">Default Policies</a>
    <a href="#starters">Starter GPOs</a>
    <div class="ng">Scope &amp; Inheritance</div>
    <a href="#outree">OU Tree with Links</a>
    <a href="#precedence">Resultant Precedence</a>
    <a href="#loopback">Loopback Processing</a>
    <a href="#sites">Site-Linked GPOs</a>
    <a href="#anomalies">Orphans &amp; Anomalies</a>
    <div class="ng">Cross-Reference</div>
    <a href="#mgpoou">GPO to Container</a>
    <a href="#mougpo">Container to GPO</a>
    <a href="#index">Setting Search Index</a>
    <a href="#groups">Security Group Usage</a>
    <a href="#principals">Principal Usage Detail</a>
    <a href="#wmi">WMI Filter Usage</a>
    <a href="#cse">Client-Side Extensions</a>
    <div class="ng">Behaviour &amp; Impact</div>
    <a href="#conflicts">Conflict &amp; Override Map</a>
    <a href="#flags">Processing Behaviour</a>
    <a href="#slow">Logon &amp; Boot Cost</a>
    <a href="#footprint">Setting Footprint</a>
    <a href="#tattoo">Tattooing</a>
    <a href="#noeffect">GPOs With No Effect</a>
    <div class="ng">Reference</div>
    <a href="#admx">ADMX &amp; Central Store</a>
    <a href="#coverage">Collection Coverage</a>
    <a href="#glossary">Glossary</a>
  </nav>
</aside>
<main class="main">

<header class="masthead">
  <div class="mh-title">GPO<em>Outline</em></div>
  <div class="mh-tagline">The Shape of Your Group Policy</div>
  <p class="mh-about">
    GPOOutline is a single-file, read-only PowerShell script that documents how Group Policy is
    configured across an Active Directory forest in one run. It captures a point-in-time record of
    every Group Policy object exactly as it stands at the moment of collection: where each one is
    linked, who it applies to, who can change it, what it contains across all seven setting areas,
    which policies win where, and how the whole layer behaves at logon and boot.
    This is a current-state document, not an assessment &mdash; it records what is configured,
    without scoring, grading, or recommending. It requires no RSAT modules and no GPMC, reads
    Group Policy directly from LDAP and SYSVOL, and never creates, modifies, or deletes a
    directory object, SYSVOL file, registry value, or GPO.
  </p>
  <div class="mh-author">
    Developed by <strong>Santhosh Sivarajan</strong>, Microsoft MVP
  </div>
  <div class="mh-contact">
    <a href="https://www.linkedin.com/in/sivarajan/" target="_blank">LinkedIn</a>
    <span>&middot;</span>
    <a href="https://github.com/SanthoshSivarajan/GPOOutline" target="_blank">github.com/SanthoshSivarajan/GPOOutline</a>
    <span>&middot;</span>
    <a href="mailto:santhosh@sivarajan.com">santhosh@sivarajan.com</a>
    <span>&middot;</span>
    <span class="mh-lic">MIT License</span>
  </div>
</header>

<div id="about" class="section">
  <div class="about">
    <div class="ac p">
      <h3>Purpose</h3>
      <p>This report is a current-state record of how Group Policy is configured in this forest,
         captured at a single point in time: the full GPO inventory, every link and its precedence,
         security filtering and delegation, WMI filters, and the settings themselves across
         Administrative Templates, security settings, scripts, preferences, folder redirection,
         and software installation.</p>
      <p>It documents what is configured, not what should be. There is no scoring, no maturity
         rating, and no remediation advice. Where the report explains behaviour &mdash; that an
         enforced link cannot be blocked, or that a preference item is not reverted &mdash; it is
         describing mechanics, not passing judgement.</p>
      <p>Cloud and Intune analysis is deliberately absent for the same reason: judging what would
         map, what would not, and what a migration would cost is interpretation, and it belongs to
         a tool built for it rather than to a current-state record.</p>
      <p>It is written to be read by someone who is not a Group Policy specialist. Each GPO opens
         with a plain-English summary; the raw detail sits underneath it. Terms are defined in the
         <a href="#glossary">glossary</a>.</p>
      <p>This report is an <b>Outline</b> tool. Its closest sibling is <b>ADOutline</b>, which does
         the same for the directory itself; <b>GPOLens</b> reads the same collected data through an
         Intune migration lens.</p>
      <div class="series">
        <div class="series-row self"><span class="sn">Outline</span><span class="sv">Document what is configured, right now.<span class="self-tag">this report</span></span></div>
        <div class="series-row"><span class="sn">Atlas</span><span class="sv">Map how it is structured and what connects to what.</span></div>
        <div class="series-row"><span class="sn">Canvas</span><span class="sv">Understand what it means and where to look.</span></div>
        <div class="series-row"><span class="sn">Lens</span><span class="sv">Compare against an earlier record and report what moved.</span></div>
      </div>
    </div>
    <div class="ac d">
      <h3>Disclaimer &amp; Method</h3>
      <p>Provided as is, without warranty of any kind. Collection is <strong>read-only</strong>:
         no directory object, SYSVOL file, registry value, or GPO is created, modified, or deleted.
         The only files written are this report, the state file, and the log.</p>
      <p>Group Policy was read directly from LDAP and from SYSVOL files. The
         <strong>ActiveDirectory</strong> and <strong>GroupPolicy</strong> modules were not used and
         are not required, so this report can be produced from a machine with no RSAT installed.</p>
      <p>Results depend on the rights of the collecting account and on domain controller
         reachability at run time. Anything skipped or unreadable is listed under
         <a href="#coverage">collection coverage</a> and in the
         <a href="#rights">permissions table</a> &mdash; a section that is empty here is empty in the
         environment, not empty because the account could not see it.</p>
      <p>Where a Group Policy Preferences item contains a <strong>cpassword</strong> attribute, this
         report records only that one is present and where. The value is never read, decrypted,
         or stored.</p>
    </div>
  </div>
</div>

<div id="summary" class="section">
  <h2 class="st"><span class="ico" style="background:rgba(77,141,250,.15);color:var(--accent)">&#9776;</span>AD Domain Summary</h2>
  <p class="sd">What this forest is, before any Group Policy detail. Group Policy does not cross a
     domain or a forest boundary, so this table also sets the edges of everything that follows.</p>
  <div class="cards">$cards</div>
  <div class="ig">
    $(New-InfoRow 'Forest' $forest)
    $(New-InfoRow 'Forest functional level' (Get-FuncLevelName $O.RootDse.ForestFunctional))
    $(New-InfoRow 'Schema version' (Get-SchemaVersionName (Get-PropValue $O 'SchemaVersion')))
    $(New-InfoRow 'Bound to' $O.RootDse.DnsHostName)
    $(New-InfoRow 'Collection mode' $O.CollectionMode)
    $(New-InfoRow 'Highest committed USN at bind' $O.RootDse.HighestCommittedUsn)
  </div>
  <p class="sd">Group Policy was read from <b>one domain controller per domain</b>, listed in the
     table below. That makes each domain's data a coherent point-in-time view of that controller
     rather than a blend across replicas, so a GPO changed elsewhere and not yet replicated to the
     controller named here would not appear.</p>
  <h3 class="sub-h">Domains</h3>
  $(New-HtmlTable -Rows $domRows -Columns @('Domain','NetBIOS','Role','Functional level','Domain controllers','PDC emulator','GPOs','OUs','WMI filters','SYSVOL replication','Central ADMX store','DC used for collection'))
  $(if ($unreadDomains.Count -gt 0) { "<p class='muted'>$($unreadDomains.Count) domain(s) could not be collected: " + (ConvertTo-OutlineHtmlText ((@($unreadDomains | ForEach-Object { "$($_.DnsRoot) -- $($_.SkipReason)" }) -join '; '))) + "</p>" })
  <div id="chartDomains" class="chart-grid"></div>
</div>

<div id="inventory" class="section">
  <h2 class="st"><span class="ico" style="background:rgba(52,211,153,.15);color:var(--green)">&#9636;</span>GPO Inventory &amp; Scope of Management</h2>
  <p class="sd">The shape of the Group Policy estate: how many objects exist, how many of them
     actually reach anything, and how the containers they attach to are configured.</p>
  <div class="cards">$invCards</div>
  <div id="chartInventory" class="chart-grid"></div>
  $warnHtml
  $obsHtml
</div>

<div id="trusts" class="section">
  <h2 class="st"><span class="ico" style="background:rgba(167,139,250,.15);color:var(--purple)">&#8646;</span>Trusts &amp; Scope Boundaries</h2>
  <p class="sd">Group Policy does not cross a trust. These are the edges at which the scope of every
     GPO in this report stops.</p>
  $trustTable
</div>

<div id="rights" class="section">
  <h2 class="st"><span class="ico" style="background:rgba(251,191,36,.15);color:var(--amber)">&#128274;</span>Collection Rights</h2>
  <p class="sd">What the collecting account could actually read, proven at run time rather than assumed.</p>
  $rightsHtml
</div>

<div id="gpos" class="section">
  <h2 class="st"><span class="ico" style="background:rgba(77,141,250,.15);color:var(--accent)">&#9635;</span>Every GPO in Detail</h2>
  <p class="sd">One block per Group Policy object, grouped by domain. Pick a domain on the left to
     narrow the list. Each block opens with a plain-English summary of what it is and what it does;
     expand it for links, filtering, delegation, and the full settings listing with the registry keys
     behind them. Note that the default policies exist once <em>per domain</em> and carry the same
     name and the same GUID in each, so the domain is what tells them apart.</p>
  <div class="gpo-layout">
    <nav class="gpo-domains" id="gpoDomains" aria-label="Filter GPOs by domain">$railHtml</nav>
    <div class="gpo-main">
      <div class="tools" id="gpoSearch"></div>
      <div id="gpoList">$gpoCards</div>
    </div>
  </div>
</div>

<div id="starters" class="section">
  <h2 class="st"><span class="ico" style="background:rgba(56,189,248,.15);color:var(--accent2)">&#9776;</span>Starter GPOs</h2>
  <p class="sd">Starter GPOs are templates used to seed new GPOs. They exist only as files on SYSVOL
     &mdash; there is no directory object for them &mdash; so they are invisible to every other
     section of this report, and they apply to nothing until someone creates a GPO from one. They
     are recorded here because an estate description that omits them is incomplete, and because a
     template carrying settings nobody remembers is worth knowing about.</p>
  $starterTable
</div>

<div id="defaults" class="section">
  <h2 class="st"><span class="ico" style="background:rgba(56,189,248,.15);color:var(--accent2)">&#9733;</span>Default Domain &amp; Domain Controllers Policies</h2>
  <p class="sd">Called out separately because these two carry the domain-wide account policy and the
     controller baseline, and are present in every domain by default.</p>
  $(New-HtmlTable -Rows $defRows -Columns @('GPO','Which','Domain','Status','Settings','Links','Modified') -Empty 'Neither default policy was found in the collected domains.')
</div>

<div id="outree" class="section">
  <h2 class="st"><span class="ico" style="background:rgba(52,211,153,.15);color:var(--green)">&#9783;</span>OU Tree with Links</h2>
  <p class="sd">The container hierarchy, with the GPOs linked at each node in link order (1 has the
     highest precedence). Containers that block inheritance and links that are enforced or disabled
     are marked.</p>
  $(New-OutlineOuTreeHtml)
</div>

<div id="precedence" class="section">
  <h2 class="st"><span class="ico" style="background:rgba(77,141,250,.15);color:var(--accent)">&#8681;</span>Resultant Precedence</h2>
  <p class="sd">For each container, the GPOs that actually apply, in the order that decides which one
     wins. Number 1 wins. This is computed from the links, the enforcement flags, and the block
     inheritance settings collected above &mdash; the same rules a client applies, worked out offline.</p>
  $(New-HtmlTable -Rows $precRows -Columns @('Container','Type','Domain','Blocks inheritance','What applies here, in order (1 wins)','GPOs applying') -MaxRows 2000 -Empty 'No container has a GPO applying to it.')
</div>

<div id="loopback" class="section">
  <h2 class="st"><span class="ico" style="background:rgba(244,114,182,.15);color:var(--pink)">&#8635;</span>Loopback Processing</h2>
  <p class="sd">Loopback changes where a user's settings come from, and it is the most common reason a
     policy appears to apply somewhere a reader does not expect. Every GPO that enables it is listed
     here with its mode and the containers it is linked to.</p>
  $loopHtml
</div>

<div id="sites" class="section">
  <h2 class="st"><span class="ico" style="background:rgba(251,146,60,.15);color:var(--orange)">&#9737;</span>Site-Linked GPOs</h2>
  <p class="sd">Site links apply by where a machine sits on the network rather than where its object
     sits in the directory, and they are easy to miss. They are listed separately for that reason.</p>
  $(New-HtmlTable -Rows $siteRows -Columns @('Site','GPO','GPO domain','Link order','Enabled','Enforced') -Empty 'No GPO is linked to a site in this forest.')
</div>

<div id="anomalies" class="section">
  <h2 class="st"><span class="ico" style="background:rgba(251,191,36,.15);color:var(--amber)">&#9888;</span>Orphans &amp; Anomalies</h2>
  <p class="sd">Structurally notable facts about the estate, recorded as facts. None of these is scored
     or presented as a fault &mdash; an unlinked GPO may be a deliberate staging copy, and a GPO scoped
     to explicit groups may be exactly as intended.</p>
  $anomalyHtml
</div>

<div id="mgpoou" class="section">
  <h2 class="st"><span class="ico" style="background:rgba(77,141,250,.15);color:var(--accent)">&#8594;</span>GPO to Container</h2>
  <p class="sd">Where each GPO lands.</p>
  $gpoToOuTable
</div>

<div id="mougpo" class="section">
  <h2 class="st"><span class="ico" style="background:rgba(56,189,248,.15);color:var(--accent2)">&#8592;</span>Container to GPO</h2>
  <p class="sd">What applies where, in precedence order.</p>
  $ouToGpoTable
</div>

<div id="index" class="section">
  <h2 class="st"><span class="ico" style="background:rgba(52,211,153,.15);color:var(--green)">&#128269;</span>Setting Search Index</h2>
  <p class="sd">Every discrete setting recorded across every GPO, in one filterable table. This is the
     fastest way to answer "who sets this?" &mdash; type the setting name or registry value into the
     filter box.</p>
  $settingIndexTable
</div>

<div id="groups" class="section">
  <h2 class="st"><span class="ico" style="background:rgba(167,139,250,.15);color:var(--purple)">&#128101;</span>Security Group Usage</h2>
  <p class="sd">Which principals are used to scope Group Policy, and which hold rights to change it.</p>
  $groupTable
</div>
<div id="principals" class="section">
  <h2 class="st"><span class="ico" style="background:rgba(167,139,250,.15);color:var(--purple)">&#128273;</span>Principal Usage Detail</h2>
  <p class="sd">Every place each principal is used, expanded from the counts above. For delegation
     this is the answer to "who can change our Group Policy, and which GPOs exactly" &mdash; and the
     <b>Can edit settings</b> figure is the one worth reading first, since it is the subset that can
     alter what actually applies. GPO names link through to that GPO's own detail block.</p>
  $principalHtml
</div>


<div id="wmi" class="section">
  <h2 class="st"><span class="ico" style="background:rgba(244,114,182,.15);color:var(--pink)">&#9881;</span>WMI Filter Usage</h2>
  <p class="sd">A WMI filter is evaluated on the target machine. If the query returns nothing there, the
     GPO does not apply to that machine whatever the links and filtering say.</p>
  $wmiTable
</div>

<div id="cse" class="section">
  <h2 class="st"><span class="ico" style="background:rgba(251,146,60,.15);color:var(--orange)">&#9881;</span>Client-Side Extensions</h2>
  <p class="sd">Which extensions the clients in this estate actually have to process, and how many GPO
     halves invoke each one.</p>
  <div id="chartCse" class="chart-grid"></div>
  $cseTable
</div>

<div id="conflicts" class="section">
  <h2 class="st"><span class="ico" style="background:rgba(248,113,113,.15);color:var(--red)">&#9876;</span>Conflict &amp; Override Map</h2>
  <p class="sd">Where the same setting is defined by more than one GPO applying to the same container,
     this shows which one wins and which are overridden. The winner is decided by the precedence
     computed above, not by inference.</p>
  $conflictTable
</div>

<div id="flags" class="section">
  <h2 class="st"><span class="ico" style="background:rgba(77,141,250,.15);color:var(--accent)">&#9881;</span>Processing Behaviour</h2>
  <p class="sd">The modes that change <em>how</em> each GPO is processed, rather than what it contains.</p>
  $flagsTable
</div>

<div id="slow" class="section">
  <h2 class="st"><span class="ico" style="background:rgba(251,191,36,.15);color:var(--amber)">&#8987;</span>Logon &amp; Boot Cost</h2>
  <p class="sd">These GPOs contain extensions or settings that are processed synchronously in the
     foreground, which means the user or the machine waits for them. This is a statement about
     mechanics &mdash; an estate may accept that cost knowingly.</p>
  $slowTable
</div>

<div id="footprint" class="section">
  <h2 class="st"><span class="ico" style="background:rgba(52,211,153,.15);color:var(--green)">&#9636;</span>Setting Footprint</h2>
  <p class="sd">Where the weight of this policy estate actually sits.</p>
  <div id="chartFootprint" class="chart-grid"></div>
  $footTable
</div>

<div id="tattoo" class="section">
  <h2 class="st"><span class="ico" style="background:rgba(167,139,250,.15);color:var(--purple)">&#9998;</span>Tattooing</h2>
  <p class="sd">Preference items and registry writes outside the four managed policy branches are not
     reverted when the GPO stops applying. Removing the GPO leaves these values behind on machines
     that already received them.</p>
  $tattooTable
</div>

<div id="noeffect" class="section">
  <h2 class="st"><span class="ico" style="background:rgba(107,131,163,.15);color:var(--text-mute)">&#8709;</span>GPOs With No Runtime Effect</h2>
  <p class="sd">These exist but do not change anything on any machine, for the reason given. Listed so
     the estate's real working size is visible.</p>
  $noEffectTable
</div>


<div id="admx" class="section">
  <h2 class="st"><span class="ico" style="background:rgba(77,141,250,.15);color:var(--accent)">&#128218;</span>ADMX &amp; Central Store</h2>
  <p class="sd">Administrative Template values are stored as raw registry keys. Turning them back into
     the policy names an administrator recognises needs the ADMX and ADML files &mdash; from the domain's
     central store where one exists, or from the collecting machine otherwise.</p>
  $csTable
  $admxNote
</div>

<div id="coverage" class="section">
  <h2 class="st"><span class="ico" style="background:rgba(52,211,153,.15);color:var(--green)">&#10003;</span>Collection Coverage</h2>
  <p class="sd">What this run actually read, and what it did not. Full honesty about completeness is
     the point: a gap stated here is a gap you can allow for.</p>
  $covHtml
</div>

<div id="glossary" class="section">
  <h2 class="st"><span class="ico" style="background:rgba(167,139,250,.15);color:var(--purple)">&#128214;</span>Glossary</h2>
  <p class="sd">The vocabulary used in this report, in plain terms.</p>
  $glossTable
</div>

<footer class="footer">
  <div class="ft-band">
    <div class="ft-title">GPO<em>Outline</em></div>
    <div class="ft-tagline">The Shape of Your Group Policy</div>
    <p class="ft-about">
      A single-file, read-only PowerShell script that documents how Group Policy is configured across
      an Active Directory forest in one run &mdash; inventory, links, precedence, filtering, delegation,
      settings, behaviour and cloud mappability, captured at a single point in time and delivered as
      one self-contained HTML report. No RSAT or GPMC required; nothing in the directory or SYSVOL is modified.
    </p>
    <div class="ft-author">Developed by <strong>Santhosh Sivarajan</strong>, Microsoft MVP</div>
    <div class="ft-contact">
      <a href="https://www.linkedin.com/in/sivarajan/" target="_blank">LinkedIn</a>
      <span>&middot;</span>
      <a href="https://github.com/SanthoshSivarajan/GPOOutline" target="_blank">github.com/SanthoshSivarajan/GPOOutline</a>
      <span>&middot;</span>
      <a href="mailto:santhosh@sivarajan.com">santhosh@sivarajan.com</a>
      <span>&middot;</span>
      <span class="mh-lic">MIT License</span>
    </div>

    <div class="ft-services">
      <strong>Need more than documentation?</strong>
      This report records the current state and stops there &mdash; deliberately. If you need the
      findings interpreted, a Group Policy consolidation or remediation plan, an Intune migration
      design, or a formal Active Directory assessment, get in touch:
      <a href="mailto:santhosh@sivarajan.com?subject=GPOOutline%20-%20Group%20Policy%20services">santhosh@sivarajan.com</a>
    </div>
  </div>

  <div class="fgrid">
    <div class="fcol">
      <h5>This report</h5>
      <p>Forest: <strong>$(ConvertTo-OutlineHtmlText $forest)</strong></p>
      <p>$(ConvertTo-OutlineHtmlText $Stats.Domains) domain(s), $(ConvertTo-OutlineHtmlText $Stats.Gpos) GPO(s), $(ConvertTo-OutlineHtmlText $Stats.Ous) OU(s)</p>
      <p>Collection took <strong>$(ConvertTo-OutlineHtmlText $O.Duration)</strong></p>
      <p>$(if (@($O.Warnings).Count -gt 0) { "<strong style='color:var(--amber)'>$(@($O.Warnings).Count) collection warning(s)</strong> &mdash; affected sections are marked." } else { "Collection completed without warnings." })</p>
    </div>
    <div class="fcol">
      <h5>Related tools</h5>
      <p><strong>GPOOutline</strong> &mdash; document how policy is configured</p>
      <p><strong>ADOutline</strong> &mdash; document the current state</p>
      <p><strong>ADAtlas</strong> &mdash; see the environment</p>
      <p><strong>ADCanvas</strong> &mdash; understand the environment</p>
      <p><a href="https://github.com/SanthoshSivarajan" target="_blank">All tools on GitHub</a></p>
    </div>
    <div class="fcol">
      <h5>Disclaimer</h5>
      <p>Provided as is, without warranty of any kind. Collection is read-only.</p>
      <p>Results depend on the rights of the collecting account and controller reachability at run time.</p>
      <p>Validate all findings before acting on them.</p>
    </div>
  </div>

  <div class="fbar">
    <span class="brand">GPOOutline $(ConvertTo-OutlineHtmlText $O.Version)</span>
    <span class="stamp">Generated $(ConvertTo-OutlineHtmlText $now) by $(ConvertTo-OutlineHtmlText $O.GeneratedBy) on $(ConvertTo-OutlineHtmlText $O.GeneratedOn) &middot; build $(ConvertTo-OutlineHtmlText $O.Build)</span>
  </div>
</footer>

</main>
</div>
<script>
window.GPOOutlineData = $json;
$($script:OutlineJs)
</script>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    return $OutputPath
}

# ==============================================================================
# ADMX RESOLUTION
# ==============================================================================

function Initialize-OutlineAdmx {
    <#
      Parses ADMX/ADML once per run and caches the map. Central store first --
      it is the authoritative per-domain source and is what the estate's own
      administrators see -- then the collecting machine's local definitions.
    #>
    param([bool]$Enabled)

    $script:AdmxMap = @{}
    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($d in $script:Outline.Domains) {
        $csPath = "\\$($d.DnsRoot)\SYSVOL\$($d.DnsRoot)\Policies\PolicyDefinitions"
        $present = $false
        try { $present = Test-Path -LiteralPath $csPath } catch { Write-OutlineQuiet $_ "CentralStore:$($d.DnsRoot)" }
        $d.CentralStore = if ($present) { 'Present' } else { 'Not present' }
        $rows.Add([pscustomobject]@{
            Domain = $d.DnsRoot
            'Central store' = $d.CentralStore
            Path = $(if ($present) { $csPath } else { '' })
            'ADMX files' = 0; 'ADML files' = 0; Language = ''; 'Policies mapped' = 0
        })
    }

    if (-not $Enabled) {
        $script:Outline.CentralStore = $rows.ToArray()
        Write-OutlineSkip 'ADMX resolution disabled (-ResolveAdmx:$false). Administrative Template values will show as raw registry keys.'
        return
    }

    # Search order: each domain's central store, then the local machine. The
    # central-store paths are kept in a lookup rather than re-derived later,
    # because deciding provenance by pattern-matching the path string is exactly
    # what went wrong before: a -like pattern of '\\\\*' requires FOUR leading
    # backslashes, while a UNC path has two, so the test never matched and every
    # run reported "no central store found" -- even when it had just used one.
    # Backslash is not an escape character in a -like pattern, and asserting
    # provenance from a string shape is fragile even when the pattern is right.
    $search = New-Object System.Collections.Generic.List[string]
    $centralPaths = @{}
    foreach ($d in $script:Outline.Domains) {
        if ($d.CentralStore -eq 'Present') {
            $cs = "\\$($d.DnsRoot)\SYSVOL\$($d.DnsRoot)\Policies\PolicyDefinitions"
            $search.Add($cs)
            $centralPaths[$cs.ToLowerInvariant()] = $d.DnsRoot
        }
    }
    $localPath = $null
    if ($env:SystemRoot) {
        $localPath = Join-Path $env:SystemRoot 'PolicyDefinitions'
        $search.Add($localPath)
    }

    $script:AdmxMap = Import-OutlineAdmx -SearchPaths $search.ToArray()
    $st = $script:AdmxStats

    if ($st) {
        $srcKey = if ($st.Source) { ([string]$st.Source).ToLowerInvariant() } else { '' }
        $usedCentralFor = $(if ($srcKey -and $centralPaths.ContainsKey($srcKey)) { $centralPaths[$srcKey] } else { $null })

        # Attribute the counts to the domain whose store was actually read, by
        # identity rather than by substring match on the domain name.
        foreach ($r in $rows) {
            if ($usedCentralFor -and $r.Domain -eq $usedCentralFor) {
                $r.'ADMX files' = $st.AdmxFiles; $r.'ADML files' = $st.AdmlFiles
                $r.Language = $st.Language; $r.'Policies mapped' = $st.Policies
            }
        }

        if ($usedCentralFor) {
            Write-OutlineNote "Administrative Template names were resolved from the central ADMX store in $usedCentralFor, which is the definition set this estate's own administrators see."
        }
        elseif ($srcKey) {
            $rows.Add([pscustomobject]@{
                Domain = '(collecting machine)'; 'Central store' = 'Local PolicyDefinitions'
                Path = $st.Source; 'ADMX files' = $st.AdmxFiles; 'ADML files' = $st.AdmlFiles
                Language = $st.Language; 'Policies mapped' = $st.Policies
            })
            Write-OutlineNote 'No central ADMX store was readable; friendly names were resolved from the collecting machine''s local policy definitions instead, which may not match the estate.'
        }

        if ($st.Reason) { Write-OutlineInfo "ADMX: $($st.Reason)" }
        Write-OutlineInfo "ADMX map built: $($script:AdmxMap.Count) registry entries from $($st.AdmxFiles) ADMX / $($st.AdmlFiles) ADML file(s) via $($st.Source)."
    }

    $script:Outline.CentralStore = $rows.ToArray()
}

# ==============================================================================
# COVERAGE
# ==============================================================================

function Build-OutlineCoverage {
    param([int]$Discovered, $SysvolResults, [bool]$SkippedSysvol)

    $O = $script:Outline
    $skipped = New-Object System.Collections.Generic.List[object]

    foreach ($d in $O.Domains) {
        if (-not $d.Collected) {
            $skipped.Add([pscustomobject]@{ What = "Domain $($d.DnsRoot)"; Why = $(if ($d.SkipReason) { $d.SkipReason } else { 'Not collected.' }) })
        }
    }
    foreach ($g in $O.Gpos) {
        if (-not $g.SysvolReadable -and $g.SysvolReason) {
            $skipped.Add([pscustomobject]@{ What = "Settings for GPO '$($g.Name)' ($($g.Domain))"; Why = $g.SysvolReason })
        }
        if (-not $g.AclReadable -and $g.AclReason) {
            $skipped.Add([pscustomobject]@{ What = "Filtering and delegation for GPO '$($g.Name)'"; Why = $g.AclReason })
        }
    }
    if ($SkippedSysvol) {
        $skipped.Add([pscustomobject]@{ What = 'All SYSVOL settings parsing'; Why = 'Skipped by -SkipSysvol. This run documents scope and metadata only.' })
    }
    foreach ($k in @($script:Outline.DCs.PSBase.Keys)) {
        $dc = $script:Outline.DCs[$k]
        if (-not $dc.Ldap) {
            $skipped.Add([pscustomobject]@{ What = "Domain controller $k"; Why = "Did not answer on LDAP: $($dc.Reasons['Ldap'])" })
        }
    }

    $read = 0; $failed = 0
    if ($SysvolResults) {
        foreach ($k in $SysvolResults.Keys) {
            if ($SysvolResults[$k].Readable) { $read++ } else { $failed++ }
        }
    }

    $O.Coverage = [ordered]@{
        GposDiscovered    = $Discovered
        SysvolRead        = $read
        SysvolFailed      = $failed
        DomainsDiscovered = @($O.Domains).Count
        DomainsCollected  = @($O.Domains | Where-Object { $_.Collected }).Count
        Skipped           = @($skipped.ToArray() | Select-Object -First 2000)
        SkippedTotal      = $skipped.Count
    }
}

# ==============================================================================
# MAIN
# ==============================================================================

$OutDir = Resolve-OutlinePath -Requested $OutputPath
$script:ShowDetail = [bool]$ShowDetail
$script:SkipSysvolFlag = [bool]$SkipSysvol

$runStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if (-not $LogPath) { $LogPath = Join-Path $OutDir "GPOOutline_$runStamp.log" }
# 12 collection phases; used for the progress percentage.
Initialize-OutlineLog -Path $LogPath -TaskCount 13
Write-OutlineLog 'INFO' "Output directory: $OutDir"
Write-OutlineLog 'INFO' ("Parameters: Server='{0}' Domain='{1}' Mode={2} PageSize={3} LdapTimeoutSec={4} MaxConcurrency={5} SkipSysvol={6} SearchBase='{7}'" -f `
    $Server, ($Domain -join ','), $Mode, $PageSize, $LdapTimeoutSec, $MaxConcurrency, $SkipSysvol, $SearchBase)

# ---------------- Re-render from a saved state file ----------------
if ($FromState) {
    if (-not (Test-Path -LiteralPath $FromState)) { throw "State file not found: $FromState" }
    Write-OutlineInfo "Re-rendering from state: $FromState"

    $raw = Get-Content -LiteralPath $FromState -Raw -Encoding UTF8
    $obj = $raw | ConvertFrom-Json

    # ConvertFrom-Json returns PSCustomObjects; the renderer expects ordered
    # dictionaries it can index and test with .Contains(). Convert back.
    function ConvertTo-OrderedDeep {
        param($Node)
        if ($null -eq $Node) { return $null }
        if ($Node -is [System.Management.Automation.PSCustomObject]) {
            $h = [ordered]@{}
            foreach ($prop in $Node.PSObject.Properties) { $h[$prop.Name] = ConvertTo-OrderedDeep $prop.Value }
            return $h
        }
        if ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [string]) {
            # The comma prefix is load-bearing. Without it `return @()` unrolls
            # to $null and a one-element array unrolls to a bare scalar, so
            # every empty collection crashes .Count on re-render and every
            # single-item collection is iterated as the wrong type.
            return ,@(foreach ($item in $Node) { ConvertTo-OrderedDeep $item })
        }
        return $Node
    }

    $script:Outline = ConvertTo-OrderedDeep $obj

    # ---- forward-compatibility for state written by an older build ----
    # The domain-qualified Key was added after GPO GUIDs were found to repeat
    # across domains. A state file written before that has no Key, and without
    # one every GPO resolves as missing -- silently, since nothing throws.
    # Derive it here rather than let an old file render a confidently empty
    # report.
    $repaired = 0
    foreach ($g in @($script:Outline.Gpos)) {
        if ($g -and -not (Get-PropValue $g 'Key') -and (Get-PropValue $g 'Id')) {
            $g['Key'] = "$($g.Domain)|$($g.Id)".ToUpperInvariant()
            $repaired++
        }
    }
    foreach ($w in @($script:Outline.WmiFilters)) {
        if ($w -and -not (Get-PropValue $w 'Key') -and (Get-PropValue $w 'Id')) {
            $w['Key'] = "$($w.Domain)|$($w.Id)".ToUpperInvariant()
        }
    }
    foreach ($c in @($script:Outline.Containers)) {
        foreach ($lk in @(Get-PropArray $c 'Links')) {
            if ($lk -and -not (Get-PropValue $lk 'GpoKey') -and (Get-PropValue $lk 'GpoId')) {
                $lk['GpoKey'] = "$(ConvertFrom-DnToDomain $lk.GpoDN)|$($lk.GpoId)".ToUpperInvariant()
            }
        }
    }
    if ($repaired -gt 0) {
        Write-OutlineInfo "State file predates the domain-qualified GPO key; derived it for $repaired GPO(s) on load."
        Write-Host ("   Note: this state file was written by an earlier build. Keys were derived on load." ) -ForegroundColor Yellow
        Write-Host ("         Re-collect for a fully current report.") -ForegroundColor DarkGray
    }

    # Restore the ADMX map so friendly names survive the re-render. Without this
    # every Administrative Template row falls back to its raw registry key, which
    # looks like an unresolved estate rather than a missing map.
    $am = Get-PropValue $script:Outline 'AdmxMap'
    if ($am) {
        $script:AdmxMap = @{}
        if ($am -is [System.Collections.IDictionary]) {
            foreach ($k in @($am.PSBase.Keys)) { $script:AdmxMap[[string]$k] = $am[$k] }
        }
        Write-OutlineInfo "Restored $($script:AdmxMap.Count) ADMX name entries from the state file."
    }
    else {
        Write-Host ("   Note: this state file carries no ADMX map, so Administrative Template") -ForegroundColor Yellow
        Write-Host ("         settings will show raw registry keys. Re-collect to restore names.") -ForegroundColor DarkGray
    }

    # An affected build recorded the central ADMX store twice: once correctly
    # against its domain, and once again as "(collecting machine) / Local
    # PolicyDefinitions" carrying the same UNC path. The second row asserts
    # something untrue about where the friendly names came from, so it is dropped
    # rather than rendered -- a report that misstates its own provenance is worse
    # than one that says less.
    $cs = @(Get-PropArray $script:Outline 'CentralStore')
    if ($cs.Count -gt 1) {
        $domainPaths = @{}
        foreach ($r in $cs) {
            $rp = Get-PropValue $r 'Path'
            if ($rp -and (Get-PropValue $r 'Domain') -ne '(collecting machine)') { $domainPaths[[string]$rp] = $true }
        }
        $kept = @($cs | Where-Object {
            $rp = Get-PropValue $_ 'Path'
            -not ((Get-PropValue $_ 'Domain') -eq '(collecting machine)' -and $rp -and $domainPaths.ContainsKey([string]$rp))
        })
        if ($kept.Count -lt $cs.Count) {
            $script:Outline.CentralStore = $kept
            Write-Host ("         Removed a duplicate ADMX provenance row recorded by that build.") -ForegroundColor DarkGray
        }
    }
    $stamp2 = Get-Date -Format 'yyyyMMdd_HHmmss'
    $safe2  = ($script:Outline.ForestName -replace '[^\w-]','_')
    $htmlOut = Join-Path $OutDir "GPOOutline_${safe2}_$stamp2.html"
    $null = New-OutlineHtml -OutputPath $htmlOut -NoJson:$NoEmbeddedJson
    $sz = [math]::Round((Get-Item $htmlOut).Length / 1KB, 1)
    Write-OutlineOk "Report written: $htmlOut ($sz KB)"

    # Write-OutlineOk only reaches the console under -ShowDetail, because in a
    # normal run the progress display carries the feedback. This path has no
    # progress display, so without an explicit summary the user sees the banner
    # and then nothing at all.
    Write-Host ""
    Write-Host " +==============================================================+" -ForegroundColor Green
    Write-Host " |          Re-rendered from state -- no directory access       |" -ForegroundColor Green
    Write-Host " +==============================================================+" -ForegroundColor Green
    Write-Host ""
    Write-Host ("   Forest      : {0}" -f $script:Outline.ForestName)
    Write-Host ("   Collected   : {0}" -f $(if ($script:Outline.Contains('GeneratedAt')) { $script:Outline.GeneratedAt } else { 'unknown' }))
    Write-Host ("   Source      : {0}" -f $FromState) -ForegroundColor DarkGray
    Write-Host ""
    Write-Host ("   Report : {0}  ({1} KB)" -f $htmlOut, $sz) -ForegroundColor Cyan
    Write-Host ("   Log    : {0}" -f $LogPath) -ForegroundColor DarkGray
    Write-Host ""

    Save-OutlineLog
    return
}

# Shared by Get-OutlineDomainConnection when it binds per domain.
$script:BoundCredential = $Credential
$script:LdapTimeout     = $LdapTimeoutSec

$Connection = $null
try {
    # ---------------- 1. bind ----------------
    Start-OutlineTask 'Connecting to directory'
    $Connection = Connect-OutlineDirectory -Target $Server -Cred $Credential -TimeoutSec $LdapTimeoutSec
    Complete-OutlineTask ("bound to {0}" -f $script:Outline.RootDse.DnsHostName)

    Write-OutlineInfo "Forest       : $($script:Outline.ForestName)"
    Write-OutlineInfo "Forest level : $(Get-FuncLevelName $script:Outline.RootDse.ForestFunctional)"
    Write-OutlineInfo "Config NC    : $($script:Outline.ConfigDN)"

    # ---------------- 2. domains ----------------
    Start-OutlineTask 'Discovering domains'
    Get-OutlinePartition -Connection $Connection -TimeoutSec $LdapTimeoutSec -PageSize $PageSize

    if ($Domain -and $Domain.Count -gt 0) {
        $before = @($script:Outline.Domains).Count
        $script:Outline.Domains = @($script:Outline.Domains | Where-Object {
            $d = $_
            @($Domain | Where-Object { $d.DnsRoot -like $_ }).Count -gt 0
        })
        Write-OutlineInfo "Scoped to $(@($script:Outline.Domains).Count) of $before discovered domain(s) by -Domain."
        if (@($script:Outline.Domains).Count -eq 0) {
            throw "No domain matched -Domain '$($Domain -join ', ')'."
        }
    }
    Complete-OutlineTask ("{0} domain(s)" -f @($script:Outline.Domains).Count)

    # ---------------- 3. domain controllers ----------------
    Start-OutlineTask 'Discovering domain controllers'
    $dcMap = Get-OutlineDomainController -Connection $Connection -TimeoutSec $LdapTimeoutSec -PageSize $PageSize
    if ($ExcludeDC) {
        foreach ($x in $ExcludeDC) {
            foreach ($k in @($dcMap.PSBase.Keys)) {
                if ($k -like $x) { $dcMap.Remove($k); Write-OutlineSkip "Excluded by parameter: $k" }
            }
        }
    }
    $script:Outline.DCs = $dcMap
    foreach ($d in $script:Outline.Domains) {
        $names = @($dcMap.PSBase.Keys | Where-Object { $dcMap[$_].Domain -eq $d.DnsRoot })
        $d.DcCount = $names.Count
        $d.DcNames = $names
    }
    Complete-OutlineTask ("{0} DC(s)" -f $dcMap.Count)

    # ---------------- 4. probe ----------------
    Start-OutlineTask 'Probing domain controllers'
    if ($NoProbe) {
        Write-OutlineSkip 'Probe skipped (-NoProbe). All DCs assumed reachable.'
        Complete-OutlineTask 'skipped'
    }
    else {
        Invoke-OutlineDCProbe -Map $dcMap -TimeoutMs $ProbeTimeoutMs -Throttle $ProbeThrottle
        $bad = @($dcMap.PSBase.Keys | Where-Object { -not $dcMap[$_].Ldap }).Count
        $script:Outline.UnreachableCount = $bad
        Complete-OutlineTask $(if ($bad -gt 0) { "$bad unreachable" } else { 'all reachable' })
    }

    # ---------------- 5. rights ----------------
    Start-OutlineTask 'Verifying collection rights'
    $script:Outline.Rights = Test-OutlineAccess -Connection $Connection -TimeoutSec $LdapTimeoutSec
    Write-OutlineRightsSummary -Rights $script:Outline.Rights
    $script:Outline.CollectionMode = if ($Mode -eq 'Native' -and $script:Outline.Rights.HasGpmc) { 'Raw (LDAP + SYSVOL), GPMC present' } else { 'Raw (LDAP + SYSVOL)' }
    Complete-OutlineTask $(if ($script:Outline.Rights.CanReadSysvol) { 'Tier A + B' } else { 'Tier A only' })

    # ---------------- 6. domain detail, sites, trusts ----------------
    Start-OutlineTask 'Reading domain detail, sites and trusts'
    Update-OutlineDomainDetail -TimeoutSec $LdapTimeoutSec
    if ($IncludeSites) { Invoke-OutlineSiteSweep -Connection $Connection -TimeoutSec $LdapTimeoutSec -PageSize $PageSize }
    Invoke-OutlineTrustSweep -TimeoutSec $LdapTimeoutSec -PageSize $PageSize
    Complete-OutlineTask ("{0} site(s), {1} trust(s)" -f @($script:Outline.Sites).Count, @($script:Outline.Trusts).Count)

    # ---------------- 7. phase 1 discovery ----------------
    Start-OutlineTask 'Enumerating GPOs, containers and WMI filters'
    $allGpos = New-Object System.Collections.Generic.List[object]
    $allCont = New-Object System.Collections.Generic.List[object]
    $allWmi  = New-Object System.Collections.Generic.List[object]

    foreach ($d in $script:Outline.Domains) {
        $conn = Get-OutlineDomainConnection -DnsRoot $d.DnsRoot
        if (-not $conn) { continue }

        foreach ($g in (Invoke-OutlineGpoSweep -DomainRec $d -TimeoutSec $LdapTimeoutSec -PageSize $PageSize)) { $allGpos.Add($g) }
        foreach ($c in (Invoke-OutlineContainerSweep -DomainRec $d -SearchBase $SearchBase -TimeoutSec $LdapTimeoutSec -PageSize $PageSize)) { $allCont.Add($c) }
        foreach ($w in (Invoke-OutlineWmiFilterSweep -DomainRec $d -TimeoutSec $LdapTimeoutSec -PageSize $PageSize)) { $allWmi.Add($w) }
        $d.Collected = $true
    }

    $script:Outline.Gpos       = $allGpos.ToArray()
    $script:Outline.Containers = $allCont.ToArray()
    $script:Outline.WmiFilters = $allWmi.ToArray()
    Complete-OutlineTask ("{0} GPO(s), {1} container(s), {2} WMI filter(s)" -f $allGpos.Count, $allCont.Count, $allWmi.Count)

    if ($allGpos.Count -eq 0) {
        Add-OutlineWarning 'No Group Policy objects were readable in any collected domain.'
    }

    # ---------------- dry run ----------------
    if ($WhatIfScope) {
        Write-Progress -Activity 'GPOOutline' -Completed
        Write-Host ""
        Write-Host " +==============================================================+" -ForegroundColor Cyan
        Write-Host " |          Scope preview (-WhatIfScope) -- nothing parsed      |" -ForegroundColor Cyan
        Write-Host " +==============================================================+" -ForegroundColor Cyan
        Write-Host ""
        Write-Host ("   Domains         : {0}" -f @($script:Outline.Domains).Count)
        Write-Host ("   GPOs to parse   : {0}" -f $allGpos.Count)
        Write-Host ("   Containers      : {0}" -f $allCont.Count)
        Write-Host ("   WMI filters     : {0}" -f $allWmi.Count)
        $conc = Get-OutlineConcurrency -Requested $MaxConcurrency
        # 0.35s per GPO is the observed mid-range for a SYSVOL parse over a LAN;
        # it is a planning figure, not a promise.
        $est = [math]::Ceiling(($allGpos.Count * 0.35) / [math]::Max($conc,1))
        Write-Host ("   Concurrency     : {0}" -f $conc)
        Write-Host ("   Rough estimate  : ~{0}s for the SYSVOL phase" -f $est) -ForegroundColor DarkGray
        Write-Host ""
        Save-OutlineLog
        return
    }

    # ---------------- 8. ADMX ----------------
    Start-OutlineTask 'Building ADMX friendly-name map'
    Initialize-OutlineAdmx -Enabled ($ResolveAdmx -and -not $SkipSysvol)
    Complete-OutlineTask ("{0} entries" -f $(if ($script:AdmxMap) { $script:AdmxMap.Count } else { 0 }))

    # ---------------- 9. phase 2 SYSVOL ----------------
    Start-OutlineTask 'Parsing SYSVOL policy files'
    $sysvolResults = @{}
    if ($SkipSysvol) {
        Write-OutlineSkip 'SYSVOL parsing skipped (-SkipSysvol). Scope and metadata only.'
        foreach ($g in $script:Outline.Gpos) { $g.SysvolReason = 'Skipped by -SkipSysvol.' }
        Complete-OutlineTask 'skipped'
    }
    elseif (-not $script:Outline.Rights.CanReadSysvol) {
        Write-OutlineSkip 'SYSVOL not readable by the collecting account. Settings sections will say so.'
        foreach ($g in $script:Outline.Gpos) { $g.SysvolReason = 'SYSVOL was not readable by the collecting account.' }
        Complete-OutlineTask 'insufficient rights'
    }
    else {
        $sysvolResults = Invoke-OutlineSysvolPhase -Gpos $script:Outline.Gpos `
            -MaxConcurrency $MaxConcurrency -ThrottleDelayMs $ThrottleDelayMs -MaxValues $MaxValuesPerFile
        Merge-OutlineSysvolResult -Gpos $script:Outline.Gpos -Results $sysvolResults
        $ok = @($sysvolResults.Keys | Where-Object { $sysvolResults[$_].Readable }).Count
        Complete-OutlineTask ("{0} of {1} GPO(s) read" -f $ok, @($script:Outline.Gpos).Count)
    }

    # ---------------- 9b. Starter GPOs ----------------
    # SYSVOL-only, so gated on the same capability as the settings pass. Cheap:
    # a handful of folders per domain, not one per GPO.
    if (-not $SkipSysvol -and $script:Outline.Rights.CanReadSysvol) {
        Start-OutlineTask 'Enumerating Starter GPOs'
        $starters = New-Object System.Collections.Generic.List[object]
        foreach ($d in $script:Outline.Domains) {
            if (-not $d.Collected) { continue }
            foreach ($sg in (Invoke-OutlineStarterGpoSweep -DomainRec $d -MaxValues $MaxValuesPerFile)) { $starters.Add($sg) }
        }
        $script:Outline.StarterGpos = $starters.ToArray()
        Complete-OutlineTask ("{0} starter GPO(s)" -f $starters.Count)
        if ($starters.Count -gt 0) {
            Write-OutlineNote ("{0} Starter GPO(s) exist on SYSVOL. They have no directory object and apply to nothing until used to create a GPO." -f $starters.Count)
        }
    }

    # ---------------- 10. analysis ----------------
    Start-OutlineTask 'Computing scope, precedence and conflicts'
    $model = Build-OutlineScopeModel
    Build-OutlinePrecedence -Model $model
    Build-OutlineLoopbackMap
    $idx = Build-OutlineSettingIndex
    if ($idx.Capped) {
        Add-OutlineWarning "The setting index is capped at $($script:MaxSettingIndex) rows; $($idx.Total) settings were counted in total."
    }
    Build-OutlineConflictMap
    Build-OutlineAnomalies
    Complete-OutlineTask ("{0} setting(s), {1} conflict row(s)" -f $idx.Total, @($script:Outline.Conflicts).Count)

    # ---------------- 11. views ----------------
    Start-OutlineTask 'Building cross-reference and behaviour views'
    Build-OutlineMatrices
    Build-OutlineBehavior
    Build-OutlineStats
    Build-OutlineCoverage -Discovered @($script:Outline.Gpos).Count -SysvolResults $sysvolResults -SkippedSysvol ([bool]$SkipSysvol)
    Complete-OutlineTask

    # Non-fatal failures that would otherwise vanish into empty catch blocks.
    if ($script:QuietFailures.PSBase.Count -gt 0) {
        $qTotal = 0
        foreach ($qk in @($script:QuietFailures.PSBase.Keys)) { $qTotal += $script:QuietFailures[$qk] }
        $script:Outline.QuietFailures = [ordered]@{ Total = $qTotal; BySite = [ordered]@{} }
        foreach ($qk in @($script:QuietFailures.PSBase.Keys | Sort-Object)) {
            $script:Outline.QuietFailures.BySite[$qk] = $script:QuietFailures[$qk]
        }
        Write-OutlineLog 'INFO' ("{0} non-fatal failure(s) across {1} site(s) -- see log lines tagged non-fatal." -f $qTotal, $script:QuietFailures.PSBase.Count)
    }

    # The ADMX map is persisted with the state, not rebuilt on re-render.
    # Friendly names for the per-GPO cards are resolved at RENDER time, so
    # without the map a -FromState re-render silently degrades every
    # Administrative Template row back to a raw registry key -- which
    # contradicts the promise that the state file re-renders the same report
    # with no directory access. Storing the map keeps that promise, and keeps
    # -FromState honest about provenance too, since it cannot reach a central
    # store over the network.
    if ($script:AdmxMap -and $script:AdmxMap.Count -gt 0) {
        $script:Outline.AdmxMap = $script:AdmxMap
        $script:Outline.AdmxSource = $(if ($script:AdmxStats) { $script:AdmxStats.Source } else { $null })
    }

    $script:Outline.Observations = $script:Observations.ToArray()

    # Persisted into state, not just logged, so a -FromState re-render carries
    # the same caveat as the live report.
    $script:Outline.ContainerReadFailures = @(
        foreach ($k in @($script:ContainerReadFailures.PSBase.Keys | Sort-Object)) {
            [pscustomobject]@{ Domain = $k; Reason = $script:ContainerReadFailures[$k] }
        })

    $script:Outline.GeneratedAt  = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    $script:Outline.Duration     = "{0:hh\:mm\:ss}" -f ((Get-Date) - $script:StartedAt)

    # ---------------- 12. output ----------------
    $safeName  = ($script:Outline.ForestName -replace '[^\w-]', '_')
    $statePath = Join-Path $OutDir "GPOOutline_${safeName}_$runStamp.state.json"
    $htmlPath  = $null

    Start-OutlineTask 'Building report'
    if (-not $NoState) {
        $script:Outline | ConvertTo-Json -Depth 12 | Out-File -FilePath $statePath -Encoding UTF8 -Force
        Write-OutlineLog 'OK' "State written: $statePath"
    }
    if (-not $NoHtml) {
        $htmlPath = Join-Path $OutDir "GPOOutline_${safeName}_$runStamp.html"
        $null = New-OutlineHtml -OutputPath $htmlPath -NoJson:$NoEmbeddedJson
        Write-OutlineLog 'OK' "Report written: $htmlPath"
    }
    Complete-OutlineTask

    Write-Progress -Activity 'GPOOutline' -Completed
    $S = $script:Outline.Stats

    Write-Host ""
    Write-Host " +==============================================================+" -ForegroundColor Green
    Write-Host " |          GPOOutline completed successfully                    |" -ForegroundColor Green
    Write-Host " +==============================================================+" -ForegroundColor Green
    Write-Host ""
    Write-Host ("   Forest      : {0}   ({1} domain(s), {2} DC(s))" -f $script:Outline.ForestName, $S.Domains, $S.DomainControllers) -ForegroundColor White
    Write-Host ("   Group Policy: {0} GPO(s), {1} linked, {2} unlinked" -f $S.Gpos, $S.LinkedGpos, $S.UnlinkedGpos) -ForegroundColor White
    Write-Host ("   Scope       : {0} OU(s), {1} link(s), {2} enforced, {3} blocking inheritance" -f $S.Ous, $S.TotalLinks, $S.EnforcedLinks, $S.OusBlocking) -ForegroundColor White
    Write-Host ("   Settings    : {0} recorded, {1} conflict row(s)" -f $S.Settings, $S.Conflicts) -ForegroundColor White
    if ($S.LoopbackGpos -gt 0)    { Write-Host ("   Loopback    : {0} GPO(s) enable loopback processing" -f $S.LoopbackGpos) -ForegroundColor Cyan }
    if ($S.CPasswordGpos -gt 0)   { Write-Host ("   Preferences : {0} GPO(s) contain a cpassword attribute -- see report" -f $S.CPasswordGpos) -ForegroundColor Yellow }
    if ($script:Outline.UnreachableCount -gt 0) { Write-Host ("   Unreachable : {0} domain controller(s) -- see report" -f $script:Outline.UnreachableCount) -ForegroundColor Yellow }
    if ($script:Observations.Count -gt 0) { Write-Host ("   Observations: {0} -- factual notes, see report" -f $script:Observations.Count) -ForegroundColor Cyan }
    if ($script:WarnCount -gt 0)  { Write-Host ("   Warnings    : {0} -- collection was impaired, see log" -f $script:WarnCount) -ForegroundColor Yellow }
    Write-Host ("   Duration    : {0}" -f $script:Outline.Duration) -ForegroundColor White
    Write-Host ""
    if ($htmlPath)   { Write-Host ("   Report : {0}" -f $htmlPath) -ForegroundColor Cyan }
    if (-not $NoState) { Write-Host ("   State  : {0}" -f $statePath) -ForegroundColor DarkCyan }
    Write-Host ("   Log    : {0}" -f $LogPath) -ForegroundColor DarkCyan
    Write-Host ""
    if (-not $NoState) {
        Write-Host ("   Re-render without re-collecting:") -ForegroundColor DarkGray
        Write-Host ("     .\GPOOutline.ps1 -FromState '{0}'" -f $statePath) -ForegroundColor DarkGray
        Write-Host ""
    }
}
catch {
    Write-Progress -Activity 'GPOOutline' -Completed
    Write-Host ""
    Write-OutlineErr "GPOOutline failed: $($_.Exception.Message)"
    Write-OutlineLog 'ERROR' $_.ScriptStackTrace
    Write-Host ("   Log: {0}" -f $LogPath) -ForegroundColor DarkCyan
    Write-Host ""
}
finally {
    Save-OutlineLog
    foreach ($k in @($script:DomainConnections.PSBase.Keys)) {
        try { if ($script:DomainConnections[$k]) { $script:DomainConnections[$k].Dispose() } } catch { }
    }
    if ($Connection) { try { $Connection.Dispose() } catch { } }
}

<#
================================================================================
 End of GPOOutline.ps1
--------------------------------------------------------------------------------
 GPOOutline -- The Shape of Your Group Policy
 Author   : Santhosh Sivarajan, Microsoft MVP
 LinkedIn : https://www.linkedin.com/in/sivarajan/
 GitHub   : https://github.com/SanthoshSivarajan/GPOOutline
 License  : MIT

 Read-only. Provided as is, without warranty of any kind.
================================================================================
#>
