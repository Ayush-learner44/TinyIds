<#
.SYNOPSIS
    Automated Attack Suite for Physical Raspberry Pi Gateway.
.DESCRIPTION
    Runs all TinyIDS attacks against the physical Pi:
      Phase 1: Laptop Direct Attacks (SYN flood, UDP flood, port scan, MQTT brute force)
      Phase 2: NodeMCU Bot Attacks (UDP flood, TCP flood via C2 broker)
.EXAMPLE
    .\run_all_attacks.ps1 -Gateway 172.29.1.135
    .\run_all_attacks.ps1 -Gateway 172.29.1.135 -Port 1884 -Seconds 10
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Gateway,
    [int]$Port = 1884,
    [int]$Seconds = 10,
    [int]$Pause = 6,
    [ValidateSet("1", "2", "all")]
    [string]$Phase = "all"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "         TinyIDS Physical Gateway Attack Suite (Laptop Host)          " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  Target Gateway:    $Gateway"
Write-Host "  Broker Port:       $Port"
Write-Host "  Flood Duration:    $Seconds s"
Write-Host "  Cooldown Pause:    $Pause s"
Write-Host "  Target Phase:      $Phase"
Write-Host "======================================================================`n"

python "$ScriptDir/run_all_attacks.py" $Gateway --port $Port --seconds $Seconds --pause $Pause --phase $Phase
