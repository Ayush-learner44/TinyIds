<#
.SYNOPSIS
    Master Automated Attack Suite for TinyIDS Testbed.
.DESCRIPTION
    Runs all TinyIDS attacks sequentially:
      Phase 1 (Without Bots): Direct Attacker (172.30.0.66)
        1. Direct SYN Flood (Port 1883)
        2. Direct UDP Flood (Port 5683)
        3. Direct Port Scan (Nmap Ports 1-1000)
        4. Direct MQTT Login Brute Force (Port 1883)
      Phase 2 (With Bots): Coordinated NodeMCU Botnet (.21, .22, .23)
        5. Botnet UDP Flood (Port 5683)
        6. Botnet TCP Flood (Port 1883)

.EXAMPLE
    .\run_all_attacks.ps1
    .\run_all_attacks.ps1 -Seconds 10 -Pause 5
    .\run_all_attacks.ps1 -Phase 1      # Only non-bot attacks
    .\run_all_attacks.ps1 -Phase 2      # Only bot attacks
#>

param(
    [int]$Seconds = 10,
    [int]$Pause = 6,
    [ValidateSet("1", "2", "all")]
    [string]$Phase = "all"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "                TinyIDS Master Automated Attack Suite                " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  Testbed Directory: $ScriptDir"
Write-Host "  Flood Duration:    $Seconds seconds per attack"
Write-Host "  Cooldown Pause:    $Pause seconds between attacks"
Write-Host "  Target Phase:      $Phase"
Write-Host "  Dashboard:         http://localhost:8501"
Write-Host "======================================================================`n"

# Ensure we're in the testbed directory
Set-Location $ScriptDir

# Check container status
Write-Host "[*] Checking Docker testbed status..." -ForegroundColor Yellow
$running = docker compose ps --status running -q 2>$null
if (-not $running) {
    Write-Host "[!] Containers are stopped. Starting TinyIDS testbed containers..." -ForegroundColor Yellow
    docker compose start
    Start-Sleep -Seconds 3
}

# Update attack scripts inside attacker container in case files were updated
Write-Host "[*] Syncing attack scripts into attacker container..." -ForegroundColor Gray
docker cp "$ScriptDir/attacker/attacks/run_all_attacks.py" tinyids-attacker-1:/usr/local/bin/run_all_attacks.py
docker cp "$ScriptDir/attacker/attacks/run_all_attacks" tinyids-attacker-1:/usr/local/bin/run_all_attacks
docker compose exec attacker chmod +x /usr/local/bin/run_all_attacks /usr/local/bin/run_all_attacks.py
docker compose exec attacker sed -i "s/\r$//" /usr/local/bin/run_all_attacks /usr/local/bin/run_all_attacks.py

Write-Host "[*] Launching Master Attack Suite inside attacker container...`n" -ForegroundColor Green

# Run the master attack runner
docker compose exec attacker python3 /usr/local/bin/run_all_attacks.py --seconds $Seconds --pause $Pause --phase $Phase

Write-Host "`n[+] All requested attacks completed successfully!" -ForegroundColor Green
Write-Host "[+] Check the dashboard at http://localhost:8501 to see all recorded alerts and SHAP values.`n" -ForegroundColor Cyan
