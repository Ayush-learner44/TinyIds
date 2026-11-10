#!/usr/bin/env python3
"""Master Automated Attack Suite for TinyIDS.

Executes all attack vectors sequentially:
  Phase 1: Direct Attacker (Without Bots) - from Attacker IP (172.30.0.66)
    1. TCP SYN Flood (Port 1883)
    2. UDP Flood (Port 5683)
    3. TCP Port Scan (Ports 1-1000)
    4. MQTT Authentication Brute Force (Port 1883)

  Phase 2: Botnet Attacks (With NodeMCU Bots) - from NodeMCUs (.21, .22, .23)
    5. Coordinated Mirai-style UDP Flood (Port 5683)
    6. Coordinated Mirai-style TCP Connection Flood (Port 1883)

Usage:
  run_all_attacks [--seconds 10] [--pause 6] [--phase 1|2|all]
"""
import argparse
import datetime
import os
import subprocess
import sys
import time

TARGET = os.environ.get("TARGET", "172.30.0.10")
ATTACK_DIR = "/usr/local/bin" if os.path.exists("/usr/local/bin/syn_flood") else os.path.dirname(os.path.abspath(__file__))

def banner(title):
    line = "=" * 70
    print(f"\n{line}\n  {title}\n{line}", flush=True)

def subbanner(title):
    line = "-" * 70
    print(f"\n{line}\n  >>> {title}\n{line}", flush=True)

def countdown_pause(seconds, msg="Cool-down pause to allow traffic to return to baseline"):
    print(f"\n[*] {msg} ({seconds}s)...", end="", flush=True)
    for remaining in range(seconds, 0, -1):
        print(f" {remaining}", end="", flush=True)
        time.sleep(1)
    print(" -> READY\n", flush=True)

def run_step(step_num, name, cmd, expected_alert, source_ip, target_port):
    subbanner(f"Attack {step_num}: {name}")
    print(f"  Source:         {source_ip}")
    print(f"  Target:         {TARGET}:{target_port}")
    print(f"  Expected Alert: {expected_alert}")
    print(f"  Start Time:     {datetime.datetime.now().strftime('%H:%M:%S')}")
    print(f"  Executing:      {' '.join(cmd)}\n", flush=True)
    
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, text=True, capture_output=False)
        status = "COMPLETED" if proc.returncode == 0 else f"EXIT CODE {proc.returncode}"
    except Exception as e:
        status = f"ERROR: {e}"
    elapsed = time.time() - t0
    
    print(f"\n[+] {name} {status} in {elapsed:.1f}s", flush=True)
    return {
        "step": step_num,
        "name": name,
        "source": source_ip,
        "alert": expected_alert,
        "duration": f"{elapsed:.1f}s",
        "status": status
    }

def main():
    parser = argparse.ArgumentParser(description="TinyIDS Automated Attack Suite")
    parser.add_argument("--seconds", type=int, default=10, help="Duration for flood attacks (default: 10s)")
    parser.add_argument("--pause", type=int, default=6, help="Cool-down seconds between attacks (default: 6s)")
    parser.add_argument("--phase", choices=["1", "2", "all"], default="all", help="Attack phase: 1 (no bots), 2 (bots only), or all")
    args = parser.parse_args()

    results = []
    start_all = time.time()

    banner(f"TinyIDS MASTER ATTACK SUITE - Target: {TARGET}")
    print(f"Dashboard URL:      http://localhost:8501")
    print(f"Attack Duration:    {args.seconds}s per flood")
    print(f"Inter-Attack Pause: {args.pause}s")
    print(f"Selected Phase:     {args.phase.upper()}")
    print(f"Started At:         {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # =========================================================================
    # PHASE 1: DIRECT ATTACKS (WITHOUT BOTS)
    # =========================================================================
    if args.phase in ("1", "all"):
        banner("PHASE 1: DIRECT ATTACKS (WITHOUT BOTS - Attacker IP: 172.30.0.66)")
        
        # 1. SYN Flood
        res = run_step(
            1, "Direct TCP SYN Flood",
            [os.path.join(ATTACK_DIR, "syn_flood"), str(args.seconds), "120"],
            expected_alert="Flood (syn_flag_number, psh_flag_number, Rate)",
            source_ip="172.30.0.66 (Attacker)",
            target_port=1883
        )
        results.append(res)
        countdown_pause(args.pause)

        # 2. UDP Flood
        res = run_step(
            2, "Direct UDP Flood",
            [os.path.join(ATTACK_DIR, "udp_flood"), str(args.seconds), "120"],
            expected_alert="Flood (Tot size, AVG, flow_duration)",
            source_ip="172.30.0.66 (Attacker)",
            target_port=5683
        )
        results.append(res)
        countdown_pause(args.pause)

        # 3. Port Scan
        res = run_step(
            3, "TCP Port Scan (Nmap SYN scan)",
            [os.path.join(ATTACK_DIR, "port_scan"), "1-1000"],
            expected_alert="Recon (flow_duration, syn_count, Rate)",
            source_ip="172.30.0.66 (Attacker)",
            target_port="1-1000"
        )
        results.append(res)
        countdown_pause(args.pause)

        # 4. MQTT Brute Force
        res = run_step(
            4, "MQTT Login Brute Force",
            [os.path.join(ATTACK_DIR, "mqtt_bruteforce"), "tinyids", "15"],
            expected_alert="BruteForce (rule: refused MQTT logins >= 5)",
            source_ip="172.30.0.66 (Attacker)",
            target_port=1883
        )
        results.append(res)
        if args.phase == "all":
            countdown_pause(args.pause)

    # =========================================================================
    # PHASE 2: BOTNET ATTACKS (WITH NODEMCU BOTS)
    # =========================================================================
    if args.phase in ("2", "all"):
        banner("PHASE 2: BOTNET ATTACKS (WITH NODEMCU BOTS - IPs: 172.30.0.21, .22, .23)")
        
        # 5. Botnet UDP Flood
        res = run_step(
            5, "Botnet Coordinated UDP Flood",
            [os.path.join(ATTACK_DIR, "bot_master"), "udp_flood", str(args.seconds)],
            expected_alert="Flood from 172.30.0.21, 172.30.0.22, 172.30.0.23",
            source_ip="172.30.0.21, 172.30.0.22, 172.30.0.23 (NodeMCU Bots)",
            target_port=5683
        )
        results.append(res)
        countdown_pause(args.pause)

        # 6. Botnet TCP Flood
        res = run_step(
            6, "Botnet Coordinated TCP Connection Flood",
            [os.path.join(ATTACK_DIR, "bot_master"), "tcp_flood", str(args.seconds)],
            expected_alert="Flood from 172.30.0.21, 172.30.0.22, 172.30.0.23",
            source_ip="172.30.0.21, 172.30.0.22, 172.30.0.23 (NodeMCU Bots)",
            target_port=1883
        )
        results.append(res)

    total_time = time.time() - start_all
    banner("ATTACK SUITE EXECUTION SUMMARY")
    print(f"{'#':<3} {'Attack Name':<38} {'Source':<20} {'Status':<12} {'Duration':<10}")
    print("-" * 88)
    for r in results:
        print(f"{r['step']:<3} {r['name']:<38} {r['source']:<20} {r['status']:<12} {r['duration']:<10}")
    print("-" * 88)
    print(f"Total Test Suite Duration: {total_time:.1f}s")
    print(f"View live alerts & SHAP breakdown at: http://localhost:8501\n")

if __name__ == "__main__":
    main()
