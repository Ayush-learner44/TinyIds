#!/usr/bin/env python3
"""Master Automated Attack Suite for Physical Hardware Deployment.

Executes all attack vectors against the Raspberry Pi gateway:
  Phase 1: Direct Attacker (from laptop)
    1. TCP SYN Flood (Port 1884/1883)
    2. UDP Flood (Port 5683)
    3. TCP Port Scan (Ports 1-1024)
    4. MQTT Brute Force (Port 1884/1883)

  Phase 2: Coordinated Botnet Attacks (from physical NodeMCU bots)
    5. Botnet UDP Flood
    6. Botnet TCP Flood

Usage:
  python run_all_attacks.py 172.29.1.135 [--port 1884] [--seconds 10] [--pause 6] [--phase all|1|2]
"""
import argparse
import datetime
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent

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

def run_step(step_num, name, cmd, expected_alert, source_desc, target_desc):
    subbanner(f"Attack {step_num}: {name}")
    print(f"  Source:         {source_desc}")
    print(f"  Target:         {target_desc}")
    print(f"  Expected Alert: {expected_alert}")
    print(f"  Start Time:     {datetime.datetime.now().strftime('%H:%M:%S')}")
    print(f"  Executing:      {' '.join(cmd)}\n", flush=True)
    
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, text=True)
        status = "COMPLETED" if proc.returncode == 0 else f"EXIT CODE {proc.returncode}"
    except Exception as e:
        status = f"ERROR: {e}"
    elapsed = time.time() - t0
    
    print(f"\n[+] {name} {status} in {elapsed:.1f}s", flush=True)
    return {
        "step": step_num,
        "name": name,
        "source": source_desc,
        "alert": expected_alert,
        "duration": f"{elapsed:.1f}s",
        "status": status
    }

def main():
    parser = argparse.ArgumentParser(description="TinyIDS Physical Gateway Attack Suite")
    parser.add_argument("gateway", help="IP address of the Raspberry Pi gateway (e.g., 172.29.1.135)")
    parser.add_argument("--port", type=int, default=1884, help="Mosquitto broker port on Pi (default: 1884)")
    parser.add_argument("--seconds", type=int, default=10, help="Duration for flood attacks (default: 10s)")
    parser.add_argument("--pause", type=int, default=6, help="Cool-down seconds between attacks (default: 6s)")
    parser.add_argument("--phase", choices=["1", "2", "all"], default="all", help="1=Laptop only, 2=Bots only, all=Both")
    args = parser.parse_args()

    py = sys.executable
    attacks_dir = HERE / "attacks"
    results = []
    start_all = time.time()

    banner(f"TinyIDS PHYSICAL TEST SUITE - Target Gateway: {args.gateway}")
    print(f"Broker Port:        {args.port}")
    print(f"Attack Duration:    {args.seconds}s per flood")
    print(f"Inter-Attack Pause: {args.pause}s")
    print(f"Phase:              {args.phase.upper()}")
    print(f"Started At:         {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # =========================================================================
    # PHASE 1: DIRECT ATTACKS (WITHOUT BOTS - FROM LAPTOP)
    # =========================================================================
    if args.phase in ("1", "all"):
        banner("PHASE 1: DIRECT ATTACKS (WITHOUT BOTS - Laptop Source)")

        # 1. SYN Flood
        res = run_step(
            1, "Direct TCP SYN Flood",
            [py, str(attacks_dir / "syn_flood.py"), args.gateway, "--port", str(args.port), "--seconds", str(args.seconds)],
            expected_alert="Flood (syn_flag_number, psh_flag_number, Rate)",
            source_desc="Laptop (Direct)",
            target_desc=f"{args.gateway}:{args.port}"
        )
        results.append(res)
        countdown_pause(args.pause)

        # 2. UDP Flood
        res = run_step(
            2, "Direct UDP Flood",
            [py, str(attacks_dir / "udp_flood.py"), args.gateway, "--port", "5683", "--seconds", str(args.seconds)],
            expected_alert="Flood (Tot size, AVG, flow_duration)",
            source_desc="Laptop (Direct)",
            target_desc=f"{args.gateway}:5683"
        )
        results.append(res)
        countdown_pause(args.pause)

        # 3. Port Scan
        res = run_step(
            3, "TCP Port Scan",
            [py, str(attacks_dir / "port_scan.py"), args.gateway, "--first", "1", "--last", "1024"],
            expected_alert="Recon (flow_duration, syn_count, Rate)",
            source_desc="Laptop (Direct)",
            target_desc=f"{args.gateway}:1-1024"
        )
        results.append(res)
        countdown_pause(args.pause)

        # 4. MQTT Brute Force
        res = run_step(
            4, "MQTT Login Brute Force",
            [py, str(attacks_dir / "mqtt_bruteforce.py"), args.gateway, "--port", str(args.port), "--tries", "15"],
            expected_alert="BruteForce (rule: refused logins >= 5)",
            source_desc="Laptop (Direct)",
            target_desc=f"{args.gateway}:{args.port}"
        )
        results.append(res)
        if args.phase == "all":
            countdown_pause(args.pause)

    # =========================================================================
    # PHASE 2: BOTNET ATTACKS (WITH NODEMCU BOTS)
    # =========================================================================
    if args.phase in ("2", "all"):
        banner("PHASE 2: BOTNET ATTACKS (WITH PHYSICAL NODEMCU BOTS)")

        # 5. Botnet UDP Flood
        res = run_step(
            5, "NodeMCU Botnet UDP Flood",
            [py, str(HERE / "bot_master.py"), args.gateway, "udp_flood", "--port", str(args.port), "--seconds", str(args.seconds)],
            expected_alert="Flood from NodeMCU IP addresses",
            source_desc="NodeMCU Bot Nodes (via C2)",
            target_desc=f"{args.gateway}:5683"
        )
        results.append(res)
        countdown_pause(args.pause)

        # 6. Botnet TCP Flood
        res = run_step(
            6, "NodeMCU Botnet TCP Flood",
            [py, str(HERE / "bot_master.py"), args.gateway, "tcp_flood", "--port", str(args.port), "--seconds", str(args.seconds)],
            expected_alert="Flood from NodeMCU IP addresses",
            source_desc="NodeMCU Bot Nodes (via C2)",
            target_desc=f"{args.gateway}:{args.port}"
        )
        results.append(res)

    total_time = time.time() - start_all
    banner("EXECUTION SUMMARY")
    print(f"{'#':<3} {'Attack Name':<35} {'Source':<25} {'Status':<12} {'Duration':<10}")
    print("-" * 88)
    for r in results:
        print(f"{r['step']:<3} {r['name']:<35} {r['source']:<25} {r['status']:<12} {r['duration']:<10}")
    print("-" * 88)
    print(f"Total Execution Time: {total_time:.1f}s")
    print("Check laptop dashboard for captured alerts & TreeSHAP explanations!\n")

if __name__ == "__main__":
    main()
