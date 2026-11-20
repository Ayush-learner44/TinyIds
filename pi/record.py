"""Record our own traffic as feature rows (for training). No model, no alerts, no blocking. No pcap is saved.

Exactly the same packets -> windows -> features path as the detector (run_tinyids.py), but every full window is
written to a CSV file as one row: time, sender IP, and ALL the features (the training script picks the columns).
The label is NOT decided here: the training script labels the rows by sender IP / file name.

Pi:      sudo ./venv/bin/python record.py benign_nodemcu.csv 1200 admin 172.29.2.40
Docker:  python record.py /data/benign_docker.csv 1800 interface eth0

Options (no dashes): <file.csv> <seconds>   then optionally:
  interface wlan0     network card to listen on (default wlan0)
  admin 172.29.2.40   leave out everything from this IP (your laptop)
"""
import csv
import sys
import time

from scapy.arch import get_if_addr
from scapy.sendrecv import sniff

from tinyids.features import AVERAGED, SIZE_STATS, FeatureBuilder, FlowTable, PacketReader
from tinyids.settings import Settings
from tinyids.windows import WindowCollector

COLUMNS = AVERAGED + SIZE_STATS          # every feature we can compute


def main(words):
    if len(words) < 2:
        raise SystemExit("use:  record.py <file.csv> <seconds> [interface <name>] [admin <ip>]")
    file_name, seconds = words[0], int(words[1])
    options = dict(zip(words[2::2], words[3::2]))
    interface = options.get("interface", "wlan0")
    my_ip = get_if_addr(interface)
    settings = Settings()
    flows = FlowTable()
    reader = PacketReader(flows)
    windows = WindowCollector(settings.window, settings.window_timeout)
    capture = f"dst host {my_ip}" + (f" and not src host {options['admin']}" if "admin" in options else "")

    out = open(file_name, "w", newline="")
    writer = csv.writer(out)
    writer.writerow(["time", "src"] + COLUMNS + ["pps"])     # pps: recorded for the report, NOT used in training
    start = time.time()
    count = {"rows": 0, "last_cleanup": start, "last_print": start}
    per_sender = {}

    def on_packet(packet):
        now = time.time()
        if now - count["last_cleanup"] > 1:            # once a second: throw away windows that never filled
            windows.drop_old()
            flows.forget_old(now)
            count["last_cleanup"] = now
        if now - count["last_print"] >= 30:            # every 30 s: show that it is working
            count["last_print"] = now
            print(f"  {int(now - start) // 60} min {int(now - start) % 60:02d} s: {count['rows']} rows so far  "
                  f"{per_sender}", flush=True)
        info = reader.read(packet)
        if info is None:
            return
        for sender, packets in windows.add(info):
            row = FeatureBuilder.values(packets)
            span = packets[-1].time - packets[0].time              # seconds from the 1st to the 10th packet
            pps = round(len(packets) / span, 2) if span > 0 else 0.0   # packets per second of this window
            writer.writerow([round(now, 3), sender] + [round(float(row[c]), 4) for c in COLUMNS] + [pps])
            out.flush()                                # every row is on disk at once (Ctrl+C loses nothing)
            count["rows"] += 1
            per_sender[sender] = per_sender.get(sender, 0) + 1

    print(f"recording {interface} ({my_ip}) for {seconds} s into {file_name} (a line every 30 s; Ctrl+C = stop early, "
          f"everything recorded so far is kept) ...", flush=True)
    try:
        sniff(iface=interface, filter=capture, prn=on_packet, store=False, timeout=seconds)
    except KeyboardInterrupt:
        print("stopped early with Ctrl+C", flush=True)
    out.close()
    print(f"done: {count['rows']} rows in {file_name}  {per_sender}", flush=True)


if __name__ == "__main__":
    main(sys.argv[1:])
