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
    writer.writerow(["time", "src"] + COLUMNS)
    count = {"rows": 0, "last_cleanup": time.time()}

    def on_packet(packet):
        now = time.time()
        if now - count["last_cleanup"] > 1:            # once a second: throw away windows that never filled
            windows.drop_old()
            flows.forget_old(now)
            count["last_cleanup"] = now
        info = reader.read(packet)
        if info is None:
            return
        for sender, packets in windows.add(info):
            row = FeatureBuilder.values(packets)
            writer.writerow([round(now, 3), sender] + [round(float(row[c]), 4) for c in COLUMNS])
            count["rows"] += 1

    print(f"recording {interface} ({my_ip}) for {seconds} s into {file_name} ...", flush=True)
    sniff(iface=interface, filter=capture, prn=on_packet, store=False, timeout=seconds)
    out.close()
    print(f"done: {count['rows']} rows", flush=True)


if __name__ == "__main__":
    main(sys.argv[1:])
