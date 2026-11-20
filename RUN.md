# RUN: the lab demo, step by step

Do the steps **in this order**. Each step says **where** to type it. Every command has its own box (copy button).
Replace `PI_IP` and `LAPTOP_IP` with the real addresses.

| Name | What it is | How to find it |
|---|---|---|
| `PI_IP` | the Raspberry Pi's address | step 1 |
| `LAPTOP_IP` | your laptop's address | step 1 |

All laptop folders are inside `C:\Users\HOME\Documents\iot\retrain`. On the Pi everything lives in `~/tinyids_new`.

---

## 0. NodeMCU firmware (only if the Pi's IP or the Wi-Fi changed)

The Pi's IP is written into the firmware, so if it changed, re-flash all 3 boards.

1. Open `laptop/nodemcu_bot/nodemcu_bot.ino` in the Arduino IDE.
2. In the `CHANGE THESE` block set:
   - `WIFI_SSID` / `WIFI_PASS` = the lab Wi-Fi (`IIITA`, empty password)
   - `GATEWAY_IP` = `PI_IP`
   - `NODE_NAME` = `node1`, then `node2`, then `node3`: **different for every board**
3. Board: *NodeMCU 1.0 (ESP-12E Module)*. Flash board 1 with `node1`, change the name, flash board 2 with `node2`,
   change it again, flash board 3 with `node3`.

---

## 1. Power on and find the addresses

Plug in the **Pi** and wait about 1 minute.

On the Pi (keyboard + screen): the first number is `PI_IP`.

```
hostname -I
```

On the laptop, PowerShell: look for "Wireless LAN adapter Wi-Fi" → IPv4 Address = `LAPTOP_IP`.

```
ipconfig
```

If `PI_IP` is different from the one in the firmware → do step 0 now.

---

## 2. Copy the newest code to the Pi (only if code changed)

Laptop, PowerShell. First go to the retrain folder:

```
cd C:\Users\HOME\Documents\iot\retrain
```

**First time ever** (the Pi has no `~/tinyids_new` yet):

```
scp -r pi pi@PI_IP:~/tinyids_new
```

**Every later time** (copies the new files over the old ones):

```
scp -r pi/run_tinyids.py pi/run_ids.sh pi/record.py pi/tinyids pi/models pi/benchmark pi@PI_IP:~/tinyids_new/
```

**Only the Flush fix of 19 Nov** (one file):

```
scp pi\tinyids\response.py pi@PI_IP:~/tinyids_new/tinyids/
```

---

## 3. Log in to the Pi from the laptop

Laptop, PowerShell:

```
ssh pi@PI_IP
```

Then go to the project folder (on the Pi):

```
cd ~/tinyids_new
```

**Only the first time ever**, set up the Pi (clock, Python packages, broker password):

```
bash setup_pi.sh
```

---

## 4. Start the broker + the detector (Pi, every time)

In the Pi window from step 3:

```
./run_ids.sh admin LAPTOP_IP | tee lab_log.txt
```

- Wait for: `our broker is running on port 1884` and `TinyIDS watching wlan0 ...`
- **Keep this window open**: it shows every alert and block (`ALERT ...`, `IPS BLOCK ...`).
- `| tee lab_log.txt` = also save everything into `lab_log.txt` on the Pi.
- `admin LAPTOP_IP` = your laptop's SSH and dashboard are never blocked.
- Stop it later with **Ctrl+C** (this also stops the broker).

---

## 5. Switch on the NodeMCUs

Plug the 3 boards into USB power. They join the Wi-Fi and publish to the Pi by themselves, every 2 seconds.
To watch one: Arduino IDE → Serial Monitor → **9600 baud**.

---

## 6. Start the dashboard (laptop)

Open a **new** PowerShell window. Go to the retrain folder:

```
cd C:\Users\HOME\Documents\iot\retrain
```

Start the dashboard:

```
streamlit run laptop/dashboard.py -- PI_IP
```

The browser opens. Check that **Sensors** shows node1, node2 and node3.

---

## 7. Normal traffic first (2–5 minutes, no attacks)

Just watch the dashboard. Expected: **0 alerts** while only the NodeMCUs are running (no false alarms).

---

## 8. Laptop attacks (WSL)

Open a **new** PowerShell window and start WSL:

```
wsl -d Ubuntu-24.04
```

Go to the laptop folder (inside WSL):

```
cd /mnt/c/Users/HOME/Documents/iot/retrain/laptop
```

**Option A:** a menu, one attack at a time (1 SYN, 2 UDP, 5 ICMP, 6 ACK / PSH-ACK / RST-FIN, 3 port scan,
4 MQTT brute force):

```
python3 launch.py PI_IP
```

**Option B:** all attacks in a row, with log files (about 12 minutes):

```
bash attack_all.sh PI_IP
```

It writes `attack_log_<time>.txt` and `dashboard_alerts_<time>.txt` into `laptop/`.

If WSL cannot reach the Pi, run this in PowerShell, then open Ubuntu-24.04 again and retry:

```
wsl --shutdown
```

---

## 9. Bot attack: DDoS from the 3 NodeMCUs

Open a **new PowerShell window (Windows, not WSL)** and go to the laptop folder:

```
cd C:\Users\HOME\Documents\iot\retrain\laptop
```

All 3 boards flood the Pi with **TCP** for 10 seconds:

```
python bot.py tcp 10
```

The same with **UDP**:

```
python bot.py udp 10
```

Stop the bots at once:

```
python bot.py stop
```

Expected: `DDoS flood (3 senders)`, all 3 nodes **quarantined** for 120 s. Let the quarantine end by itself, or press
**Flush Bans** on the dashboard.

---

## 10. After the demo: save and stop

1. In the Pi window press **Ctrl+C** (stops detector + broker).
2. Copy the Pi's log to the laptop. Laptop PowerShell, go to the laptop folder:

```
cd C:\Users\HOME\Documents\iot\retrain\laptop
```

```
scp pi@PI_IP:~/tinyids_new/lab_log.txt lab_log_DATE.txt
```

3. In the dashboard's PowerShell window press **Ctrl+C**.

---

## 11. If the Pi's firewall is in a mess: clear it

On the Pi. **First stop the detector** (Ctrl+C in its window), otherwise it adds rules back.

Look at the rules. The **first line must be `-P INPUT ACCEPT`**; if it says `-P INPUT DROP`, stop and ask
(clearing would then cut your SSH):

```
sudo iptables -S INPUT
```

Clear all block / quarantine / rate-limit rules:

```
sudo iptables -F INPUT
```

Check it is empty (only `-P INPUT ACCEPT` left):

```
sudo iptables -S INPUT
```

Start the detector again (it re-adds its 2 "keep the admin laptop open" rules by itself):

```
./run_ids.sh admin LAPTOP_IP | tee lab_log3.txt
```

---

## Order at a glance

| Step | Where | What |
|---|---|---|
| 1 | Pi + laptop | power on, note `PI_IP` and `LAPTOP_IP` (re-flash the NodeMCUs, step 0, if `PI_IP` changed) |
| 2 | laptop PowerShell | copy the code to the Pi (only if it changed) |
| 3 | laptop → Pi | `ssh`, go to `~/tinyids_new` (setup only the first time) |
| 4 | Pi | start broker + detector, keep the window open |
| 5 | NodeMCUs | plug in |
| 6 | laptop PowerShell | start the dashboard |
| 7 | — | 2–5 minutes normal traffic: 0 alerts |
| 8 | laptop WSL | laptop attacks: menu or all in a row |
| 9 | laptop PowerShell | bot DDoS: tcp / udp / stop |
| 10 | Pi + laptop | Ctrl+C, copy the log back |

---

## Without the lab: the Docker testbed on the laptop

Docker Desktop must be running ("Engine running"). PowerShell, go to the testbed folder:

```
cd C:\Users\HOME\Documents\iot\retrain\testbed
```

Start everything:

```
docker compose up -d --build
```

Check that all 7 containers are "Up":

```
docker compose ps
```

Dashboard: open **http://localhost:8503** in the browser.

Attack menu (the fake Pi is `172.28.70.10`):

```
docker compose exec attacker python3 launch.py 172.28.70.10
```

Bot DDoS from the 3 fake NodeMCUs:

```
docker compose exec attacker python3 bot.py tcp 10
```

Watch the detector live (Ctrl+C stops watching, not the detector):

```
docker compose logs ids -f
```

Stop everything:

```
docker compose down
```
