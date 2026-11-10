// ESP8266 (NodeMCU) board health check for the TinyIDS testbed.
// Board: "NodeMCU 1.0 (ESP-12E Module)". Serial Monitor at 115200 baud, press RST.
// PASS = chip info prints, LED blinks, Wi-Fi scan finds networks.

#include <ESP8266WiFi.h>

#define LED_PIN 2   // onboard blue LED on GPIO2, ON when pin is LOW

void setup() {
  Serial.begin(9600);
  delay(1000);
  pinMode(LED_PIN, OUTPUT);

  Serial.println("\n===== ESP8266 BOARD TEST =====");
  Serial.printf("Chip ID        : %08X\n", ESP.getChipId());
  Serial.printf("CPU freq       : %d MHz\n", ESP.getCpuFreqMHz());
  Serial.printf("Flash size     : %u MB\n", ESP.getFlashChipRealSize() / (1024 * 1024));
  Serial.printf("Free heap      : %u bytes\n", ESP.getFreeHeap());

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  Serial.printf("MAC address    : %s   <-- write this on a sticker on the board\n",
                WiFi.macAddress().c_str());

  Serial.println("\nScanning Wi-Fi...");
  int n = WiFi.scanNetworks();
  if (n <= 0) {
    Serial.println("FAIL: no networks found (check antenna / board)");
  } else {
    Serial.printf("PASS: found %d networks\n", n);
    for (int i = 0; i < n && i < 10; i++) {
      Serial.printf("  %2d. %-32s %4d dBm\n", i + 1, WiFi.SSID(i).c_str(), WiFi.RSSI(i));
    }
  }
  Serial.println("\nLED should now blink once per second. Uptime counter below.");
}

void loop() {
  digitalWrite(LED_PIN, LOW);   // LED on
  delay(500);
  digitalWrite(LED_PIN, HIGH);  // LED off
  delay(500);
  Serial.printf("alive, uptime %lu s\n", millis() / 1000);
}
