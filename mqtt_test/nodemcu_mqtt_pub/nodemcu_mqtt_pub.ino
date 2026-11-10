// NodeMCU (ESP8266) -> MQTT broker test.
// Publishes the board's own stats every 2 s to topic "test/01".
// Needs library: "PubSubClient" by Nick O'Leary (Library Manager).
// Board: NodeMCU 1.0 (ESP-12E Module). Serial Monitor: 9600 baud.

#include <ESP8266WiFi.h>
#include <PubSubClient.h>

// ---------- CHANGE THESE ----------
const char* WIFI_SSID = "IIITA";            // Wi-Fi name
const char* WIFI_PASS = "";                 // Wi-Fi password ("" if the network has none)
const char* TOPIC     = "test/01";

// --- Broker: keep exactly ONE of these lines uncommented ---
//const char* BROKER = "172.29.0.43";            // OPTION A: Mosquitto on your laptop (its IP from ipconfig; can change)
const char* BROKER = "172.29.1.135";   // the Pi
// const char* BROKER = "broker.hivemq.com";   // OPTION B: free public broker (needs internet: use a phone hotspot,
                                               //           the college network blocks MQTT to the internet)
// NOTE: there is no proxy setting here on purpose. The ESP8266 cannot use an HTTP proxy for MQTT.
//       A local broker (option A) never needs the proxy anyway.
// ----------------------------------

WiFiClient net;
PubSubClient mqtt(net);
unsigned long lastSend = 0;

void connectWiFi() {
  Serial.printf("Connecting to Wi-Fi '%s'", WIFI_SSID);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.printf("\nWi-Fi OK, my IP: %s\n", WiFi.localIP().toString().c_str());
}

void connectMQTT() {
  while (!mqtt.connected()) {
    String clientId = "nodemcu-" + String(ESP.getChipId(), HEX);
    Serial.printf("Connecting to MQTT broker %s ... ", BROKER);
    if (mqtt.connect(clientId.c_str())) {
      Serial.println("OK");
    } else {
      Serial.printf("failed (state %d), retry in 3 s\n", mqtt.state());
      delay(3000);
    }
  }
}

void setup() {
  Serial.begin(9600);
  delay(500);
  connectWiFi();
  mqtt.setServer(BROKER, 1883);
  connectMQTT();
  Serial.printf("Publishing to topic: %s\n", TOPIC);
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) connectWiFi();
  if (!mqtt.connected()) connectMQTT();
  mqtt.loop();

  if (millis() - lastSend >= 2000) {
    lastSend = millis();
    char msg[128];
    snprintf(msg, sizeof(msg),
             "{\"uptime_s\":%lu,\"rssi_dbm\":%d,\"free_heap\":%u,\"a0\":%d}",
             millis() / 1000, WiFi.RSSI(), ESP.getFreeHeap(), analogRead(A0));
    bool ok = mqtt.publish(TOPIC, msg);
    Serial.printf("%s  %s\n", ok ? "sent" : "FAILED", msg);
  }
}
