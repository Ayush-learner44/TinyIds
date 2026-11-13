// NodeMCU (ESP8266) as a CoAP server.
// The laptop asks for data; the NodeMCU answers. No broker.
//
//   GET coap://<nodemcu-ip>/stats      -> JSON with uptime, rssi, free heap, a0
//   GET coap://<nodemcu-ip>/led        -> "on" or "off"
//   PUT coap://<nodemcu-ip>/led  "on"  -> switches the blue LED on (or "off")
//
// Needs library: "CoAP simple library" by Hirotaka Niisato (Library Manager).
// Board: NodeMCU 1.0 (ESP-12E Module). Serial Monitor: 9600 baud.

#include <ESP8266WiFi.h>
#include <WiFiUdp.h>
#include <coap-simple.h>

// ---------- CHANGE THESE ----------
const char* WIFI_SSID = "IIITA";   // Wi-Fi name
const char* WIFI_PASS = "";        // Wi-Fi password ("" if none)
// ----------------------------------
// No broker and no proxy: the laptop talks to this board directly over the local Wi-Fi (UDP port 5683).

#define LED_PIN 2   // blue LED, ON when pin is LOW

WiFiUDP udp;
Coap coap(udp);
bool ledOn = false;

void reply(CoapPacket &p, IPAddress ip, int port, const char *text, COAP_CONTENT_TYPE type) {
  coap.sendResponse(ip, port, p.messageid, text, strlen(text),
                    COAP_CONTENT, type, p.token, p.tokenlen);
}

// GET /stats
void onStats(CoapPacket &p, IPAddress ip, int port) {
  char msg[128];
  snprintf(msg, sizeof(msg),
           "{\"uptime_s\":%lu,\"rssi_dbm\":%d,\"free_heap\":%u,\"a0\":%d}",
           millis() / 1000, WiFi.RSSI(), ESP.getFreeHeap(), analogRead(A0));
  Serial.printf("GET /stats from %s -> %s\n", ip.toString().c_str(), msg);
  reply(p, ip, port, msg, COAP_APPLICATION_JSON);
}

// GET /led  or  PUT /led with payload "on" / "off"
void onLed(CoapPacket &p, IPAddress ip, int port) {
  if (p.code == COAP_PUT) {
    String body = String((char*)p.payload).substring(0, p.payloadlen);
    body.trim();
    ledOn = (body == "on");
    digitalWrite(LED_PIN, ledOn ? LOW : HIGH);
    Serial.printf("PUT /led '%s' from %s\n", body.c_str(), ip.toString().c_str());
  } else {
    Serial.printf("GET /led from %s\n", ip.toString().c_str());
  }
  reply(p, ip, port, ledOn ? "on" : "off", COAP_TEXT_PLAIN);
}

void setup() {
  Serial.begin(9600);
  delay(500);
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, HIGH);   // LED off

  Serial.printf("\nConnecting to Wi-Fi '%s'", WIFI_SSID);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.printf("\nWi-Fi OK. CoAP server ready at  coap://%s/stats\n",
                WiFi.localIP().toString().c_str());
  Serial.println(">>> Use this IP in coap_client.py <<<");

  coap.server(onStats, "stats");
  coap.server(onLed, "led");
  coap.start();   // listens on UDP port 5683
}

void loop() {
  coap.loop();
  delay(1);
}
