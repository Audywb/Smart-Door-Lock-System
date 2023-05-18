#include <ESP8266WiFi.h>
#include <PubSubClient.h>

const char* ssid = "DSSI_IoT_Project";
const char* password = "##############";

const char* mqtt_server = "192.168.1.1";

WiFiClient espClient;
PubSubClient client(espClient);

const int pinGPIO5 = 5;
const int pinGPIO4 = 4;

void setup_wifi() {
  delay(10);
  Serial.println();
  Serial.print("Connecting to ");
  Serial.println(ssid);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("");
  Serial.print("WiFi connected - ESP IP address: ");
  Serial.println(WiFi.localIP());
}

void callback(String topic, byte* message, unsigned int length) {
  Serial.print("Message arrived on topic: ");
  Serial.print(topic);
  Serial.print(". Message: ");
  String messageTemp;
  
  for (int i = 0; i < length; i++) {
    Serial.print((char)message[i]);
    messageTemp += (char)message[i];
  }
  Serial.println();

  if(topic=="esp8266_02/4"){
      Serial.print("Changing GPIO 4 to ");
      if(messageTemp == "1"){
        digitalWrite(pinGPIO4, HIGH);
        Serial.print("On");
      }
      else if(messageTemp == "0"){
        digitalWrite(pinGPIO4, LOW);
        Serial.print("Off");
        digitalWrite(pinGPIO5, HIGH);
        delay(200);
        digitalWrite(pinGPIO5, LOW);
      }
  }
  if(topic=="esp8266_02/5"){
      Serial.print("Changing GPIO 5 to ");
      if(messageTemp == "1"){
        digitalWrite(pinGPIO5, HIGH);
        Serial.print("On");
        delay(500);
        digitalWrite(pinGPIO5, LOW);
        Serial.print("Off");
      }
      else if(messageTemp == "0"){
        digitalWrite(pinGPIO5, LOW);
        Serial.print("Off");
      }
  }
  Serial.println();
}

void reconnect() {
  // Loop until we're reconnected
  while (!client.connected()) {
    Serial.print("Attempting MQTT connection...");

    if (client.connect("ESP8266Client2")) {
      Serial.println("connected");  
      // Subscribe or resubscribe to a topic
      // You can subscribe to more topics (to control more LEDs in this example)
      client.subscribe("esp8266_02/4");
      client.subscribe("esp8266_02/5");
    } else {
      Serial.print("failed, rc=");
      Serial.print(client.state());
      Serial.println(" try again in 5 seconds");
      // Wait 5 seconds before retrying
      delay(5000);
    }
  }
}

void setup() {
  pinMode(pinGPIO4, OUTPUT);
  pinMode(pinGPIO5, OUTPUT);
  
  Serial.begin(115200);
  setup_wifi();
  client.setServer(mqtt_server, 1883);
  client.setCallback(callback);
}

void loop() {
  if (!client.connected()) {
    reconnect();
  }
  if(!client.loop())
    client.connect("ESP8266Client");
}