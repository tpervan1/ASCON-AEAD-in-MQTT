
import uos, machine
import time
import sys
import gc
import micropython
import network
import esp
esp.osdebug(None)
gc.collect()

max_attempts = 5
attempt_count = 0
ssid = 'your_ssid'
password = 'your_password'
station = network.WLAN(network.STA_IF)
station.active(True)
station.connect(ssid, password)

print("Connecting to WiFi...")
while not station.isconnected() and attempt_count<max_attempts:
  attempt_count+=1
  time.sleep(1)


if attempt_count == max_attempts:
  print('Could not connect to the WiFi network')
  sys.exit()
else:
  print('Connection successful')
  print(station.ifconfig())























