
from umqttsimple import MQTTClient
import time
import os,sys
import ubinascii
import ascon
import urequests
import ntptime
import ujson as json

broker= '192.168.1.101'
client_id='sensor01'
topic_sub = b'house/balcony/weather/notification'
topic_pub = b'house/balcony/weather/data'

last_message = 0
message_interval = 1000*5
web_query_delay = 1000*300
update_time = time.ticks_ms() - web_query_delay

key=(0xae772877c34b31ab55967e6e7f28a8e1).to_bytes(16,'big')
associated_data = client_id.encode('utf-8')

open_weather_map_api_key = 'your_api_key'
city='Sarajevo'
country='BA'
open_weather_map_url = 'http://api.openweathermap.org/data/2.5/weather?q=' + city + ',' + country + '&APPID=' + open_weather_map_api_key+ '&units=metric'
temperature=23.15
humidity=30
pressure=1021

def sub_cb(topic, msg):
  print('\nReceived message on topic ',topic, ': ', msg)
  received_msg, notification_msg=ascon.timestamp_authentication(msg,time.time()+946684800,key, len(associated_data))
  print('Decoded message is: ', received_msg)
  print('Did authentication succeed? ', notification_msg)

def connect_and_subscribe():
  global client_id, broker, topic_sub
  client = MQTTClient(client_id, broker)
  client.set_callback(sub_cb)
  client.connect()
  client.subscribe(topic_sub)
  print('Connected to MQTT broker', broker, ', subscribed to topic', topic_sub)
  return client

def exit():
  print('Failed to connect to MQTT broker. Terminating...')
  time.sleep(2)
  sys.exit()

print('Connecting to broker', broker)

try:
  client = connect_and_subscribe()
except Exception as e:
  print(e.__class__.__name__,":", e )
  exit() 

while True:
 
  if time.ticks_ms() - update_time >= web_query_delay:
    try:
        ntptime.settime()
    except Exception as e:
        print(e.__class__.__name__,":", e )
    update_time=time.ticks_ms()
    print('Time updated')
    response = urequests.get(open_weather_map_url)
    if response.status_code == 200:
      parsed=response.json()
      temperature=parsed['main']['temp']
      humidity=parsed['main']['humidity']
      pressure=parsed['main']['pressure']
    
  try:
    client.check_msg()
    if (time.ticks_ms() - last_message) > message_interval:
      weather_data={'humidity': humidity, 'pressure':pressure, 'temp':temperature}
      weather_data=json.dumps(weather_data)
      msg=ascon.timestamped_message(time.time()+946684800, weather_data)
      nonce=ascon.generate_random_bytes(16)
      t1=time.ticks_ms()
      enc_msg,tag=ascon.encrypt(key,nonce, msg, associated_data)
      print('\nEncryption time:', time.ticks_ms()-t1, 'ms')
      data=ascon.data_to_send(associated_data,nonce,enc_msg,tag)
      client.publish(topic_pub, data)
      print('Data published')
      last_message = time.ticks_ms()
  except OSError as e:
    print(e.__class__.__name__,":", e )
    exit()



















