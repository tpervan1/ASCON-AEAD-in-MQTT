import paho.mqtt.client as mqtt
from datetime import datetime
import time
import ascon
import os

key=(0x12345678123456781234567812345678).to_bytes(16,'big')
client_id='pcnode01'
associated_data=client_id.encode('utf-8')

def on_log(client, userdata, level, buf):
    print("Log: ", buf)

def on_publish(client,userdata,mid):
    print("Data published \n")

def on_connect(client, userdata, flags, rc):
    if rc==0:
        print('Connected OK')
    else:
        print("Connection refused, result code ", rc)

def on_disconnect(client, userdata, flags, rc=0):
    print("Dissconected, result code: ", str(rc))

def on_message(client, userdata, msg):
    print('Received message on topic ',msg.topic, ': ', msg.payload)
    received_msg, notification_msg=ascon.timestamp_authentication(msg.payload,time.time(),key, len(associated_data))
    print('Decrypted message: ', received_msg)
    print('Did authentication succeed? ', notification_msg)

    if notification_msg!='Auth. fail':
        received_msg=received_msg.decode('utf-8')
        with open('data.txt', 'a') as f:
            f.write(received_msg[:10] +": " + received_msg[10:]+"\n")
    
    msg1=ascon.timestamped_message(round(time.time()), notification_msg)
    nonce1=ascon.generate_random_bytes(16)
    ciphertext,tag=ascon.encrypt(key,nonce1, msg1, associated_data)
    data=ascon.data_to_send(associated_data,nonce1,ciphertext,tag)
    client.publish('house/balcony/weather/notification', data)

broker="your_broker_ip_address"
client=mqtt.Client(client_id)

client.on_connect=on_connect
client.on_disconnect=on_disconnect
#client._on_log=on_log
client.on_message=on_message
client.on_publish=on_publish

print("Connecting to broker ", broker)
try:
    client.connect(broker)
except Exception as e:
    print(e)
    client.disconnect()

client.subscribe("house/balcony/weather/data")
client.loop_forever()
client.disconnect()
