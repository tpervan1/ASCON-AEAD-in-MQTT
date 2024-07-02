# Ascon AEAD Cipher for MQTT Communication
Python implementation of the Ascon AEAD cipher for secure encryption and authentication of MQTT communication between a PC and an ESP8266 microcontroller.

This project demonstrates how to use the Ascon cipher to secure MQTT messages. Ascon is a family of authenticated encryption and hashing algorithms that provides confidentiality, integrity, and authenticity. It is designed to be lightweight and suitable for constrained environments like IoT devices. Ascon has been selected as the new standard for lightweight cryptography in the NIST Lightweight Cryptography competition (2019–2023). Here, Ascon was used for payload encryption of the MQTT message, ensuring that the information in message remains confidential and secure from unauthorized access during transmission.

Implementation of the ASCON cipher functionality is based on [existing work](https://github.com/meichlseder/pyascon) from authors, with modifications made to support MicroPython on ESP8266.

