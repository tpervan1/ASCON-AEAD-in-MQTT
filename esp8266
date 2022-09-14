
import gc
import os
import time

#we form initial state s, then apply permutation and then xor with key
def initialization(key, nonce):
    #iv=k+r+a+b+ (160-k) zeros
    #k=128, r=128,a=12,b=8
    iv=0x80800c0800000000
    s=[iv]
    s.append(int.from_bytes(key[0:8],'big'))
    s.append(int.from_bytes(key[8:16],'big'))
    s.append(int.from_bytes(nonce[0:8],'big'))
    s.append(int.from_bytes(nonce[8:16],'big'))
    permutation(s,12)
    #now we xor with 320-k zeros and key
    s[3]^=int.from_bytes(key[0:8],'big')
    s[4]^=int.from_bytes(key[8:16],'big')
    return s

def permutation(s,n):
    for i in range(n):
        #addition of constants
        s[2]^=(16*(n+3-i)+(12-n+i))
        #substitution layer
        s[0] ^= s[4]
        s[4] ^= s[3]
        s[2] ^= s[1]

        t0=s[0] & (s[4]^0XFFFFFFFFFFFFFFFF)
        s[0]^=s[2] & (s[1]^0XFFFFFFFFFFFFFFFF)
        s[2]^=s[4] & (s[3]^0XFFFFFFFFFFFFFFFF)
        s[4]^=s[1] & (s[0]^0XFFFFFFFFFFFFFFFF)
        s[1]^=s[3] & (s[2]^0XFFFFFFFFFFFFFFFF)
        s[3]^=t0
        
        s[1] ^= s[0]
        s[0] ^= s[4]
        s[3] ^= s[2]
        s[2] ^= 0XFFFFFFFFFFFFFFFF

        #permutation layer
        s[0]^=(((s[0]>>19)|(s[0]<<(64-19))) ^ ((s[0]>>28)|(s[0]<<(64-28)))) & 0XFFFFFFFFFFFFFFFF
        s[1]^=(((s[1]>>61)|(s[1]<<(64-61))) ^ ((s[1]>>39)|(s[1]<<(64-39))))& 0XFFFFFFFFFFFFFFFF
        s[2]^=(((s[2]>>1)|(s[2]<<(64-1))) ^ ((s[2]>>6)|(s[2]<<(64-6)))) & 0XFFFFFFFFFFFFFFFF
        s[3]^=(((s[3]>>10)|(s[3]<<(64-10))) ^ ((s[3]>>17)|(s[3]<<(64-17)))) & 0XFFFFFFFFFFFFFFFF
        s[4]^=(((s[4]>>7)|(s[4]<<(64-7))) ^ ((s[4]>>41)|(s[4]<<(64-41)))) & 0XFFFFFFFFFFFFFFFF

#adds byte padding to plaintext
def pad(data):
    zeros_length=16-(len(data)%16)-1
    padding=b'\x80'+b'\x00'*zeros_length
    return data+padding

def process_associated_data(s,associated_data):
    if (len(associated_data)>0):
        padded_associated_data=pad(associated_data)
        for i in range(0, len(padded_associated_data)//16):
            s[0]^=int.from_bytes(padded_associated_data[16*i:(16*i+8)],'big')
            s[1]^=int.from_bytes(padded_associated_data[16*i+8:(16*i+16)],'big')
            permutation(s,8)
    s[4]^=1

def process_plaintext(s,plaintext):
    ciphertext=b''
    padded_plaintext=pad(plaintext)
    number_of_blocks=len(padded_plaintext)//16
    for i in range(0, number_of_blocks-1):
       s[0]^=int.from_bytes(padded_plaintext[16*i:(16*i+8)],'big')
       s[1]^=int.from_bytes(padded_plaintext[16*i+8:(16*i+16)],'big')
       ciphertext+=s[0].to_bytes(8,'big')
       ciphertext+=s[1].to_bytes(8,'big')
       permutation(s,8)
    
    s[0]^=int.from_bytes(padded_plaintext[16*number_of_blocks-16:(16*number_of_blocks-8)],'big')
    s[1]^=int.from_bytes(padded_plaintext[16*number_of_blocks-8:(16*number_of_blocks)],'big')
    ciphertext+=(s[0].to_bytes(8,'big')+s[1].to_bytes(8,'big'))[0:(len(plaintext)%16)]
    return ciphertext

#xor ciphertext with state(128 bits) and get plaintext, apply permutation, for the last block we do the same thing, but have to pad it first
def process_ciphertext(s,ciphertext):
    plaintext=b''
    number_of_blocks=len(ciphertext)//16
    for i in range(0, number_of_blocks):
        c0=int.from_bytes(ciphertext[16*i:(16*i+8)], 'big')
        c1=int.from_bytes(ciphertext[16*i+8:(16*i+16)], 'big')
        plaintext+=(s[0]^c0).to_bytes(8,'big')+(s[1]^c1).to_bytes(8,'big')
        s[0]=c0
        s[1]=c1
        permutation(s,8)
    #have to test this for zero length ciphertext
    last_block=ciphertext[16*number_of_blocks:]
    last_block_length=len(last_block)
    last_block+=b'\x00'*(16-(len(last_block)))
    c0=s[0]^int.from_bytes(last_block[0:8],'big')
    c1=s[1]^int.from_bytes(last_block[8:16],'big')
    last_plaintext_block=(c0.to_bytes(8,'big')+c1.to_bytes(8,'big'))[0:last_block_length]

    plaintext+=last_plaintext_block
    last_plaintext_block=pad(last_plaintext_block)
    s[0]^=int.from_bytes(last_plaintext_block[0:8],'big')
    s[1]^=int.from_bytes(last_plaintext_block[8:16],'big')
    return plaintext

def finalization(s,key):
    s[2]^=int.from_bytes(key[0:8],'big')
    s[3]^=int.from_bytes(key[8:16],'big')
    permutation(s,12)
    s[3]^=int.from_bytes(key[0:8],'big')
    s[4]^=int.from_bytes(key[8:16],'big')
    return s[3].to_bytes(8,'big')+ s[4].to_bytes(8,'big')

def decrypt(key,nonce, associated_data, ciphertext,tag):
    s=initialization(key,nonce)
    process_associated_data(s,associated_data)
    plaintext=process_ciphertext(s,ciphertext)
    calculated_tag=finalization(s,key)
    if tag==calculated_tag:
        return plaintext
    else:
        print("Authentication failed!")
        return None

def encrypt(key,nonce, plaintext,associated_data):
    s=initialization(key,nonce)
    process_associated_data(s,associated_data)
    ciphertext=process_plaintext(s,plaintext)
    tag=finalization(s,key)
    return ciphertext, tag

def bytes_to_hex(bytes):
    x="{:0"+str(len(bytes)*2)+"x}"
    return x.format(int.from_bytes(bytes,'big'))

def from_hex_to_byte(hex_string):
    return int(hex_string,16).to_bytes(len(hex_string)//2,'big')

#accepts bytes data, converts it to hex and concats it
def data_to_send(associated_data, nonce, ciphertext, tag):
    return associated_data+nonce+ciphertext+tag

#accepts hex-string and converts it to bytes,returns each of required properties
def data_to_retrieve(message, associated_data_length):
    associated_data=message[0:associated_data_length]
    nonce=message[associated_data_length:associated_data_length+16]
    ciphertext=message[associated_data_length+16:-16]
    tag=message[-16:]
    return associated_data,nonce, ciphertext,tag

def generate_random_bytes(size):
    return os.urandom(size)

def timestamped_message(timestamp, message, encoding='utf-8'):
    return str(timestamp).encode(encoding)+message.encode(encoding)

def timestamp_authentication(message, timestamp, key, associated_data_length):
    associated_data,nonce,ciphertext,tag=data_to_retrieve(message, associated_data_length)
    plaintext=decrypt(key,nonce, associated_data, ciphertext,tag)
    notification_message='Auth. fail'
    if plaintext!=None:
        received_timestamp=plaintext[:10]
        if abs(timestamp-int(received_timestamp))<5:
            notification_message='Auth. okay'
        else:
            print("Problem with timestamps! Received timestamp is ", received_timestamp, " but current timestamp is: ", timestamp)
    return plaintext, notification_message


gc.collect()

