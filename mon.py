import time
import subprocess
import os
import sys
import re
import threading
from scapy.all import *
import requests


#global
token = open("./LMS.cfg").readlines()[0].split("=")[1].strip()
chatID = open("./LMS.cfg").readlines()[1].split("=")[1].strip()
bucle = 0
icmp_buffer = []
tcp_scan_buffer = []
tcp_flood_buffer = []
icmp_attack_counter = 0
tcp_scan_counter = 0
    #set a counter of 8 secs
counter = 0

#utils
def get_own_ipaddr():
    interface = subprocess.check_output(['ip', 'route']).decode("utf-8").split(" ")[4]
    output = subprocess.check_output(['ip', 'addr', 'show', "dev", interface]).decode("utf-8")
    regex = re.compile("[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}/[0-9]{1,2}")
    ipaddr = re.findall(regex, output)[0]
    ipaddr = re.findall("[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}", ipaddr)[0]
    global local_ipaddr
    return(ipaddr)


def set_timer():
    while (True):
        time.sleep(1)
        global counter
        global bucle
        global icmp_buffer
        global tcp_scan_buffer
        global tcp_flood_buffer
        counter += 1
        if(counter == 8):
            counter = 0
            icmp_buffer = []
            tcp_scan_buffer = []
            tcp_flood_buffer = []
            bucle += 1

def bot_send_message(message):
    global token
    global chatID
    bot_token = token
    bot_chatID = chatID
    send_text = "https://api.telegram.org/bot{bot_token}/sendMessage?chat_id={bot_chatID}&parse_mode=Markdown&text={message}".format(bot_token=token, bot_chatID=bot_chatID, message=message)

    response = requests.get(send_text)


# detecting attacks

# Layer 4 tcp_scan
def detect_tcp_scan(pkt):
    global tcp_scan_buffer
    global tcp_scan_counter
    if pkt[IP].src != get_own_ipaddr() :
        flags = pkt[TCP].flags
        for flag in flags :
            if flag == "S":
                tcp_scan_buffer.append(pkt[IP].src)

        counter = 0
        for ip in tcp_scan_buffer:
            if ip != get_own_ipaddr() :
                counter += 1

        if counter == 60:
            tcp_scan_buffer = []
            bot_send_message(" [!] the host with ip address %s is scanning you" % pkt[IP].src)
        
# Layer 4 tcp_flood
def detect_tcp_flood(pkt):
    global tcp_flood_buffer
    attack = ""
    if pkt[IP].src != get_own_ipaddr() and pkt[TCP].dport < 32000 :
        attack = "{ip_src} -> {port_dst}".format(ip_src=pkt[IP].src, port_dst=pkt[TCP].dport)
        tcp_flood_buffer.append(attack)    
    
    counter = 0
    for i in tcp_flood_buffer:
        if i == attack:
            counter += 1

    if counter == 45:
        bot_send_message("[!] {ip_src} is flooding your port {port_dst}".format(ip_src=pkt[IP].src, port_dst=pkt[TCP].dport))       
        

# Layer 3 icmp_flood
def detect_icmp_flood(pkt):    
   global icmp_buffer    
   global icmp_attack_counter
   icmp_addr_src = pkt[IP].src 
   
   if icmp_addr_src != get_own_ipaddr():
        icmp_buffer.append(icmp_addr_src)
        counter = 0
        
        for address in icmp_buffer:
            if address == icmp_addr_src :
                counter += 1
        
        if counter == 7:
            icmp_attack_counter += 1
        if icmp_attack_counter == 3:
            bot_send_message(" [!] the host with ip address %s is icmp flooding you" % pkt[IP].src)
            icmp_attack_counter = 0


# Layer 2 arp spoofing
def detect_arp_spoofing():
    while True:
        macs = []
        output = subprocess.check_output(['arp', '-a'])
        output = output.decode("utf-8")
        output = output.split(" ")

        for i in output:
            if (re.match(r"[0-9a-z][0-9a-z]:[0-9a-z][0-9a-z]:[0-9a-z][0-9a-z]:", i) != None):
                macs.append(i)

        for mac in macs:
            counter = 0
            for mac_tocompare in macs:
                if(counter != 0 and mac == mac_tocompare):
                    bot_send_message("[!] mac {mac} has been clonned".format(mac=mac))
        time.sleep(8)
                

#def icmp_flood_detect(): 
if __name__ == "__main__":
    thread1 = threading.Thread(target=set_timer)
    thread2 = threading.Thread(target=detect_arp_spoofing)
    thread3 = threading.Thread(target=sniff, kwargs={"prn": detect_icmp_flood, "filter": "icmp"})
    thread4 = threading.Thread(target=sniff, kwargs={"prn": detect_tcp_scan, "filter": "tcp"})
    thread5 = threading.Thread(target=sniff, kwargs={"prn": detect_tcp_flood, "filter": "tcp"})

    thread1.start()
    thread2.start()
    thread3.start()
    thread4.start()
    thread5.start()
    
        
    