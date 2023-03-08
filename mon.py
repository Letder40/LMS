import time
import subprocess
import re
import threading

#global
bucle = 0

#set a counter of 8 secs
counter = 0
def set_timer():
    while (True):
        time.sleep(1)
        global counter
        global bucle
        counter += 1
        if(counter == 8):
            counter = 0
            bucle += 1
            print(bucle)

# Layer 2 arp spoofing
def detect_arp_spoofing():
    macs = []
    output = subprocess.check_output(['arp', '-a'])
    output = output.decode("utf-8")
    output = output.split(" ")
    
    for i in output:
        if (re.match(r"[0-9a-z][0-9a-z]:", i) != None):
            macs.append(i)
    
    for mac in macs:
        counter = 0
        for mac_tocompare in macs:
            if(counter != 0 and mac == mac_tocompare):
                print("mac %s has been clonned" % mac)
                

#def icmp_flood_detect(): 
if __name__ == "__main__":
    threading.Thread(target=set_timer())
    
        
    