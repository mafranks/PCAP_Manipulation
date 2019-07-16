#Use with files larger than 100M.  The scapy.all.PcapReader module reads the packets into 
# memory one at a time and then releases them. This makes your computer usable while
# the PCAP is processing vs the rdpcap version which reads the entier pcap into memory.

import os
import sys
from datetime import datetime
import scapy.all
import scapy.utils
import pyshark

startTime = datetime.now()
currentDirectory = '/Users/mafranks/Desktop/National Guard/WOAC/Python/Playground'
filename = 'Practical_Application.pcap'
targetDirectory = f"splitPCAPs-{filename.split('.')[0]}"


def process_packet(pcap):
    IPCount = 0
    etherCount = 0
    for packet in scapy.all.PcapReader(pcap):
        try:
            scapy.all.wrpcap(f'{currentDirectory}/{targetDirectory}/{packet.payload.src}.pcap', packet, append=True)  
            scapy.all.wrpcap(f'{currentDirectory}/{targetDirectory}/{packet.payload.dst}.pcap', packet, append=True)
            IPCount += 1
        except:
            etherCount += 1
    return IPCount, etherCount
print('[+] Creating output directory')
if not os.path.exists(f'{currentDirectory}/{targetDirectory}'):
    os.mkdir(f'{currentDirectory}/{targetDirectory}')
    print(f'[+] Output directory {currentDirectory}/{targetDirectory} created')
else:
    print(f'[-] Output directory {currentDirectory}/{targetDirectory} exists')
    sys.exit(f'[-] Please delete {currentDirectory}/{targetDirectory} and try again')

print('[+] Processing PCAP (be patient)')
sTime = datetime.now()
try:
    pcap = f'{currentDirectory}/{filename}'
    IPCount, etherCount = process_packet(pcap)
except Exception as e:
    sys.exit(f'[-] Encountered error: {e}')
eTime = datetime.now()
print(f'[+] It took {eTime-sTime} to load the pcap')

print('[+] Splitting into separate PCAPs')


print('[+] Processing complete')
print(f'[+] Total packets: {IPCount + etherCount}')
print(f'[+] IP packets: {IPCount}')
print(f'[+] Ether packets: {etherCount}')

endTime = datetime.now()
print(f'[+] Processing time {endTime-startTime}')
