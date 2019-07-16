#Split PCAP into multiple files based on Source or Destination IP.
#This works well for smaller PCAPs but anything over 100M or so takes too long.


import os
import sys
import scapy.all
import multiprocessing
from datetime import datetime

startTime = datetime.now()
currentDirectory = '/Users/mafranks/Desktop/National Guard/WOAC'
filename = 'Practical_Application.pcap'
targetDirectory = f"splitPCAPs-{filename.split('.')[0]}"

def process_packet(pcap):
    for packet in pcap[0]:
        print(packet)

print('[+] Creating output directory')
if not os.path.exists(f'{currentDirectory}/{targetDirectory}'):
    os.mkdir(f'{currentDirectory}/{targetDirectory}')
    print(f'[+] Output directory {currentDirectory}/{targetDirectory} created')
else:
    print(f'[-] Output directory {currentDirectory}/{targetDirectory} exists')
    sys.exit(f'[-] Please delete {currentDirectory}/{targetDirectory} and try again')

print('[+] Loading PCAP (be patient)')
try:
    pcap = scapy.all.rdpcap(f'{currentDirectory}/{filename}')
except Exception as e:
    sys.exit(f'[-] Encountered error: {e}')

print('[+] Splitting into separate PCAPs')
pool = multiprocessing.Pool()
pool.map(process_packet, pcap)

print('[+] Processing complete')
endTime = datetime.now()
print(f'[+] Processing time {endTime-startTime}')
