#Split PCAP into multiple files based on Source or Destination IP.
#This works well for smaller PCAPs but anything over 100M or so takes too long.


import os
import sys
from datetime import datetime
import scapy.all

startTime = datetime.now()
currentDirectory = '/Users/mafranks/Desktop/National Guard/WOAC'
filename = 'final201.pcap'
targetDirectory = f"splitPCAPs-{filename.split('.')[0]}"
IPCount = 0
etherCount = 0


print('[+] Creating output directory')
if not os.path.exists(f'{currentDirectory}/{targetDirectory}'):
    os.mkdir(f'{currentDirectory}/{targetDirectory}')
    print(f'[+] Output directory {currentDirectory}/{targetDirectory} created')
else:
    print(f'[-] Output directory {currentDirectory}/{targetDirectory} exists')
    sys.exit(f'[-] Please delete {currentDirectory}/{targetDirectory} and try again')

print('[+] Loading PCAP (be patient)')
sTime = datetime.now()
try:
    pcap = scapy.all.rdpcap(f'{currentDirectory}/{filename}')

except Exception as e:
    sys.exit(f'[-] Encountered error: {e}')
eTime = datetime.now()
print(f'[+] It took {eTime-sTime} to load the pcap')

print('[+] Splitting into separate PCAPs')
for packet in pcap:
    try:
        scapy.all.wrpcap(f'{currentDirectory}/{targetDirectory}/{packet.payload.src}.pcap', packet, append=True)  
        scapy.all.wrpcap(f'{currentDirectory}/{targetDirectory}/{packet.payload.dst}.pcap', packet, append=True)
        IPCount += 1
    except:
        etherCount += 1

print('[+] Processing complete')
print(f'[+] Total packets: {IPCount + etherCount}')
print(f'[+] IP packets: {IPCount}')
print(f'[+] Ether packets: {etherCount}')

endTime = datetime.now()
print(f'[+] Processing time {endTime-startTime}')
