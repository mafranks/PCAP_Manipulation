import os
import sys
from datetime import datetime
import scapy.all
import multiprocessing

startTime = datetime.now()
currentDirectory = '/Users/mafranks/Desktop/National Guard/WOAC/Python/Playground'
filename = 'Practical_Application.pcap'
targetDirectory = f"splitPCAPs-{filename.split('.')[0]}"

def process_packet(packet):

    try:
        scapy.all.wrpcap(f'{currentDirectory}/{targetDirectory}/{packet.payload.src}.pcap', packet, append=True)  
        scapy.all.wrpcap(f'{currentDirectory}/{targetDirectory}/{packet.payload.dst}.pcap', packet, append=True)
    except:
        scapy.all.wrpcap(f'{currentDirectory}/{targetDirectory}/{packet.src}.pcap', packet, append=True)
        scapy.all.wrpcap(f'{currentDirectory}/{targetDirectory}/{packet.dst}.pcap', packet, append=True)
print('[+] Creating output directory')
if not os.path.exists(f'{currentDirectory}/{targetDirectory}'):
    os.mkdir(f'{currentDirectory}/{targetDirectory}')
    print(f'[+] Output directory {currentDirectory}/{targetDirectory} created')
else:
    print(f'[-] Output directory {currentDirectory}/{targetDirectory} exists')
    sys.exit(f'[-] Please delete {currentDirectory}/{targetDirectory} and try again')

print('[+] Processing PCAP (be patient)')
try:
    pcap = f'{currentDirectory}/{filename}'
    pool = multiprocessing.Pool()
    for packet in scapy.all.PcapReader(pcap):
        pool.apply_async(process_packet, packet)

except Exception as e:
    sys.exit(f'[-] Encountered error: {e}')

print('[+] Splitting into separate PCAPs')

print('[+] Processing complete')

endTime = datetime.now()
print(f'[+] Processing time {endTime-startTime}')
