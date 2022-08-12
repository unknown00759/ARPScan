from scapy.all import srp
from scapy.layers.l2 import ARP, Ether
import sys

target_ip = sys.argv[1]
online_ip = []

ether = Ether(dst="ff:ff:ff:ff:ff:ff")
arp = ARP(pdst=target_ip)
probe = ether / arp

result = srp(probe, timeout=3, verbose=0)

answered = result[0]

for send, recv in answered:
    online_ip.append({'ip': recv.psrc, 'mac': recv.hwsrc})

print(" [+] Available Host:")

print("IP"+ " "*20 +"  Mac")

for client in online_ip:
    print('{}\t\t{}'.format(client['ip'], client['mac']))
