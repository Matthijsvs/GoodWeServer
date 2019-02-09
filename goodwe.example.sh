#to open ports for DNS/DHCP/HTTP we need root access.
#please make this shell script executable and run as root.

#because python cannot send DHCP replies to a MAC address, we need to update the ARP cache.
#create static ARP entry to allow bogus DHCP response.
arp -s 192.168.2.20 AA:BB:CC:DD:EE:FF
#arp -s 192.168.2.21 AA:BB:CC:DD:EE:FF
#arp -s 192.168.2.22 AA:BB:CC:DD:EE:FF

python dhcp.py &
python dns.py &
