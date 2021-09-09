import scapy.all as sc
import optparse

usage = """
'USAGE'
------------------------------------------------
1. python netscanner.py -i <ip/24>
2. python3 netscanner.py -i <ip/24>
3. python netscanner.py --ipaddress <ip/24> 
4. python3 netscanner.py --ipaddress <ip/24>
------------------------------------------------
"""
def get_user_input():
    parse_object = optparse.OptionParser()
    parse_object.add_option("-i","--ipaddress", dest="ip_addr",help="Enter IP Address")

    (user_input,arguments) = parse_object.parse_args()

    if not user_input.ip_addr:
        print(usage)
    return user_input
   
def scanning(ip):
    arp_pack = sc.ARP(pdst=ip)
    broadcast_pack = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_pack = broadcast_pack/arp_pack
    (answered_list,unanswered_list) = sc.srp(combined_pack,timeout=1)
    answered_list.summary()

user_ip_address = get_user_input()
scanning(user_ip_address.ip_addr)

print("\nThanks for using 'net_scanner'")
