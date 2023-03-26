import warnings
warnings.filterwarnings("ignore")
from scapy.all import *


class WireFishSniffer:
    def __init__(self, target_interface=None, packet_filter=None, ):
        self.target_interface = target_interface
        self.packet_filter = packet_filter

    @staticmethod
    def get_network_interfaces(resolve_mac=False, print_result=False):
        return show_interfaces(resolve_mac, print_result)

    @staticmethod
    def sniffer_callback(pkt):
        pkt_info = pkt.show(dump=True).replace(" ", "")
        pkt_info = pkt_info.split("\n")
        print(pkt_info)

    def sniff(self, count=0, store=False, timeout=10):
        return sniff(iface=self.target_interface,
                     count=count,
                     store=store,
                     prn=self.sniffer_callback,
                     filter=self.packet_filter,
                     timeout=timeout)


if __name__ == "__main__":
    sniffer = WireFishSniffer()
    # for index, interface, ip, mac in WireFishSniffer.get_network_interfaces(resolve_mac=True, print_result=False):
    #     print(f"{interface} ||| {ip} ||| {mac}")

    sniffer.target_interface = "Realtek Gaming 2.5GbE Family Controller"
    sniffer.packet_filter = "tcp and ip.src==10.211.2.211"
    pkts = sniffer.sniff(count=1, store=True)
    pkts.show()
