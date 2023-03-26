import warnings

warnings.filterwarnings("ignore")
from scapy.all import *
import os


class WireFishSniffer:
    def __init__(self, target_interface=None, packet_filter=None):
        self.target_interface = target_interface
        self.packet_filter = packet_filter
        self.packet_dump = None
        self.packet_info_dump = []
        self.status = "idle"

    @staticmethod
    def get_network_interfaces(resolve_mac=False, print_result=False):
        return show_interfaces(resolve_mac, print_result)

    def flush(self):
        self.packet_info_dump.clear()
        self.packet_dump = None

    def reset(self):
        self.flush()
        if os.path.exists("./tmp/dump.pcap"):
            os.remove("./tmp/dump.pcap")

    def sniffer_callback(self, pkt):
        self.packet_info_dump.append(pkt.show(dump=True).replace(" ", ""))

    def sniff_realtime(self, count=0, timeout=5):
        self.status = "buzy"
        self.reset()
        self.packet_dump = sniff(
            iface=self.target_interface,
            count=count,
            store=True,
            prn=self.sniffer_callback,
            filter=self.packet_filter,
            timeout=timeout)
        wrpcap("./tmp/dump.pcap", self.packet_dump)
        self.status = "idle"

    def sniff_offline(self, ):
        self.status = "buzy"
        self.flush()
        self.packet_dump = sniff(
            offline="./tmp/dump.pcap",
            store=True,
            prn=self.sniffer_callback,
            filter=self.packet_filter)
        self.status = "idle"

    def get_update(self, num_current):
        return "@@@@@@@@".join(self.packet_info_dump[num_current:])


if __name__ == "__main__":
    sniffer = WireFishSniffer()
    # for index, interface, ip, mac in WireFishSniffer.get_network_interfaces(resolve_mac=True, print_result=False):
    #     print(f"{interface} ||| {ip} ||| {mac}")

    sniffer.target_interface = "Realtek Gaming 2.5GbE Family Controller"
    sniffer.packet_filter = "tcp"
    sniffer.sniff_realtime(5)
    sniffer.packet_dump.show()

    # sniffer.sniff_offline()
    # sniffer.packet_dump.show()
