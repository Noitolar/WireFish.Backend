import warnings
import pprint

import scapy.packet

warnings.filterwarnings("ignore")
from scapy.all import *
import utils


class WireFishSniffer:
    def __init__(self, target_interface=None, packet_filter=None):
        self.target_interface = target_interface
        self.packet_filter = packet_filter
        self.packets = None
        self.infos = []
        self.status = "idle"

    @staticmethod
    def get_network_interfaces(resolve_mac=False, print_result=False):
        return show_interfaces(resolve_mac, print_result)

    def flush(self):
        self.infos.clear()
        self.packets = None

    def reset(self):
        self.flush()
        self.status = "idle"
        # if os.path.exists("./tmp/dump.pcap"):
        #     os.remove("./tmp/dump.pcap")

    def sniffer_callback(self, pkt: scapy.packet.Packet):
        info_string = utils.extrac_packet_info(pkt)
        # info_string = f"index={len(self.infos)}\n" + info_string
        self.infos.append(info_string)

    def sniff_realtime(self, count=0, timeout=5):
        self.status = "buzy"
        self.reset()
        self.packets = sniff(
            iface=self.target_interface,
            count=count,
            store=True,
            prn=self.sniffer_callback,
            filter=self.packet_filter,
            timeout=timeout)
        # wrpcap("./tmp/dump.pcap", self.packets)
        self.status = "idle"

    # def sniff_offline(self, ):
    #     self.status = "buzy"
    #     self.flush()
    #     self.packets = sniff(
    #         offline="./tmp/dump.pcap",
    #         store=True,
    #         prn=self.sniffer_callback,
    #         filter=self.packet_filter)
    #     self.status = "idle"

    def get_update(self, num_current):
        return [utils.scapy_str_to_dict(info) for info in self.infos[num_current:]]

    def extract_sessions(self):
        session_indexes = []
        sessions = self.packets.sessions().values()
        for session in sessions:
            session_indexes.append([self.infos.index(utils.extrac_packet_info(pkt)) for pkt in session])
        return session_indexes


if __name__ == "__main__":
    sniffer = WireFishSniffer()
    # for index, interface, ip, mac in WireFishSniffer.get_network_interfaces(resolve_mac=True, print_result=False):
    #     print(f"{interface} ||| {ip} ||| {mac}")

    # sniffer.target_interface = "Realtek Gaming 2.5GbE Family Controller"
    # sniffer.target_interface = "Realtek RTL8852AE WiFi 6 802.11ax PCIe Adapter"
    # sniffer.packet_filter = "ip host 10.211.2.211"

    sniffer.sniff_realtime(200)
    # sniffer.packets.show()
    # print(sniffer.get_update(0))
    # pprint.pprint(utils.scapy_str_to_dict(sniffer.infos[0]))
    print(sniffer.extract_sessions())
