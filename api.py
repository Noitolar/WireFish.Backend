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
        self.session_infos = []
        self.status = "idle"

    @staticmethod
    def get_network_interfaces(resolve_mac=False, print_result=False):
        return show_interfaces(resolve_mac, print_result)

    def flush(self):
        self.infos.clear()
        self.packets = None

    def reset(self):
        self.flush()
        # if os.path.exists("./tmp/dump.pcap"):
        #     os.remove("./tmp/dump.pcap")

    def sniffer_callback(self, pkt: scapy.packet.Packet):
        index = len(self.infos)
        cap_time = pkt.time
        summary = pkt.summary()
        protocol = " / ".join([x if len(x) < 8 and x.isalnum() else x.split(" ")[0] for x in summary.split(" / ")])
        details = pkt.show(dump=True).replace(" ", "")

        src = ""
        dst = ""
        if pkt.haslayer("IP"):
            src = pkt["IP"].src
            dst = pkt["IP"].dst
        elif pkt.haslayer("IPv6"):
            src = pkt["IPv6"].src
            dst = pkt["IPv6"].dst
        elif pkt.haslayer("Ethernet"):
            src = pkt["Ethernet"].src
            dst = pkt["Ethernet"].dst

        if pkt.haslayer("TCP"):
            src += f":{pkt['TCP'].sport}"
            dst += f":{pkt['TCP'].dport}"
        elif pkt.haslayer("UDP"):
            src += f":{pkt['UDP'].sport}"
            dst += f":{pkt['UDP'].dport}"

        info_string = ""
        info_string += f"index={index}\n"
        info_string += f"cap_time={cap_time}\n"
        info_string += f"protocol={protocol}\n"
        info_string += f"src={src}\n"
        info_string += f"dst={dst}\n"
        info_string += f"summary={summary}\n"
        info_string += details
        self.infos.append(utils.scapy_str_to_dict(info_string))

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
        sessions = self.packets.sessions()


if __name__ == "__main__":
    sniffer = WireFishSniffer()
    # for index, interface, ip, mac in WireFishSniffer.get_network_interfaces(resolve_mac=True, print_result=False):
    #     print(f"{interface} ||| {ip} ||| {mac}")

    # sniffer.target_interface = "Realtek Gaming 2.5GbE Family Controller"
    # sniffer.target_interface = "Realtek RTL8852AE WiFi 6 802.11ax PCIe Adapter"
    # sniffer.packet_filter = "ip.src==10.211.2.211"
    # sniffer.packet_filter = "ip.src==10.202.40.207"

    sniffer.sniff_realtime(1)
    # sniffer.packets.show()
    # print(sniffer.get_update(0))
    pprint.pprint(sniffer.infos[0])
