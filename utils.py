import re


def get_layer_names(pkt):
    counter = 0
    while counter < 100:
        layer = pkt.getlayer(counter)
        if layer is None:
            break
        else:
            counter += 1
            yield layer.name


def extrac_packet_info(pkt):
    cap_time = pkt.time
    summary = pkt.summary()
    # protocol = " / ".join([x if len(x) < 8 and x.isalnum() else x.split(" ")[0] for x in summary.split(" / ")])
    protocol = " || ".join([name for name in get_layer_names(pkt)])
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
    info_string += f"cap_time={cap_time}\n"
    info_string += f"protocol={protocol}\n"
    info_string += f"src={src}\n"
    info_string += f"dst={dst}\n"
    info_string += f"summary={summary}\n"
    info_string += details

    return info_string


def scapy_str_to_dict(scapy_str):
    infos = scapy_str.split("\n")
    datadict = dict()
    header = None
    for info in infos:
        if info.startswith("###"):
            header = re.sub(u"([^\u0041-\u005a\u0061-\u007a\u0030-\u0039])", "", info)
            datadict[header] = dict()
            continue
        if "=" in info:
            datas = info.split("=")
            key = datas[0].replace("|", "")
            value = "=".join(datas[1:])
            if header is not None:
                datadict[header][key] = value
            else:
                datadict[key] = value
    return datadict
