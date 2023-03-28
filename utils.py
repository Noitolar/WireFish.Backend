import re


def scapy_str_to_dict(scapy_str):
    infos = scapy_str.replace(" ", "").split("\n")
    datadict = dict()
    header = None
    for info in infos:
        if info.startswith("###"):
            header = re.sub(u"([^\u0041-\u005a\u0061-\u007a\u0030-\u0039])", "", info)
            datadict[header] = dict()
            continue
        if "=" in info and header is not None:
            datas = info.split("=")
            key = datas[0]
            value = "=".join(datas[1:])
            datadict[header][key] = value
    return datadict
