import re


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
