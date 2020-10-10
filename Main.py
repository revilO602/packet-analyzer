from tkinter import *
from operator import attrgetter
from scapy.all import *
from IpAddress import IpAddress
from Frame import Frame
from Protocols import Protocols


# TODO zamysliet sa nad monozstvom a velkostou dicts + velkostou kluca - int?

# TODO pridat medzery, mozno returnovat bytes

# TODO mozno C like konstanty/makra namiesto stringou

# TODO printovat nakoniec
def print_info(frame, output):
    output.insert(END, "dĺžka rámca poskytnutá pcap API – " + str(frame.api_len) + '\n' +
                  "dĺžka rámca prenášaného po médiu - " + str(frame.real_len) + '\n' +
                  frame.print_layer2() + '\n' +
                  "Zdrojová MAC adresa: " + frame.smac.hex().upper() + '\n' +
                  "Cieľová MAC adresa: " + frame.dmac.hex().upper() + '\n')
    try:
        output.insert(END, frame.print_layer3_protocol() + '\n')
    except KeyError:
        output.insert(END, "Neznamy Protokol" + '\n')
    if frame.is_eth_ipv4():
        saddr = frame.saddr
        daddr = frame.daddr
        output.insert(END, "Zdrojová IP adresa: " + '.'.join(
            [str(saddr[0]), str(saddr[1]), str(saddr[2]), str(saddr[3])]) + '\n' +
            "Cieľová IP adresa: " + '.'.join(
            [str(daddr[0]), str(daddr[1]), str(daddr[2]), str(daddr[3])]) + '\n' +
            frame.protocols.ip_protocols[int.from_bytes(frame.layer4_protocol, 'big')] + '\n')
    output.insert(END, frame.print_frame() + "\n\n")


def analyse_frame(frame_bytes, dicts, output):
    frame = Frame(raw(frame_bytes), frame_bytes.wirelen, dicts)
    frame.build()
    print_info(frame, output)
    return frame


def add_daddr(ips, new_daddr):
    if ips:
        new = 1
        for ip in ips:
            if new_daddr.bytes == ip.bytes:
                ip.count += 1
                new = 0
                break
        if new:
            ips.append(new_daddr)
    else:
        ips.append(new_daddr)


def show_daddrs(ips, output):
    output.insert(END, "IP adresy prijímajúcich uzlov:\n")
    for ip in ips:
        output.insert(END, ip.humanize() + '\n')
    output.insert(END, "Adresa uzla s najväčším počtom prijatých paketov:\n")
    daddr_max = max(ips, key=attrgetter('count'))
    output.insert(END, daddr_max.humanize() + " " + str(daddr_max.count) + " paketov\n")


def show_frames(filename, output):
    frames_reader = PcapReader(filename)
    protocols = Protocols()
    ips = []
    i = 0
    for frame in frames_reader:
        i += 1
        output.insert(END, str(i) + ". rámec\n")
        my_frame = analyse_frame(frame, protocols, output)
        new_daddr = my_frame.daddr
        if new_daddr:
            new_daddr = IpAddress(1, new_daddr)
            add_daddr(ips, new_daddr)
    show_daddrs(ips, output)
