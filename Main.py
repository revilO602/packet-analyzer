import sys
from operator import attrgetter
from scapy.all import *
from IpAddress import IpAddress
from Frame import Frame
from Protocols import Protocols

#TODO zamysliet sa nad monozstvom a velkostou dicts + velkostou kluca - int?

#TODO pridat medzery, mozno returnovat bytes

#TODO mozno C like konstanty/makra namiesto stringou

#TODO printovat nakoniec
def analyse_frame(frame_bytes,dicts):
    frame = Frame(raw(frame_bytes),frame_bytes.wirelen,dicts)
    frame.build()
    frame.print_info()
    print('')
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

def show_daddrs(ips):
    daddr_max = max(ips, key=attrgetter('count'))
    print("IP adresy prijímajúcich uzlov:")
    for ip in ips:
        print(ip.humanize())
    print('')
    print("Adresa uzla s najväčším počtom prijatých paketov:")
    print(daddr_max.humanize(), daddr_max.count,"paketov")


def show_frames(filename):
    frames = rdpcap(filename)
    protocols = Protocols()
    ips = []
    i = 0
    for frame in frames:
        i += 1
        print(str(i) + ". rámec")
        my_frame = analyse_frame(frame, protocols)
        new_daddr = my_frame.daddr
        if new_daddr:
            new_daddr = IpAddress(1, my_frame.daddr)
            add_daddr(ips, new_daddr)
    show_daddrs(ips)





















