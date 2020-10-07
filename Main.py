import sys
from operator import attrgetter
from scapy.all import *
from IpAddress import IpAddress
from Frame import Frame

# file_path = input("Enter file path:")
# pouzit pathlib na otvorenie filu alebo os.path
frames = rdpcap('pcap_files\eth-1.pcap')

#TODO zamysliet sa nad monozstvom a velkostou dicts + velkostou kluca - int?
def make_dict(filename):
    new_dict = {}
    with open(filename,"r") as f:
        for line in f:
            key,value = line.split()
            new_dict[int(key,base=16)] = value
        return new_dict

def make_dicts():
    dicts = [make_dict("layer3_protocols.txt"),
             make_dict("layer4_protocols.txt"),
             make_dict("ports.txt")]
    return dicts

#TODO pridat medzery, mozno returnovat bytes

#TODO mozno C like konstanty/makra namiesto stringou




#TODO printovat nakoniec
def analyse_frame(frame_bytes,dicts):
    frame = Frame(raw(frame_bytes),frame_bytes.wirelen,dicts)
    frame.print_info()
    return frame

dicts = make_dicts()
ips = []
i = 0
for frame in frames:
    i += 1
    print(str(i) + ". rámec")
    my_frame = analyse_frame(frame,dicts)
    new_daddr = IpAddress(1,my_frame.get_daddr())
    if ips:
        new = 1
        for ip in ips:
            if new_daddr.bytes == ip.bytes:
                ip.count += 1
                new = 0
                break
        if new:
            ips.append(new_daddr)
    else :
        ips.append(new_daddr)
    print('')
daddr_max = max(ips, key=attrgetter('count'))
print("IP adresy prijímajúcich uzlov:")
for ip in ips:
    print(ip.humanize())
print("Adresa uzla s najväčším počtom prijatých paketov:")
print(daddr_max.humanize(), daddr_max.count,"paketov")

#frame=raw(frames[0])
#print(frame[12:14])
#print(int.from_bytes(frame[12:14],"big"))



















