from tkinter import *
from operator import attrgetter
from scapy.all import *
from IpAddress import IpAddress
from FrameStructure.NetFrame import NetFrame
from CommunicationStreams.ArpPair import ArpPair
from CommunicationStreams.TcpComm import TcpComm
from CommunicationStreams.TftpComm import TftpComm


# Transform IP in bytes to standard decimal notation string
def ip_to_str(ip_bytes):
    return '.'.join(str(ip_bytes[i]) for i in range(0, 4))


# Transform MAC address in bytes to formatted string
def mac_to_str(mac_bytes):
    mac_str = mac_bytes.hex().upper()
    return ' '.join(mac_str[i:i + 2] for i in range(0, len(mac_str), 2))


# Return a string with all the bytes in the frame in a readable format
def bytes_to_formatted_string(bytes):
    str = bytes.hex().upper()
    i = 0
    formatted_str = ''
    for c in str:
        formatted_str += c
        i += 1
        if i == 32:
            i = 0
            formatted_str += '\n'
        elif i % 2 == 0:
            formatted_str += ' '
    return formatted_str


def print_layer3(frame, output, protocols):
    output.insert(END, ''.join(["Zdrojová IP adresa: ", ip_to_str(frame.layer3.sip), '\n',
                                "Cieľová IP adresa: ", ip_to_str(frame.layer3.dip), '\n',
                                frame.translate_layer4_prot(protocols.ip_protocols), '\n']))


def print_layer4(frame, output, protocols, tftp=False):
    layer4 = frame.translate_layer4_prot(protocols.ip_protocols)
    if layer4 == "ICMP":
        output.insert(END, frame.layer4.get_icmp_type() + '\n')
    elif layer4 == "TCP" or layer4 == "UDP":
        if tftp:
            output.insert(END, "TFTP\n")
        else:
            translated_sport = translate_port(frame.layer4.sport, protocols, layer4)
            translated_dport = translate_port(frame.layer4.dport, protocols, layer4)
            if translated_sport:
                output.insert(END, ''.join([translated_sport, '\n']))
            elif translated_dport:
                output.insert(END, ''.join([translated_dport, '\n']))
        output.insert(END, ''.join(["Zdrojový port: ", str(int.from_bytes(frame.layer4.sport, 'big')), '\n',
                                    "Cieľový port: ", str(int.from_bytes(frame.layer4.dport, 'big')), '\n']))


# Print frames attributes to output with formatting and translation of protocol bytes
def print_frame_info(frame, output, protocols, tftp=False):
    output.insert(END, ''.join([str(frame.index) + ". rámec\n", "dĺžka rámca poskytnutá pcap API – ",
                                str(frame.api_len), '\n', "dĺžka rámca prenášaného po médiu - ",
                                str(frame.real_len), '\n', frame.print_layer2(), '\n',
                                "Zdrojová MAC adresa: ", mac_to_str(frame.smac), '\n',
                                "Cieľová MAC adresa: ", mac_to_str(frame.dmac), '\n']))
    output.insert(END, frame.print_layer3_protocol(protocols) + '\n')
    if frame.translate_layer3_protocol(protocols.ethertypes) == "IPV4":
        layer4 = frame.translate_layer4_prot(protocols.ip_protocols)
        print_layer3(frame, output, protocols)
        if layer4 == "ICMP" or layer4 == "TCP" or layer4 == "UDP":
            print_layer4(frame, output, protocols, tftp)
    output.insert(END, bytes_to_formatted_string(frame.bytes) + "\n\n")


# Translate TCP or UDP port from bytes to string if well-known
def translate_port(port_bytes, dict, layer4):
    if port_bytes:
        port_int = int.from_bytes(port_bytes, 'big')
        try:
            if layer4 == "TCP":
                return dict.tcp_ports[port_int].upper()
            if layer4 == "UDP":
                return dict.udp_ports[port_int].upper()
        except KeyError:
            return False


# Checks whether the frame fits the filter
def check_filter(frame, dicts, filter):
    if frame.translate_layer3_protocol(dicts.ethertypes) == filter:
        return True
    elif frame.translate_layer3_protocol(dicts.ethertypes) == "IPV4":
        layer4_prot = frame.translate_layer4_prot(dicts.ip_protocols)
        if layer4_prot == filter:
            return True
        elif layer4_prot == "TCP" or layer4_prot == "UDP":
            trans_sport = translate_port(frame.layer4.sport, dicts, layer4_prot)
            trans_dport = translate_port(frame.layer4.dport, dicts, layer4_prot)
            if trans_sport == filter or trans_dport == filter:
                return True
            elif (filter == "FTP" and (trans_sport == "FTP CONTROL" or trans_sport == "FTP DATA" or
                                       trans_dport == "FTP CONTROL" or trans_dport == "FTP DATA")):
                return True


# Displays the frames with an applied filter
def filter_frames(file_reader, dicts, output, filter):
    i = 0
    rip_amount = 0
    if filter == "TFTP":
        tftp_comm(file_reader, output, dicts)
    for api_frame in file_reader:
        i += 1
        frame = NetFrame(i, raw(api_frame), api_frame.wirelen, dicts)
        if check_filter(frame, dicts, filter):
            print_frame_info(frame, output, dicts)
            if filter == "RIP":
                rip_amount += 1
    if filter == "RIP":
        output.insert(END, "Počet RIP rámcov je:\n" + str(rip_amount))


# Prints one communication stream (list of frames) - used for tftp and tcp streams
def print_comm(comm, comm_number, output, dicts, tftp=False):
    output.insert(END, ''.join(['\n', str(comm_number), ". Komunikácia:\n"]))
    if len(comm.frames) > 20:
        for frame in comm.frames[:10]:
            print_frame_info(frame, output, dicts, tftp)
        for frame in comm.frames[-10:]:
            print_frame_info(frame, output, dicts, tftp)
    else:
        for frame in comm.frames:
            print_frame_info(frame, output, dicts, tftp)


# Print complete streams and open-ended streams after
def print_tcp_comms(comms, output, dicts, one_comm=False):
    comm_number = 0
    for comm in comms:
        if comm.handshake_stage == 3 and comm.end_stage == 4:
            if comm_number == 0:
                output.insert(END, "Úplne komunikácie:\n")
            comm_number += 1
            print_comm(comm, comm_number, output, dicts)
            if one_comm:
                break
    comm_number = 0
    for comm in comms:
        if comm.handshake_stage == 3 and not comm.end_stage == 4:
            if comm_number == 0:
                output.insert(END, "Začaté ale neukončené (neúplne) komunikácie:\n")
            comm_number += 1
            print_comm(comm, comm_number, output, dicts)
            if one_comm:
                break


# Add a TCP frame where it belongs (to open stream or open new stream or put into rest[] if no SYN flag)
def add_tcp_comm(frame, comms, rest):
    if not comms:
        if frame.layer4.is_3wh_start():
            comms.append(TcpComm(frame))
        else:
            rest.append(frame)
    else:
        frame.placed = False
        for comm in comms:
            if comm.end_stage < 4 and comm.belongs(frame):
                frame.placed = True
        if not frame.placed and frame.layer4.is_3wh_start():
            comms.append(TcpComm(frame))
        elif not frame.placed:
            rest.append(frame)


# Create a list of TCP streams and print them out
def tcp_comm(file_reader, output, dicts, filter='', one_comm=False):
    i = 0
    comms = []
    rest = []
    for api_frame in file_reader:
        i += 1
        frame = NetFrame(i, raw(api_frame), api_frame.wirelen, dicts)
        if (frame.translate_layer3_protocol(dicts.ethertypes) == "IPV4" and
                frame.translate_layer4_prot(dicts.ip_protocols) == "TCP"):
            if not filter or check_filter(frame, dicts, filter):
                add_tcp_comm(frame, comms, rest)
    print_tcp_comms(comms, output, dicts, one_comm)
    if not one_comm:
        for comm in comms:
            if comm.handshake_stage < 3:
                for frame in comm.frames:
                    rest.append(frame)
        if rest:
            output.insert(END, "Zvyšné rámce (neprebehol three-way handshake):\n")
            rest.sort(key=lambda j: j.index)
            for frame in rest:
                print_frame_info(frame, output, dicts)


# Print one ARP frame
def print_arp(frame, output, dicts):
    if frame.layer3.is_arp_req():
        output.insert(END, ''.join([frame.layer3.get_op(), ", IP adresa: ", ip_to_str(frame.layer3.dip),
                                    ", MAC adresa: ???", '\n', "Zdrojová IP: ", ip_to_str(frame.layer3.sip),
                                    ", Cieľová IP: ", ip_to_str(frame.layer3.dip), '\n']))
    else:
        output.insert(END, ''.join([frame.layer3.get_op(), ", IP adresa: ", ip_to_str(frame.layer3.sip),
                                    ", MAC adresa: ", mac_to_str(frame.smac), '\n', "Zdrojová IP: ",
                                    ip_to_str(frame.layer3.sip), ", Cieľová IP: ",
                                    ip_to_str(frame.layer3.dip), '\n']))
    print_frame_info(frame, output, dicts)


# Transfer unfinished pairs to one list, sort them by frame index and print them
def print_unpaired_arps(pairs, unpaired, output, dicts):
    output.insert(END, "Zvyšné ARP rámce:\n")
    for pair in pairs:
        for frame in pair.frames:
            unpaired.append(frame)
    unpaired.sort(key=lambda i: i.index)
    for frame in unpaired:
        print_arp(frame, output, dicts)


# Add the ARP frame where it belongs (reply to request, request to request, new pair etc.)
def add_arp_frame(frame, pairs, unpaired, pair_number, output, dicts):
    if not pairs:
        if frame.layer3.is_arp_req():
            pairs.append(ArpPair(frame))
        else:
            unpaired.append(frame)
    else:
        frame.placed = False
        for pair in pairs:
            if pair.is_reply(frame):
                pair_number += 1
                output.insert(END, ''.join(["Komunikácia č.", str(pair_number), '\n']))
                for frame in pair.frames:
                    print_arp(frame, output, dicts)
                pairs.remove(pair)
                frame.placed = True
                break
        if not frame.placed and frame.layer3.is_arp_req():
            pairs.append(ArpPair(frame))
        elif not frame.placed:
            unpaired.append(frame)


# Create a list of ARP pairs and print them out
def arp_pairs(file_reader, dicts, output):
    i = 0
    pair_number = 0
    pairs = []
    unpaired = []
    for api_frame in file_reader:
        i += 1
        frame = NetFrame(i, raw(api_frame), api_frame.wirelen, dicts)
        if frame.translate_layer3_protocol(dicts.ethertypes) == "ARP":
            add_arp_frame(frame, pairs, unpaired, pair_number, output, dicts)
    if unpaired or pairs:
        print_unpaired_arps(pairs, unpaired, output, dicts)


# Create a list of TFTP streams and print them out
def tftp_comm(file_reader, output, dicts):
    comms = []
    i = 0
    for api_frame in file_reader:
        i += 1
        frame = NetFrame(i, raw(api_frame), api_frame.wirelen, dicts)
        if (frame.translate_layer3_protocol(dicts.ethertypes) == "IPV4" and
                frame.translate_layer4_prot(dicts.ip_protocols)) == "UDP":
            if (translate_port(frame.layer4.sport, dicts, "UDP") == "TFTP" or
                    translate_port(frame.layer4.dport, dicts, "UDP") == "TFTP"):
                comms.append(TftpComm(frame))
            else:
                for comm in comms:
                    comm.check(frame)
    if comms:
        comm_number = 0
        for comm in comms:
            comm_number += 1
            print_comm(comm, comm_number, output, dicts, True)


# Add unique address or increment count
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


# Print all the destination IP addresses to output
def show_daddrs(ips, output):
    output.insert(END, "IP adresy prijímajúcich uzlov:\n")
    for ip in ips:
        output.insert(END, ip_to_str(ip.bytes) + '\n')
    output.insert(END, "Adresa uzla s najväčším počtom prijatých paketov:\n")
    daddr_max = max(ips, key=attrgetter('count'))
    output.insert(END, ' '.join([ip_to_str(daddr_max.bytes), str(daddr_max.count), "paketov\n"]))


# Function that displays all the frames with IP destination addresses at the end
def show_frames(file_reader, dicts, output):
    ips = []
    i = 0
    for api_frame in file_reader:
        i += 1
        frame = NetFrame(i, raw(api_frame), api_frame.wirelen, dicts)
        print_frame_info(frame, output, dicts)
        if frame.translate_layer3_protocol(dicts.ethertypes) == "IPV4":
            new_daddr = frame.layer3.dip
            new_daddr = IpAddress(1, new_daddr)
            add_daddr(ips, new_daddr)
    show_daddrs(ips, output)
