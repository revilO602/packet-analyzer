from tkinter import *
from operator import attrgetter
from scapy.all import *
from IpAddress import IpAddress
from FrameStructure.Frame import Frame
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


# Translate ICMP type byte to string
def get_icmp_type(byte):
    dict = {0: "Echo Reply", 3: "Destination Unreachable", 4: "Source Quench",
            5: "Redirect", 8: "Echo", 9: "Router Advertisement", 10: "Router Selection",
            11: "Time Exceeded", 12: "Parameter Problem", 13: "Timestamp", 14: "Timestamp Reply",
            15: "Information Request", 16: "Information Reply", 17: "Address Mask Request",
            18: "Address Mask Reply", 30: "Traceroute"}
    try:
        return dict[int.from_bytes(byte, 'big')]
    except KeyError:
        return "Unknown ICMP type"


# Print frames attributes to output with formatting and translation of protocol bytes
def print_frame_info(frame, output, protocols):
    output.insert(END, ''.join([str(frame.index) + ". rámec\n", "dĺžka rámca poskytnutá pcap API – ",
                                str(frame.api_len), '\n', "dĺžka rámca prenášaného po médiu - ",
                                str(frame.real_len), '\n', frame.print_layer2(), '\n',
                                "Zdrojová MAC adresa: ", mac_to_str(frame.smac), '\n',
                                "Cieľová MAC adresa: ", mac_to_str(frame.dmac), '\n']))
    output.insert(END, frame.print_layer3_protocol(protocols) + '\n')
    if frame.translate_layer3_protocol(protocols.ethertypes) == "IPV4":
        layer4 = frame.translate_layer4_prot(protocols.ip_protocols)
        output.insert(END, ''.join(["Zdrojová IP adresa: ", ip_to_str(frame.layer3.sip), '\n',
                                    "Cieľová IP adresa: ", ip_to_str(frame.layer3.dip), '\n',
                                    layer4, '\n']))
        if layer4 == "ICMP":
            output.insert(END, get_icmp_type(frame.layer4.icmp_type) + '\n')
        if layer4 == "TCP" or layer4 == "UDP":
            translated_sport = translate_port(frame.layer4.sport, protocols, layer4)
            translated_dport = translate_port(frame.layer4.dport, protocols, layer4)
            if translated_sport:
                output.insert(END, ''.join([translated_sport, '\n']))
            if translated_dport:
                output.insert(END, ''.join([translated_dport, '\n']))
            output.insert(END, ''.join(["Zdrojový port: ", str(int.from_bytes(frame.layer4.sport, 'big')), '\n',
                                        "Cieľový port: ", str(int.from_bytes(frame.layer4.dport, 'big')), '\n']))
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
    if filter == "TFTP":
        tftp_comm(file_reader, output, dicts)
    for api_frame in file_reader:
        i += 1
        frame = Frame(i, raw(api_frame), api_frame.wirelen, dicts)
        if check_filter(frame, dicts, filter):
            print_frame_info(frame, output, dicts)


# Prints one communication stream (list of frames)
def print_comm(comm, comm_number, output, dicts):
    output.insert(END, ''.join(['\n', str(comm_number), ". Komunikácia:\n"]))
    if len(comm.frames) > 20:
        for frame in comm.frames[:10]:
            print_frame_info(frame, output, dicts)
        for frame in comm.frames[-10:]:
            print_frame_info(frame, output, dicts)
    else:
        for frame in comm.frames:
            print_frame_info(frame, output, dicts)


def print_tcp_comms(comms, output, dicts):
    comm_number = 0
    for comm in comms:
        if comm_number == 0:
            output.insert(END, "Úplne komunikácie:\n")
        if comm.handshake_stage == 3 and comm.end_stage == 4:
            comm_number += 1
            print_comm(comm, comm_number, output, dicts)
    comm_number = 0
    for comm in comms:
        if comm.handshake_stage == 3 and not comm.end_stage == 4:
            if comm_number == 0:
                output.insert(END, "Začaté ale neukončené (neúplne) komunikácie:\n")
            comm_number += 1
            print_comm(comm, comm_number, output, dicts)


def tcp_comm(file_reader, output, dicts, filter=''):
    i = 0
    comms = []
    rest = []
    for api_frame in file_reader:
        i += 1
        frame = Frame(i, raw(api_frame), api_frame.wirelen, dicts)
        if (frame.translate_layer3_protocol(dicts.ethertypes) == "IPV4" and
                frame.translate_layer4_prot(dicts.ip_protocols) == "TCP"):
            if not filter or check_filter(frame, dicts, filter):
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
    print_tcp_comms(comms, output, dicts)
    if rest:
        output.insert(END, "Zvyšné rámce (neprebehol three-way handshake):\n")
        for frame in rest:
            print_frame_info(frame, output, dicts)


def print_arp_pair(pair, pair_number, output, dicts):
    output.insert(END, ''.join(["Komunikácia č.", str(pair_number), '\n']))
    for frame in pair.frames:
        if frame.layer3.is_arp_req():
            output.insert(END, ''.join([frame.layer3.get_op(), ", IP adresa: ", ip_to_str(pair.requested_ip),
                                        ", MAC adresa: ???", '\n', "Zdrojová IP: ", ip_to_str(frame.layer3.sip),
                                        ", Cieľová IP: ", ip_to_str(frame.layer3.dip), '\n']))
        else:
            output.insert(END, ''.join([frame.layer3.get_op(), ", IP adresa: ", ip_to_str(pair.requested_ip),
                                        ", MAC adresa: ", mac_to_str(frame.smac), '\n', "Zdrojová IP: ",
                                        ip_to_str(frame.layer3.sip), ", Cieľová IP: ",
                                        ip_to_str(frame.layer3.dip), '\n']))
        print_frame_info(frame, output, dicts)


def print_unpaired_arps(pairs, unpaired, output, dicts):
    output.insert(END, "Zvyšné ARP rámce:\n")
    for pair in pairs:
        for frame in pair.frames:
            unpaired.append(frame)
    unpaired.sort(key=lambda i: i.index)
    for frame in unpaired:
        output.insert(END, frame.layer3.get_op() + '\n')
        print_frame_info(frame, output, dicts)


def arp_pairs(file_reader, dicts, output):
    i = 0
    pair_number = 0
    pairs = []
    unpaired = []
    for api_frame in file_reader:
        i += 1
        frame = Frame(i, raw(api_frame), api_frame.wirelen, dicts)
        if frame.translate_layer3_protocol(dicts.ethertypes) == "ARP":
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
                        print_arp_pair(pair, pair_number, output, dicts)
                        pairs.remove(pair)
                        frame.placed = True
                        break
                if not frame.placed and frame.layer3.is_arp_req():
                    pairs.append(ArpPair(frame))
                elif not frame.placed:
                    unpaired.append(frame)
    if unpaired or pairs:
        print_unpaired_arps(pairs, unpaired, output, dicts)


# Print the TFTP streams, if more than 20 frames, print only first 10 and last 10
def print_tftp_comms(comms, output, dicts):
    comm_number = 0
    for comm in comms:
        comm_number += 1
        print_comm(comm, comm_number, output, dicts)


# Create a list of TFTP streams
def tftp_comm(file_reader, output, dicts):
    comms = []
    i = 0
    for api_frame in file_reader:
        i += 1
        frame = Frame(i, raw(api_frame), api_frame.wirelen, dicts)
        if (frame.translate_layer3_protocol(dicts.ethertypes) == "IPV4" and
                frame.translate_layer4_prot(dicts.ip_protocols)) == "UDP":
            if (translate_port(frame.layer4.sport, dicts, "UDP") == "TFTP" or
                    translate_port(frame.layer4.dport, dicts, "UDP") == "TFTP"):
                comms.append(TftpComm(frame))
            else:
                for comm in comms:
                    comm.check(frame)
    if comms:
        print_tftp_comms(comms, output, dicts)


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
        frame = Frame(i, raw(api_frame), api_frame.wirelen, dicts)
        print_frame_info(frame, output, dicts)
        if frame.translate_layer3_protocol(dicts.ethertypes) == "IPV4":
            new_daddr = frame.layer3.dip
            new_daddr = IpAddress(1, new_daddr)
            add_daddr(ips, new_daddr)
    show_daddrs(ips, output)
