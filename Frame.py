
class Frame:
    def __init__(self,bytes,api_len,dicts):
        self.dicts = dicts
        self.api_len = api_len
        self.real_len = self.set_real_len()
        self.bytes = bytes
        self.dmac = bytes[0:6]
        self.smac = bytes[6:12]
        self.layer2_type = None
        self.layer3_protocol = None
        self.layer4_protocol = None
        self.saddr = None
        self.daddr = None

    def set_real_len(self):
        real_len = self.api_len + 4
        if real_len < 64:
            real_len = 64
        return real_len

    # Checks whether frame is Ethernet II and IPv4, since we only analyze those deeper
    def is_eth_ipv4(self):
        if (self.layer2_type == "eth" and
                self.dicts[0][int.from_bytes(self.layer3_protocol, 'big')] == "IPv4"):
            return True
        return False

    def build(self):
        self.layer2_type = self.get_layer2_type()
        self.set_layer3_protocol()
        if self.is_eth_ipv4():
            self.set_layer4_protocol()



    def get_layer2_type(self):
        ETHERNET_LIMIT = 0x600
        RAW = b'\xff\xff'
        SNAP = b'\xaa'

        if int.from_bytes(self.bytes[12:14], "big") > ETHERNET_LIMIT:
            return "eth"
        elif self.bytes[14:16] == RAW:
            return "raw"
        elif self.bytes[14:15] == SNAP:
            return "snap"
        else:
            return "llc"

    def print_len(self):
        print("dĺžka rámca poskytnutá pcap API –", str(self.api_len))
        print("dĺžka rámca prenášaného po médiu - " + str(self.real_len))

    def print_layer2(self):
        if self.layer2_type == "eth":
            print("Ethernet II")
        elif self.layer2_type == "raw":
            print("802.3 - RAW")
        elif self.layer2_type == "snap":
            return "802.3 - SNAP"
        else:
            return "802.3 - LLC"


    def set_layer3_protocol(self):
        if self.layer2_type == "eth":
           self.layer3_protocol = self.bytes[12:14]
        elif self.layer2_type == "raw":
            self.layer3_protocol = b'\xe0'
        elif self.layer2_type == "snap":
            self.layer3_protocol = self.bytes[20:22]
        else:
            self.layer3_protocol = self.bytes[14:15]

    def get_saddr(self):
        if self.check():
            return self.bytes[26:30]
        return False

    def get_daddr(self):
        if self.check():
            return self.bytes[30:34]
        return False

    def get_layer4_protocol(self):
        return self.bytes[23]

    # def get_layer3_protocol(self):
    #     if int.from_bytes(self.bytes[12:14], "big") > 0x600:
    #         return self.bytes[12:14]
    #     elif self.bytes[14:16] == b'\xff\xff':
    #         return b'\xe0'
    #     elif self.bytes[14:15] == b'\xaa':
    #         return self.bytes[20:22]
    #     else:
    #         return self.bytes[14:15]

    #Sets layer 4 protocol, but only for Ethernet II - IPv4 packets
    def set_layer4_protocol(self):
        self.layer4_protocol = self.bytes[23]

    def get_sport(self):
        if self.check():
            return self.bytes[34:36]
        return False

    def get_dport(self):
        if self.check():
            return self.bytes[36:38]
        return False

    def print_frame(self):
        frame_str = self.bytes.hex().upper()
        i = 0
        frame_formatted_str = ''
        for c in frame_str:
            frame_formatted_str += c
            i += 1
            if i == 32:
                i = 0
                frame_formatted_str += '\n'
            elif i % 2 == 0:
                frame_formatted_str += ' '
        print(frame_formatted_str)


    def print_info(self):

        print(self.get_layer2_type())
        print("Zdrojová MAC adresa:", self.smac.hex().upper())
        print("Cieľová MAC adresa:", self.dmac[0:6].hex().upper())
        layer3_key = int.from_bytes(self.get_layer3_protocol(), 'big')
        print(self.dicts[0][layer3_key])
        if int.from_bytes(self.layer3_protocol, 'big') == 0x0800:
            saddr = self.get_saddr()
            daddr = self.get_daddr()
            print("Zdrojová IP adresa:", '.'.join([str(saddr[0]), str(saddr[1]), str(saddr[2]), str(saddr[3])]))
            print("Cieľová IP adresa:", '.'.join([str(daddr[0]), str(daddr[1]), str(daddr[2]), str(daddr[3])]))
            print(self.dicts[1][self.get_layer4_protocol()])
        self.print_frame()
