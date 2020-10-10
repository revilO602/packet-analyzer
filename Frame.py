#import Protocols from Protocols

class Frame:
    def __init__(self, bytes, api_len, protocols):
        self.protocols = protocols
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
        self.sport = None
        self.dport = None

    def set_real_len(self):
        real_len = self.api_len + 4
        if real_len < 64:
            real_len = 64
        return real_len

    # Checks whether frame is Ethernet II and IPv4, since we only analyze those deeper
    def is_eth_ipv4(self):
        if (self.layer2_type == "eth" and
                self.protocols.ethertypes[int.from_bytes(self.layer3_protocol, 'big')] == "IPv4"):
            return True
        return False

    def build(self):
        self.layer2_type = self.get_layer2_type()
        self.set_layer3_protocol()
        if self.is_eth_ipv4():
            self.set_layer4_protocol()
            self.set_daddr()
            self.set_saddr()
            self.set_sport()
            self.set_dport()


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

    def print_layer2(self):
        if self.layer2_type == "eth":
            return "Ethernet II"
        elif self.layer2_type == "raw":
            return "802.3 - RAW"
        elif self.layer2_type == "snap":
            return "802.3 - SNAP"
        else:
            return "802.3 - LLC"


    def set_layer3_protocol(self):
        if self.layer2_type == "eth":
            self.layer3_protocol = self.bytes[12:14]
        elif self.layer2_type == "raw":
            self.layer3_protocol = b'\xe0' #TODO jaajjaja
        elif self.layer2_type == "snap":
            self.layer3_protocol = self.bytes[20:22]
        else:
            self.layer3_protocol = self.bytes[14:15]

    def print_layer3_protocol(self):
        layer3_key = int.from_bytes(self.layer3_protocol,'big')
        if self.layer2_type == "raw":
            return "IPX"
        elif self.layer2_type == "eth" or self.layer2_type == "snap":
            return self.protocols.ethertypes[layer3_key]
        else:
            return self.protocols.lsaps[layer3_key]

    def set_saddr(self):
        self.saddr = self.bytes[26:30]

    def set_daddr(self):
        self.daddr = self.bytes[30:34]

    #Sets layer 4 protocol, but only for Ethernet II - IPv4 packets
    def set_layer4_protocol(self):
        self.layer4_protocol = self.bytes[23:24]

    def set_sport(self):
        self.sport = self.bytes[34:36]

    def set_dport(self):
         self.dport = self.bytes[36:38]

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
        return frame_formatted_str


