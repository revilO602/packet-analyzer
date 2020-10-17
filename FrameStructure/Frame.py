from FrameStructure.Layer3 import Layer3
from FrameStructure.Layer4 import Layer4


def set_layer2_type(bytes):
    if int.from_bytes(bytes[12:14], "big") > 0x600:
        return 'e'
    elif bytes[14:16] == b'\xff\xff':
        return 'r'
    elif bytes[14:15] == b'\xaa':
        return 's'
    else:
        return "l"


class Frame:
    def __init__(self, index, bytes, api_len, protocols):
        self.index = index
        self.bytes = bytes
        self.api_len = api_len
        self.real_len = self.set_real_len()
        self.dmac = bytes[0:6]
        self.smac = bytes[6:12]
        self.layer2_type = None
        self.layer3_protocol = None
        self.layer3 = None
        self.layer4 = None
        self.build(bytes, protocols)

    def set_real_len(self):
        real_len = self.api_len + 4
        if real_len < 64:
            real_len = 64
        return real_len

    # Checks what protocol is used on layer 3 of the frame - ONLY FOR ETHERNET II frames
    def translate_layer3_protocol(self, dict):
        try:
            if self.layer2_type == "e":
                return dict[int.from_bytes(self.layer3_protocol, 'big')]
        except KeyError:
            return False
        return False

    # Translate layer 4 protocol from bytes to string name using a dictionary
    def translate_layer4_prot(self, dict):
        try:
            layer4_protocol = dict[int.from_bytes(self.layer3.layer4_prot, 'big')]
        except KeyError:
            return "Neznamy protokol"
        return layer4_protocol

    # Sets all the attributes using the bytes of the frame TODO pozor na KeyExcept
    def build(self, bytes, protocols):
        self.layer2_type = set_layer2_type(bytes)
        self.set_layer3_protocol(bytes)
        layer3_protocol = self.translate_layer3_protocol(protocols.ethertypes)
        if layer3_protocol == "IPV4" or layer3_protocol == "ARP":
            self.layer3 = Layer3(bytes[14:], layer3_protocol)
            if layer3_protocol == "IPV4":
                layer4_protocol = self.translate_layer4_prot(protocols.ip_protocols)
                if layer4_protocol == "TCP" or layer4_protocol == "UDP" or layer4_protocol == "ICMP":
                    self.layer4 = Layer4(bytes[14 + self.layer3.get_len():], layer4_protocol)

    def print_layer2(self):
        if self.layer2_type == 'e':
            return "Ethernet II"
        elif self.layer2_type == 'r':
            return "802.3 - RAW"
        elif self.layer2_type == 's':
            return "802.3 - SNAP"
        else:
            return "802.3 - LLC"

    # Sets Layer 3 protocol and finds it using the Layer 2 type
    def set_layer3_protocol(self, bytes):
        if self.layer2_type == "e":
            self.layer3_protocol = bytes[12:14]
        if self.layer2_type == "s":
            self.layer3_protocol = bytes[20:22]
        if self.layer2_type == "l":
            self.layer3_protocol = bytes[14:15]

    def print_layer3_protocol(self, protocols):
        if self.layer2_type == "r":
            return "IPX"
        layer3_key = int.from_bytes(self.layer3_protocol, 'big')
        try:
            if self.layer2_type == "e" or self.layer2_type == "s":
                return protocols.ethertypes[layer3_key]
            else:
                return protocols.lsaps[layer3_key]
        except KeyError:
            return "Neznamy protokol"
