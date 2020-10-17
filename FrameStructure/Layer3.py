class Layer3:
    def __init__(self, bytes, type):
        if type == "ARP":
            self.op = bytes[6:8]
            self.smac = bytes[8:14]
            self.sip = bytes[14:18]
            self.dmac = bytes[18:24]
            self.dip = bytes[24:28]
        elif type == "IPV4":
            self.ihl = bytes[0:1]
            self.fragment = bytes[6:8]
            self.layer4_prot = bytes[9:10]
            self.sip = bytes[12:16]
            self.dip = bytes[16:20]

    # For IPV4 returns header length
    def get_len(self):
        return (int.from_bytes(self.ihl, 'big') % 16) * 4

    def is_arp_req(self):
        if self.op == b'\x00\x01':
            return True
        return False

    # For ARP returns returns operation as string
    def get_op(self):
        if self.op == b'\x00\x01':
            return "ARP-Request"
        elif self.op == b'\x00\x02':
            return "ARP-Reply"
        return str(self.op)