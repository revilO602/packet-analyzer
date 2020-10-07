
class Frame:
    def __init__(self,bytes,api_len,dicts):
        self.bytes = bytes
        self.api_len = api_len
        self.dicts = dicts
        self.real_len = self.set_real_len()
        self.dmac = bytes[0:6]
        self.smac = bytes[6:12]
        self.layer3_protocol = self.get_layer3_protocol()

    def set_real_len(self):
        real_len = self.api_len + 4
        if real_len < 64:
            real_len = 64
        return real_len

    def get_layer2_type(self):
        if int.from_bytes(self.bytes[12:14], "big") > 0x600:
            return "Ethernet II"
        elif self.bytes[14:16] == '\xff\xff':
            return "802.3 - RAW"
        elif self.bytes[14] == '\xaa':
            return "802.3 - SNAP"
        else:
            return "802.3 - LLC"

    def get_layer3_protocol(self):
        if int.from_bytes(self.bytes[12:14], "big") > 0x600:
            return self.bytes[12:14]
        elif self.bytes[14:16] == '\xff\xff':
            return '\xe0'
        elif self.bytes[14] == '\xaa':
            return self.bytes[20:22]
        else:
            return int.to_bytes(self.bytes[14])

    def get_layer4_protocol(self):
        return self.bytes[23]

    def get_saddr(self):
        return self.bytes[26:30]

    def get_daddr(self):
        return self.bytes[30:34]

    def get_sport(self):
        return self.bytes[34:36]

    def get_dport(self):
        return self.bytes[36:38]

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
        print("dĺžka rámca poskytnutá pcap API –", str(self.api_len))
        print("dĺžka rámca prenášaného po médiu - " + str(self.real_len))
        print(self.get_layer2_type())
        print("Zdrojová MAC adresa: ", self.smac.hex().upper())
        print("Cieľová MAC adresa: ", self.dmac[0:6].hex().upper())
        layer3_key = int.from_bytes(self.get_layer3_protocol(), 'big')
        print(self.dicts[0][layer3_key])
        if int.from_bytes(self.layer3_protocol, 'big') == 0x0800:
            saddr = self.get_saddr()
            daddr = self.get_daddr()
            print('.'.join([str(saddr[0]), str(saddr[1]), str(saddr[2]), str(saddr[3])]))
            print('.'.join([str(daddr[0]), str(daddr[1]), str(daddr[2]), str(daddr[3])]))
            print(self.dicts[1][self.get_layer4_protocol()])
            print
        self.print_frame()
