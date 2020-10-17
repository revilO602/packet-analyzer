class Layer4:
    def __init__(self, bytes, type):
        if type == "ICMP":
            self.icmp_type = bytes[0:1]
        elif type == "TCP" or type == "UDP":
            self.sport = bytes[0:2]
            self.dport = bytes[2:4]
            if type == "TCP":
                self.flags = bytes[12:14] #TODO meoda na extrakciu bitov