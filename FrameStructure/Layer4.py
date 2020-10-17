class Layer4:
    def __init__(self, bytes, type):
        if type == "ICMP":
            self.icmp_type = bytes[0:1]
        elif type == "TCP" or type == "UDP":
            self.sport = bytes[0:2]
            self.dport = bytes[2:4]
            if type == "TCP":
                self.flags = bytes[13:14] #TODO metoda na extrakciu bitov

    # Is three-way handshake start? Returns yes if flag is just SYN
    def is_3wh_start(self):
        if int.from_bytes(self.flags, 'big') == 2:
            return True
        return False

