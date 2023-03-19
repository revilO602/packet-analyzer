class Layer4:
    def __init__(self, bytes, type):
        if type == "ICMP":
            self.icmp_type = bytes[0:1]
        elif type == "TCP" or type == "UDP":
            self.sport = bytes[0:2]
            self.dport = bytes[2:4]
            if type == "TCP":
                self.flags = bytes[13:14]
                self.len = bytes[12:13]

    # Returns length of TCP header
    def get_len(self):
        return (int.from_bytes(self.len, 'big') / 16) * 4

    # Is three-way handshake start? Returns yes if flag is just SYN
    def is_3wh_start(self):
        if int.from_bytes(self.flags, 'big') == 2:
            return True
        return False

    # Translate ICMP type byte to string
    def get_icmp_type(self):
        dict = {0: "Echo Reply", 3: "Destination Unreachable", 4: "Source Quench",
                5: "Redirect", 8: "Echo", 9: "Router Advertisement", 10: "Router Selection",
                11: "Time Exceeded", 12: "Parameter Problem", 13: "Timestamp", 14: "Timestamp Reply",
                15: "Information Request", 16: "Information Reply", 17: "Address Mask Request",
                18: "Address Mask Reply", 30: "Traceroute"}
        try:
            return dict[int.from_bytes(self.icmp_type, 'big')]
        except KeyError:
            return "Unknown ICMP type"

