# Class for keeping all the dictionaries for protocols and ports
class Protocols:
    def __init__(self):
        self.ethertypes = self.make_dict("external_files/ethertypes.txt")
        self.lsaps = self.make_dict("external_files/lsaps.txt")
        self.tcp_ports = self.make_dict("external_files/tcp_ports.txt")
        self.udp_ports = self.make_dict("external_files/udp_ports.txt")
        self.ip_protocols = self.make_dict("external_files/ip_protocols.txt")

    def make_dict(self, filename):
        new_dict = {}
        with open(filename, "r") as f:
            for line in f:
                key, value = line.split(' ', 1)
                new_dict[int(key, base=16)] = value.strip().upper()
            return new_dict

