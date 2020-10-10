class IpAddress:
    def __init__(self, count, bytes):
        self.count = count
        self.bytes = bytes

    def humanize(self):
        return '.'.join([str(self.bytes[0]), str(self.bytes[1]), str(self.bytes[2]), str(self.bytes[3])])
