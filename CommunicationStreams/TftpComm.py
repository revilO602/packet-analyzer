class TftpComm:
    def __init__(self, frame):
        self.first_port = None
        self.second_port = None
        self.set_port(frame)
        self.frames = [frame]

    def set_port(self, frame):
        if frame.layer4.sport == b'\x00\x45':
            self.first_port = frame.layer4.dport
        else:
            self.first_port = frame.layer4.sport

    def check(self, frame):
        if self.second_port is None:
            if frame.layer4.sport == self.first_port:
                self.second_port = frame.layer4.dport
                self.frames.append(frame)
            elif frame.layer4.dport == self.first_port:
                self.second_port = frame.layer4.sport
                self.frames.append(frame)
        elif ((frame.layer4.sport, frame.layer4.dport) == (self.first_port, self.second_port) or
              (frame.layer4.dport, frame.layer4.sport) == (self.first_port, self.second_port)):
            self.frames.append(frame)