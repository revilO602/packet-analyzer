class TcpComm:
    def __init__(self, frame):
        self.starters_ip = frame.layer3.sip
        self.starters_port = frame.layer4.sport
        self.recievers_ip = frame.layer3.dip
        self.recievers_port = frame.layer4.dport
        self.handshake_stage = 1    # Starts at 1 because SYN is a prerequisite to TcpComm objects creation
        self.expected_port = self.recievers_port
        self.end_stage = 0
        self.frames = [frame]

    def update_handshake(self, frame):
        if self.handshake_stage == 1:
            if int.from_bytes(frame.layer4.flags, 'big') == 18 and frame.layer4.sport == self.expected_port:
                self.handshake_stage = 2
                self.expected_port = frame.layer4.dport
        elif self.handshake_stage == 2:
            if int.from_bytes(frame.layer4.flags, 'big') == 16 and frame.layer4.sport == self.expected_port:
                self.handshake_stage = 3

    def update_end(self, frame):
        if int.from_bytes(frame.layer4.flags, 'big') & 4:
            self.end_stage = 4
        elif self.end_stage == 0 and int.from_bytes(frame.layer4.flags, 'big') & 1:
            self.end_stage = 1
            self.expected_port = frame.layer4.dport
        elif (self.end_stage == 1 and int.from_bytes(frame.layer4.flags, 'big') & 16 and
              frame.layer4.sport == self.expected_port):
            if int.from_bytes(frame.layer4.flags, 'big') & 1:
                self.end_stage = 3
                self.expected_port = frame.layer4.dport
            else:
                self.end_stage = 2
                self.expected_port = frame.layer4.sport
        elif (self.end_stage == 2 and int.from_bytes(frame.layer4.flags, 'big') & 1 and
              frame.layer4.sport == self.expected_port):
            self.end_stage = 3
            self.expected_port = frame.layer4.dport
        elif (self.end_stage == 3 and int.from_bytes(frame.layer4.flags, 'big') & 16 and
              frame.layer4.sport == self.expected_port):
            self.end_stage = 4

    def belongs(self, frame):
        if ((frame.layer3.sip, frame.layer3.dip, frame.layer4.sport, frame.layer4.dport) == (
                self.starters_ip, self.recievers_ip, self.starters_port, self.recievers_port) or
                (frame.layer3.sip, frame.layer3.dip, frame.layer4.sport, frame.layer4.dport) == (
                        self.recievers_ip, self.starters_ip, self.recievers_port, self.starters_port)):
            if self.handshake_stage < 3:
                self.update_handshake(frame)
            elif self.end_stage < 4:
                self.update_end(frame)
            self.frames.append(frame)
            return True
