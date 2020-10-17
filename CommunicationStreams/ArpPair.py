#
class ArpPair:
    def __init__(self, frame):
        self.requested_ip = frame.layer3.dip
        self.askers_ip = frame.layer3.sip
        self.frames = [frame]

    def is_reply(self, frame):
        if frame.layer3.op == b'\x00\x02':
            if frame.layer3.sip == self.requested_ip and frame.layer3.dip == self.askers_ip:
                self.frames.append(frame)
                frame.placed = True
                return True
        elif frame.layer3.op == b'\x00\x01':
            if frame.layer3.sip == self.askers_ip and frame.layer3.dip == self.requested_ip:
                self.frames.append(frame)
                frame.placed = True
                return False
        return False
