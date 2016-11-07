
from spoofing.assembler import my_IP
from collections import deque,defaultdict

class IpPool:
    def __init__(self, ip_range_start, ip_range_end):
        self.pool = defaultdict(int)
        self.header_ip = my_IP()[:3]
        self.ipqueue = deque()
        for ip in range(ip_range_start, ip_range_end):
            self.ipqueue.append(self.header_ip + ip.to_bytes(1, byteorder='big'))
    def get_ip_for(self, mac):
        if not self.pool[mac]:
            self.pool[mac] = self.ipqueue.popleft()
        return self.pool[mac]

