'''
mDNS discovery module for peer discovery.
'''

import socket
from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf, ServiceStateChange
import threading

SERVICE_TYPE = "_securep2pfiles._tcp.local."

class Discovery:
    def __init__(self, name, port=5000):
        self.name = name
        self.port = port
        self.zeroconf = Zeroconf()
        self.browser = None
        self.peers = {}

    def start(self):
        info = ServiceInfo(
            SERVICE_TYPE,
            f"{self.name}.{SERVICE_TYPE}",
            addresses = [socket.inet_aton(socket.gethostbyname(socket.gethostname()))],
            port = self.port,
            properties = {"name": self.name.encode()},
        )
        self.zeroconf.register_service(info)

    def browse(self):
        def on_service_state_change(zeroconf, service_type, name, state_change):
            if state_change is ServiceStateChange.Added:
                info = zeroconf.get_service_info(service_type, name)
                if info:
                    ip = socket.inet_ntoa(info.addresses[0])
                    friendly = info.properties.get(b"name", b"?").decode()
                    self.peers[name] = (friendly, ip, info.port)
                    print(f"[DISCOVERED] {friendly}@{ip}:{info.port}")
        self.browser = ServiceBrowser(self.zeroconf, SERVICE_TYPE, handlers=[on_service_state_change])

    def close(self):
        self.zeroconf.close()


# temp test: TODO move to proper test file
import time
def run_discovery_pair():
    # Create two peers with unique instance names and ports
    d1 = Discovery("peer1id", port=5051)
    d2 = Discovery("peer2id", port=5052)
    # Start advertising and browsing
    d1.start()
    d2.start()
    d1.browse()
    d2.browse()
    print("[TEST] Both discovery instances started, waiting for detection...")
    # Allow some time for mDNS packets to propagate
    time.sleep(5)
    # Check that each discovered the other
    peer1_found = any("peer2id" in name for name in d1.peers)
    peer2_found = any("peer1id" in name for name in d2.peers)
    print("[RESULT] Peer1 sees Peer2:", peer1_found)
    print("[RESULT] Peer2 sees Peer1:", peer2_found)
    # Cleanup
    d1.close()
    d2.close()
    return peer1_found and peer2_found

if __name__ == "__main__":
    d = Discovery("testpeerid")
    print(d)
    d.start()
    print(d)
    if d is not None:
        d.browse()
    else:
        print("d is none")
    print("[TEST] Discovery advertisement started.")
    time.sleep(2)
    d.close()
    print("[TEST] Discovery closed cleanly.")

    ok = run_discovery_pair()
    if ok:
        print("[TEST] Discovery confirmed bidirectional visibility.")
    else:
        print("[TEST] Discovery failed — check network or mDNS restrictions.")
