from scapy.all import sniff, Ether

MY_MAC = '00:28:f8:6b:ea:cc'

def filter_by_mac(frame):
    return Ether in frame and frame[Ether].dst == MY_MAC

def main():
    frames = sniff(count = 1, iface = 'wlp4s0', lfilter = lambda f: Ether in f and f[Ether].dst == MY_MAC)
    first_frame = frames[0]
    first_frame.show()

if __name__ == "__main__":
    main()