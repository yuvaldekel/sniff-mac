from scapy.all import sniff, Ether

MY_MAC = '00:28:f8:6b:ea:cc'
TIME = 5 *60 

def filter_by_mac(frame):
    return Ether in frame and frame[Ether].dst == MY_MAC

def main():
    mac_addresses = set({})
    frames = sniff(timeout =5 , iface = 'wlp4s0', lfilter = lambda f: Ether in f and f[Ether].dst == MY_MAC)
    
    if len(frames) == 0:
        print("Didn't sniff any packets that fit the requirements.")
        exit()

    for frame in enumerate(frames):
        mac_address = frame[1][Ether].src
        mac_addresses.add(mac_address)

        print(f"packet {frame[0]} was sent from card with mac address {mac_address}", end='')
        if mac_address in mac_addresses:
            print(f", i have already got packet from the same address.")
        else:
            print('.')

if __name__ == "__main__":
    main()