from scapy.all import sniff

def main():
    frames = sniff(count = 2, iiface = 'wlp4s0')
    first_frame = frames[0]
    first_frame.show()

if __name__ == "__main__":
    main()