import socket
import struct

def format_mac(bytes_addr):
    return ':'.join(f'{b:02x}' for b in bytes_addr).upper()

def parse_ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return format_mac(dest_mac), format_mac(src_mac), socket.htons(proto), data[14:]

def parse_ip_header(data):
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    src_ip = socket.inet_ntoa(src)
    target_ip = socket.inet_ntoa(target)
    return proto, src_ip, target_ip, data[header_length:]

def analyze_packet_payload(data):
    try:
        payload_str = data.decode('utf-8', errors='ignore')
        if "HTTP" in payload_str or "GET" in payload_str or "POST" in payload_str:
            return "[WARNING] Unencrypted HTTP traffic detected!"
    except Exception:
        pass
    return "Payload encrypted or binary format."

def run_packet_analysis():
    print("=" * 60)
    print("      NETWORK TRAFFIC ANALYZER & PACKET INSPECTOR")
    print("=" * 60)

    sample_raw_packet = (
        b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00'
        b'\x45\x00\x00\x40\x12\x34\x00\x00\x80\x06\x00\x00'
        b'\xc0\xa8\x01\x0a\xc0\xa8\x01\x01'
        b'GET /login.php HTTP/1.1\r\nHost: example.com\r\n\r\n'
    )

    dest_mac, src_mac, eth_proto, ip_data = parse_ethernet_frame(sample_raw_packet)
    print(f"\n[+] Ethernet Frame:")
    print(f"    - Source MAC      : {src_mac}")
    print(f"    - Destination MAC : {dest_mac}")
    print(f"    - Protocol        : {eth_proto}")

    if eth_proto == 8:
        proto, src_ip, target_ip, payload = parse_ip_header(ip_data)
        print(f"\n[+] IPv4 Packet:")
        print(f"    - Source IP       : {src_ip}")
        print(f"    - Target IP       : {target_ip}")
        print(f"    - Protocol ID     : {proto} (TCP)")

        alert = analyze_packet_payload(payload)
        print(f"\n[+] Security Analysis:")
        print(f"    - Status          : {alert}")

if __name__ == "__main__":
    run_packet_analysis()
