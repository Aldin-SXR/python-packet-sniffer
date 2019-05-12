import socket
import struct
import textwrap

# Unpack an ethernet frame
def ethernet_frame(data):
    # Unpack relevant data and convert from big-endian to little-endian
    destination_mac, source_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return mac_address(destination_mac), mac_address(source_mac), socket.htons(protocol), data[14:]


# Return a properly-formatted MAC address.
def mac_address(byte_data):
    string_bytes = map('{:02x}'.format, byte_data)
    # formatted with colons and uppercased
    return ':'.join(string_bytes).upper()


# Unpack IP packets
def ip_packet(data):
    version_header_length = data[0]
    # Extract data from the byte (4 bits each)
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    time_to_live, protocol, source, destination = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, time_to_live, protocol, ipv4_address(source), ipv4_address(destination), data[20:]


# Return a properly-formatted IPv4 address
def ipv4_address(address):
    return '.'.join(map(str, address))


# Unpack ICMP packets
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


# Unpack TCP segment
def tcp_segment(data):
    source_port, destination_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    # 3-way handshake flags
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 4
    flag_syn = (offset_reserved_flags & 2) >> 2
    flag_fin = offset_reserved_flags & 1
    return source_port, destination_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


# Unpack UDP segment
def udp_segment(data):
    source_port, destination_port, size = struct.unpack('! H H H 2x', data[:8])
    return source_port, destination_port, size, data[8:]


# Unpack ARP packet
def arp_packet(data):
    hardware_type, protocol_type, hardware_address_length = struct.unpack('! H H B', data[:5])
    protocol_address_length, opcode = struct.unpack('! B H', data[5:8])
    source_hardware_address, source_protocol_address = struct.unpack('! 6s 4s', data[8:18])
    target_hardware_address, target_protocol_address = struct.unpack('! 6s 4s', data[18:28])
    return hardware_type, protocol_type, hardware_address_length, protocol_address_length, opcode, mac_address(source_hardware_address), ipv4_address(source_protocol_address), mac_address(target_hardware_address), ipv4_address(target_protocol_address)