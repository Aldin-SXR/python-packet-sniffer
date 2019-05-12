# Custom function imports
from packet_types import *
from utils import *

# Main loop
def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, address = connection.recvfrom(65536)
        destination_mac, source_mac, eth_protocol, data = ethernet_frame(raw_data)
        print('\nEthernet frame: ')
        print('\tDestination: {}, Source: {}, Protocol: {}'.format(destination_mac, source_mac, format_ethernet_protocol(eth_protocol)))

        # Ethernet protocol 8 --> IPv4
        if eth_protocol == 8:
            version, header_length, time_to_live, ip_protocol, ip_source, ip_destination, data = ip_packet(data)
            print('\tIPv4 packet: ')
            print('\t\t Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, time_to_live))
            print('\t\t Protocol: {}, Source: {}, Destination: {}'.format(format_ip_protocol(ip_protocol), ip_source, ip_destination))

            # Format different types of IP payloads.
            # ICMP packet
            if ip_protocol == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print('\tICMP packet:')
                print('\t\tType: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print('\t\tData:')
                print(format_output('\t\t\t', data))
            
            # TCP segment
            elif ip_protocol == 6:
                source_port, destination_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                print('\tTCP segment:')
                print('\t\tSource Port: {}, Destination Port: {}'.format(source_port, destination_port))
                print('\t\tSequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
                print('\t\tFlags:')
                print('\t\t\tURG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print('\t\tData:')
                print(format_output('\t\t\t', data))

            # UDP segment
            elif ip_protocol == 17:
                source_port, destination_port, size, data = udp_segment(data)
                print('\tUDP segment:')
                print('\t\tSource Port: {}, Destination Port: {}, Length: {}'.format(source_port, destination_port, size))
                print('\t\tData:')
                print(format_output('\t\t\t', data)) 
            
            # Other protocols
            else:
                print('\t\tData:')
                print(format_output('\t\t\t', data)) 

        # Ethernet protocol 1544 --> ARP (Address Resolution Protocol)
        if eth_protocol == 1544:
            hardware_type, protocol_type, hardware_address_length, protocol_address_length, opcode, source_hardware_address, source_protocol_address, target_hardware_address, target_protocol_address = arp_packet(data)
            print('\tARP packet: ')
            print('\t\tHardware Type: {}, Protocol Type: {}'.format(hardware_type, protocol_type))
            print('\t\tHardware Address Length: {}, Protocol Address Length: {}, Opcode: {}'.format(hardware_address_length, protocol_address_length, opcode))
            print('\t\tSource Hardware Address: {}, Destination Hardware Address: {}'.format(source_hardware_address, target_hardware_address))
            print('\t\tSource Protocol Address: {}, Destination Protocol Address: {}'.format(source_protocol_address, target_protocol_address))

main()
