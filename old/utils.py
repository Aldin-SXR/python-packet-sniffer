import socket
import struct
import textwrap


def format_ethernet_protocol(protocol):
    if protocol == 8:
        return 'IPv4'
    elif protocol == 1544:
        return 'ARP'
    else:
        return protocol

def format_ip_protocol(protocol):
    if protocol == 1:
        return 'ICMP'
    elif protocol == 6:
        return 'TCP'
    elif protocol == 17:
        return 'UDP'
    else:
        return protocol 


# Format output
def format_output(prefix, string, size=80):
    # return bytes(string).decode('mac_roman')
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ' '.join(r'{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])