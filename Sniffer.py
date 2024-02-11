
import socket
import struct
import textwrap

TAB_1='\t - '
TAB_2='\t\t - '
TAB_3='\t\t\t - '
TAB_4='\t\t\t\t - '
DTAB_1='\t '
DTAB_2='\t\t '
DTAB_3='\t\t\t '
DTAB_4='\t\t\t\t '


def main():
    conn=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
    while True:
        raw_data, addr=conn.recvfrom(65536)
        dest_mac,src_mac,eth_proto,data=ethernet_frame(raw_data)
        if dest_mac!="00:00:00:00:00:00":
         print('\nEthernet Frame: ')
         print(TAB_1 +'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac,src_mac,eth_proto))
         if eth_proto==8:
            (version,header_length,ttl,proto,src,target,data)=ipv4_packet(data)
            print(TAB_1+'IPV4 Packet:')
            print(TAB_2+'Version: {}, Header Length: {}, TTL: {}'.format(version,header_length,ttl))
            print(TAB_2+'Protocol: {}, Source: {}, Target: {}'.format(proto,src,target))
            
            #ICMP
            if proto==1:
                (icmp_type,code,checksum, data)=icmp_packet(data)
                print(TAB_1+'ICMP Packet:')
                print(TAB_2+'Type: {},Code: {}, Checksum: {}'.format(icmp_type,code,checksum))
                print(TAB_2+'Data: ')
                print(multi_line(DTAB_3,str(data)))

            #TCP
            elif proto==6:
              
                src_port,dest_port,seq,ack,flag_ack,flag_fin,flag_psh,flag_rst,flag_urg,flag_syn,data=tcp_seg(data)  
                print(TAB_1+'TCP Segment:')
                print(TAB_2 + 'Source_port: {}, Dest_port: {}'.format(src_port,dest_port)) 
                print(TAB_2 + 'Sequence: {}, ACK: {}'.format(seq,ack)) 
                print(TAB_2 + 'Flags: ')  
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN:{}'.format(flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin)) 
                if len(data)!=0:
                    print(TAB_2 + 'DATA: ') 
                    print(multi_line(DTAB_3,str(data)))
            
            
            #UDP
            elif proto== 17:
                src_port,dest_port,size,data=udp_seg(data)
                print(TAB_1+'UDP Segment:')
                print(TAB_2+'Source port: {}, Destination port: {}, Length: {}'.format(src_port,dest_port,size))
                print(TAB_2 + 'DATA: ') 
                print(multi_line(DTAB_3,str(data)))

def ethernet_frame(data):
    dest_mac,src_mac, proto=struct.unpack('!6s6sH', data[:14])
    return get_mac_addr(dest_mac),get_mac_addr(src_mac),socket.htons(proto), data[14:]




def get_mac_addr(bytes):
    bytes_str = [format(byte, '02x') for byte in bytes]
    return ':'.join(bytes_str).upper()


def ipv4_packet(data):
    v_header_length=data[0]
    version=v_header_length >> 4
    header_length=(v_header_length & 15) * 4
    ttl,proto,src,target=struct.unpack('!8xBB2x4s4s',data[:20])
    return version,header_length,ttl,proto,ipv4(src),ipv4(target),data[header_length:]

def ipv4(addr):
    return '.'.join(map(str,addr))

def icmp_packet(data):
    icmp_type,code,checksum=struct.unpack('!BBH',data[:4])
    return icmp_type,code,checksum, data[4:]


def tcp_seg(data):
    if len(data) >= 20:  # Ensure at least 20 bytes for a minimal TCP header
        src_port, dest_port, seq, ack, off_res_flg = struct.unpack('!HHLLH', data[:14])
        header_length = (off_res_flg >> 12) * 4
        if len(data) >= header_length:
            flags = off_res_flg & 0x3F
            flag_urg = (flags & 0x20) >> 5
            flag_ack = (flags & 0x10) >> 4
            flag_psh = (flags & 0x08) >> 3
            flag_rst = (flags & 0x04) >> 2
            flag_syn = (flags & 0x02) >> 1
            flag_fin = flags & 0x01
            return src_port, dest_port, seq, ack, flag_ack, flag_fin, flag_psh, flag_rst, flag_urg, flag_syn, data[header_length:]
        else:
            print(TAB_3+f"Expected header length: {header_length}, Actual data length: {len(data)}")
    else:
        print(TAB_3+f"Expected at least 20 bytes, Actual data length: {len(data)}")
        print(TAB_3+"Probably an error in the Packet")
    # Return a tuple with placeholder values to prevent TypeError during unpacking
    return (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, b'')




def udp_seg(data):
    src_port,dest_port,size=struct.unpack('!HH2xH',data[:8])
    return src_port,dest_port,size,data[8:]

def multi_line(prefix,string,size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        if size % 2:
            size -=1
    return '\n'.join([prefix + line for line in textwrap.wrap(string,size)])



main()


