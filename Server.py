import socket
import struct


define_Binary_Data = '!BBHHHBBH4s4s'
byte_Array = []

def listen():
  s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
  s.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
  data = s.recvfrom(1508)
  return data

def parse_ICMP(data):
    ver_ihl, tos, tot_len, ident, flags_frag, ttl, proto, chksum, src, dst = struct.unpack(define_Binary_Data, data[:20])
    return ttl

def convert_Int_To_Bytes(ttl):
    byte = ttl.to_bytes(1, 'big')
    byte_Array.append(byte)

if __name__ == '__main__':
    while 1:
        data, addr = listen()
        ttl = parse_ICMP(data)
        convert_Int_To_Bytes(ttl)
        formated_Byte_Array = b''.join(byte_Array)
        if b"<Done>-|_|-<stop>" in formated_Byte_Array:
            print(formated_Byte_Array)
            byte_Array = []
