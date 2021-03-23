import socket
import struct
from datetime import datetime

# Create a raw packet detection socket for Linux
s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, 8)

dict = {}  # Empty dict

# Open text file + output the data/time of current compilation
file_txt = open("dos-output.txt", 'a')
time = str(datetime.now().strftime("Current time of compilation: %Y-%m-%d %H:%M:%S"))
file_txt.writelines(time)
file_txt.writelines("\n")

print("Running detection...")  # Report to user to ensure somethings happening

# Minimum number of packets required to be flagged as a DoS attack
packets_req = 1000
packets_req_stop = packets_req + 2  # Ensures line only printed once

while True:
    pkt = s.recvfrom(2048)
    ipheader = pkt[0][14:34]
    ip_hdr = struct.unpack("!8sB3s4s4s", ipheader)
    IP = socket.inet_ntoa(ip_hdr[3])

    print("Source IP", IP)
    if IP in dict:
        dict[IP] = dict[IP] + 1
        print(dict[IP])
        if (dict[IP] > packets_req) and (dict[IP] < packets_req_stop):
            line = "DoS detected from: "
            file_txt.writelines(line)
            file_txt.writelines(IP)
            file_txt.writelines("\n")

    else:
        dict[IP] = 1

# ------------------------------------------------
# Sections of code derived from:
# https://hub.packtpub.com/pentesting-using-python/
# ------------------------------------------------
