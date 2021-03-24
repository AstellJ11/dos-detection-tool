import socket
import struct
from datetime import datetime
import tkinter as tk
import tkinter.font as tkFont
from threading import Thread
import os


def DoSDetection():
    # Create a raw packet detection socket for Linux
    s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, 8)

    dict = {}  # Empty dict

    # Open text file + output the data/time of current compilation
    file_txt = open("dos-output.txt", 'a')

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
                time = str(datetime.now().strftime("Current time of compilation: %Y-%m-%d %H:%M:%S"))
                file_txt.writelines(time)
                file_txt.writelines("\n")
                line = "DoS detected from: "
                file_txt.writelines(line)
                file_txt.writelines(IP)
                file_txt.writelines("\n")

        else:
            dict[IP] = 1

        if stop == 1:
            time = str(datetime.now().strftime("Current time of compilation: %Y-%m-%d %H:%M:%S"))
            file_txt.writelines(time)
            file_txt.writelines("\n")
            line2 = "No DoS detected at this time "
            file_txt.writelines(line2)
            break  # Break while loop when stop = 1


def start_thread():
    # Assign global variable and initialize value
    global stop
    stop = 0

    # Create and launch a thread
    t = Thread(target=DoSDetection)
    t.start()


def stop_thread():
    # Assign global variable and set value to stop
    global stop
    stop = 1
    print("Stopping detection...")


# def DoSAttack():
## TO DO


# Open file and output results to text widget
def refresh():
    configfile.delete("1.0", "end")  # Clear the text widget
    filename = "dos-output.txt"

    # Check if anything exists in the file
    if (os.stat(filename).st_size == 0) is True:
        configfile.insert(tk.END, "No data currently! Run the DoS Detection Tool to gather data.")
    else:
        with open(filename, 'r') as f:
            configfile.insert(tk.INSERT, f.read())  # Populate widget with contents of text file


# Create tkinter window
window = tk.Tk()
window.geometry("800x500")
window.title("DoS Identification Tool")

fontStyle = tkFont.Font(family="Lucida Grande", size=20)
greeting = tk.Label(text="DoS Attack Results", font=fontStyle)
greeting.place(relx=0.28, rely=0.07, anchor='center')

btn = tk.Button(window, text="Start DoS\nDetection", fg='blue', command=lambda: start_thread())
btn.place(x=500, y=125)

btn2 = tk.Button(window, text="Stop DoS\nDetection", fg='blue', command=lambda: stop_thread())
btn2.place(x=650, y=125)

# btn3 = tk.Button(window, text="Start DoS\nAttack", fg='blue', command=lambda: DoSAttack())
# btn3.place(x=500, y=250)

btn4 = tk.Button(window, text="Stop DoS\nAttack", fg='blue', command=lambda: stop_thread())
btn4.place(x=650, y=250)

# Button to close tk window
btn_end = tk.Button(window, text="Close", fg='blue', command=window.destroy)
btn_end.place(x=575, y=376)

btn_rfs = tk.Button(window, text="Refresh", fg='blue', command=lambda: refresh())
btn_rfs.place(x=175, y=450)

# Create text widget
configfile = tk.Text(window, wrap=tk.WORD, width=50, height=22)
configfile.place(relx=0.27, rely=0.50, anchor='center')

# Add scroll bar to text widget
S = tk.Scrollbar(window)
S.pack(side=tk.LEFT)
S.config(command=configfile.yview)
configfile.config(yscrollcommand=S.set)

# Ensure the current contents of the text file are displayed on first run through
filename = "dos-output.txt"
if (os.stat(filename).st_size == 0) is True:
    configfile.insert(tk.END, "No data currently! Run the DoS Detection Tool to gather data.")
else:
    with open(filename, 'r') as f:
        configfile.insert(tk.INSERT, f.read())

window.mainloop()

# ------------------------------------------------
# Sections of code derived from:
# https://hub.packtpub.com/pentesting-using-python/
# ------------------------------------------------
