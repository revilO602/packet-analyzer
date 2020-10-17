import scapy.all as sc
from Protocols import Protocols
from tkinter.filedialog import askopenfilename
import tkinter.scrolledtext as st
from Main import *

root = Tk()
root.title("Packet Analyzer")


def choose_file():
    file = askopenfilename(title="Select a pcap file", filetypes=(("PCAP Files", "*.pcap"),))
    filename.set(file)


# Show all frames with no filtering
def show_all():
    try:
        file_reader = sc.PcapReader(filename.get())
        output.delete('1.0', END)
        show_frames(file_reader, dictionary, output)
    except FileNotFoundError:
        root.destroy()


# Show frames with HTTP
def use_filter():
    try:
        file_reader = sc.PcapReader(filename.get())
        output.delete('1.0', END)
        filter_frames(file_reader, dictionary, output, filter_entry.get().upper())
    except FileNotFoundError:
        root.destroy()


def show_arp_pairs():
    try:
        file_reader = sc.PcapReader(filename.get())
        output.delete('1.0', END)
        arp_pairs(file_reader, dictionary, output)
    except FileNotFoundError:
        root.destroy()


filename = StringVar(root, value="CHOOSE A FILE!")
file_lbl = Label(root, textvariable=filename)
filter_entry = Entry(root)
output = st.ScrolledText(root)
show_all_button = Button(root, text="Show all frames", command=show_all)
use_filter_button = Button(root, text="Use Filter", command=use_filter)
choose_file_button = Button(root, text="Choose file", command=choose_file)
arp_button = Button(root, text="Show ARP pairs", command=show_arp_pairs)

file_lbl.pack()
filter_entry.pack()
output.pack()
output.delete('1.0', END)
show_all_button.pack()
use_filter_button.pack()
choose_file_button.pack()
arp_button.pack()
# User selects a pcap file

dictionary = Protocols()  # creates an object with all the protocols and ports in different dictionaries

root.mainloop()
