import scapy.all as sc
from Protocols import Protocols
from tkinter.filedialog import askopenfilename
import tkinter.scrolledtext as st
from Main import *


class App:
    def __init__(self, master, dictionary):
        self.master = master
        master.title("Packet Analyzer")
        self.filename = StringVar(root, value="CHOOSE A FILE!")
        self.dictionary = dictionary
        self.create_widgets()
        self.show_widgets()

    def create_widgets(self):
        self.file_lbl = Label(root, textvariable=self.filename)
        self.filter_lbl = Label(root, text="Filter:")
        self.filter_entry = Entry(root)
        self.output = st.ScrolledText(root)
        self.choose_file_button = Button(root, text="Choose file", command=self.choose_file)
        self.show_all_button = Button(root, text="Show all frames", command=self.show_all)
        self.use_filter_button = Button(root, text="Use Filter", command=self.use_filter)
        self.show_tcp_comm_button = Button(root, text="Show TCP Communications", command=self.show_tcp_comm)
        self.show_tftp_comm_button = Button(root, text="Show TFTP Communications", command=self.show_tftp_comm)
        self.arp_button = Button(root, text="Show ARP pairs", command=self.show_arp_pairs)

    def show_widgets(self):
        self.file_lbl.pack()
        self.filter_lbl.pack()
        self.filter_entry.pack()
        self.output.pack()
        self.output.delete('1.0', END)
        self.choose_file_button.pack()
        self.show_all_button.pack()
        self.use_filter_button.pack()
        self.show_tftp_comm_button.pack()
        self.show_tcp_comm_button.pack()
        self.arp_button.pack()

    # User selects a pcap file
    def choose_file(self):
        file = askopenfilename(title="Select a pcap file", filetypes=(("PCAP Files", "*.pcap"),))
        self.filename.set(file)

    # Show all frames with no filtering
    def show_all(self):
        try:
            file_reader = sc.PcapReader(self.filename.get())
            self.output.delete('1.0', END)
            show_frames(file_reader, dictionary, self.output)
        except FileNotFoundError:
            root.destroy()

    # Show all frames with filter applied
    def use_filter(self):
        try:
            file_reader = sc.PcapReader(self.filename.get())
            self.output.delete('1.0', END)
            filter_frames(file_reader, dictionary, self.output, self.filter_entry.get().upper())
        except FileNotFoundError:
            root.destroy()

    # Show TCP frames grouped into streams
    def show_tcp_comm(self):
        try:
            file_reader = sc.PcapReader(self.filename.get())
            self.output.delete('1.0', END)
            tcp_comm(file_reader, self.output, dictionary, self.filter_entry.get().upper())
        except FileNotFoundError:
            root.destroy()

    # Show TFTP frames grouped into streams
    def show_tftp_comm(self):
        try:
            file_reader = sc.PcapReader(self.filename.get())
            self.output.delete('1.0', END)
            tftp_comm(file_reader, self.output, dictionary)
        except FileNotFoundError:
            root.destroy()

    # Show ARP frames grouped into pairs
    def show_arp_pairs(self):
        try:
            file_reader = sc.PcapReader(self.filename.get())
            self.output.delete('1.0', END)
            arp_pairs(file_reader, dictionary, self.output)
        except FileNotFoundError:
            root.destroy()


dictionary = Protocols()  # creates an object with all the protocols and ports in different dictionaries
root = Tk()
app = App(root, dictionary)
root.mainloop()
