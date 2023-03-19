import scapy.all as sc
from Protocols import Protocols
from tkinter.filedialog import askopenfilename
from tkinter import messagebox
import tkinter.scrolledtext as st
from Main import *


class App:
    def __init__(self, master, dictionary):
        self.master = master
        master.title("Packet Analyzer")
        self.filename = StringVar(root, value="CHOOSE A FILE!")
        self.checkvar = BooleanVar(master)
        self.dictionary = dictionary
        self.create_widgets()
        self.show_widgets()

    def create_widgets(self):
        self.frame_bot1 = Frame(self.master)
        self.frame_bot2 = Frame(self.master)
        self.file_lbl = Label(root, textvariable=self.filename)
        self.filter_lbl = Label(root, text="Filter:")
        self.filter_entry = Entry(root)
        self.output = st.ScrolledText(root)
        self.choose_file_button = Button(self.frame_bot1, text="Choose file", command=self.choose_file)
        self.show_all_button = Button(self.frame_bot1, text="Show all frames", command=self.show_all)
        self.use_filter_button = Button(self.frame_bot1, text="Use Filter", command=self.use_filter)
        self.show_tcp_comm_button = Button(self.frame_bot1, text="Show TCP Communications", command=self.show_tcp_comm)
        self.check = Checkbutton(self.frame_bot1, text="Only one communication", variable=self.checkvar,
                                 onvalue=True, offvalue=False)
        self.show_tftp_comm_button = Button(self.frame_bot2, text="Show TFTP Communications",
                                            command=self.show_tftp_comm)
        self.arp_button = Button(self.frame_bot2, text="Show ARP pairs", command=self.show_arp_pairs)
        self.rip_button = Button(self.frame_bot2, text="Show RIP frames", command=self.show_rip)
        self.save_button = Button(self.frame_bot2, text="Save to out.txt", command=self.save_output)

    def show_widgets(self):
        self.file_lbl.pack()
        self.filter_lbl.pack()
        self.filter_entry.pack()
        self.output.pack()
        self.output.delete('1.0', END)
        self.frame_bot1.pack()
        self.frame_bot2.pack()
        self.choose_file_button.pack(side=LEFT)
        self.show_all_button.pack(side=LEFT)
        self.use_filter_button.pack(side=LEFT)
        self.show_tftp_comm_button.pack(side=LEFT)
        self.show_tcp_comm_button.pack(side=LEFT)
        self.check.pack(side=LEFT)
        self.arp_button.pack(side=LEFT)
        self.rip_button.pack(side=LEFT)
        self.save_button.pack(side=LEFT)

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
            messagebox.showerror("Error: File not found", "Please choose a file by clicking the 'Choose file' button")

    # Show all frames with filter applied
    def use_filter(self):
        try:
            file_reader = sc.PcapReader(self.filename.get())
            self.output.delete('1.0', END)
            filter_frames(file_reader, dictionary, self.output, self.filter_entry.get().upper())
        except FileNotFoundError:
            messagebox.showerror("Error: File not found", "Please choose a file by clicking the 'Choose file' button")

    # Show TCP frames grouped into streams
    def show_tcp_comm(self):
        try:
            file_reader = sc.PcapReader(self.filename.get())
            self.output.delete('1.0', END)
            tcp_comm(file_reader, self.output, dictionary, self.filter_entry.get().upper(), self.checkvar.get())
        except FileNotFoundError:
            messagebox.showerror("Error: File not found", "Please choose a file by clicking the 'Choose file' button")

    # Show TFTP frames grouped into streams
    def show_tftp_comm(self):
        try:
            file_reader = sc.PcapReader(self.filename.get())
            self.output.delete('1.0', END)
            tftp_comm(file_reader, self.output, dictionary)
        except FileNotFoundError:
            messagebox.showerror("Error: File not found", "Please choose a file by clicking the 'Choose file' button")

    # Show ARP frames grouped into pairs
    def show_arp_pairs(self):
        try:
            file_reader = sc.PcapReader(self.filename.get())
            self.output.delete('1.0', END)
            arp_pairs(file_reader, dictionary, self.output)
        except FileNotFoundError:
            messagebox.showerror("Error: File not found", "Please choose a file by clicking the 'Choose file' button")

    # Show RIP frames
    def show_rip(self):
        try:
            file_reader = sc.PcapReader(self.filename.get())
            self.output.delete('1.0', END)
            filter_frames(file_reader, dictionary, self.output, "RIP")
        except FileNotFoundError:
            messagebox.showerror("Error: File not found",
                                 "Please choose a file by clicking the 'Choose file' button")

    # Save the displayed output to out.txt file
    def save_output(self):
        with open("out.txt", "w") as out:
            out.write(self.output.get('1.0', END))


dictionary = Protocols()  # creates an object with all the protocols and ports in different dictionaries
root = Tk()
app = App(root, dictionary)
root.mainloop()
