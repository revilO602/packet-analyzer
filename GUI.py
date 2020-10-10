from tkinter import *
from tkinter.filedialog import askopenfilename
import tkinter.scrolledtext as scrolledtext
from Main import *


root = Tk()
root.title("Packet Analyzer")
output = scrolledtext.ScrolledText(root)
output.delete('1.0', END)
output.pack()

def chooseFile():
    filename = askopenfilename()
    show_frames(filename, output)

choose_file_button = Button(root, text="Choose pcap file", command=chooseFile).pack()


root.mainloop()



