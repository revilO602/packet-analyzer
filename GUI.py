from tkinter import *
from tkinter.filedialog import askopenfilename
from Main import *

root = Tk()
root.title("Packet Analyzer")
filename = askopenfilename()

show_frames(filename)