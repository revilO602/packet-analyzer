from tkinter import *
from tkinter.filedialog import askopenfilename
from Main import *

root = Tk()
filename = askopenfilename()

show_frames(filename)