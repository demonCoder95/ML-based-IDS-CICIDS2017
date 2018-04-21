# This module represents all of the Front-end for the IDS and will be
# used in a thread to render the front-end of the IDS
# Author: Noor Muhammad Malik
# Date: April 21, 2018
# =====================================================================

import tkinter as tk 
from tkinter import ttk
import tkinter.messagebox

# Main frontend for the IDS
class MainWindow(tk.Tk):
    # the main class is mostly going to be just a constructor
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)

        # setup some window parameters
        self.title("IDSv1.0")
        self.geometry("1024x768")
        self.minsize(width=800, height=600)

        # ---------------- menu bar ----------------------------
        # the menu bar object - as a container on the top
        self.menu_bar = tk.Menu(self)
        self.config(menu=self.menu_bar)
        # the "File" sub-menu
        self.sub_menu_file = tk.Menu(self.menu_bar)
        self.menu_bar.add_cascade(label="File", menu=self.sub_menu_file)
        self.sub_menu_file.add_command(label="Exit", command=self.exit_routine)
        
        # the "Edit" sub-menu
        self.sub_menu_edit = tk.Menu(self.menu_bar)
        self.menu_bar.add_cascade(label="Edit", menu=self.sub_menu_edit)
        # the "Help" sub-menu
        self.sub_menu_help = tk.Menu(self.menu_bar)
        self.menu_bar.add_cascade(label="Help", menu=self.sub_menu_help)
        
        # --------------- tool bar ----------------------------
        self.toolbar = tk.Frame(self, bg="blue")
        self.open_button = tk.Button(self.toolbar, text="Open")
        self.open_button.pack(side="left", padx=4, pady=2)
        
        self.toolbar.pack(side="top", fill="x")

        # --------------- satus bar ---------------------------
        self.status_bar_main = tk.Label(self, text="Program running..", bd=1, relief="sunken", anchor="w")
        self.status_bar_main.pack(side="bottom", fill="x")

        # --------------- scan button ------------------------
        self.scan_button = tk.Button(self, text="Start Scan", bg="gray", fg="black", command=self.scan_routine)
        self.scan_button.pack(side="bottom", anchor="e", padx=20, pady=20)

        self.message_text = "Welcome to IDS v1.0\nPlease select the attacks to detect and hit the \"Start Scan\" button."


        # --------------- the text box for information
        self.message_field = tk.Message(self, justify="left", padx=10, pady=10,
                                    text=self.message_text, relief="sunken")
        self.message_field.pack(anchor="e", padx=20, pady=20)


    # open a new log file for analysis
    # ADD THIS FUNCTIONALITY!



    # exit routine made separate to handle anything just in case
    def exit_routine(self):
        response = tkinter.messagebox.askquestion("Exit", "Are you sure you want to exit?")
        if response == "yes":
            self.quit()

    # scan routine is used to handle whatever
    def scan_routine(self):
        response = tkinter.messagebox.askquestion("Scan", "Are you sure you want to start the scan?")
        if response == "yes":
            self.scan_window = ScanWindow()

# GUI of the Scan Window
class ScanWindow(tk.Tk):
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)

        # set window parameters
        self.title("Scan Window")
        self.geometry("800x600")
        self.minsize(width=800, height=600)


        # ------------- progress bar ---------------
        self.progress_bar = ttk.Progressbar(self,
        orient="horizontal", length=300,
        mode="indeterminate")
        self.progress_bar.pack(side="bottom", anchor="w", padx=10, pady=10)

        self.progress_bar.start(10)
        self.progress_bar.step(10)

gui = MainWindow()
gui.mainloop()