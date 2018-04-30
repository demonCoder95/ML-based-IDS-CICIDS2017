"""
=====================================================================
This code is the final script for running/managing the IDS
it is a multithreaded model, with fully functional GUI as well
as a log-getter daemon, for efficient logging of data

Author: Noor Muhammad Malik
Date: April 21, 2018
License: None
=====================================================================
"""

# gui imports
import tkinter as tk 
from tkinter import ttk
import tkinter.messagebox
import tkinter.scrolledtext

# personal modules
import flowmeter
import dnnengine

# threading related
import threading
import queue

# for getting timestamps - log-getter related
import datetime
import time

# graph plotting lib imports
import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2TkAgg
from matplotlib.figure import Figure
import matplotlib.animation as animation
from matplotlib import style
style.use("ggplot")
import numpy as np



# ============== GLOBAL PARAMS FOR THREAD-EVENT HANDLING ===============================

# queue to exchange data between GUI and feature-engine
gui_queue = queue.Queue()
# queue to exchange data between log-getter daemon and feature-engine
log_queue = queue.Queue()
# queue to exchange data between feature-engine and DNN
engine_dnn_queue = queue.Queue()
# queue to exchange data between DNN and GUI
dnn_gui_queue = queue.Queue()

# event to start/stop the feature-engine daemon
scan_event = threading.Event()
# event to signal the gui to refresh itself after editing something on it
gui_event = threading.Event()
# event to signal when to dump logs into a file - based on user requirement
log_event = threading.Event()
# event to signal for the logging-daemon to start/stop
run_log_event = threading.Event()
# event to signal DNN thread ready for predictions - only used during the start
dnn_ready_event = threading.Event()
#=======================================================================================

# bool indicators to keep track of running daemons when scan window is re-instantiated
sniffer_running = False
gui_running = False
log_getter_running = False
dnn_running = False

# Main frontend for the IDS
class MainWindow(tk.Tk):

    scan_running = False
    selected_attacks = []

    # the main class is mostly going to be just a constructor
    def __init__(self, *args, **kwargs):
        super(MainWindow, self).__init__(*args, **kwargs)

        # setup some window parameters
        self.title("IDSv1.0")
        self.geometry("1024x768")
        self.minsize(width=1024, height=768)

        # --------------- tool bar ----------------------------
        self.toolbar = tk.Frame(self, bg="gray")
        self.open_button = tk.Button(self.toolbar, text="Open")
        self.open_button.pack(side="left", padx=4, pady=2)
        self.toolbar.pack(side="top", fill="x")

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
        
        # --------------- satus bar ---------------------------
        self.status_var = tk.StringVar()
        self.status_var.set("No Scan Started")
        self.status_bar_main = tk.Label(self, textvar=self.status_var, bd=1, relief="sunken", anchor="w")
        self.status_bar_main.pack(side="bottom", fill="x")

        # ------------- THE GRID LAYOUT CODE ------------------
        # configuring the grid layout
        # build the main frame with border
        self.main_frame = tk.Frame(self, bd=1, bg="gray")
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10, ipadx=10, ipady=10)
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.columnconfigure(1, weight=1)
        self.main_frame.rowconfigure(0, weight=1)
        self.main_frame.rowconfigure(1, weight=1)

        # --------------- scan button ------------------------
        self.scan_button = ttk.Button(self.main_frame, text="Start Scan", command=self.scan_routine)
        self.scan_button.grid(row=1, column=1, padx=20, pady=20, sticky="SE")

        # --------------- exit button ------------------------
        self.exit_button = ttk.Button(self.main_frame, text="Exit", command=self.exit_routine)
        self.exit_button.grid(row=1, column=0, padx=20, pady=20, sticky="SW")

        # --------------- the text box for information
        self.NORMAL_FONT = ("TimesNewRoman", 12, "italic")
        self.message_text_box = tk.Text(self.main_frame, padx=10, pady=10, font=self.NORMAL_FONT, bg="lightgray", height=30)
        self.message_text = "Welcome to IDS v1.0\n\nPlease select the attacks to detect and hit the \"Start Scan\" button.\n"
        self.message_text += "This program gives close to real-time performance when scanning live traffic on your host. It uses raw sockets, therefore, listens to all the interfaces for IP packets.\n"
        self.message_text += "It detects attacks using predictions from a Deep Neural Network engine that runs in the background, and relies on the feature-extraction engine to provide it with features from live traffic."
        self.message_text += "It then makes predictions about each flow of traffic received by the host, and displays them on the screen.\n\n\n\n\n\n\n\n\n"
        self.message_text_box.grid(row=0, column=1,padx=5, pady=5, sticky="NE")
        self.message_text_box.insert(tk.INSERT, self.message_text)
        self.message_text_box.insert(tk.END, "Author: Noor Muhammad Malik")
        self.message_text_box.configure(state="disabled")


        # ---------------- the checkboxes frame -----------------------------------------
        self.check_frame = tk.Frame(self.main_frame)
        self.check_frame.grid(row=0, column=0, padx=5, pady=5, sticky="NW", ipady=5, ipadx=5)

        # add the title label
        self.select_attack_label = tk.Label(self.check_frame, text="Select the attacks to detect by the IDS, for details of the attack, see the help section.", font=("TimesNewRoman", 12, "italic"))
        self.select_attack_label.pack(padx=10, pady=5)
        # adding checkbuttons for each individual attack
        self.dos_hulk_var = tk.StringVar(self.check_frame)
        self.dos_hulk_var.set("")
        self.dos_hulk_box = ttk.Checkbutton(self.check_frame, text="Detect Hulk DoS Attack", command=self.update_hulk_dos,
        variable=self.dos_hulk_var, onvalue="Hulk DoS Attack", offvalue="" )
        self.dos_hulk_box.pack(anchor="w", padx=10, pady=5)

        self.dos_goldeneye_var = tk.StringVar(self.check_frame)
        self.dos_goldeneye_var.set("")
        self.dos_goldeneye_box = ttk.Checkbutton(self.check_frame, text="Detect GoldenEye DoS Attack", command=self.update_goldeneye_dos,
        variable=self.dos_goldeneye_var, onvalue="GoldenEye DoS Attack", offvalue="")
        self.dos_goldeneye_box.pack(anchor="w", padx=10, pady=5)

        self.heartbleed_var = tk.StringVar(self.check_frame)
        self.heartbleed_var.set("")
        self.heartbleed_box = ttk.Checkbutton(self.check_frame, text="Detect HeartBleed Attack", command=self.update_heartbleed,
        variable=self.heartbleed_var, onvalue="HeartBleed Attack", offvalue="")
        self.heartbleed_box.pack(anchor="w", padx=10, pady=5)

        self.dos_slowhttp_var = tk.StringVar(self.check_frame)
        self.dos_slowhttp_var.set("")
        self.dos_slowhttp_box = ttk.Checkbutton(self.check_frame, text="Detect SlowHTTP DoS Attack", command=self.update_slowhttp_dos,
        variable=self.dos_slowhttp_var, onvalue="SlowHTTP DoS Attack", offvalue="")
        self.dos_slowhttp_box.pack(anchor="w", padx=10, pady=5)

        self.dos_slowloris_var = tk.StringVar(self.check_frame)
        self.dos_slowloris_var.set("")
        self.dos_slowloris_box = ttk.Checkbutton(self.check_frame, text="Detect Slowloris DoS Attack", command=self.update_slowloris_dos,
        variable=self.dos_slowloris_var, onvalue="Slowloris DoS Attack", offvalue="")
        self.dos_slowloris_box.pack(anchor="w", padx=10, pady=5)

        self.patator_ssh_var = tk.StringVar(self.check_frame)
        self.patator_ssh_var.set("")
        self.patator_ssh_box = ttk.Checkbutton(self.check_frame, text="Detect SSH-Patator Attack", command=self.update_ssh_patator,
        variable=self.patator_ssh_var, onvalue="SSH-Patator Attack", offvalue="")
        self.patator_ssh_box.pack(anchor="w", padx=10, pady=5)

        self.patator_ftp_var = tk.StringVar(self.check_frame)
        self.patator_ftp_box = ttk.Checkbutton(self.check_frame, text="Detect FTP-Patator Attack", command=self.update_ftp_patator,
        variable=self.patator_ftp_var, onvalue="FTP-Patator Attack", offvalue="")
        self.patator_ftp_box.pack(anchor="w", padx=10, pady=5)

        self.web_var = tk.StringVar(self.check_frame)
        self.web_var.set("")
        self.web_box = ttk.Checkbutton(self.check_frame, text="Detect Web Attack", command=self.update_web,
        variable=self.web_var, onvalue="Web Attack", offvalue="")
        self.web_box.pack(anchor="w", padx=10, pady=5)

        self.infiltration_var = tk.StringVar(self.check_frame)
        self.infiltration_var.set("")
        self.infiltration_box = ttk.Checkbutton(self.check_frame, text="Detect Infiltration Attack", command=self.update_infiltration,
        variable=self.infiltration_var, onvalue="Infiltration Attack", offvalue="")
        self.infiltration_box.pack(anchor="w", padx=10, pady=5)

        self.bot_var = tk.StringVar(self.check_frame)
        # self.bot_var.set("")
        self.bot_box = ttk.Checkbutton(self.check_frame, text="Detect Botnet Attack", command=self.update_bot,
        variable=self.bot_var, onvalue="Botnet Attack", offvalue="")
        self.bot_box.pack(anchor="w", padx=10, pady=5)

        self.portscan_var = tk.StringVar(self.check_frame)
        # self.portscan_var.set("")
        self.portscan_box = ttk.Checkbutton(self.check_frame, text="Detect PortScan Attack", command=self.update_portscan,
        variable=self.portscan_var, onvalue="PortScan Attack", offvalue="")
        self.portscan_box.pack(anchor="w", padx=10, pady=5)

        self.ddos_var = tk.StringVar(self.check_frame)
        # self.ddos_var.set("")
        self.ddos_box = ttk.Checkbutton(self.check_frame, text="Detect DDoS Attack", command=self.update_ddos,
        variable=self.ddos_var, onvalue="DDoS Attack")
        self.ddos_box.pack(anchor="w", padx=10, pady=5)

        self.select_all_var = tk.StringVar(self.check_frame)
        self.select_all_box = tk.Checkbutton(self.check_frame, text="Select All", command=self.select_all_method,
        variable=self.select_all_var, onvalue="all", offvalue="")
        self.select_all_box.pack(anchor="w", padx=10, pady=20)
    # open a new log file for analysis
    # ADD THIS FUNCTIONALITY!

    def select_all_method(self):
        attacks = MainWindow.selected_attacks
        # if the box is checked
        if self.select_all_var.get() == "all":
            self.ddos_var.set("DDoS Attack")
            # if the attack isn't already in list, add it, otherwise it's in the list anyway
            if "DDoS Attack" not in attacks:
                MainWindow.selected_attacks.append("DDoS Attack")
            self.portscan_var.set("PortScan Attack")
            if "PortScan Attack" not in attacks:
                MainWindow.selected_attacks.append("PortScan Attack")
            self.bot_var.set("Botnet Attack")
            if "Botnet Attack" not in attacks:
                MainWindow.selected_attacks.append("Botnet Attack")
            self.infiltration_var.set("Infiltration Attack")
            if "Infiltration Attack" not in attacks:
                MainWindow.selected_attacks.append("Infiltration Attack")
            self.web_var.set("Web Attack")
            if "Web Attack" not in attacks:
                MainWindow.selected_attacks.append("Web Attack")
            self.patator_ftp_var.set("FTP-Patator Attack")
            if "FTP-Patator" not in attacks:
                MainWindow.selected_attacks.append("FTP-Patator Attack")
            self.patator_ssh_var.set("SSH-Patator Attack")
            if "SSH-Patator" not in attacks:
                MainWindow.selected_attacks.append("SSH-Patator Attack")
            self.dos_slowloris_var.set("Slowloris DoS Attack")
            if "Slowloris DoS Attack" not in attacks:
                MainWindow.selected_attacks.append("Slowloris DoS Attack")
            self.dos_slowhttp_var.set("SlowHTTP DoS Attack")
            if "SlowHTTP Attack" not in attacks:
                MainWindow.selected_attacks.append("SlowHTTP DoS Attack")
            self.heartbleed_var.set("HeartBleed Attack")
            if "HeartBleed Attack" not in attacks:
                MainWindow.selected_attacks.append("HeartBleed Attack")
            self.dos_goldeneye_var.set("GoldenEye DoS Attack")
            if "GoldenEye DoS Attack" not in attacks:
                MainWindow.selected_attacks.append("GoldenEye DoS Attack")
            self.dos_hulk_var.set("Hulk DoS Attack")
            if "Hulk DoS Attack" not in attacks:
                MainWindow.selected_attacks.append("Hulk DoS Attack")
        else:
            # clear the selected attacks array
            MainWindow.selected_attacks = []
            # clear all the buttons
            self.dos_hulk_var.set("")
            self.dos_goldeneye_var.set("")
            self.heartbleed_var.set("")
            self.dos_slowhttp_var.set("")
            self.dos_slowloris_var.set("")
            self.patator_ssh_var.set("")
            self.patator_ftp_var.set("")
            self.web_var.set("")
            self.infiltration_var.set("")
            self.bot_var.set("")
            self.portscan_var.set("")
            self.ddos_var.set("")

    # routine(s) to update selected attacks
    def update_hulk_dos(self):
        # if attack is not in the list, add it, and if it is already added, remove it
        if "Hulk DoS Attack" not in MainWindow.selected_attacks:
            MainWindow.selected_attacks.append(self.dos_hulk_var.get())
        else:
            MainWindow.selected_attacks.remove("Hulk DoS Attack")

    def update_goldeneye_dos(self):
        if "GoldenEye DoS Attack" not in MainWindow.selected_attacks:
            MainWindow.selected_attacks.append(self.dos_goldeneye_var.get())
        else:
            MainWindow.selected_attacks.remove("GoldenEye DoS Attack")

    def update_heartbleed(self):
        if "HeartBleed Attack" not in MainWindow.selected_attacks:
            MainWindow.selected_attacks.append(self.heartbleed_var.get())
        else:
            MainWindow.selected_attacks.remove("HeartBleed Attack")

    def update_slowhttp_dos(self):
        if ("SlowHTTP DoS Attack" not in MainWindow.selected_attacks):
            MainWindow.selected_attacks.append(self.dos_slowhttp_var.get())
        else:
            MainWindow.selected_attacks.remove("SlowHTTP DoS Attack")

    def update_slowloris_dos(self):
        if ("Slowloris DoS Attack" not in MainWindow.selected_attacks):
            MainWindow.selected_attacks.append(self.dos_slowloris_var.get())
        else:
            MainWindow.selected_attacks.remove("Slowloris DoS Attack")
    
    def update_ssh_patator(self):
        if ("SSH-Patator Attack" not in MainWindow.selected_attacks):
            MainWindow.selected_attacks.append(self.patator_ssh_var.get())
        else:
            MainWindow.selected_attacks.remove("SSH-Patator Attack")

    def update_ftp_patator(self):   
        if ("FTP-Patator Attack" not in MainWindow.selected_attacks):
            MainWindow.selected_attacks.append(self.patator_ftp_var.get())
        else:
            MainWindow.selected_attacks.remove("FTP-Patator Attack")

    def update_web(self):    
        if ("Web Attack" not in MainWindow.selected_attacks):
            MainWindow.selected_attacks.append(self.web_var.get())
        else:
            MainWindow.selected_attacks.remove("Web Attack")

    def update_infiltration(self):
        if ("Infiltration Attack" not in MainWindow.selected_attacks):
            MainWindow.selected_attacks.append(self.infiltration_var.get())
        else:
            MainWindow.selected_attacks.remove("Infiltration Attack")

    def update_bot(self):
        if ("Botnet Attack" not in MainWindow.selected_attacks):
            MainWindow.selected_attacks.append(self.bot_var.get())
        else:
            MainWindow.selected_attacks.remove("Botnet Attack")

    def update_portscan(self):
        if ("PortScan Attack" not in MainWindow.selected_attacks):
            MainWindow.selected_attacks.append(self.portscan_var.get())
        else:
            MainWindow.selected_attacks.remove("PortScan Attack")

    def update_ddos(self):
        if ("DDoS Attack" not in MainWindow.selected_attacks):
            MainWindow.selected_attacks.append(self.ddos_var.get())
        else:
            MainWindow.selected_attacks.remove("DDoS Attack")

            
    # exit routine made separate to handle anything just in case
    def exit_routine(self):
        response = tkinter.messagebox.askquestion("Exit", "Are you sure you want to exit?")
        if response == "yes":
            self.destroy()

    # scan routine is used to handle whatever
    def scan_routine(self):
        if len(MainWindow.selected_attacks) == 0:
            tkinter.messagebox.showerror("No Attacks Selected", "No attack selected, please select one or more attack and press the button again.")
            return
        if not MainWindow.scan_running:
            response = tkinter.messagebox.askquestion("Scan", "Are you sure you want to start the scan?")
            if response == "yes":
                MainWindow.scan_running = True
                self.scan_window = ScanWindow(self)
                self.status_var.set("Scan Running")
                
        else:
            tkinter.messagebox.showerror("Already Running","A scan window is already running. Close it to open another one.")

    def destroy(self):
        if MainWindow.scan_running:
            response = tkinter.messagebox.askquestion("Exit", "A scan is running, are you sure you want to exit?")
            if response == "yes":
                # destroy the scan window
                self.scan_window.destroy()
                # destroy the main window
                super(MainWindow, self).destroy()
            else:
                return
        else:
            super(MainWindow,self).destroy()


# GUI of the Scan Window
class ScanWindow(tk.Toplevel):
    def __init__(self, master, *args, **kwargs):
        super(ScanWindow, self).__init__(*args, **kwargs)

        # set window parameters
        self.title("Scan Window")
        self.geometry("1000x600")
        self.minsize(width=800, height=600)

        # ------------- menu bar -------------------
        self.menu_bar = tk.Menu(self)
        self.config(menu=self.menu_bar)
        self.sub_menu_file = tk.Menu(self.menu_bar)
        self.menu_bar.add_cascade(label="File", menu=self.sub_menu_file)
        self.sub_menu_file.add_command(label="Exit", command=self.destroy)
        self.sub_menu_scan = tk.Menu(self.menu_bar)
        self.menu_bar.add_cascade(label="Scan", menu=self.sub_menu_scan)
        self.sub_menu_scan.add_command(label="Start Scan", command=self.start_scan_routine)
        self.sub_menu_scan.add_command(label="Stop Scan", command=self.stop_scan_routine)
        self.sub_menu_view = tk.Menu(self.menu_bar)
        self.menu_bar.add_cascade(label="View", menu=self.sub_menu_view)
        self.sub_menu_view.add_command(label="Live Error Graph", command=self.graph_routine)
        self.sub_menu_help = tk.Menu(self.menu_bar)
        self.menu_bar.add_cascade(label="Help", menu=self.sub_menu_help)
        self.sub_menu_help.add_command(label="Show basic help", command=self.help_routine)

        # --------------- tool bar ----------------------------
        self.toolbar = tk.Frame(self, bg="gray")
        self.start_icon = tk.PhotoImage(file="frontend/res/start.png")
        self.start_scan_button = tk.Button(self.toolbar,image=self.start_icon , command=self.start_scan_routine)
        self.start_scan_button.pack(side="left", padx=4, pady=2)
        self.stop_icon = tk.PhotoImage(file="frontend/res/stop.png")
        self.stop_scan_button = tk.Button(self.toolbar, image=self.stop_icon, command=self.stop_scan_routine)
        self.stop_scan_button.pack(side="left", padx=4, pady=2)
        self.save_icon = tk.PhotoImage(file="frontend/res/save.png")
        self.save_button = tk.Button(self.toolbar, image=self.save_icon, command=self.save_log_routine)
        self.save_button.pack(side="left", padx=15, pady=2)       
        self.toolbar.pack(side="top", fill="x")
        # -------------- main frame ----------------
        # it will handle 3 frames
        self.main_frame = tk.Frame(self, bg="gray")
        self.main_frame.pack(side="top",fill="both", expand = True, padx=10, pady=5, ipadx=10, ipady=10)

        self.LARGE_FONT = ("TimesNewRoman", 16)

                # live flow-data frame
        self.flow_data_frame = tk.Frame(self.main_frame, bg="gray")
        self.flow_data_frame.grid(row=0, column=0, padx=10, pady=10, ipadx=10, ipady=10)
        self.flow_data_label = tk.Label(self.flow_data_frame, text="Live Flow Data Capture", bg="gray", font=self.LARGE_FONT)
        self.flow_data_label.pack()
        self.flow_data_box = tk.scrolledtext.ScrolledText(self.flow_data_frame, width=50, height=30)
        self.flow_data_box.pack() 

        # the frame to hold the attack flows info
        self.attack_flows_frame = tk.Frame(self.main_frame, bg="gray")
        self.attack_flows_frame.grid(row=0, column=1, padx=10, pady=10, ipadx=10, ipady=10)
        self.attack_flows_label = tk.Label(self.attack_flows_frame, text="Attack Flows Detected", bg="gray", font=self.LARGE_FONT)
        self.attack_flows_label.pack()
        self.attack_flows_text = tk.scrolledtext.ScrolledText(self.attack_flows_frame, width=50, height=30)
        self.attack_flows_text.pack()

        # selected attacks frame
        self.attack_selected_frame = tk.Frame(self.main_frame, bg="gray")
        self.attack_selected_frame.grid(row=0, column=2, padx=10, pady=10, ipadx=10, ipady=10, sticky="nsew")
        self.attack_selected_label = tk.Label(self.attack_selected_frame, text="Selected Attack(s)", bg="gray", font=self.LARGE_FONT)
        self.attack_selected_label.pack()
        self.attack_selected_text = tk.Text(self.attack_selected_frame, width=40, height=30)
        # retrieve the list of attacks from main window
        self.attacks_list = MainWindow.selected_attacks
        # insert each attack name in the scan window
        for each_attack in self.attacks_list:
            self.attack_selected_text.insert(tk.END, each_attack + "\n")
        self.attack_selected_text.pack()
        self.attack_selected_text.configure(state="disabled")


        # the information box feature if the verbose mode is on in the settings
        # maybe implement later, too much to do!


        # -------------- status frame --------------
        self.status_frame = tk.Frame(self, bg="lightgray", bd=2)
        self.status_frame.pack(side="bottom",anchor="s", fill="x", padx = 5, pady = 5, ipadx = 2, ipady=2)

        # ------------- progress bar ---------------
        self.progress_bar = ttk.Progressbar(self.status_frame,
        orient="horizontal", length=300,
        mode="indeterminate")
        self.progress_bar.pack(side="left")
        self.progress_bar.step(10)
        self.progress_bar.start(10)

        # ------------- status bar -----------------
        self.status_var = tk.StringVar(self.status_frame)
        self.status_var.set("Scanning...")
        self.status_bar = tk.Label(self.status_frame, textvar=self.status_var, padx=20)
        self.status_bar.pack(side="left", before=self.progress_bar)



        global sniffer_running, gui_running, log_getter_running, dnn_running
        # ------------ THREADING CODE ----------------

        # same thing for log_getter thread
        if not log_getter_running:
            self.log_getter_thread = threading.Thread(target=self.log_getter_daemon, daemon=True, name="Log Getter Thread")
            self.log_getter_thread.start()
            log_getter_running = True

        else:
            run_log_event.set()

        # if a sniffer thread wasn't started before, start it
        if not sniffer_running:
            self.sniffer_thread = threading.Thread(target=self.sniffer, daemon=True, name="Sniffer Thread")
            self.sniffer_thread.start()
            sniffer_running = True
        # else, resume the same thread!
        else:
            scan_event.set()

        # same thing for the GUI thread
        # GUI event is only set by the sniffer thread when 
        # it puts some data on the queue
        if not gui_running:
            self.refresh_gui_thread = threading.Thread(target=self.refresh_gui, args=(master, ), daemon=True, name="Refresh GUI Thread")
            self.refresh_gui_thread.start()
            gui_running = True
        else:
            gui_event.set()


        # the DNN thread
        if not dnn_running:
            self.dnn_thread = threading.Thread(target=self.dnn_routine, daemon=True, name="DNN Thread")
            self.dnn_thread.start()
            dnn_running = True

    # event handler for save log button
    def save_log_routine(self):

        # if the feature engine is running, don't allow to log the data
        if scan_event.is_set():
            tk.messagebox.showerror("Scan Running", "Can't log data when a scan is running.\nStop the running scan and try again.", parent=self)
            return

        global log_event
        response = tk.messagebox.askquestion("Save Log to File", "Are you sure you want to save the logs to a file?", parent=self)
        if response == "yes":
            # set the event to allow the log_getter daemon to dump the logs into a disk file 
            log_event.set()            
        else:
            return

    # event handlers for start/stop buttons
    def stop_scan_routine(self):
        # clear the event flag to stop scanning
        if scan_event.is_set():
            scan_event.clear()

        # stop the progress bar
        self.progress_bar.stop()
        self.status_var.set("Scan Stopped")
   
    def start_scan_routine(self):
        # set the event flag to start scanning
        if not scan_event.is_set():
            scan_event.set()

        # start the progress bar again
        self.progress_bar.start(10)
        self.status_var.set("Scanning...")

    # the thread for running feature-engine daemon
    def sniffer(self):
        global scan_event, gui_event, gui_queue, log_queue, run_log_event, engine_dnn_queue, dnn_ready_event
        self.feature_engine = flowmeter.FlowMeter(scan_event, gui_queue, gui_event, log_queue, run_log_event, engine_dnn_queue, dnn_ready_event)
        # if this is the first time running the scan, continue
        if not MainWindow.scan_running:
            scan_event.set()
            self.feature_engine.run_flow_meter()

        # else, a scan thread is already running, but paused,
        # use the same thread, and resume it
        else:
            scan_event.set()
            self.feature_engine.run_flow_meter()

    # the thread for running the DNN daemon
    def dnn_routine(self):
        global dnn_ready_event, engine_dnn_queue, dnn_gui_queue, gui_event
        self.dnn_engine = dnnengine.DNNEngine(MainWindow.selected_attacks, dnn_ready_event, engine_dnn_queue, dnn_gui_queue, gui_event)
        self.dnn_engine.run_dnn_engine()

    # the thread responsible for refreshing the GUI 
    def refresh_gui(self, master):
        global gui_queue
        global gui_event, dnn_ready_event, dnn_gui_queue
        # make the refresh_gui code independent of the current scan window object
        # since if the window is closed (object deleted) it leaves the thread
        # with a dangling 'self' pointer and raises an exception
        # wait for the dnn to get ready
        dnn_ready_event.wait()
        while True:    
            # wait for data to be ready to start printing
            gui_event.wait()        
            # handle if event raised by feature-engine   
            try:
                print("[DEBUG-GUI] engine - in try")
                # see if the event was raised by the feature-engine
                q_data = gui_queue.get(block=False)
            except queue.Empty:
                print("[DEBUG-GUI] engine - in except")
                pass
            else:
                print("[DEBUG-GUI] engine - in else")
                master.scan_window.flow_data_box.insert(tk.END, "{} : {} [{}, {}, {}]\n".format(q_data[0], q_data[1], q_data[2], q_data[3], q_data[4]))
                # master.scan_window.flow_data_box.insert(tk.END, q.get() + "\n")
                master.scan_window.flow_data_box.see(tk.END)
                master.scan_window.update()

            # handle if event raised by dnn-engine
            try:
                print("[DEBUG-GUI] dnn - in try")
                q_data = dnn_gui_queue.get(block=False)
            except queue.Empty:
                print("[DEBUG-GUI] dnn - in except")
                pass
            else:
                print("[DEBUG-GUI] dnn - in else")
                master.scan_window.attack_flows_text.insert(tk.END, "{} : {}\n".format(q_data[0], q_data[1]))
                master.scan_window.attack_flows_text.see(tk.END)
                master.scan_window.update()

            # if the q's are empty, block the refresh thread until there's data in q's
            # to save processing time
            if gui_queue.empty() and dnn_gui_queue.empty():
                gui_event.clear()

    # the code for the log-getter daemon, resonsible for logging flow data
    def log_getter_daemon(self):
        global log_event
        global log_queue
        global run_log_event
        # empty buffer to be filled by the daemon
        log_buffer = []

        # dump_log subroutine as a sub-thread for log-getter
        def dump_logs(log_event, self):
            nonlocal log_buffer
            while True:
                # wait for log_event to occur
                log_event.wait()
                # make sure the buffer has something before dumping into the log file
                if len(log_buffer) > 0:
                    print("[DEBUG-LogGetter] writing log")
                    # name the file as the current time-stamp for identification
                    with open("logs/ids_log_{}.log".format(datetime.datetime.fromtimestamp(time.time()).strftime("%Y-%m-%d_%H:%M:%S")), "w") as log_file:
                        for each_entry in log_buffer:
                            log_file.write(each_entry + "\n")
                    print("[DEBUG-LogGetter] done writing log")
                    tkinter.messagebox.showinfo("Log Written", "Program finished logging data.", parent=self)
                    # clear the event
                    log_event.clear()
                    # clear the log buffer BUGGGG!!
                    log_buffer = []
                else:
                    tkinter.messagebox.showerror("Empty Buffer", "There is nothing to log, wait for some traffic data!", parent=self)
                    log_event.clear()

        # run the dump_logs daemon in background waiting for the log_event
        dump_logs_daemon = threading.Thread(target=dump_logs, args=(log_event, self), daemon=True, name="Dump Logs Daemon")
        dump_logs_daemon.start()

        while True:
            # wait for the feature-engine thread to signal data
            print("[DEBUG-LogGetter] waiting")
            run_log_event.wait()
            while run_log_event.is_set():

                # get the data from the log_queue and store it in the buffer
                log_buffer.append(log_queue.get())
                print("[DEBUG-LogGetter] buffered something")

                # if the queue is empty, clear the event and wait for it to happen in next iteration
                if log_queue.empty():
                    run_log_event.clear()

    # the code for drawing a live graph
    def graph_routine(self):

        # some local event functions
        def exit_button():
            self.graph_window.destroy()

        # the main graphing window to pop-up
        self.graph_window = tk.Toplevel(master=self)
        self.graph_window.title("RealTime DNN Statistics Graphs")

        x = [1, 2, 3]
        y = [0.1, 0.3, 0.5]

        def tick_method(i):
            nonlocal x, y, fig_prec_plot, fig_recall_plot
            # to start/stop the graph animation along with the scan
            global scan_event

            # if the scan is not running, don't do anything!
            if not scan_event.is_set():
                return
            # otherwise, just continue with the usual stuff!
            else:
                # add a random value to the array every second
                if len(x) > 10:
                    x.remove(x[0])
                x.append(x[len(x) - 1] + 1)
                if len(y) > 10:
                    y.remove(y[0])
                y.append(np.random.randint(1, 10)/10.0)
                fig_prec_plot.clear()
                fig_prec_plot.plot(x, y)
                fig_prec_plot.set(xlabel="time (s)", ylabel="Rand(int)", title="Precision RealTime")
                limits = fig_prec_plot.axis()
                fig_prec_plot.axis([limits[0], limits[1], 0, 1])

                fig_recall_plot.clear()
                fig_recall_plot.plot(x, y)
                fig_recall_plot.set(xlabel="time (s)", ylabel="Rand(int)", title="Recall RealTime")
                limits=fig_recall_plot.axis()
                fig_recall_plot.axis([limits[0], limits[1], 0, 1])

        # the main graphing frame, for tkinter purposes
        graph_frame = tk.Frame(self.graph_window)
        graph_frame.pack(side="top")

        # the big 'figure' object for matplotlib purposes
        main_figure = Figure(figsize=(10, 5), dpi=100)

        # the precision subplot on the main_figure
        fig_prec_plot = main_figure.add_subplot(121)
        fig_prec_plot.plot(x, y)
        fig_prec_plot.set(xlabel="time (s)", ylabel="Rand(int)", title="Precision RealTime")
        limits = fig_prec_plot.axis()
        fig_prec_plot.axis([limits[0], limits[1], 0, 1])
        # the recall subplot on the main_figure
        fig_recall_plot = main_figure.add_subplot(122)
        fig_recall_plot.plot(x, y)
        fig_recall_plot.set(xlabel="time (s)", ylabel="Rand(int)", title="Recall RealTime")
        limits = fig_recall_plot.axis()
        fig_recall_plot.axis([limits[0], limits[1], 0, 1])

        # draw stuff on the canvas to link tkinter and matplotlib figure
        canvas = FigureCanvasTkAgg(main_figure, graph_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(side="top", expand=True)
        toolbar = NavigationToolbar2TkAgg(canvas, graph_frame)
        toolbar.update()
        canvas._tkcanvas.pack(side="bottom", fill="both", expand=True)
        # make the graph come alive!
        ani = animation.FuncAnimation(main_figure, tick_method, interval=1000)
        
        self.graph_exit_button = tk.Button(master=self.graph_window, text="Exit", command=exit_button)
        self.graph_exit_button.pack(side="bottom")
        self.graph_window.mainloop()

    # the code for displaying help
    def help_routine(self):
        pass

    def destroy(self):
        if scan_event.is_set():
            response = tkinter.messagebox.askquestion("Exit", "A scan is in progress, are you sure you want to exit?", parent=self)
            if response == "yes":
                pass
            else:
                return
        # let the main window know scan window is no longer running
        MainWindow.scan_running = False
        # stop the progress bar to avoid any runtime-errors
        self.progress_bar.stop()
        # clear the event flags
        scan_event.clear()
        gui_event.clear()
        # destroy the window
        super(ScanWindow, self).destroy()

# generate the main gui window
main_gui = MainWindow()
# refresh the GUI
main_gui.mainloop()