# This module represents all of the Front-end for the IDS and will be
# used in a thread to render the front-end of the IDS
# Author: Noor Muhammad Malik
# Date: April 21, 2018
# =====================================================================

import tkinter as tk 
from tkinter import ttk
import tkinter.messagebox
import tkinter.scrolledtext


import flowmeter
import threading
import queue
import time

q = queue.Queue()
scan_event = threading.Event()
gui_event = threading.Event()

sniffer_running = False
gui_running = False

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
        self.message_text = "Welcome to IDS v1.0\n\nPlease select the attacks to detect and hit the \"Start Scan\" button.\n"
        self.message_text += "This program gives close to real-time performance when scanning live traffic on your host. It uses raw sockets, therefore, listens to all the interfaces for IP packets.\n"
        self.message_text += "It detects attacks using predictions from a Deep Neural Network engine that runs in the background, and relies on the feature-extraction engine to provide it with features from live traffic."
        self.message_text += "It then makes predictions about each flow of traffic received by the host, and displays them on the screen.\n\n\n\n\n\n\n\n\n"

        self.message_field = tk.Message(self.main_frame, justify="left", padx=10, pady=10,
                                    text=self.message_text, relief="sunken", font="TimesNewRoman")
        self.message_field.configure(text=self.message_text + "\nAuthor: Noor Muhammad Malik", font=("TimesNewRoman", 12, "italic"))
        self.message_field.grid(row=0, column=1,padx=5, pady=5, sticky="NE")


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
        self.sub_menu_file.add_command(label="Exit", command=self.exit_routine)
        self.sub_menu_scan = tk.Menu(self.menu_bar)
        self.menu_bar.add_cascade(label="Scan", menu=self.sub_menu_scan)
        self.sub_menu_scan.add_command(label="Start Scan", command=self.start_scan_routine)
        self.sub_menu_scan.add_command(label="Stop Scan", command=self.stop_scan_routine)
        self.sub_menu_help = tk.Menu(self.menu_bar)
        self.menu_bar.add_cascade(label="Help", menu=self.sub_menu_help)
        self.sub_menu_help.add_command(label="Show basic help")

        # --------------- tool bar ----------------------------
        self.toolbar = tk.Frame(self, bg="gray")
        self.start_icon = tk.PhotoImage(file="frontend/res/start.png")
        self.start_scan_button = tk.Button(self.toolbar,image=self.start_icon , command=self.start_scan_routine)
        self.start_scan_button.pack(side="left", padx=4, pady=2)
        self.stop_icon = tk.PhotoImage(file="frontend/res/stop.png")
        self.stop_scan_button = tk.Button(self.toolbar, image=self.stop_icon, command=self.stop_scan_routine)
        self.stop_scan_button.pack(side="left", padx=4, pady=2)
        self.toolbar.pack(side="top", fill="x")

        # -------------- main frame ----------------
        # it will handle 3 frames
        self.main_frame = tk.Frame(self, bg="gray")
        self.main_frame.pack(side="top",fill="both", expand = True, padx=10, pady=5, ipadx=10, ipady=10)

                # live flow-data frame
        self.flow_data_frame = tk.Frame(self.main_frame, bg="gray")
        self.flow_data_frame.grid(row=0, column=0, padx=10, pady=10, ipadx=10, ipady=10)
        self.flow_data_label = tk.Label(self.flow_data_frame, text="Live Flow Data Capture", bg="gray")
        self.flow_data_label.pack()
        self.flow_data_box = tk.scrolledtext.ScrolledText(self.flow_data_frame, width=40, height=30)
        self.flow_data_box.pack() 

        # the frame to hold the attack flows info
        self.attack_flows_frame = tk.Frame(self.main_frame, bg="gray")
        self.attack_flows_frame.grid(row=0, column=1, padx=10, pady=10, ipadx=10, ipady=10)
        self.attack_flows_label = tk.Label(self.attack_flows_frame, text="Attack Flows Detected", bg="gray")
        self.attack_flows_label.pack()
        self.attack_flows_text = tk.scrolledtext.ScrolledText(self.attack_flows_frame, width=40, height=30)
        self.attack_flows_text.insert(tk.INSERT, "Attack Flows Detected will go here")
        self.attack_flows_text.pack()

        # selected attacks frame
        self.attack_selected_frame = tk.Frame(self.main_frame, bg="gray")
        self.attack_selected_frame.grid(row=0, column=2, padx=10, pady=10, ipadx=10, ipady=10, sticky="nsew")
        self.attack_selected_label = tk.Label(self.attack_selected_frame, text="Selected Attack(s)", bg="gray")
        self.attack_selected_label.pack()
        self.attack_selected_text = tk.Text(self.attack_selected_frame, width=40, height=20)
        # retrieve the list of attacks from main window
        self.attacks_list = MainWindow.selected_attacks
        # insert each attack name in the scan window
        for each_attack in self.attacks_list:
            self.attack_selected_text.insert(tk.END, each_attack + "\n")
        self.attack_selected_text.pack()
        self.attack_selected_text.configure(state="disabled")

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

        global sniffer_running, gui_running

        # ------------ THREADING CODE ----------------
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

    def sniffer(self):
        global scan_event, gui_event
        self.feature_engine = flowmeter.FlowMeter(q, scan_event, gui_event)
        # if this is the first time running the scan, continue
        if not MainWindow.scan_running:
            scan_event.set()
            self.feature_engine.run_flow_meter()

        # else, a scan thread is already running, but paused,
        # use the same thread, and resume it
        else:
            scan_event.set()
            self.feature_engine.run_flow_meter()

    # the thread responsible for refreshing the GUI 
    def refresh_gui(self, master):
        global q
        global gui_event
        # make the refresh_gui code independent of the current scan window object
        # since if the window is closed (object deleted) it leaves the thread
        # with a dangling 'self' pointer and raises an exception
        while True:    
            # wait for data to be ready to start printing
            gui_event.wait()           
            q_data = q.get()
            master.scan_window.flow_data_box.insert(tk.END, "{} : {}\n".format(q_data[0], q_data[1]))
            # master.scan_window.flow_data_box.insert(tk.END, q.get() + "\n")
            master.scan_window.flow_data_box.see(tk.END)
            master.scan_window.update()

            # if the q is empty, block the refresh thread until there's data in q
            # to save processing time
            if q.empty():
                gui_event.clear()



    def exit_routine(self):
        response = tkinter.messagebox.askquestion("Exit", "Are you sure you want to exit?")
        if response == "yes":
            self.destroy()

    def destroy(self):
        if scan_event.is_set():
            response = tkinter.messagebox.askquestion("Exit", "A scan is in progress, are you sure you want to exit?")
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