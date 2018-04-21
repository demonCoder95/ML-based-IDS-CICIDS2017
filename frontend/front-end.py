import tkinter as tk
import tkinter.messagebox

def do_nothing():
    print("Doing nothing...")

root = tk.Tk()
root.title("IDS v1.0")
root.geometry("1024x768")

def exit_routine():
    response = tkinter.messagebox.askquestion("Exit", "Are you sure you want to quit?")
    if response == "yes":
        root.quit()

scan_window = None

def render_scan_window():
    status_bar_scan = tk.Label(scan_window, text="Scanning...", bd=1, relief="sunken", anchor="w")
    status_bar_scan.pack(side="bottom", fill="x")

def scan_routine():
    response = tkinter.messagebox.askquestion("Start Scan", "Are you sure you want to start the scan?")
    if response == "yes":
        scan_window = tk.Tk()
        scan_window.title("Scanning...")
        scan_window.geometry("800x600")
        render_scan_window()

# ------------ menu bar ----------------
# create a menu object - serves as the main menu_bar object, a container
menu_bar = tk.Menu(root)
# configure the menu in the root window
root.config(menu=menu_bar)

# create a sub-menu to serve as drop down
sub_menu_file = tk.Menu(menu_bar)
menu_bar.add_cascade(label="File", menu=sub_menu_file)
sub_menu_file.add_command(label="New...", command=do_nothing)
sub_menu_file.add_command(label="Open...", command=do_nothing)
sub_menu_file.add_separator()
sub_menu_file.add_command(label="Exit", command=exit_routine)

# add another item in the menu bar
sub_menu_edit = tk.Menu(menu_bar)
menu_bar.add_cascade(label="Edit", menu=sub_menu_edit)
sub_menu_edit.add_command(label="Redo", command=do_nothing)

# ------------ toolbar -----------------
toolbar = tk.Frame(root, bg="blue")

insert_button = tk.Button(toolbar, text="Insert Image", command=do_nothing)
insert_button.pack(side="left", padx=4, pady=2)

print_button = tk.Button(toolbar, text="Print", command=do_nothing)
print_button.pack(side="left", padx=4, pady=2)

toolbar.pack(side="top", fill="x")

# ------------ status bar - main window --------------
status_bar_main = tk.Label(root, text="Program running...", bd=1, relief="sunken", anchor="w")
status_bar_main.pack(side="bottom", fill="x")

scan_button = tk.Button(root, text="Start Scan", bg="gray", fg="black", command=scan_routine)
scan_button.pack(side="bottom", anchor="e", padx=20, pady=20)


root.mainloop()