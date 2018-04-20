import tkinter as tk
import tkinter.messagebox

def do_nothing():
    print("Doing nothing...")

root = tk.Tk()
root.title("IDS v1.0")

def exit_routine():
    # tk.messagebox.showinfo("Scan Info", "The scan is complete!")
    response = tkinter.messagebox.askquestion("Exit", "Are you sure you want to quit?")
    if response == "yes":
        root.quit()


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

# ------------ status bar --------------
status_bar = tk.Label(root, text="Program running...", bd=1, relief="sunken", anchor="w")
status_bar.pack(side="bottom", fill="x")



root.mainloop()