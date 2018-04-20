import tkinter as tk


# the main window        
root = tk.Tk()
# set the main window size
root.geometry("800x600")
# set the main window title
root.title("IDS v1.0")

# 
# keep the window running
root.mainloop()


# class Sample:
#     def __init__(self, master):
#         frame = tk.Frame(master)
#         frame.pack()


#         self.print_button = tk.Button(frame, text="Print message", command=self.print_message)
#         self.print_button.pack(side="left")

#         self.quit_button = tk.Button(frame, text="Quit", command=frame.quit)
#         self.quit_button.pack(side="left")

#     def print_message(self):
#         print("Printing stuff")

# ====================mouse-click events

# def left_click(event):
#     print("left")

# def middle_click(event):
#     print("middle")

# def right_click(event):
#     print("right")

# basic_frame = tk.Frame(root, width=300, height=250, bg="gray")
# basic_frame.bind("<Button-1>", left_click)
# basic_frame.bind("<Button-2>", middle_click)
# basic_frame.bind("<Button-3>", right_click)

# basic_frame.pack()
 #============= bindings

# use the bind() function
# def print_name(event):
#     print("I'm noor!")

# button_2 = tk.Button(root, text="Print my name!")
# button_2.bind("<Button-1>", print_name)
# button_2.pack() 

# def print_name():
#     print("I'm noor!")

# binding function to widget
# button_1 = tk.Button(root, text="Print my name", command=print_name)
# button_1.pack()


# ============== grid layout =========================
# stat_title = tk.Label(root, text="Live Flow Statistics")
# stat_title.pack(side="top")

# stat_frame = tk.Frame(root)

# stat_1 = tk.Label(stat_frame, text="packet count", borderwidth=2, relief="groove")
# stat_2 = tk.Label(stat_frame, text="bwd count", borderwidth=2, relief="groove")
# stat_3 = tk.Label(stat_frame, text="fwd count", borderwidth=2, relief="groove")
# stat_4 = tk.Label(stat_frame, text="packet length/s", borderwidth=2, relief="groove")
# stat_5 = tk.Label(stat_frame, text="Testing", borderwidth=2, relief="groove")

# stat_1.grid(row=0, column=0, sticky="N")
# stat_2.grid(row=0, column=1, sticky="N")
# stat_3.grid(row=0, column=2, sticky="N")
# stat_4.grid(row=0, column=3, sticky="N")
# stat_5.grid(row=0, column=4, sticky="N")

# stat_frame.pack()

# box = tk.Checkbutton(stat_frame, text="Show live statistics", bg="gray")
# box.grid(columnspan=2)




#======= PACK LAYOUT =============================

# top_frame = tk.Frame(root, bg="gray")
# # frame stretches across the screen
# top_frame.pack(fill="x")
# top_label = tk.Label(top_frame, text="Select an Attack to detect", bg="gray", fg="black")
# top_label.pack()


# bottom_frame = tk.Frame(root)
# bottom_frame.pack(side="bottom")
# bottom_label = tk.Label(bottom_frame, text="Attack selected")
# bottom_label.pack()

# bottom_button = tk.Button(bottom_frame, text="Button", fg="black", bg="gray")
# bottom_button.pack(side="bottom")