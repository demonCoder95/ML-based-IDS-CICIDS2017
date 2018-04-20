import tkinter as tk

root = tk.Tk()

# photos need labels to be printed
photo = tk.PhotoImage(file="res/icon1.png")
label = tk.Label(root, image=photo)
label.pack()

root.mainloop()


# # basic canvas drawings

# main_canvas = tk.Canvas(root, width=200, height=100)
# main_canvas.pack()

# black_line = main_canvas.create_line(0, 0, 200, 50, fill="black")
# red_line = main_canvas.create_line(0, 100, 200, 50, fill="red")

# green_box = main_canvas.create_rectangle(25, 25, 150, 50, fill="green")

# main_canvas.delete(red_line)
# main_canvas.delete("all")
