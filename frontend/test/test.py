import tkinter as tk
from tkinter import ttk

# specify the font macro
LARGE_FONT = ("Verdana", 12)

class TestClass(tk.Tk):
    # args -> argument list, variable
    # kwargs -> keyword arguments, dictionary type
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)

        # tk.Tk.iconbitmap(self, default="../res/icon1.ico")

        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        # hold all possible frames to be displayed in the application
        self.frames = {}

        for frame in (StartPage, PageOne, PageTwo):
            current_frame = frame(container, self)
            self.frames[frame] = current_frame
            current_frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame(StartPage)


    def show_frame(self, cont):
        # pull out the frame object
        frame = self.frames[cont]
        # display it to the front
        frame.tkraise()

class StartPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="Start Page", font=LARGE_FONT)
        label.pack(padx=10, pady=10)

        button1 = ttk.Button(self, text="Visit Page 1",
        command= lambda: controller.show_frame(PageOne))
        button1.pack()

        button2 = ttk.Button(self, text="Visit Page 2",
        command= lambda: controller.show_frame(PageTwo))
        button2.pack()

class PageOne(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="Page 1", font=LARGE_FONT)
        label.pack(padx=10, pady=10)

        button1 = ttk.Button(self, text="Back to Home",
        command= lambda: controller.show_frame(StartPage))
        button1.pack()

        button2 = ttk.Button(self, text="Page 2",
        command= lambda: controller.show_frame(PageTwo))
        button2.pack()

class PageTwo(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        label = tk.Label(self, text="Page 2", font=LARGE_FONT)
        label.pack(padx=10, pady=10)

        button1 = ttk.Button(self, text="Back to Home",
        command= lambda: controller.show_frame(StartPage))
        button1.pack()

        button2 = ttk.Button(self, text="Page 1",
        command= lambda: controller.show_frame(PageOne))
        button2.pack()

app = TestClass()
app.mainloop()