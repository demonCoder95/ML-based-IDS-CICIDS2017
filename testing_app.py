import tkinter as tk

import threading



class Application(tk.Tk):
    def __init__(self, *args, **kwargs):
        super(Application, self).__init__(*args, **kwargs)

        self.title("Testing app")
        self.geometry("800x600")

        self.label_var = tk.StringVar(self)
        self.label_var.set("testing...")
        self.test_label = tk.Label(self, textvar=self.label_var)
        self.test_label.pack()

    def fuck_some_shit(self, value):
        self.label_var.set(value)


i = 10

def increment():
    global i
    while i < 1000000000:
        i += 1
    print("thread exited")

t = threading.Thread(target=increment)
app = Application()
t.start()
t.join(3)

app.label_var.set(i)
app.mainloop()