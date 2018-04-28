import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2TkAgg
from matplotlib.figure import Figure

import matplotlib.animation as animation
from matplotlib import style
style.use("ggplot")

import tkinter as tk

import threading
import time
import numpy as np

LARGE_FONT = ("TimesNewRoman", 14)

x = [1, 2, 3]
y = [2, 4, 6]

def tick_method(i):
    global x, y, fig_plot
    # add a random value to the array every second
    if len(x) > 10:
        x.remove(x[0])
    x.append(x[len(x) - 1] + 1)
    if len(y) > 10:
        y.remove(y[0])
    y.append(np.random.randint(1, 10))
    fig_plot.clear()
    fig_plot.plot(x, y)
    fig_plot.set(xlabel="time (s)", ylabel="Rand(int)", title="Plotting RealTime")
    limits = fig_plot.axis()
    fig_plot.axis([limits[0], limits[1], 0, 10])

main_window = tk.Tk()

graph_frame = tk.Frame(main_window)
graph_frame.pack()

graph_label = tk.Label(graph_frame, text="RealTime Graph", font=LARGE_FONT)
graph_label.pack(pady=10, padx=10)

figure = Figure(figsize=(5, 5), dpi=100)
fig_plot = figure.add_subplot(111)
fig_plot.plot(x, y)
fig_plot.set(xlabel="time (s)", ylabel="Rand(int)", title="Plotting RealTime")
limits = fig_plot.axis()
fig_plot.axis([limits[0], limits[1], 0, 10])

canvas = FigureCanvasTkAgg(figure, graph_frame)
canvas.draw()
canvas.get_tk_widget().pack(side="bottom", fill="both", expand=True)

toolbar = NavigationToolbar2TkAgg(canvas, graph_frame)
toolbar.update()
canvas._tkcanvas.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

ani = animation.FuncAnimation(figure, tick_method, interval=10)

main_window.mainloop()