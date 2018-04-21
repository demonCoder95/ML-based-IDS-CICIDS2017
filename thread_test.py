import threading
import time



# def sleeper(n, name):
#     print("{} is going to sleep for {} seconds.".format(name, n))
#     time.sleep(n)
#     print("{} has woken up from sleep.".format(name))

# threads_list = []

# start = time.time()

# for i in range(5):
#     t = threading.Thread(target=sleeper, 
#                         name = 'thread{}'.format(i),
#                         args = (5, 'thread{}'.format(i)))
#     threads_list.append(t)

#     t.start()
#     print('{} has started'.format(t.name))

# for t in threads_list:
#     # wait for all threads to finish
#     t.join()

# end = time.time()
# print("Time taken: {}".format(end-start))

# print("All threads finished execution")


#--------------------------------------


# import tkinter as tk

# def create_gui():
#     root = tk.Tk()
#     label = tk.Label(root, text="GUI Created")
#     label.pack(padx=10, pady=10)
#     quit_button = tk.Button(root, text="quit", command=root.quit)
#     quit_button.pack()
#     root.mainloop()

# # just to be safe, make the threads daemon, so they get terminated
# # along with the main thread
# t = threading.Thread(target=create_gui, daemon=True)
# t.start()

# t.join()
# print("The GUI thread ended!")