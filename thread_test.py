import threading
import time
import queue
import numpy as np



# class MyThread (threading.Thread):
#     def __init__(self, threadID, name, *args, **kwargs):
#         # invoke the parent class instructor
#         super(MyThread, self).__init__(*args, **kwargs)
#         # set some instance varaibles
#         self.threadID = threadID
#         self.name = name

#     def run(self, *args, **kwargs):
#         # print some debug message
#         print("[DEBUG] Starting " + self.name)
#         # call thread class's run method
#         super(MyThread, self).run(*args, **kwargs)    

#         # for now, simply run the front-end renderer in the thread

#         # # acquire the thread lock in case of sharing variables
#         # threadLock.acquire()
#         # threadLock.release()

# threadLock = threading.Lock()


# def flag():
#     time.sleep(3)
#     event.set()
#     print("Starting countdown")
#     time.sleep(7)
#     print("event is clear")
#     event.clear()


# def start_operations():
#     print("waiting for event to happen")
#     event.wait()
#     while event.is_set():
#         print("starting random integer task")
#         x = np.random.randint(1, 30)
#         time.sleep(.5)
#         if x == 29:
#             print("True")

#     print("Event flag is cleared.")

# event = threading.Event()
# t1 = threading.Thread(target=flag)
# t2 = threading.Thread(target=start_operations)

# t1.start()
# t2.start()




# event = threading.Event()

# # a flag to signal the other thread of an event
# event.set()
# event.clear()

# # block the thread until the other thread responds
# event.wait()


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