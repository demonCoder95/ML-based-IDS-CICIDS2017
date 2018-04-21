# This script will bind together all elements of the IDS
# Author: Noor Muhammad Malik
# Date: April 21, 2018
# License: None
# =======================================================

# libs for multi-threading support
import threading
import time

# libs for front-end rendering
#import front-end

# libs for feature-engine 
# import feature-engine


class MyThread (threading.Thread):
    def __init__(self, threadID, name):
        # initialize the parent class instructor
        threading.Thread.__init__(self)
        # set some instance varaibles
        self.threadID = threadID
        self.name = name

    def run(self):
        print("[DEBUG] Starting " + self.name)
        
        # for now, simply run the front-end renderer in the thread

        # # acquire the thread lock in case of sharing variables
        # threadLock.acquire()
        # threadLock.release()

threadLock = threading.Lock()

# create new threads
thread1 = MyThread(1, "Thread-1")
thread2 = MyThread(2, "Thread-2")

# Start new threads
thread1.start()
thread2.start()

# wait for threads to complete
thread1.join()
thread2.join()

print("Exiting main...")
