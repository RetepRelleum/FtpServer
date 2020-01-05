import sys
sys.path.append(sys.path[0]+"/..")
print(sys.path)

from ftpServer import FtpServer

ftpServer=FtpServer(2121,"192.168.1.113")

while True:
    pass

