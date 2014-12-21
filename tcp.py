import socket
import sys
import struct
import time
import select
import argparse


#some of the code are not commented, finished in a rush
class tcp():
    def __init__(self):
        self.author = 'ryan'
    def init(self):
        ## prompt input
        parser = argparse.ArgumentParser(prog='CSEE4119 TCP sever and client program',description=
                "program should invoked like this:\
                sender <filename> <remote_IP> <remote_port> <ack_port_num> <log_filename> <window_size>  \
                receiver <filename> <listening_port> <sender_IP> <sender_port> <log_filename>  \
                sender example:python tcp.py sender cn4119.txt 192.168.90.143 20002 20000 stdout 8  \
                receiver example:python tcp.py receiver copycn4119.txt 20001 127.0.0.1 20000 stdout")
        parser.add_argument('usage', choices={'sender','receiver'}, help='choose from sender or receiver')
        parser.add_argument('args', nargs='*')
        args = parser.parse_args()
        self.usage = args.usage
        self.args=args.args     # args is a list include all the args from input
        print self.usage, self.args
        #initialize sender
        if self.usage == 'sender' and self.args[2].isdigit() and self.args[3].isdigit() and self.args[5].isdigit():
            self.source_port = int(self.args[3])
            self.remote_port = int(self.args[2])
            self.window = int(self.args[5])
            self.dup_count=0
            self.SeqNo = 0
            self.base = 0
            self.addr = (self.args[1], int(self.args[2]))
            self.timeron = False
            self.window=int(self.args[5])
            self.sent=[]                              # the stack of sent yet acked packet
            self.senttime = []
            self.Estimatedrtt = 0
            self.Devrtt = 0
            dir = 'r'

        #initialize receiver
        elif self.usage == 'receiver' and self.args[1].isdigit() and self.args[3].isdigit():
            self.source_port = int(self.args[1])
            self.remote_port = int(self.args[3])
            self.addr = (self.args[2], int(self.args[3]))
            self.Exp=0
            self.acked = 0
            self.ack_seq=0
            dir = 'w'
        else:
            print("port num and window size has to be integer")
            sys.exit()

        # initialize shared variables
        self.rss = 576
        self.fin = False

        #initialize file and deal with file error
        try :self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except socket.error, msg :
            print 'Failed to create socket. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
            sys.exit()
        try:
            self.s.bind(('', self.source_port))
        except socket.error, msg:
            print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
            sys.exit()
        try:
            self.f = open(self.args[0], dir)
            if self.args[4] != "stdout":
                self.logf = open(self.args[4], "w")
                self.logf.writelines("timestamp\tsourceport\tdestport\tseq\tack_seq\tflags\trtt\n")  # logfile format
        except:
            print "file not found"
            sys.exit()

    def checksum(self, pkt, cal = True):
        s = 0
        # loop taking 2 characters at a time
        if len(pkt)%2 == 1:
            pkt = pkt +'0'
        for i in range(0, len(pkt), 2):
            w = (ord(pkt[i])<<8)+ord(pkt[i+1])
            if i == 16 :
                check = w
                continue    # skip checksum itself.
            s = s + w
        s = (s>>16) + (s & 0xffff);
        s = s + (s >> 16);
        #complement and mask to 4 byte short
        s = ~s & 0xffff
        if cal:return s
        elif check == s: return True
        elif check != s: return False


    def pack(self, data, seq=0, ack_seq=0, doff=5, fin=False, syn=False, rst=False,
             psh=False, ack=False, urg=False, urg_pointer=0):  # pack header,calculate the checksum
        offset_res = (doff << 4) + 0
        flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)
        # header in total 4*5=20bytes
        # the ! in the pack format string means network order: network (= big-endian)
        header = struct.pack('!HHLLBBHHH', self.source_port, self.remote_port, seq, ack_seq, offset_res, flags, self.rss, 0, urg_pointer)
        check = self.checksum(header+data)
        header = (self.source_port, self.remote_port, seq, ack_seq, offset_res, flags, self.rss, check, urg_pointer)
        pktheader = struct.pack('!HHLLBBHHH', self.source_port, self.remote_port, seq, ack_seq, offset_res, flags, self.rss, check, urg_pointer)
        return header, pktheader+data

    def unpack(self, packet):
        h=struct.unpack('!HHLLBBHHH', packet[0:20])  # (source,dest,seq,ack,offset, flags, window ,checksum,urgpoint)
        return h  # return header only

    def close(self):
        self.s.close()
        self.f.close()
        if self.args[4] != "stdout":self.logf.close()
        sys.exit()

    def log(self, header, rtt = ''):
        line = time.strftime("%c")+'\t'    # timestamp
        for i in range(4): line = line + str(header[i]) +'\t'
        for i in range(5,-1,-1):
            line = line + str((header[5]/2**i) % 2)+','
        ## fin = str(flags % 2)
        ## syn = str((flags/2)%2)
        ## rst = str((flags/4)%2)
        ## psh = str((flags/8)%2)
        ## ack = str((flags/16)%2)
        ## urg = str((flags/32)%2)
        line = line + rtt +'\n'
        if self.args[4]=="stdout":sys.stdout.write(line)
        else:self.logf.writelines(line)

    ## optional function: recover to interrupted point
    def recover(self):
        while self.SeqNo < self.base:
            self.f.read(self.rss)
            self.SeqNo = 1 + self.SeqNo
        if self.SeqNo > self.base + self.window:
            self.f.close()
            self.f = open(self.args[0], 'r')
            self.SeqNo = 0
            self.base = 0

    def estimate_rtt(self):                 # estimate the rtt whenever a ack received
        k = len(self.senttime) - self.SeqNo + self.base
        for i in range(0,k):
            Samplertt = time.time()-self.senttime[i]
            if self.Estimatedrtt:
                self.Estimatedrtt = Samplertt*0.125+self.Estimatedrtt*0.875
                if self.Devrtt: 0.75 * self.Devrtt + 0.25*abs(Samplertt-self.Estimatedrtt)
                else:self.Devrtt = abs(Samplertt-self.Estimatedrtt)
            else:
                self.Estimatedrtt = Samplertt

    def rdt_send(self):
        while 1:
            try:
                self.recover()

                while self.base <= self.SeqNo < self.base + self.window and not self.fin:
                    data = self.f.read(self.rss)
                    if len(data) < self.rss:                                              # end of file,set fin
                        self.fin = True
                        bytecount = self.SeqNo*self.rss +len(data)
                    header, pkt = self.pack(data,seq=self.SeqNo*self.rss,fin = self.fin)  # packet data
                    self.s.sendto(pkt, self.addr)                                         # send pkt
                    self.log(header,rtt='\t'+str(self.Estimatedrtt))                           # log header
                    self.sent.append(pkt)                                                 # stack
                    self.senttime.append(time.time())                                     # stack pkt sent time
                    if not self.timeron:
                        self.timeron = True
                        timer = time.time()
                    self.SeqNo = 1 + self.SeqNo


# fin and close()
# all situation exit print(catch keyborad interruption)

# readme

                while select.select([self.s], [], [], 0.0001)[0]:   # nonblocking udp_rcv
                    d = self.s.recv(4096)
                    if not self.checksum(d, cal = False):continue   # when cal is set to False, switch to check mode. checksum will return true or flase
                    headerrcv = self.unpack(d)              # checksum included in unpack
                    Seqack = headerrcv[3]/self.rss
                    if headerrcv[3]%self.rss: Seqack = Seqack + 1
                    if Seqack < self.base or Seqack > self.base+self.window:  # if not in window some interrupt happened, set base and clear the buffered pkt to recover
                        self.base = Seqack
                        self.sent = []
                        self.senttime = []
                        self.timeron = False
                    if Seqack == self.SeqNo:self.timeron = False    # if all acked, close timer
                    if Seqack > self.base:                          # if ack in window,calculate rtt, delete acked pkt and sent time in buffer set base
                        k = Seqack - self.base
                        self.base = Seqack
                        self.estimate_rtt()
                        del self.sent[0:k]
                        del self.senttime[0:k]
                    self.log(headerrcv,rtt='\t'+str(self.Estimatedrtt))  # log received header


                if self.fin and self.base == self.SeqNo:            # if file read finish and acked number = file read number
                    print("Delivery completed successfully")
                    print("Total bytes sent ="+str(bytecount))
                    print("Segments sent ="+str(self.SeqNo))
                    print("Segments retransmitted ="+str(self.dup_count))
                    self.close()

                timeout = self.Estimatedrtt+4*self.Devrtt+0.01
                if self.timeron and time.time()-timer>timeout:      # timeout, retransmit
                    for p in self.sent:                             # all pkt need retransmit buffered in self.sent
                        self.s.sendto(p, self.addr)
                        self.senttime =[time.time()]*len(self.senttime)
                        # since the header has already been logged, don't need to log it again, or if you want, uncomment to below
                        # header = self.unpack(p)
                        # self.log(header,rtt='\t'+str(self.Estimatedrtt))
                        self.dup_count = self.dup_count+1           # count retransmit segments
                        timer = time.time()                         # restart timer

            except KeyboardInterrupt:
                print("Delivery failed, exit by KeyboardInterrupt")
                self.close()
    def rdt_rcv(self):
        t = 0.01
        try:
            while 1:
                while select.select([self.s], [], [], t)[0]:
                    d = self.s.recv(4096)
                    if not self.checksum(d, cal = False):continue   # checksum, cal = False means check mode
                    header = self.unpack(d)
                    msg = d[20:]
                    seq,flags =header[2]/self.rss, header[5]
                    self.log(header)
                    if seq == self.Exp:                                  # if seq expected,
                        if flags%2: self.fin =True                      # check fin
                        self.f.write(msg)
                        self.ack_seq = self.Exp*self.rss + len(msg) # just in case the last pkt
                        self.Exp = self.Exp +1
                        t = 0.01                                  # wait for another pkt to send accumulative ack
                    else:
                        self.acked = self.Exp - 1                   # if seq not expected, send ack immediately,
                        t = 0                                       # only wait for clear the recv buffer

                if self.acked < self.Exp:
                    rheader, rmsg = self.pack("", ack_seq = self.ack_seq, ack=True, fin = self.fin)
                    self.s.sendto(rmsg, self.addr)
                    self.log(rheader)
                    self.acked = self.Exp
                    if self.fin:
                        print('Delivery completed successfully')
                        self.close()

        except KeyboardInterrupt:
            print("Delivery failed, exit by KeyboardInterrupt")
            self.close()

    def run(self):
        self.init()
        if self.usage =='sender':self.rdt_send()
        else:self.rdt_rcv()

if __name__ == "__main__":
    t = tcp()
    t.run()
