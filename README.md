RDT_TCP_ON_UDP
==============
1.launch the program like this.
$python tcp.py sender cn4119.txt 128.59.15.38 20000 20001 logfile.txt 6
$python tcp.py receiver file.txt 20000 128.59.15.37 20001 logfile.txt
the add of proxy have to be matched properly.
if have any question. type $python tcp.py -h

or you can try stdout,but make sure the file to tranfer is available in the path. cn4119.txt is my example file.

2.features:
a.variable window_size accomplished: this window_size in my program stands for pipeline.My rss is 576. So if you want the window_size=5760bytes. just fill in 10.
b.automatically recover if interrupted or loss connection. i.e you are able to ctrl+c in the middle. and just start the program again. you will find it recover automatically.
c.no sender and receiver. both one can be sender. I wrote a class called tcp very easy to extend. In this class I build the rdt_send() and rdt_rcv(). they are free to use for real tcp applications!

a reliable tcp protocol built on udp
