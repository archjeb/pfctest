# pfctest


The purpose of this script is to provide an easy way to test priority-based flow control, as defined in the IEEE 802.1Qbb standard.
This allows Network Engineers and other technical staff a way to easily test their PFC settings on their network and the impact
that various PFC quanta values can have.  


# Author
Jeremy Georges 

# Description

pfctest creates pfc packets based on a quanta value per traffic class.
The purpose of this tool is it help Network Engineers and other technical staff to test their PFC implementation on their
network. It is not intended to be used to DoS a network by forcing hosts to pause to eternity. Therefore, use
at your own risk and preferably in a lab environment.


The Ethernet Frame format for PFC packets is the following:

                     -------------------------
     Destination MAC |   01:80:C2:00:00:01   |
                     -------------------------
     Source MAC      |      Station MAC      |
                     -------------------------
     Ethertype       |         0x8808        |
                     -------------------------
     OpCode          |         0x0101        |
                     -------------------------
     Class Enable V  | 0x00 E7...E0          |   - Class-enable vector, 8 bits for each class 
                     -------------------------
     Time Class 0    |       0x0000          |
                     -------------------------
     Time Class 1    |       0x0000          |
                     -------------------------
     ...     
                     -------------------------
     Time Class 7    |       0x0000          |
                     -------------------------


Note: Time in quanta where each quantum represents time it takes to transmit 512 bits at the current network speed. For example, Fast Ethernet
takes 10ns per bit, Gb Ethernet is 1ns and 10Gb is 0.1ns per bit time. So if quanta is set to max of 65535 for a 10Gb link PFC class,
then 0.1(512)*65535 = 3.3ms pause time.


Each block above from Ethertype down is 16bits (2 octets)

Sending a quanta of 0 for a specific class tells a receiver that it can 'unpause' explictly for that class. 


# Usage

pfctest.py requires a few arguments. The egress interface must be specified and a PFC class. The Quanta value can be 
from 0 - 65535. 

Additionally, an iteration value can be specified which is really the number of packets the script will send out. The default 
is only one packet.


     Usage: pfctest.py [options] arg1 arg2
     
     Options:
       -h, --help            show this help message and exit
       -V, --version         The version
       -d Interface, --device=Interface
                             The Interface to egress packets
       --p0                  Priority Flow Control Enable Class 0
       --p1                  Priority Flow Control Enable Class 1
       --p2                  Priority Flow Control Enable Class 2
       --p3                  Priority Flow Control Enable Class 3
       --p4                  Priority Flow Control Enable Class 4
       --p5                  Priority Flow Control Enable Class 5
       --p6                  Priority Flow Control Enable Class 6
       --p7                  Priority Flow Control Enable Class 7
       --q0=Quanta           Time in Quanta for Class 0
       --q1=Quanta           Time in Quanta for Class 1
       --q2=Quanta           Time in Quanta for Class 2
       --q3=Quanta           Time in Quanta for Class 3
       --q4=Quanta           Time in Quanta for Class 4
       --q5=Quanta           Time in Quanta for Class 5
       --q6=Quanta           Time in Quanta for Class 6
       --q7=Quanta           Time in Quanta for Class 7
       -i number, --iteration=number
                             Number of times to iterate




Additionally, please note that this script only supports Python 2.6/2.7 and Linux.
