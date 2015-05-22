#!/usr/bin/env python
#**********************************************************************
# Version 1.0  - 05/22/2015 - Written by Jeremy Georges -Initial Script
#
#***********************************************************************

"""
Tool to generate PFC packets.  

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
Class Enable V  | 0x00 E7...E0          |   - Class-enable vector, 8 bits for each class MSB E7 LSB E0. 1 enabled 0 disable
                -------------------------
Time Class 0    |       0x0000          |
                -------------------------
Time Class 1    |       0x0000          |
                -------------------------
...
                -------------------------
Time Class 7    |       0x0000          |
                -------------------------


Note: Time in quanta where each quantum represents time it takes to transmit 512 bits at the current network speed.

Each block above from Ethertype down is 16bits (2 octets)

"""

#===========================================================
# Modules
#===========================================================
from socket import socket, AF_PACKET, SOCK_RAW
import sys, os
from struct import *
import binascii
import optparse

#===========================================================
# Variables
#===========================================================
VERSION='1.0'

#===========================================================
# Function Definitions
#===========================================================
# checksum functions needed for calculation checksum
def checksum(msg):
    s = 0
     
    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        s = s + w
     
    s = (s>>16) + (s & 0xffff);
    s = s + (s >> 16);
     
    #complement and mask to 4 byte short
    s = ~s & 0xffff
     
    return s


#============================
# MAIN
#============================
def main():
    usage = "usage: %prog [options] arg1 arg2"
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("-V", "--version", action="store_true",dest="version", help="The version")
    parser.add_option("-d", "--device", type="string", dest="interface", help="The Interface to egress packets",metavar="Interface")
    parser.add_option('--p0',action="store_true", default=False, help="Priority Flow Control Enable Class 0")
    parser.add_option("--p1",action="store_true", default=False, help="Priority Flow Control Enable Class 1")
    parser.add_option("--p2",action="store_true", default=False, help="Priority Flow Control Enable Class 2")
    parser.add_option("--p3",action="store_true", default=False, help="Priority Flow Control Enable Class 3")
    parser.add_option("--p4",action="store_true", default=False, help="Priority Flow Control Enable Class 4")
    parser.add_option("--p5",action="store_true", default=False, help="Priority Flow Control Enable Class 5")
    parser.add_option("--p6",action="store_true", default=False, help="Priority Flow Control Enable Class 6")
    parser.add_option("--p7",action="store_true", default=False, help="Priority Flow Control Enable Class 7")
    parser.add_option("--q0", type="int", dest="quanta0", help="Time in Quanta for Class 0",metavar="Quanta")
    parser.add_option("--q1", type="int", dest="quanta1", help="Time in Quanta for Class 1",metavar="Quanta")
    parser.add_option("--q2", type="int", dest="quanta2", help="Time in Quanta for Class 2",metavar="Quanta")
    parser.add_option("--q4", type="int", dest="quanta3", help="Time in Quanta for Class 3",metavar="Quanta")
    parser.add_option("--q5", type="int", dest="quanta4", help="Time in Quanta for Class 4",metavar="Quanta")
    parser.add_option("--q6", type="int", dest="quanta5", help="Time in Quanta for Class 5",metavar="Quanta")
    parser.add_option("--q7", type="int", dest="quanta6", help="Time in Quanta for Class 6",metavar="Quanta")
    parser.add_option("--q8", type="int", dest="quanta7", help="Time in Quanta for Class 7",metavar="Quanta")
    parser.add_option("-i", "--iteration", type="int", dest="iteration", help="Number of times to iterate",metavar="number",default=1)
    (options, args) = parser.parse_args()

    if options.version:
        print os.path.basename(sys.argv[0]), "  Version: ", VERSION
        sys.exit(0)
    
    if options.interface is None:
        print "Egress Interface must be specified!"
        parser.print_help()
        sys.exit(1)
  
    try:  
       s = socket(AF_PACKET, SOCK_RAW)
    except:
        print "Unable to create socket. Check your permissions"
        sys.exit(1)
        
    s.bind((options.interface, 0))

    # We're putting together an ethernet frame here, 
    # but you could have anything you want instead
    # Have a look at the 'struct' module for more 
    # flexible packing/unpacking of binary data
    # and 'binascii' for 32 bit CRC
    src_addr = "\x01\x02\x03\x04\x05\x06"
    dst_addr = "\x01\x80\xC2\x00\x00\x01"
    opcode = "\x01\x01"
    ethertype = "\x88\x08"
    
    #Set initial value of classvector to all zeros
    #Its a two byte value where the upper two bytes should be set to zero
    #We'll stick with raw ASCII. Leave the upper 8 bits to all zeros in ASCII hex
    #
    #for the lower 8 bits, we'll we'll set it to an all 0 byte value in binary
    #then we'll just add bits. In the end, we'll convert that to ASCII again...its easy to concatenate
     
    #The lower bits are set based on which class is enabled where MSB is class 7, LSB is class0
    classvectorbyteUpper="\x00"
    classvectorbyteLower=0b00000000
    #Lets enable the appropriate class vectors.
    if options.p0:
        classvectorbyteLower=0b00000001+classvectorbyteLower
    if options.p1:
        classvectorbyteLower=0b00000010+classvectorbyteLower    
    if options.p2:
        classvectorbyteLower=0b00000100+classvectorbyteLower   
    if options.p3:
        classvectorbyteLower=0b00001000+classvectorbyteLower  
    if options.p4:
        classvectorbyteLower=0b00010000+classvectorbyteLower  
    if options.p5:
        classvectorbyteLower=0b00100000+classvectorbyteLower
    if options.p6:
        classvectorbyteLower=0b01000000+classvectorbyteLower
    if options.p7:
        classvectorbyteLower=0b10000000+classvectorbyteLower  
    #Need to covert to a string with escaped hex literal  
    classvectorbyteLower = binascii.unhexlify(str(hex(classvectorbyteLower)).strip('0x'))
    #Concatenate the full enable vector two bytes.
    classvector = classvectorbyteUpper + classvectorbyteLower
   
   
    # Build time for each class enabled.  
    # Each time class is 2 byte value for each pause frame. Time in quanta where each
    # quantum represents time int takes to transmit 512 bits at the current network speed.. 
    classtimebyteUpper="\x00"  
    
    if options.quanta0:
        if options.quanta0 < 256: 
            pfc0=classtimebyteUpper+binascii.unhexlify(hex(options.quanta0).strip('0x'))
        else:
            print "Not a valid quanta value. But be in the range of 0 - 255"
            sys.exit(1)
    else: 
        #If no CLI argument, pass a zero value for this class       
        pfc0="\x00\x00"    
        
    if options.quanta1:
        if options.quanta1 < 256: 
            pfc1=classtimebyteUpper+binascii.unhexlify(hex(options.quanta1).strip('0x'))
        else:
            print "Not a valid quanta value. But be in the range of 0 - 255"
            sys.exit(1)
    else: 
        #If no CLI argument, pass a zero value for this class       
        pfc1="\x00\x00"  
            
    if options.quanta2:
        if options.quanta2 < 256: 
            pfc2=classtimebyteUpper+binascii.unhexlify(hex(options.quanta2).strip('0x'))
        else:
            print "Not a valid quanta value. But be in the range of 0 - 255"
            sys.exit(1)
    else: 
        #If no CLI argument, pass a zero value for this class       
        pfc2="\x00\x00"
   
    if options.quanta3:
        if options.quanta3 < 256: 
            pfc3=classtimebyteUpper+binascii.unhexlify(hex(options.quanta3).strip('0x'))
        else:
            print "Not a valid quanta value. But be in the range of 0 - 255"
            sys.exit(1)
    else: 
        #If no CLI argument, pass a zero value for this class       
        pfc3="\x00\x00"

    if options.quanta4:
        if options.quanta4 < 256: 
            pfc4=classtimebyteUpper+binascii.unhexlify(hex(options.quanta4).strip('0x'))
        else:
            print "Not a valid quanta value. But be in the range of 0 - 255"
            sys.exit(1)
    else: 
        #If no CLI argument, pass a zero value for this class       
        pfc4="\x00\x00"
        
    if options.quanta5:
        if options.quanta5 < 256: 
            pfc5=classtimebyteUpper+binascii.unhexlify(hex(options.quanta5).strip('0x'))
        else:
            print "Not a valid quanta value. But be in the range of 0 - 255"
            sys.exit(1)
    else: 
        #If no CLI argument, pass a zero value for this class       
        pfc5="\x00\x00"
        
    if options.quanta6:
        if options.quanta6 < 256: 
            pfc6=classtimebyteUpper+binascii.unhexlify(hex(options.quanta6).strip('0x'))
        else:
            print "Not a valid quanta value. But be in the range of 0 - 255"
            sys.exit(1)
    else: 
        #If no CLI argument, pass a zero value for this class       
        pfc6="\x00\x00"
        
    if options.quanta7:
        if options.quanta7 < 256: 
            pfc7=classtimebyteUpper+binascii.unhexlify(hex(options.quanta7).strip('0x'))
        else:
            print "Not a valid quanta value. But be in the range of 0 - 255"
            sys.exit(1)
    else: 
        #If no CLI argument, pass a zero value for this class       
        pfc7="\x00\x00"
        
    fullpacket=dst_addr+src_addr+ethertype+opcode+classvector+pfc0+pfc1+pfc2+pfc3+pfc4+pfc5+pfc6+pfc7
    x = checksum(fullpacket) 

    thechecksum=hex(x)
     
    print "Generating %s Packet(s)" % options.iteration
    while options.iteration > 0:
        s.send(dst_addr+src_addr+ethertype+opcode+classvector+pfc0+pfc1+pfc2+pfc3+pfc4+pfc5+pfc6+pfc7+thechecksum)
        options.iteration -= 1
        
        
if __name__ == "__main__":
    main()
