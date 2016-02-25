# PcapPacketSniffer
PcapPacketSniffer is a lightweight C program that captures packets and prints header information. It resorts to libpcap for functionality. It comprises a component of a larger software project developed for Raspberry Pi 2 (hence its simplicity and small code footprint). It comprises a good choice for applications requiring the need to capture and catalog traffic continuously using a low amount of resources. For example, associating this program with crontab allows having a report on the main types of traffic flowing through a device without impacting its performance.

# User Manual

The program requires to arguments to run: the filter expression and the number of packets to be captured. As such, it can be run as follows:

    pcapsniffer "tcp or udp or icmp" 10

The following command should be used to compile the program:

    gcc pcapsniffer.c -lpcap

# Dependency

The program requires the installation of libpcap, which can be found [here](http://www.tcpdump.org/#latest-release).

# Author

Bernardo Sequeiros

For questions, please contact at bernardo.seq@gmail.com

#License

Software:	Pcap Packet Sniffer
Environment:	ANSI C

Copyright (c) 2016 Bernardo Sequeiros
Department of Computer Science, University of Beira Interior.
All rights reserved.

Redistribution of this software and use in source and binary forms, with 
or without modification, are permitted without a fee for private, research, 
academic, or other non-commercial purposes, provided that the following 
conditions are met:

* Redistributions of source code must retain the above copyright notice, 
this list of conditions and the following disclaimer;
* Redistributions in binary form must reproduce the above copyright notice, 
this list of conditions and the following disclaimer in the documentation 
and/or other materials provided with the distribution;
* Neither the name of this software nor the names of its contributors may 
be used to endorse or promote products derived from this software without 
specific prior written permission;
* Any changes made to this software must be clearly identified as such.

Any use of this software in a commercial environment requires a written 
licence from the copyright owner.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


