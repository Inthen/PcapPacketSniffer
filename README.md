# PcapPacketSniffer
PcapPacketSniffer is a lightweight C program that captures packets and prints header information. It resorts to libpcap for functionality. It comprises a component of a larger software project developed for Raspberry Pi 2 (hence its simplicity and small code footprint). It comprises a good choice for applications requiring the need to capture and catalog traffic continuously using a low amount of resources. As an example, associating this program with crontab allows for having a report on the main type of traffic flowing through a device without impacting its performance.

# User Manual

The program requires to arguments to run: the filter expression and the number of packets to be captured. As such, it can be run as follows:

    pcapsniffer "tcp or udp or icmp" 10

To compile the script the following command can be used:

    gcc pcapsniffer.c -lpcap

# Dependency

The program requires the installation of libpcap, which can be found [here](http://www.tcpdump.org/#latest-release).

# Author

Bernardo Sequeiros

For questions, please contact at bernardo.seq@gmail.com



