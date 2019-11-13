README

Date: November, 2018

This project uses data structures and networking principles to simulate an network communications environment. The objective of this project is creating utilize Python to simulate a packet sniffer. The packet sniffer will read in raw packets and and then analyze them. 

The packet analyzer is a network analysis software that is used to intercept and log data traffic through a network interface. However the data is communicated (ethernet, WiFi, etc.) packets are coming into the network and need to be analyzed. 

PacketInformation.py
	Functions:
	Ethernet Details
		Reads and interprets information from packets from ethernet cable
	IPPacketDetails
		Reads and interprets information about IP; unpacks and formats data
	ARPPacketDetails
		Reads and interprets ARP packet details
	TCPInfo(self)
		Understands TCP protocol and interprets
	UDPInfo(self)
		Understands UDP Protocol and interprets
	HTTPInfo
		Understands HTTP information and interprets
	print_information
		7 functions to print all information that was interpreted. Prints to command line interface to interpret pack speeds. 


PythonSniffer.py
	Functions:
	start_capture
		Opens packet to digest information
	load_capture
		Downloads read information to send to packetInfo section
	write_with_pickle
		writes over to protocol layer
	signal_handler
		determines signal used and directs as needed
	
