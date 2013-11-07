import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Scanner;


public class PacketParser {
	
	// The values are assigned as hex, but their int value is decimal (normal integers).
	
	// Types:
	final static int TYPE_IPv4 = 0x0800;
	final static int TYPE_IPv6 = 0x29;
	final static int TYPE_ARP = 0x0806;
	final static int TYPE_ICMP = 0x01;
	final static int TYPE_ICMP_PING_REQUEST = 0x08;
	final static int TYPE_ICMP_PING_REPLY = 0x00;
	final static int TYPE_TCP = 0x06;
	final static int TYPE_UDP = 0x11;
	final static int TYPE_DHCP = 0x06;
	final static int TYPE_DNS = 0;
	
	// Port Numbers in Application Layer:
	final static int PORT_DNS = 53;
	final static int PORT_DHCP_SERVER = 67;
	final static int PORT_DHCP_CLIENT = 68;
		
	final static int ETHERNET_FRAME_MIN_SIZE = 14;
	
	static int IP = 0;
	static int ARP = 0;
	static int ICMP = 0;
	static int TCP = 0;
	static int UDP = 0;
	static int ICMP_Ping_Request = 0;
	static int ICMP_Ping_Reply = 0;
	static int DHCP = 0;
	static int DNS = 0;
	
	public static void printResults(){
		System.out.println("total number of Ethernet (IP + ARP) packets = " + (IP + ARP));
		System.out.println("total number of IP packets = " + IP);
		System.out.println("total number of ARP packets = " + ARP);
		System.out.println("total number of ICMP packets = " + ICMP);
		System.out.println("total number of TCP packets = " + TCP);
		System.out.println("total number of UDP packets = " + UDP);
		System.out.println("total number of Ping packets = " + (ICMP_Ping_Request + ICMP_Ping_Reply) + " Request: " + ICMP_Ping_Request + " Reply: " + ICMP_Ping_Reply);
		System.out.println("total number of DHCP packets = " + DHCP);
		System.out.println("total number of DNS packets = " + DNS);
	}
	
	// ----- First Layer: Ethernet  ---
	
	public static void processPacket(ArrayList<Integer> packet){
		if (packet.size() < ETHERNET_FRAME_MIN_SIZE){
			return;
		}
				
		int type = packet.get(12) * 256 + packet.get(13);
		
		switch (type){
			case TYPE_IPv4:
				IP++;
				processIPv4Packet(packet);
				break;
			case TYPE_IPv6:
				IP++;
				break;
			case TYPE_ARP:
				ARP++;
				break;
		}
	}
	
	// --- Second Layer: Transport Layer ---
	
	public static void processIPv4Packet(ArrayList<Integer> packet){
		int type = packet.get(23);
		switch (type){
			case TYPE_ICMP:
				ICMP++;
				processICMPPacket(packet);
				break;
			case TYPE_TCP:
				TCP++;
				break;
			case TYPE_UDP:
				UDP++;
				processUDPPacket(packet);
				break;
		}
	}
	
	public static void processICMPPacket(ArrayList<Integer> packet){
		int type = packet.get(34);
		switch (type){
			case TYPE_ICMP_PING_REQUEST:
				ICMP_Ping_Request++;
				break;
			case TYPE_ICMP_PING_REPLY:
				ICMP_Ping_Reply++;
				break;
		}
	}
	
	// --- Third Layer: Application Layer ---
	
	public static void processTCPPacket(ArrayList<Integer> packet){
		int sourcePortNumber = packet.get(34) * 256 + packet.get(35);
		int destinationPortNumber = packet.get(36) * 256 + packet.get(37);
		
		if (!findMatchedPortNumber(sourcePortNumber)){
			findMatchedPortNumber(destinationPortNumber);
		}
	}
	
	public static void processUDPPacket(ArrayList<Integer> packet){
		int sourcePortNumber = packet.get(34) * 256 + packet.get(35);
		int destinationPortNumber = packet.get(36) * 256 + packet.get(37);
		
		if (!findMatchedPortNumber(sourcePortNumber)){
			findMatchedPortNumber(destinationPortNumber);
		}
	}
	
	public static boolean findMatchedPortNumber(int portNumber){
		switch (portNumber){
			case PORT_DNS:
				DNS++;
				return true;
			case PORT_DHCP_CLIENT:
			case PORT_DHCP_SERVER:
				DHCP++;
				return true;
			default:
				return false;
		}
	}

	// Main Function:
	
	public static void main(String[] args) {
		
		if (args.length != 1){
			System.out.println("Usage: java PacketParser fileName");
			System.exit(0);
		}
		
		// Assume all packets are Ethernet frames:
		BufferedReader br;
		try {
			br = new BufferedReader(new FileReader(args[0]));
			String line;
			ArrayList<Integer> currentPacket = new ArrayList<Integer>();
			
			while ((line = br.readLine()) != null) {

				Scanner scanner = new Scanner(line);
				
				// If the line doesn't starts with an integer, discard it.
				if (!scanner.hasNextInt(16)){
					continue;
				}
				
				// If offSet is 0, process the old packet, and start a new packet storage:
				int offSet = scanner.nextInt(16);
				if (offSet == 0 && currentPacket.size() > 0){
					processPacket(currentPacket);
					currentPacket.clear();
				}
				
				// Read in everything into the packet:
				while(scanner.hasNextInt(16)){
					int newInt = scanner.nextInt(16);
					currentPacket.add(newInt);
				}
				scanner.close();
			}
			
			// At the end of file, process the last packet:
			if (currentPacket.size() > 0){
				processPacket(currentPacket);
				currentPacket.clear();
			}
			br.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		printResults();
		

	}

}
