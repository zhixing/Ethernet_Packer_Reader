import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Scanner;


public class DNSParser {
	
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
	
	final static int TYPE_A = 1; 
	final static int TYPE_NS = 2; 
	final static int TYPE_CNAME = 5; 
	final static int TYPE_SOA = 6;
	final static int TYPE_PTR = 12; 
	
	final static int OFFSET_IN_ETHERNET_FRAME = 14;
	
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
	
	static int DNS = 0;
	static int DNS_Transactions = 0;
	
	static ArrayList<Integer> transactionIDs = new ArrayList<Integer>();
	
	public static void printResults(){
		System.out.println("total number of DNS packets = " + DNS);
		System.out.println("total number of DNS transactions = " + transactionIDs.size());
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
		}
	}
	
	// --- Second Layer: Transport Layer ---
	
	public static void processIPv4Packet(ArrayList<Integer> packet){
		int type = packet.get(23);
		switch (type){
			case TYPE_UDP:
				UDP++;
				processUDPPacket(packet);
				break;
		}
	}

	// --- Third Layer: Application Layer ---

	public static void processUDPPacket(ArrayList<Integer> packet){
		int IHL = computeIPv4HeaderLength(packet);
		int baseIndex = OFFSET_IN_ETHERNET_FRAME + IHL * 4;
		int sourcePortNumber = packet.get(baseIndex) * 256 + packet.get(baseIndex + 1); // 34 35
		int destinationPortNumber = packet.get(baseIndex + 2) * 256 + packet.get(baseIndex + 3); // 36 37
		
		if (!findMatchedPortNumber(sourcePortNumber, IHL, packet)){
			findMatchedPortNumber(destinationPortNumber, IHL, packet);
		}
	}
	
	public static int computeIPv4HeaderLength(ArrayList<Integer> packet){
		// First 4 bit is Version, Last 4 bit is IHL (Internal Header Length)
		// Trim off the first 28 bits, leaving the last 4 bits:
		// 14 is the offset in Ethernet Frame (6 dst, 6 src, 2 EtherType)
		return (packet.get(OFFSET_IN_ETHERNET_FRAME) << 28) >> 28;		
	}
	
	// This function is not used.
	public static int computeUDPHeaderLength(ArrayList<Integer> packet, int IHL){
		int baseIndex = OFFSET_IN_ETHERNET_FRAME + IHL * 4 + 4;
		return (packet.get(baseIndex) * 256 + packet.get(baseIndex + 1));
	}
	
	public static boolean findMatchedPortNumber(int portNumber, int IHL, ArrayList<Integer> packet){
		switch (portNumber){
			case PORT_DNS:
				DNS++;
				processDNSPacket(packet, IHL);
				return true;
			default:
				return false;
		}
	}

	public static void processDNSPacket(ArrayList<Integer> packet, int IHL){
		// MAC + IP + UPD
		int baseIndex = OFFSET_IN_ETHERNET_FRAME + IHL * 4 + 8;
		int flags = packet.get(baseIndex + 2);
		// Take the first bit. 0: Query. 1: Response
		int isResponse = (flags >> 7);
		if (isResponse == 1){
			int transactionID = packet.get(baseIndex) * 256 + packet.get(baseIndex + 1);
			// Un-comment the following line to count the distinc number of transactions:
			//if (!transactionIDs.contains(transactionID)){
				transactionIDs.add(transactionID);
			//}
			processTransaction(packet, baseIndex, transactionID);
		}
	}
	
	public static void processTransaction(ArrayList<Integer> packet, int baseIndex, int transactionID){
		
		ArrayList<String> result = readNameInDNS(packet, baseIndex + 12 - 1, baseIndex);
		String name = result.get(0);
		int currentPointer = Integer.parseInt(result.get(1));
		
		int queryType = packet.get(++currentPointer) * 256 + packet.get(++currentPointer);
		int queryClass = packet.get(++currentPointer) * 256 + packet.get(++currentPointer);
		
		int answerRRsCount = (packet.get(baseIndex + 6) * 256 + packet.get(baseIndex + 7));
		int authorityRRsCount = (packet.get(baseIndex + 8) * 256 + packet.get(baseIndex + 9));
		int additionalRRsCount = (packet.get(baseIndex + 10) * 256 + packet.get(baseIndex + 11));
		
		//if (queryType != TYPE_A) return;

		System.out.println("\n------------------DNS Transaction------------------------");
		System.out.println("transaction_id = " + Integer.toHexString(transactionID));
		System.out.println("Questions = " + (packet.get(baseIndex + 4) * 256 + packet.get(baseIndex + 5)));
		System.out.println("Answer RRs = " + answerRRsCount);
		System.out.println("Authority RRs = " + authorityRRsCount);
		System.out.println("Additional RRs = " + additionalRRsCount);
		
		System.out.println("Queries:");
		System.out.println("\tName = " + name);
		System.out.println("\tType = " + queryType);
		System.out.println("\tClass = " + queryClass);
	
		
		for (int i = 0; i < answerRRsCount + authorityRRsCount + additionalRRsCount; i++){
			
			if ( i == 0){
				System.out.println("Answers:");
			} else if ( i == answerRRsCount){
				System.out.println("Authoritative nameservers:");
			} else if ( i == answerRRsCount + authorityRRsCount){
				System.out.println("Additional records:");
			}
			
			result = readNameInDNS(packet, currentPointer, baseIndex);
			String answerName = result.get(0);
			currentPointer = Integer.parseInt(result.get(1));
			
			queryType = packet.get(++currentPointer) * 256 + packet.get(++currentPointer);
			queryClass = packet.get(++currentPointer) * 256 + packet.get(++currentPointer);
			int TTL = packet.get(++currentPointer) * 256 * 256 * 256 + 
					packet.get(++currentPointer) * 256 * 256 +
					packet.get(++currentPointer) * 256 + 
					packet.get(++currentPointer);
			int dataLength = packet.get(++currentPointer) * 256 + packet.get(++currentPointer);
			
			System.out.println("\tName = " + answerName);
			System.out.println("\tType = " + queryType);
			System.out.println("\tClass = " + queryClass);
			System.out.println("\tTime to live = " + TTL);
			System.out.println("\tData Length = " + dataLength);
			
			switch (queryType){
				case TYPE_A:{
					String addr = 	packet.get(++currentPointer) + "." + 
							packet.get(++currentPointer) + "." + 
							packet.get(++currentPointer) + "." +
							packet.get(++currentPointer);
					System.out.println("\tAddr = " + addr);
					break;
				}
				case TYPE_NS:{
					result = readNameInDNS(packet, currentPointer, baseIndex);
					String nameServer = result.get(0);
					currentPointer = Integer.parseInt(result.get(1));
					System.out.println("\tNS: " + nameServer);
					break;
				}
				case TYPE_CNAME:{
					result = readNameInDNS(packet, currentPointer, baseIndex);
					String cname = result.get(0);
					currentPointer = Integer.parseInt(result.get(1));
					System.out.println("\tCNAME = " + cname);
					break;
				}
				case TYPE_SOA:{
					result = readNameInDNS(packet, currentPointer, baseIndex);
					String pName = result.get(0);
					currentPointer = Integer.parseInt(result.get(1));
					System.out.println("\tPrimary Name Server = " + pName);
					
					result = readNameInDNS(packet, currentPointer, baseIndex);
					String rMail = result.get(0);
					currentPointer = Integer.parseInt(result.get(1));
					System.out.println("\tResponsible Authority's Mailbox = " + rMail);
					
					int serialNumber = packet.get(++currentPointer) * 256 * 256 * 256 + 
										packet.get(++currentPointer) * 256 * 256 +
										packet.get(++currentPointer) * 256 + 
										packet.get(++currentPointer);
					System.out.println("\tSerial Number = " + serialNumber);
					
					int refresh = packet.get(++currentPointer) * 256 * 256 * 256 + 
							packet.get(++currentPointer) * 256 * 256 +
							packet.get(++currentPointer) * 256 + 
							packet.get(++currentPointer);
					System.out.println("\tRefresh Interval = " + refresh);
					
					int retry = packet.get(++currentPointer) * 256 * 256 * 256 + 
							packet.get(++currentPointer) * 256 * 256 +
							packet.get(++currentPointer) * 256 + 
							packet.get(++currentPointer);
					System.out.println("\tRetry Interval = " + retry);
					
					int expiry = packet.get(++currentPointer) * 256 * 256 * 256 + 
							packet.get(++currentPointer) * 256 * 256 +
							packet.get(++currentPointer) * 256 + 
							packet.get(++currentPointer);
					System.out.println("\tExpiration Limit = " + expiry);
					
					int minTTL = packet.get(++currentPointer) * 256 * 256 * 256 + 
							packet.get(++currentPointer) * 256 * 256 +
							packet.get(++currentPointer) * 256 + 
							packet.get(++currentPointer);
					System.out.println("\tMin TTL = " + minTTL);
					break;
				}
				case TYPE_PTR:{
					result = readNameInDNS(packet, currentPointer, baseIndex);
					String pName = result.get(0);
					currentPointer = Integer.parseInt(result.get(1));
					System.out.println("\tPTR Domain Name = " + pName);
					break;
				}
				default:
					System.out.println("\tThis type is not supported");
					currentPointer += dataLength;
					break;
			}
			System.out.println("\n");
		}
	}
	
	public static ArrayList<String> readNameInDNS(ArrayList<Integer> packet, int currentPointer, int baseIndex){
		int currentLength = packet.get(++currentPointer);
		int currentChar = 0;
		String name = "";
		
		while (currentLength != 0){
			if (currentLength >= 0xc0){
				ArrayList<String> result = readNameInDNS(packet, (currentLength - 192) * 256 + packet.get(++currentPointer) + baseIndex - 1, baseIndex);
				name += result.get(0);
				break;
			}
			for (int i = 0; i < currentLength; i++){
				currentChar = packet.get(++currentPointer);
				name += (char)currentChar;
			}
			name += '.';
			currentLength = packet.get(++currentPointer);
		}
		
		ArrayList<String> toReturn = new ArrayList<String>();
		toReturn.add(name);
		toReturn.add("" + currentPointer);
		return toReturn;
	}
		
	// Main Function:
	
	public static void main(String[] args) {
		
		if (args.length < 1){
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
