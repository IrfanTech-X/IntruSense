import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;

import java.util.HashSet;
import java.util.Set;

public class PacketCapture {
    public static void main(String[] args) {
        try {
            // Step 1: Select a Network Interface
            PcapNetworkInterface nif = new NifSelector().selectNetworkInterface();
            if (nif == null) {
                System.out.println("No interface selected.");
                return;
            }
            System.out.println("Using interface: " + nif.getName());

            // Step 2: Open a Handle for Capturing Packets
            int snaplen = 65536; // Capture all packets
            int timeout = 50;    // Timeout in milliseconds
            PcapHandle handle = nif.openLive(snaplen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeout);

            // Step 3: Capture and Debug Packets
            System.out.println("Capturing packets...");
            Set<String> nodes = new HashSet<>(); // To store unique IPs
            for (int i = 0; i < 50; i++) { // Capture 50 packets
                Packet packet = handle.getNextPacket();
                if (packet != null) {
                    System.out.println("Packet captured: " + packet); // Debug full packet content
                    
                    if (packet.contains(org.pcap4j.packet.IpV4Packet.class)) {
                        org.pcap4j.packet.IpV4Packet ipv4Packet = packet.get(org.pcap4j.packet.IpV4Packet.class);
                        String srcIp = ipv4Packet.getHeader().getSrcAddr().getHostAddress();
                        String dstIp = ipv4Packet.getHeader().getDstAddr().getHostAddress();
                        System.out.println("Source IP: " + srcIp + ", Destination IP: " + dstIp);
                        nodes.add(srcIp);
                        nodes.add(dstIp);
                    } else {
                        System.out.println("Non-IPv4 Packet captured.");
                    }
                } else {
                    System.out.println("No packet captured.");
                }
            }

            // Step 4: Print Collected Nodes
            System.out.println("Nodes in the network: " + nodes);

            // Close Handle
            handle.close();
            System.out.println("Packet capture completed.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
