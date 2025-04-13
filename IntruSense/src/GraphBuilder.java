import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;
import org.jgrapht.graph.SimpleGraph;
import org.jgrapht.graph.DefaultEdge;

public class GraphBuilder {
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
            int timeout = 10;    // Timeout in milliseconds
            PcapHandle handle = nif.openLive(snaplen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeout);

            // Step 3: Create the Graph
            SimpleGraph<String, DefaultEdge> networkGraph = new SimpleGraph<>(DefaultEdge.class);

            // Step 4: Capture and Parse Packets (Capture 100 packets for more thorough analysis)
            System.out.println("Capturing packets...");
            for (int i = 0; i < 100; i++) { // Capture 100 packets
                Packet packet = handle.getNextPacket();
                if (packet != null) {
                    // Check if it's an IPv4 packet
                    IpV4Packet ipv4Packet = packet.get(IpV4Packet.class);
                    if (ipv4Packet != null) {
                        String srcIp = ipv4Packet.getHeader().getSrcAddr().getHostAddress();
                        String dstIp = ipv4Packet.getHeader().getDstAddr().getHostAddress();
                        System.out.println("Source IP: " + srcIp + ", Destination IP: " + dstIp);

                        // Add nodes to the graph
                        networkGraph.addVertex(srcIp);
                        networkGraph.addVertex(dstIp);

                        // Add an edge between source and destination IPs
                        networkGraph.addEdge(srcIp, dstIp);
                    } else {
                        // If it's not an IPv4 packet, print the type of packet
                        System.out.println("Non-IPv4 packet captured: " + packet);
                    }
                }
            }

            // Step 5: Display the Network Graph
             System.out.println("\nNetwork Graph (IP Communication):");
            networkGraph.edgeSet().forEach(edge -> {
                String srcIp = networkGraph.getEdgeSource(edge);
                String dstIp = networkGraph.getEdgeTarget(edge);
                System.out.println("Edge between: " + srcIp + " and " + dstIp);
            });

            // Close the Handle
            handle.close();
            System.out.println("Packet capture completed.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
