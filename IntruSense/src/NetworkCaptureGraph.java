import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;
import org.jgrapht.graph.SimpleGraph;
import org.jgrapht.graph.DefaultEdge;

import com.mxgraph.layout.mxCircleLayout;
import com.mxgraph.swing.mxGraphComponent;
import com.mxgraph.view.mxGraph;

import javax.swing.*;
import java.util.HashMap;
import java.util.Map;

public class NetworkCaptureGraph {
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
            int timeout = 20;    // Timeout in milliseconds
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

            // Step 5: Visualize the Network Graph
            visualizeGraph(networkGraph);

            // Close the Handle
            handle.close();
            System.out.println("Packet capture completed.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Method to Visualize the Graph
    public static void visualizeGraph(SimpleGraph<String, DefaultEdge> networkGraph) {
        mxGraph mxGraph = new mxGraph();
        Object parent = mxGraph.getDefaultParent();

        // Mapping IPs to graph nodes
        Map<String, Object> vertexMap = new HashMap<>();

        mxGraph.getModel().beginUpdate();
        try {
            // Add vertices (nodes) to the graph
            for (String ip : networkGraph.vertexSet()) {
                Object vertex = mxGraph.insertVertex(parent, null, ip, 0, 0, 80, 30);
                vertexMap.put(ip, vertex);
            }

            // Add edges between nodes
            for (DefaultEdge edge : networkGraph.edgeSet()) {
                String srcIp = networkGraph.getEdgeSource(edge);
                String dstIp = networkGraph.getEdgeTarget(edge);
                mxGraph.insertEdge(parent, null, "", vertexMap.get(srcIp), vertexMap.get(dstIp));
            }
        } finally {
            mxGraph.getModel().endUpdate();
        }

        // Layout the graph in a circular format
        mxCircleLayout layout = new mxCircleLayout(mxGraph);
        layout.execute(mxGraph.getDefaultParent());

        // Display the graph in a JFrame
        JFrame frame = new JFrame("Network Graph Visualization");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.getContentPane().add(new mxGraphComponent(mxGraph));
        frame.setSize(800, 800);
        frame.setVisible(true);
    }
}
