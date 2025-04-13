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
import java.util.*;

public class IntrusionDetectionSystem {
    private static SimpleGraph<String, DefaultEdge> networkGraph;
    private static mxGraph mxGraph;
    private static Map<String, Object> vertexMap;

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

            // Step 3: Initialize Graph and Visualization
            networkGraph = new SimpleGraph<>(DefaultEdge.class);
            mxGraph = new mxGraph();
            vertexMap = new HashMap<>();

            // Step 4: Setup JFrame for Visualization
            JFrame frame = setupGraphVisualization();

            // Step 5: Start Packet Capture in a Separate Thread
            Thread captureThread = new Thread(() -> capturePackets(handle));
            captureThread.start();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static JFrame setupGraphVisualization() {
        JFrame frame = new JFrame("Real-Time Network Graph Visualization");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(1000, 1000);

        mxGraphComponent graphComponent = new mxGraphComponent(mxGraph);
        frame.getContentPane().add(graphComponent);
        frame.setVisible(true);

        return frame;
    }

    private static void capturePackets(PcapHandle handle) {
        try {
            System.out.println("Capturing packets...");
            while (true) {
                Packet packet = handle.getNextPacket();
                if (packet != null) {
                    IpV4Packet ipv4Packet = packet.get(IpV4Packet.class);
                    if (ipv4Packet != null) {
                        String srcIp = ipv4Packet.getHeader().getSrcAddr().getHostAddress();
                        String dstIp = ipv4Packet.getHeader().getDstAddr().getHostAddress();
                        System.out.println("Source IP: " + srcIp + ", Destination IP: " + dstIp);

                        synchronized (networkGraph) {
                            // Add vertices for source and destination IPs
                            if (!networkGraph.containsVertex(srcIp)) {
                                Object vertex = mxGraph.insertVertex(mxGraph.getDefaultParent(), null, srcIp, 0, 0, 80, 30);
                                vertexMap.put(srcIp, vertex);
                                networkGraph.addVertex(srcIp);
                            }
                            if (!networkGraph.containsVertex(dstIp)) {
                                Object vertex = mxGraph.insertVertex(mxGraph.getDefaultParent(), null, dstIp, 0, 0, 80, 30);
                                vertexMap.put(dstIp, vertex);
                                networkGraph.addVertex(dstIp);
                            }

                            // Add an edge between source and destination IPs
                            if (!networkGraph.containsEdge(srcIp, dstIp)) {
                                mxGraph.insertEdge(mxGraph.getDefaultParent(), null, "", vertexMap.get(srcIp), vertexMap.get(dstIp));
                                networkGraph.addEdge(srcIp, dstIp);
                            }

                            // Perform BFS after turning the node green and waiting for 1 second
                            updateVertexColor(srcIp, "green"); // First, turn the source node green
                            updateVertexColor(dstIp, "green"); // Then, turn the destination node green
                            Thread.sleep(100); // Wait for 1 second before starting BFS
                            performBFSAndVisualize(srcIp); // Start BFS after the delay
                        }

                        SwingUtilities.invokeLater(() -> {
                            mxCircleLayout layout = new mxCircleLayout(mxGraph);
                            layout.execute(mxGraph.getDefaultParent());
                        });
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                handle.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    // Method to Perform BFS Traversal and Update the Visualization
    private static void performBFSAndVisualize(String startNode) {
        Set<String> visited = new HashSet<>();
        Queue<String> queue = new LinkedList<>();

        queue.add(startNode);
        visited.add(startNode);

        System.out.println("BFS Traversal Starting from: " + startNode);

        // Perform BFS and update the visualization
        while (!queue.isEmpty()) {
            String current = queue.poll();
            System.out.println("Visited: " + current);

            // Highlight the current node by updating the visual state
            updateVertexColor(current, "yellow"); // Highlight node as visited

            // Visit all neighbors (connected nodes)
            for (DefaultEdge edge : networkGraph.edgesOf(current)) {
                String neighbor = networkGraph.getEdgeSource(edge).equals(current)
                        ? networkGraph.getEdgeTarget(edge)
                        : networkGraph.getEdgeSource(edge);

                if (!visited.contains(neighbor)) {
                    visited.add(neighbor);
                    queue.add(neighbor);
                    updateVertexColor(neighbor, "green"); // Mark new nodes as green
                }
            }
        }
    }

    // Method to Update Vertex Color in the Graph
    private static void updateVertexColor(String ip, String color) {
        Object vertex = vertexMap.get(ip);
        if (vertex != null) {
            mxGraph.getModel().beginUpdate();
            try {
                mxGraph.setCellStyle("rounded=1;fillColor=" + color, new Object[]{vertex});
            } finally {
                mxGraph.getModel().endUpdate();
            }
        }
    }
}

