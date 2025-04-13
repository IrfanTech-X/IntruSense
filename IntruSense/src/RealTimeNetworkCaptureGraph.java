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

public class RealTimeNetworkCaptureGraph {
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
                            if (!networkGraph.containsEdge(srcIp, dstIp)) {
                                mxGraph.insertEdge(mxGraph.getDefaultParent(), null, "", vertexMap.get(srcIp), vertexMap.get(dstIp));
                                networkGraph.addEdge(srcIp, dstIp);
                            }
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
}
