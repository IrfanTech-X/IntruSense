import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.jgrapht.graph.SimpleGraph;
import org.jgrapht.graph.DefaultEdge;

import org.jgrapht.graph.DefaultUndirectedGraph;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.alg.spanning.KruskalMinimumSpanningTree;

import com.mxgraph.layout.mxCircleLayout;
import com.mxgraph.swing.mxGraphComponent;
import com.mxgraph.view.mxGraph;

import javax.swing.*;
import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class IntruSenseGUI {
    private JFrame frame;
    private DefaultListModel<String> ipListModel; // Model for frequently accessed IPs
    private SimpleGraph<String, DefaultEdge> networkGraph;
    private mxGraph mxGraph;
    private Map<String, Object> vertexMap;
    private Map<String, Integer> ipAccessCount; // To store the access count for each IP
    private JTextArea threatMessageArea; // Area to display threat messages(text field ashole)
    private boolean captureRunning = false; // Flag to control the packet capture loop(live network capturer jonno variable)
    private Thread captureThread; // Thread for packet capture( parallal kaj korar jonno thread)

    // MST-related variables
    private JButton mstButton; // Button to trigger MST calculation(shuru hobe)
    private JPanel mstPanel; // Panel to display MST(test field e dekhano)
    private JTextArea mstTextArea;
    
    
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            IntruSenseGUI gui = new IntruSenseGUI(); // lembda expressen edt edvent dipacth thread er jonno
            gui.createAndShowGUI();
        });
    }
//invoke later buiuld in asynchoronus edt er sathe
    public void createAndShowGUI() {
        frame = new JFrame("IntruSense: Network Intrusion Detection System");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(1200, 800);
        frame.setLayout(new BorderLayout());

        // Start Screen
        JPanel startPanel = new JPanel();
        startPanel.setLayout(new GridBagLayout());
        JButton startButton = new JButton("Start");
        startButton.setPreferredSize(new Dimension(200, 50)); // Set button size
        startButton.setFont(new Font("Arial", Font.BOLD, 16)); // Button text style
        startPanel.add(startButton);
        frame.add(startPanel, BorderLayout.CENTER);

        // Action Listener for Start Button(network selection e niye jabe)
        startButton.addActionListener(e -> showNetworkSelectionPanel());

        frame.setVisible(true);
    }

    private void showNetworkSelectionPanel() {
        frame.getContentPane().removeAll();

        // Panel for Network Selection
        JPanel networkSelectionPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10)); // FlowLayout for horizontal alignment
        JLabel label = new JLabel("Select a Network Interface:");
        label.setFont(new Font("Arial", Font.PLAIN, 18)); // Label font style
        networkSelectionPanel.add(label);

        JComboBox<String> networkComboBox = new JComboBox<>();
        List<PcapNetworkInterface> allNifs = getAllNetworkInterfaces();
        for (PcapNetworkInterface nif : allNifs) {
            networkComboBox.addItem(nif.getName() + " - " + nif.getDescription());
        }
        networkComboBox.setPreferredSize(new Dimension(400, 30)); // Smaller, more compact size for the combo box
        networkSelectionPanel.add(networkComboBox);

        JPanel buttonPanel = new JPanel();
        JButton confirmButton = new JButton("Confirm");
        JButton cancelButton = new JButton("Cancel");
        buttonPanel.add(confirmButton);
        buttonPanel.add(cancelButton);
        networkSelectionPanel.add(buttonPanel);

        frame.add(networkSelectionPanel, BorderLayout.CENTER);
        frame.revalidate();
        frame.repaint();

        confirmButton.addActionListener(e -> {
            int selectedIndex = networkComboBox.getSelectedIndex();
            if (selectedIndex >= 0) {
                PcapNetworkInterface selectedNif = allNifs.get(selectedIndex);
                transitionToMainInterface(selectedNif);
            } else {
                JOptionPane.showMessageDialog(frame, "Please select a network interface.", "Error", JOptionPane.ERROR_MESSAGE);
            }
        });

        cancelButton.addActionListener(e -> System.exit(0));
    }

    private List<PcapNetworkInterface> getAllNetworkInterfaces() {
        try {
            return Pcaps.findAllDevs();
        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(frame, "Failed to retrieve network interfaces.", "Error", JOptionPane.ERROR_MESSAGE);
            return List.of();
        }
    }

    private void transitionToMainInterface(PcapNetworkInterface nif) {
        frame.getContentPane().removeAll();

        JPanel graphPanel = new JPanel();
        graphPanel.setBorder(BorderFactory.createTitledBorder("Network Graph Visualization"));

        mxGraph = new mxGraph();
        vertexMap = new HashMap<>();
        networkGraph = new SimpleGraph<>(DefaultEdge.class);
        mxGraphComponent graphComponent = new mxGraphComponent(mxGraph);
        graphPanel.setLayout(new BorderLayout());
        graphPanel.add(graphComponent, BorderLayout.CENTER);

        JPanel ipActivityPanel = new JPanel();  //(frq. acc. ip dekhanor panel)
        ipActivityPanel.setBorder(BorderFactory.createTitledBorder("Frequently Accessed IPs"));
        ipListModel = new DefaultListModel<>();
        JList<String> ipList = new JList<>(ipListModel);
        JScrollPane ipScrollPane = new JScrollPane(ipList);
        ipActivityPanel.setLayout(new BorderLayout());
        ipActivityPanel.add(ipScrollPane, BorderLayout.CENTER);

        JPanel controlPanel = new JPanel();//(start and pause the recevie of ip)
        controlPanel.setBorder(BorderFactory.createTitledBorder("Controls"));

        JButton startCaptureButton = new JButton("Start Capture");
        JButton stopCaptureButton = new JButton("Stop Capture");
        stopCaptureButton.setEnabled(false); // Disable stop button initially

        controlPanel.setLayout(new GridLayout(3, 1));
        controlPanel.add(startCaptureButton);
        controlPanel.add(stopCaptureButton);

        // Panel for Threat Messages
        JPanel threatPanel = new JPanel();
        threatPanel.setBorder(BorderFactory.createTitledBorder("Threat Messages"));
        threatMessageArea = new JTextArea(5, 20);
        threatMessageArea.setEditable(false);
        JScrollPane threatScrollPane = new JScrollPane(threatMessageArea);
        threatPanel.add(threatScrollPane);

       // MST Panel
mstPanel = new JPanel();
mstPanel.setBorder(BorderFactory.createTitledBorder("Minimum Spanning Tree"));
mstPanel.setLayout(new BorderLayout()); // Set layout for proper alignment

mstButton = new JButton("Calculate MST");
mstPanel.add(mstButton, BorderLayout.NORTH); // Add the button at the top

// Initialize the JTextArea for MST
mstTextArea = new JTextArea(10, 30); // Set rows and columns
mstTextArea.setEditable(false); // Make it non-editable
JScrollPane mstScrollPane = new JScrollPane(mstTextArea);
mstPanel.add(mstScrollPane, BorderLayout.CENTER); // Add the scroll pane at the center

// Frame layout setup
frame.setLayout(new BorderLayout());
frame.add(graphPanel, BorderLayout.CENTER);

JPanel rightPanel = new JPanel();
rightPanel.setLayout(new GridLayout(4, 1)); // Adjusted grid layout to match components
rightPanel.add(ipActivityPanel);
rightPanel.add(controlPanel);
rightPanel.add(threatPanel);
rightPanel.add(mstPanel); // Add MST panel to the right
frame.add(rightPanel, BorderLayout.EAST);

// Refresh the frame to apply changes
frame.revalidate(); // update er arrange,ment thik rakhte
frame.repaint();  // visually dekhate je thik hoice update er por


        // Initialize IP access count map
        ipAccessCount = new HashMap<>();

        startCaptureButton.addActionListener(e -> {
            captureRunning = true;
            stopCaptureButton.setEnabled(true);
            startCaptureButton.setEnabled(false); // Disable start button once capture starts
            captureThread = new Thread(() -> capturePackets(nif));
            captureThread.start();
        });

        stopCaptureButton.addActionListener(e -> {
            captureRunning = false;
            stopCaptureButton.setEnabled(false);
            startCaptureButton.setEnabled(true); // Enable start button after stopping capture
            if (captureThread != null && captureThread.isAlive()) {
                captureThread.interrupt(); // Interrupt the capture thread
            }
        });

        mstButton.addActionListener(e -> calculateMST());
    }

    private void capturePackets(PcapNetworkInterface nif) {
        try (PcapHandle handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10)) {
            while (captureRunning) {
                Packet packet = handle.getNextPacket();
                if (packet != null) {
                    IpV4Packet ipv4Packet = packet.get(IpV4Packet.class);
                    if (ipv4Packet != null) {
                        String srcIp = ipv4Packet.getHeader().getSrcAddr().getHostAddress();
                        String dstIp = ipv4Packet.getHeader().getDstAddr().getHostAddress();

                        System.out.println("Source IP: " + srcIp + ", Destination IP: " + dstIp); // showing source and des ip in terminal
                        
                        SwingUtilities.invokeLater(() -> updateGraph(srcIp, dstIp));
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

   // Map to store the edge weights between nodes map kintu interface jei pair of  key values nay
private Map<String, Integer> edgeWeights = new HashMap<>();

private void updateGraph(String srcIp, String dstIp) {
    mxGraph.getModel().beginUpdate();
    try {
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

        // Create a unique key for the edge to track its weight
        String edgeKey = srcIp + "-" + dstIp;

        // Check if the edge already exists
        DefaultEdge edge = networkGraph.getEdge(srcIp, dstIp);
        int weight = edgeWeights.getOrDefault(edgeKey, 0); // Get current weight, default is 0

        if (edge == null) {
            // Edge doesn't exist, so create a new one with the default weight
            mxGraph.insertEdge(mxGraph.getDefaultParent(), null, String.valueOf(weight), vertexMap.get(srcIp), vertexMap.get(dstIp));
            networkGraph.addEdge(srcIp, dstIp);
        } else {
            // Edge exists, update the weight
            weight++; // Increase the weight (or calculate based on your logic)
            edgeWeights.put(edgeKey, weight); // Update the weight in the map
            updateEdgeLabel(srcIp, dstIp, weight); // Update the edge label with the new weight
        }
    } finally {
        mxGraph.getModel().endUpdate();
    }

    updateVertexColor(srcIp, "green");
    updateVertexColor(dstIp, "green");

    performBFSAndUpdate(srcIp);

    detectLoopsAndGenerateThreatMessage();

    SwingUtilities.invokeLater(() -> {
        mxCircleLayout layout = new mxCircleLayout(mxGraph);
        layout.execute(mxGraph.getDefaultParent());
    });
}

// Update the edge label to show its weight
private void updateEdgeLabel(String srcIp, String dstIp, int weight) {
    String edgeKey = srcIp + "-" + dstIp;
    for (Object edge : mxGraph.getEdgesBetween(vertexMap.get(srcIp), vertexMap.get(dstIp))) {
        mxGraph.getModel().beginUpdate();
        try {
            // Set the edge label (weight) using the correct method
            mxGraph.getModel().setValue(edge, String.valueOf(weight)); // Set the weight as the edge label
        } finally {
            mxGraph.getModel().endUpdate();
        }
    }
}

private void calculateMST() {
    // Clear previous MST output
    mstTextArea.setText("");

    // Step 1: Create a list to hold all edges and their weights
    List<Edge> edges = new ArrayList<>();
    for (String vertex : networkGraph.vertexSet()) {
        for (DefaultEdge edge : networkGraph.edgesOf(vertex)) {
            String source = networkGraph.getEdgeSource(edge);
            String target = networkGraph.getEdgeTarget(edge);
            String edgeKey = source + "-" + target;
            int weight = edgeWeights.getOrDefault(edgeKey, 0);
            edges.add(new Edge(source, target, weight));
        }
    }

    // Step 2: Sort the edges by weight
    Collections.sort(edges);

    // Step 3: Apply Kruskal's algorithm using a Union-Find (Disjoint Set) structure
    UnionFind unionFind = new UnionFind(networkGraph.vertexSet());

    // Step 4: Create the MST by adding edges that don't form a cycle
    SimpleGraph<String, DefaultEdge> mstGraph = new SimpleGraph<>(DefaultEdge.class);
    StringBuilder mstResult = new StringBuilder();  // StringBuilder to store MST results
    for (Edge edge : edges) {
        if (!unionFind.connected(edge.source, edge.target)) {
            unionFind.union(edge.source, edge.target);
            mstGraph.addVertex(edge.source);
            mstGraph.addVertex(edge.target);
            mstGraph.addEdge(edge.source, edge.target);

            // Append the edge and weight to the MST result
            mstResult.append(edge.source)
                     .append(" - ")
                     .append(edge.target)
                     .append(" (Weight: ")
                     .append(edge.weight)
                     .append(")\n");

            // Insert the MST edge into the mxGraph
            mxGraph.getModel().beginUpdate();
            try {
                mxGraph.insertEdge(mxGraph.getDefaultParent(), null, String.valueOf(edge.weight), 
                        vertexMap.get(edge.source), vertexMap.get(edge.target));
            } finally {
                mxGraph.getModel().endUpdate();
            }
        }
    }

    // Step 5: Update the JTextArea with the MST result
    SwingUtilities.invokeLater(() -> mstTextArea.setText(mstResult.toString()));

    // Step 6: Show a message after MST calculation
    JOptionPane.showMessageDialog(frame, "Minimum Spanning Tree Calculated", "MST", JOptionPane.INFORMATION_MESSAGE);
}





// Edge class to store the source, target, and weight
private static class Edge implements Comparable<Edge> {
    String source;
    String target;
    int weight;

    public Edge(String source, String target, int weight) {
        this.source = source;
        this.target = target;
        this.weight = weight;
    }

    @Override
    public int compareTo(Edge other) {
        return Integer.compare(this.weight, other.weight);
    }
}

// Union-Find (Disjoint Set) class to manage connected components
// Union-Find (Disjoint Set) class to manage connected components
private static class UnionFind { // a disjoint set
    private Map<String, String> parent = new HashMap<>();
    private Map<String, Integer> rank = new HashMap<>();

    public UnionFind(Set<String> vertices) {
        for (String vertex : vertices) {
            parent.put(vertex, vertex);
            rank.put(vertex, 0);
        }
    }

    public String find(String vertex) {
        if (!parent.get(vertex).equals(vertex)) {
            parent.put(vertex, find(parent.get(vertex))); // Path compression
        }
        return parent.get(vertex);
    }

    public void union(String vertex1, String vertex2) {
        String root1 = find(vertex1);
        String root2 = find(vertex2);

        if (!root1.equals(root2)) {
            // Union by rank
            if (rank.get(root1) > rank.get(root2)) {
                parent.put(root2, root1);
            } else if (rank.get(root1) < rank.get(root2)) {
                parent.put(root1, root2);
            } else {
                parent.put(root2, root1);
                rank.put(root1, rank.get(root1) + 1);
            }
        }
    }

    public boolean connected(String vertex1, String vertex2) {
        return find(vertex1).equals(find(vertex2));
    }
}





    // Perform BFS and update the IP access count
    private void performBFSAndUpdate(String startNode) {
        Set<String> visited = new HashSet<>();
        Queue<String> queue = new LinkedList<>();

        queue.add(startNode);
        visited.add(startNode);

        // Perform BFS and update the access count
        while (!queue.isEmpty()) {
            String currentNode = queue.poll();
            
            System.out.println("Visited: " + currentNode); // just showing visited node in the netbeans terminal
            updateVertexColor(currentNode, "yellow"); // Highlight node as visited
            ipAccessCount.put(currentNode, ipAccessCount.getOrDefault(currentNode, 0) + 1);

            // Update the frequently accessed IP list
            ipListModel.clear();
            ipAccessCount.forEach((ip, count) -> ipListModel.addElement(ip + " - " + count));

            // Add adjacent nodes to the queue
            for (DefaultEdge edge : networkGraph.edgesOf(currentNode)) {
                String neighbor = networkGraph.getEdgeSource(edge).equals(currentNode) ? 
                                  (String) networkGraph.getEdgeTarget(edge) : 
                                  (String) networkGraph.getEdgeSource(edge);
                if (!visited.contains(neighbor)) {
                    queue.add(neighbor);
                    visited.add(neighbor);
                }
            }
        }
    }

    // Update the vertex color
    private void updateVertexColor(String ip, String color) {
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

    private void detectLoopsAndGenerateThreatMessage() {
        Set<String> visited = new HashSet<>();
        Set<String> recStack = new HashSet<>();
        for (String node : networkGraph.vertexSet()) {
            if (detectLoopDFS(node, visited, recStack, null)) {
                threatMessageArea.append("Threat Detected: Loop in the network!\n");
                break; // Only display one loop threat at a time
            }
        }
    }

    // Detect a loop using DFS
      private boolean detectLoopDFS(String node, Set<String> visited, Set<String> recStack, String parent) {
    if (recStack.contains(node)) {
        return true; // Loop detected
    }
    if (visited.contains(node)) {
        return false; // Already visited, no loop
    }

    visited.add(node);
    recStack.add(node);

    for (DefaultEdge edge : networkGraph.edgesOf(node)) {
        String neighbor = networkGraph.getEdgeSource(edge).equals(node)
                ? (String) networkGraph.getEdgeTarget(edge)
                : (String) networkGraph.getEdgeSource(edge);

        if (!neighbor.equals(parent) && detectLoopDFS(neighbor, visited, recStack, node)) {
            return true;
        }
    }

    recStack.remove(node);
    return false;
}

}


