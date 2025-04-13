/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package intrusense;

import javax.swing.*;
import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.Queue;

import com.mxgraph.swing.mxGraphComponent;
import com.mxgraph.view.mxGraph;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.SimpleDirectedGraph;

public class IntruSense {

    private static final SimpleDirectedGraph<String, DefaultEdge> networkGraph = new SimpleDirectedGraph<>(DefaultEdge.class);
    private static boolean isGraphVisible = true;

    public static void main(String[] args) {
        JFrame frame = setupInterface();
        capturePackets(frame);
    }

    private static JFrame setupInterface() {
        JFrame frame = new JFrame("IntruSense: Network Intrusion Detection System");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(1200, 800);

        // Graph Visualization Panel
        mxGraph mxGraph = new mxGraph();
        mxGraphComponent graphComponent = new mxGraphComponent(mxGraph);
        frame.getContentPane().add(graphComponent, BorderLayout.CENTER);

        // Right Panel for Notifications
        JPanel rightPanel = new JPanel();
        rightPanel.setLayout(new BoxLayout(rightPanel, BoxLayout.Y_AXIS));

        // Frequent IPs Section
        JLabel frequentIpsLabel = new JLabel("Frequent IPs:");
        JTextArea frequentIpsArea = new JTextArea(10, 20);
        frequentIpsArea.setEditable(false);
        rightPanel.add(frequentIpsLabel);
        rightPanel.add(new JScrollPane(frequentIpsArea));

        // Threat Alerts Section
        JLabel threatAlertsLabel = new JLabel("Threat Alerts:");
        JTextArea threatAlertsArea = new JTextArea(10, 20);
        threatAlertsArea.setEditable(false);
        rightPanel.add(threatAlertsLabel);
        rightPanel.add(new JScrollPane(threatAlertsArea));

        // Graph Visualization Toggle Button
        JButton toggleGraphButton = new JButton("Hide Graph");
        toggleGraphButton.addActionListener(e -> {
            isGraphVisible = !isGraphVisible;
            graphComponent.setVisible(isGraphVisible);
            toggleGraphButton.setText(isGraphVisible ? "Hide Graph" : "Show Graph");
        });
        rightPanel.add(toggleGraphButton);

        frame.getContentPane().add(rightPanel, BorderLayout.EAST);
        frame.setVisible(true);

        return frame;
    }

    private static void capturePackets(JFrame frame) {
        JTextArea frequentIpsArea = (JTextArea) ((JScrollPane) ((JPanel) frame.getContentPane().getComponent(1)).getComponent(1)).getViewport().getView();
        JTextArea threatAlertsArea = (JTextArea) ((JScrollPane) ((JPanel) frame.getContentPane().getComponent(1)).getComponent(3)).getViewport().getView();

        // Simulating packet capture (replace this with actual packet capture logic)
        new java.util.Timer().schedule(new java.util.TimerTask() {
    @Override
    public void run() {
        String srcIp = "192.168.1." + (new Random().nextInt(50) + 1);
        String destIp = "192.168.1." + (new Random().nextInt(50) + 1);

        addEdgeToGraph(srcIp, destIp);
        performBFSForFrequentIPs(srcIp, frequentIpsArea);
        performDFSForLoops(srcIp, threatAlertsArea);
    }
}, 0, 2000); // Simulate new packet every 2 seconds
    }

    private static void addEdgeToGraph(String srcIp, String destIp) {
        networkGraph.addVertex(srcIp);
        networkGraph.addVertex(destIp);
        networkGraph.addEdge(srcIp, destIp);
    }

    private static void performBFSForFrequentIPs(String startNode, JTextArea frequentIpsArea) {
        Map<String, Integer> ipFrequency = new HashMap<>();

        Queue<String> queue = new LinkedList<>();
        Set<String> visited = new HashSet<>();

        queue.add(startNode);
        visited.add(startNode);

        while (!queue.isEmpty()) {
            String current = queue.poll();
            ipFrequency.put(current, ipFrequency.getOrDefault(current, 0) + 1);

            for (DefaultEdge edge : networkGraph.edgesOf(current)) {
                String neighbor = networkGraph.getEdgeSource(edge).equals(current)
                        ? networkGraph.getEdgeTarget(edge)
                        : networkGraph.getEdgeSource(edge);

                if (!visited.contains(neighbor)) {
                    visited.add(neighbor);
                    queue.add(neighbor);
                }
            }
        }

        // Update UI with frequent IPs
        SwingUtilities.invokeLater(() -> {
            frequentIpsArea.setText("");
            ipFrequency.entrySet().stream()
                    .sorted((a, b) -> b.getValue() - a.getValue())
                    .forEach(entry -> frequentIpsArea.append(entry.getKey() + ": " + entry.getValue() + "\n"));
        });
    }

    private static void performDFSForLoops(String startNode, JTextArea threatAlertsArea) {
        Set<String> visited = new HashSet<>();
        Set<String> stack = new HashSet<>();

        if (detectCycleDFS(startNode, visited, stack)) {
            SwingUtilities.invokeLater(() -> {
                threatAlertsArea.append("Threat Alert: Loop detected starting at " + startNode + "\n");
            });
        }
    }

    private static boolean detectCycleDFS(String node, Set<String> visited, Set<String> stack) {
        if (stack.contains(node)) {
            return true; // Cycle detected
        }
        if (visited.contains(node)) {
            return false;
        }

        visited.add(node);
        stack.add(node);

        for (DefaultEdge edge : networkGraph.edgesOf(node)) {
            String neighbor = networkGraph.getEdgeSource(edge).equals(node)
                    ? networkGraph.getEdgeTarget(edge)
                    : networkGraph.getEdgeSource(edge);

            if (detectCycleDFS(neighbor, visited, stack)) {
                return true;
            }
        }

        stack.remove(node);
        return false;
    }
}

