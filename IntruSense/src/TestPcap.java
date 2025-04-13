/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

import org.pcap4j.core.Pcaps;

public class TestPcap {
    public static void main(String[] args) {
        try {
            System.out.println("Available Network Interfaces:");
            Pcaps.findAllDevs().forEach(dev -> {
                System.out.println(dev.getName() + " - " + dev.getDescription());
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
