/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package redes120153;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import jpcap.*;
import jpcap.packet.ARPPacket;
import jpcap.packet.*;

/**
 *
 * @author Juan Pablo Rodríguez
 */

//https://code.google.com/p/tcp-connection-sniffer/source/browse/trunk/jpcap/sample/ARP.java?r=5
public class Redes120153 {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws UnknownHostException, IOException {
        Scanner sc = new Scanner(System.in);
        String ip, mascara;
        System.out.println("La IP: ");
        ip = sc.nextLine();
        System.out.println("La Mascara: ");
        mascara = sc.nextLine();
        List<InetAddress> ips = obtenerDispositivos(ip, mascara);

    }

    private static List<InetAddress> obtenerDispositivos(String ip, String mascara) throws UnknownHostException, IOException {
        List<InetAddress> ips = new ArrayList();
        String[] partIp = ip.split("\\.+");
        String newIp = partIp[0] + "." + partIp[1] + "." + partIp[2] + ".";
        int timeout = 1050;
        int num = 0, maxD = -1;
        for (int i = 0; i < 20; i++) {
            if (num == maxD) {
                break;
            }
            String host = newIp + i;
            InetAddress auxiliar = InetAddress.getByName(host);
            if (auxiliar.isReachable(timeout)) {
                ips.add(auxiliar);
                /*for (byte b : auxiliar.getAddress())
                 System.out.print(Integer.toHexString(b&0xff) + ":");
                 System.out.println("");*/
                num++;
            }
        }
        return ips;
    }

    private static byte[] arp(InetAddress ip) throws IOException {
        NetworkInterface[] devices = JpcapCaptor.getDeviceList();
        NetworkInterface device = null;

        for (NetworkInterface d : devices) {
            for (NetworkInterfaceAddress addr : d.addresses) {
                if (!(addr.address instanceof Inet4Address)) {
                    continue;
                }
                byte[] bip = ip.getAddress();
                byte[] subnet = addr.subnet.getAddress();
                byte[] bif = addr.address.getAddress();
                for (int i = 0; i < 4; i++) {
                    bip[i] = (byte) (bip[i] & subnet[i]);
                    bif[i] = (byte) (bif[i] & subnet[i]);
                }
                if (Arrays.equals(bip, bif)) {
                    device = d;
                    break;
                }
            }
        }

        if (device == null) {
            throw new IllegalArgumentException(ip + " is not a local address");
        }

        //open Jpcap
        JpcapCaptor captor = JpcapCaptor.openDevice(device, 2000, false, 3000);
        captor.setFilter("arp", true);
        JpcapSender sender = captor.getJpcapSenderInstance();
        InetAddress srcip = null;
        for (NetworkInterfaceAddress addr : device.addresses) {
            if (addr.address instanceof Inet4Address) {
                srcip = addr.address;
                break;
            }
        }

        byte[] broadcast = new byte[]{(byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255};
        ARPPacket arp = new ARPPacket();
        arp.hardtype = ARPPacket.HARDTYPE_ETHER;
        arp.prototype = ARPPacket.PROTOTYPE_IP;
        arp.operation = ARPPacket.ARP_REQUEST;
        arp.hlen = 6;
        arp.plen = 4;
        arp.sender_hardaddr = device.mac_address;
        arp.sender_protoaddr = srcip.getAddress();
        arp.target_hardaddr = broadcast;
        arp.target_protoaddr = ip.getAddress();

        EthernetPacket ether = new EthernetPacket();
        ether.frametype = EthernetPacket.ETHERTYPE_ARP;
        ether.src_mac = device.mac_address;
        ether.dst_mac = broadcast;
        arp.datalink = ether;
        sender.sendPacket(arp);
        while (true) {
            ARPPacket p = (ARPPacket) captor.getPacket();
            if (p == null) {
                throw new IllegalArgumentException(ip + " is not a local address");
            }
            if (Arrays.equals(p.target_protoaddr, srcip.getAddress())) {
                return p.sender_hardaddr;
            }
        }
    }
}
