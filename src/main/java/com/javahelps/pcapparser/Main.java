package com.javahelps.pcapparser;

import io.pkts.PacketHandler;
import io.pkts.Pcap;
import io.pkts.buffer.Buffer;
import io.pkts.packet.Packet;
import io.pkts.packet.TCPPacket;
import io.pkts.packet.UDPPacket;
import io.pkts.protocol.Protocol;

import java.io.IOException;

public class Main {

    public static void main(String[] args) throws IOException {

        final Pcap pcap = Pcap.openStream("PATH TO FILE");

        pcap.loop(new PacketHandler() {
            public boolean nextPacket(Packet packet) throws IOException {

                if (packet.hasProtocol(Protocol.TCP)) {

                    TCPPacket tcpPacket = (TCPPacket) packet.getPacket(Protocol.TCP);
                    Buffer buffer = tcpPacket.getPayload();
                    if (buffer != null) {
                        final String[] arr = buffer.toString().split(" ", 2);                       
                        if(arr[0].equals("USER")){
                            System.out.println("Utilisateur : " + arr[1]);
                        }
                        if(arr[0].equals("PASS")){
                            System.out.println("Mot de passe : " + arr[1]);
                        }
                    }
                }
                return true;
            }
        });
    }
}