package com.javahelps.pcapparser;

import io.pkts.PacketHandler;
import io.pkts.Pcap;
import io.pkts.buffer.Buffer;
import io.pkts.packet.Packet;
import io.pkts.packet.TCPPacket;
import io.pkts.protocol.Protocol;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;

public class Main {

    public static void main(String[] args) throws IOException {
        final Pcap pcap = Pcap.openStream("parse.pcap");
     

        pcap.loop(new PacketHandler() {
            
            StringBuffer csvData = new StringBuffer("");

            public boolean nextPacket(Packet packet) throws IOException {
                if (packet.hasProtocol(Protocol.TCP)) {

                    final PrintWriter pw = new PrintWriter(new File("result.csv"));
 
                    StringBuffer csvHeader = new StringBuffer("");
                    csvHeader.append("Login:password\n");
            
                    pw.write(csvHeader.toString());

                    TCPPacket tcpPacket = (TCPPacket) packet.getPacket(Protocol.TCP);
                    Buffer buffer = tcpPacket.getPayload();
                    if (buffer != null) {
                        final String[] arr = buffer.toString().split(" ", 2);                       
                        if(arr[0].equals("USER")){
                            csvData.append(arr[1].replace("\r\n",""));
                        }
                        if(arr[0].equals("PASS")){
                            csvData.append(":"+arr[1]);
                        }
                    }
                    pw.write(csvData.toString());
                    pw.close();


                }
                
                return true;
                
            }

        });
    }
}