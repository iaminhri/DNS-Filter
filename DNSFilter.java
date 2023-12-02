import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Arrays;

public class DNSFilter {

    public static void main(String[] args) throws Exception {

        //Attributes
        String [] blacklist = {
                "zombo.com",
                "en.wikipedia.org.",
                "208.80.154.224"
        };

        String ip_to_be_replaced = "139.57.100.6";

        int listenPort = 5754;
        String externalDNS = "8.8.8.8";
        int externalDNSPort = 53;

        // Datagram socket creation for listening on the specified port.
        DatagramSocket socket = new DatagramSocket(listenPort);

        while (true) {
            byte[] recvData = new byte[1024];
            int offset = 12;

            //Recieves packet from dig query
            DatagramPacket recvPacket = new DatagramPacket(recvData, recvData.length);
            socket.receive(recvPacket);

            //Get clientAddress
            InetAddress clientAddress = recvPacket.getAddress();
            int clientPort = recvPacket.getPort();

            //copies recv data to querydata array.
            byte[] queryData = Arrays.copyOfRange(recvData, 0, recvPacket.getLength());

            // new datagram socket and inetaddress of googles for the query to send.
            DatagramSocket externalSocket = new DatagramSocket();
            InetAddress externalDNSAddress = InetAddress.getByName(externalDNS);

            //Sends the data to google or 8.8.8.8 for dns query
            DatagramPacket sendPacket = new DatagramPacket(queryData, queryData.length, externalDNSAddress, externalDNSPort);
            externalSocket.send(sendPacket);

            byte[] responseData = new byte[1024];

            //recieves response from google DNS, stores it in response data byte array.
            DatagramPacket responsePacket = new DatagramPacket(responseData, responseData.length);
            externalSocket.receive(responsePacket);
            externalSocket.close();

            // skipping header section
            offset = 12;

            //Prints the response in hex value.
            System.out.println("Response Receive: ");
            for (int i = 0; i < responsePacket.getLength(); i++) {
                System.out.print(" 0x" + String.format("%x", responseData[i]) + " " );
            }
            System.out.println("\n");

            // ----------------------------------------------------------------
            // Calculates the number of answers returned by DNS server.
            int numAnswers = responseData[6] * 256 + responseData[7];
            System.out.println(numAnswers + " answers received.");

            //Iterating until domain name is terminated by null character.
            while(responseData[offset] != 0){
                offset += responseData[offset]+1;
            }

            System.out.println();

            offset += 2; //type

            offset += 8; // class, TTL, RDlength fields

            offset += 4; // rdl

            offset += 2; // offset at rdata

            String extractedIP;
            String getBlockedIP;

            //Iterates till reaches the numbers of answers
            for(int i = 0; i < numAnswers; i++){
                int rdl = responseData[offset] & 0xFF;
                boolean replace = false;
                /**
                 *  if data length is 4 than extracts IP in a string format
                 *  than compares with the blacklist for each IP than stores the information in a boolean variable.
                 */
                if(rdl == 4){
                    //extracts IP at the offset location
                    extractedIP =(responseData[offset+1] & 0xFF) + "." + (responseData[offset+2] & 0xFF) + "." + (responseData[offset+3] & 0xFF) + "." + (responseData[offset+4] & 0xFF);
                    // checks each IP from blacklist with the extracted IP from the response.
                    for(String blockIP : blacklist){
                        // gets the host address of the blacklisted IP's
                        // note: For some reason the ip replies with a different IP, so I hard codeed one of IP address in the blacklist 
                        InetAddress s = InetAddress.getByName(blockIP);
                        getBlockedIP = s.getHostAddress();
                        System.out.println("Blocked IP Address: " + getBlockedIP);
                        //if extracted ip and blocked ip matches returns true.
                        if(extractedIP.equals(getBlockedIP)){
                            extractedIP = getBlockedIP;
                            replace = true;
                        }
                    }
                    /**
                     * if replace == true
                     * than it replaces the provided IP by converting it into byte values
                     * than going to the offset of the IP of DNS response and Replaces it.
                     * */
                    if(replace){
                        String [] ipParts = ip_to_be_replaced.split("\\.");
                        byte[] replacedIpBytes = new byte[ipParts.length];


                        // converts data from ipParts (String) to (bytes)
                        for(int k = 0; k < ipParts.length; k++){
                            replacedIpBytes[k] = (byte)Integer.parseInt(ipParts[k]);
                        }

                        System.out.println("Replace IP Bytes: ");

                        //Modifies the response by going to the offset of IP address
                        for(int k = 0; k < replacedIpBytes.length; k++){
                            responseData[offset+k+1] = replacedIpBytes[k];
                        }
                    }
                    System.out.println("Extracted IP: " + extractedIP);
                    offset += 16; //Offset set for the next answer 
                    // 4 bytes for IP that was replaced andn 12 bytes for answer section 
                }
                else{
                    offset = offset + rdl + 12; // offset goes to the next r data section if it's CNAME Or something else other than IP.
                }
            }
            /**
             * Forwards the modified response to the targeted address and port.
             * */
            DatagramPacket clientResponsePacket = new DatagramPacket(responseData, responsePacket.getLength(), clientAddress, clientPort);
            socket.send(clientResponsePacket);
        }
    }
}

