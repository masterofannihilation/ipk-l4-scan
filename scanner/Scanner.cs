using System;
using System.Net;
using System.Net.Sockets;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using ipk_l4_scan.socket;
using ipk_l4_scan.headers;
using ipk_l4_scan.packet;

namespace ipk_l4_scan.scanner
{
    public class Scanner
    {
        public void StartScanner(string interfaceName)
        {
            Console.WriteLine("Initializing scanner socket");
            var scanner = ScannerSocket.InitSocket(interfaceName);

            Console.WriteLine("Initializing remote endpoint");
            IPAddress targetAddress = IPAddress.Parse("127.0.0.1");
            IPEndPoint remoteEp = new IPEndPoint(targetAddress,1200);
            
            // Crafting raw packet
            byte[] packet = Packet.CraftPacket("147.229.197.85", "127.0.0.1", 12345, 1200);
            
            // Sending packet
            Packet.SendPacket(scanner, packet, remoteEp);
            
            scanner.Close();
        }
    }
}