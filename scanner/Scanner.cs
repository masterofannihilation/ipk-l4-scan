using System;
using System.Net;
using System.Net.Sockets;
using System.Reflection.Emit;
using ipk_l4_scan.socket;
using ipk_l4_scan.headers;

namespace ipk_l4_scan.scanner
{
    public class Scanner
    {
        public void StartScanner(string interfaceName){
            Console.WriteLine("Starting scanner");
            
            var scanner = ScannerSocket.InitSocket(interfaceName);
            Console.WriteLine("Initializing socket");

            // IPAddress targetAddress = IPAddress.Parse("127.0.0.1");
            // IPEndPoint remoteEp = new IPEndPoint(targetAddress,12345);
            // Console.WriteLine("Initialized remote endpoint");

            IpV4 ipV4 = new IpV4("147.229.197.85", "127.0.0.1");
            
            scanner.Close();
        }
    }
}