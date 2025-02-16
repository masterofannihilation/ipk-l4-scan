#### 1. Command-Line Argument Parsing (Done)

    Goal: Parse the command-line arguments for parameters like target IP/domain, ports (TCP/UDP), timeout, and interface.
    Action: You’ve already set up ArgParser, so now you can continue with:
        Parse the target IP/domain.
        Handle multiple ports.
        Add logic to specify network interface (if given).

#### 2. Network Interface Selection

    Goal: Bind the socket to a specific network interface if provided.
    Action: Use NetworkInterface.GetAllNetworkInterfaces() to get available interfaces. If the interface is provided via command line, bind the socket to it.

#### 3. Port Scanning Logic

    Goal: Connect to specified ports (TCP/UDP) on the target machine.
    Action:
        For TCP: Create a Socket for each port, attempt a connection, and determine if the port is open or closed.
        For UDP: Send a datagram and check for a response or timeout.
    Timeout Handling: Implement a timeout mechanism (e.g., using Socket.ConnectAsync with a timeout or CancellationToken).

#### 4. Report Results

    Goal: Output the results of the scan to the user.
    Action: For each port, print whether it’s open or closed. You can also add additional details like response time.