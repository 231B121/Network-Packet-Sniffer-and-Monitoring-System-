pip install -r requirements.txt
   ```

2. **Run the Packet Sniffer**

   Execute the main script to start capturing packets:

   ```bash
   python main.py
   ```

   > **Note:** Administrator or root privileges may be required for live packet capture. On Linux, you can run with `sudo`:
   >
   > ```bash
   > sudo python main.py
   > ```

3. **Monitor Output**

   The system will display real-time packet information including:
   - Source and destination MAC addresses
   - Source and destination IP addresses
   - Protocol type (TCP, UDP, ICMP)
   - Port numbers (for TCP/UDP)
   - TCP flags (for TCP packets)
   - Packet size

4. **Stop Capture**

   Press `Ctrl+C` to stop the packet capture and view the summary statistics.

## How to Run

Install dependencies: