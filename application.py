import argparse
import socket
import struct
import os
import time
from datetime import datetime 

HEADER_LENGTH = 8 
DATA_CHUNK_SIZE = 992 
PACKET_SIZE = HEADER_LENGTH + DATA_CHUNK_SIZE

DEFAULT_PORT = 8088
DEFAULT_WINDOW_SIZE = 3 
RECEIVER_WINDOW_ON_SYN_ACK = 15 
GBN_TIMEOUT_DURATION = 0.4  # 400 ms
CONNECTION_SETUP_TIMEOUT = 5.0 

# DRTP Flags 
FLAG_RST = 1 << 0  
FLAG_ACK = 1 << 1  
FLAG_SYN = 1 << 2  
FLAG_FIN = 1 << 3  

def log_message_ts(message_text): # For messages that need a timestamp as per example
    """
    Description:
        Prints a log message with a timestamp, like in the assignment examples.
    Arguments:
        str message_text: the message the user wants to log 
    Returns:
        None, but prints to console for logging purposes.
    """
    timestamp_str = datetime.now().strftime('%H:%M:%S.%f')
    print(f"{timestamp_str} -- {message_text}")

# --- DRTPPacket Class ---
class DRTPPacket:
    """
        Handles DRTP packet creation and parsing.
        Contains methods to pack and unpack packets, and manage header fields.    """
    _header_format_string = '!HHHH' 

    def __init__(self, seq_num=0, ack_num=0, flags=0, recv_window=0, data_payload=b''):
        """
        Description:
            Initializes a DRTP packet with given parameters.
        Arguments:
            sets all the attributes to 0 by default:
                seq_num: sequence number to identify the packet
                ack_num: Acknowledgment number to acknowledge received packets
                flags: the different flags for the packet 
                recv_window: sets the receiver window size
                data_payload: the data to be sent in the packet
        Returns:
            None because it is a constructor.
        """
        self.seq_num = seq_num & 0xFFFF
        self.ack_num = ack_num & 0xFFFF
        self.flags = (flags & ~FLAG_RST) & 0xFFFF # R flag not used, ensure it's 0 unless specified
        self.recv_window = recv_window & 0xFFFF
        self.data = data_payload

    def pack(self):
        """
        Description:
            Packs the packets header and appends data into a byte string for sending
        Arguments:
            None it uses instance attributes
        Returns:
            The complete packet as a byte string , since it is the raw format for UDP sending.
        Error Handling:
            raises struct.error if packing fails
        """
        try:
            packed_header = struct.pack(self._header_format_string,
                                        self.seq_num, self.ack_num,
                                        self.flags, self.recv_window)
        except struct.error as e:
            # This kind of error is critical, so logging and raising is good.
            print(f"Error: Pack failed - {e}") 
            raise 
        return packed_header + self.data

    @staticmethod
    def unpack(raw_packet_bytes):
        """
        Description:
            Parses a raw byte string into a DRTPPacket object unpacking the header fields
        Arguments:
            raw_packet_bytes: The raw bytes received from the network to be unpacked
        Returns:
            DRTPPacket or None: An instance if parsing is successful, else raises error and returns None
        Error Handling:
            try to unpack the header and if it fails, log a warning and return None
            raises struct.error if unpacking fails
        """
        if len(raw_packet_bytes) < HEADER_LENGTH:
            return None 
        try:
            header_tuple = struct.unpack(DRTPPacket._header_format_string,
                                         raw_packet_bytes[:HEADER_LENGTH])
        except struct.error:
            return None 
        
        data_payload_part = raw_packet_bytes[HEADER_LENGTH:]
        return DRTPPacket(seq_num=header_tuple[0], ack_num=header_tuple[1],
                          flags=header_tuple[2], recv_window=header_tuple[3],
                          data_payload=data_payload_part)

class DRTPServer:
    """
    Description:
        Implements the DRTP server. listens for the client, receives a file,calculates throughput, then shuts down.
    """
    def __init__(self, ip_addr, port_num, discard_packet_seq=None):
        """
        Description:
            Initializes the server.
        Arguments:
            ip_addr: IP address to bind to.
            port_num: Port to listen on.
            discard_packet_seq: Sequence number to discard once for testing.
        Returns:
            None
        """
        self.host_ip = ip_addr
        self.port = port_num
        self.discard_seq = discard_packet_seq 
        self.discard_seq_triggered = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.expected_seq_num = 1
        self.client_addr = None
        self.output_filename = "received_file.dat" 
        self.connection_active = False
        self.total_bytes_received_payload = 0
        self.total_bytes_received_with_header = 0
        self.start_time_transfer = 0.0
        self.end_time_transfer = 0.0

    def start(self):
        """
        Description:
            Main server loop: binds, establishes connection, receives data, closes.
        Arguments:
            None
        Returns:
            None Orchestrates server operation.
        Error Handling:
            Handles socket errors and general exceptio
        """
        try:
            self.sock.bind((self.host_ip, self.port))
            print(f"Server listening on {self.host_ip}:{self.port}") 
            if not self._establish_connection_server():
                return
            self._receive_file_data()
        except socket.error as e_sock:
            print(f"Server Socket Err: {e_sock}") 
        except Exception as e_general:
            print(f"Server General Err: {e_general}")
        finally:
            if self.start_time_transfer > 0: # Check if transfer even started
                if self.connection_active and self.end_time_transfer == 0: # If connection was active but FIN not received (e.g. client crash)
                    self.end_time_transfer = time.time()
                
                if self.end_time_transfer > self.start_time_transfer and self.total_bytes_received_with_header > 0:
                    duration = self.end_time_transfer - self.start_time_transfer
                    if duration > 0: # Avoid division by zero if times are too close or identical
                        throughput_mbps = (self.total_bytes_received_with_header * 8) / (duration * 1000000.0) # 1MB = 1000KB = 1,000,000 Bytes
                        print(f"The throughput is {throughput_mbps:.2f} Mbps")
                elif self.total_bytes_received_with_header == 0 and self.connection_active : # Connection established but no data
                     print("Throughput: No data received for calculation.")
                # else:
                    # print("Throughput: Not enough data or valid duration.") # Optional

                print("Connection Closes")
            
            if self.sock:
                self.sock.close()
            print("Server shut down.")

    def _establish_connection_server(self):
        """
        Description:
            Server-side 3-way handshake. Waits for SYN, sends SYN-ACK, waits for ACK.
        Arguments:
            None
        Returns:
            bool: True if successful, False otherwise, signals if data transfer can proceed.
        Error Handling:
            Handles socket timeouts and general exceptions
        """
        try:
            self.sock.settimeout(None) # Wait indefinitely for the first SYN
            raw_syn, client_address_info = self.sock.recvfrom(PACKET_SIZE)
            syn_pkt = DRTPPacket.unpack(raw_syn)
            if not syn_pkt or not (syn_pkt.flags & FLAG_SYN):
                print("Did not receive a valid SYN packet.")
                return False 
            self.client_addr = client_address_info
            print("SYN packet is received")

            syn_ack_pkt = DRTPPacket(flags=FLAG_SYN | FLAG_ACK,
                                     recv_window=RECEIVER_WINDOW_ON_SYN_ACK) # Server advertises its window
            self.sock.sendto(syn_ack_pkt.pack(), self.client_addr)
            print("SYN-ACK packet is sent")

            # Make sure this timeout is reasonable for handshake
            self.sock.settimeout(CONNECTION_SETUP_TIMEOUT) 
            raw_ack, _ = self.sock.recvfrom(PACKET_SIZE)
            ack_pkt = DRTPPacket.unpack(raw_ack)
            # ACK should have only ACK flag, not SYN
            if not ack_pkt or not ((ack_pkt.flags & FLAG_ACK) and not (ack_pkt.flags & FLAG_SYN)):
                print("Did not receive a valid ACK for SYN-ACK.") 
                return False
            print("ACK packet is received")
            print("Connection established")
            self.connection_active = True
            self.start_time_transfer = time.time() # Start timing for throughput calculation
            return True
        except socket.timeout:
            print("Server: Timeout in handshake.") 
            return False
        except Exception as e: 
            print(f"Server: Error in handshake - {e}") # Catch other errors
            return False

    def _receive_file_data(self):
        """
        Description:
            Receives file data using GBN logic. Writes to file, sends ACKs. Handles FIN.
        Arguments:
            None
        Returns:
            None, since it manages data reception state and side effects.
        Error Handling:
            Handles socket timeouts and general exceptions
        """
        try:
            with open(self.output_filename, 'wb') as file_out:
                while self.connection_active:
                    try:
                        # Using a longer timeout for data/FIN than GBN client timeout
                        self.sock.settimeout(GBN_TIMEOUT_DURATION * 5) # e.g. 2 seconds, or CONNECTION_SETUP_TIMEOUT * 2
                        raw_data, sender_addr = self.sock.recvfrom(PACKET_SIZE)
                        
                        if sender_addr != self.client_addr: 
                            continue
                        
                        pkt = DRTPPacket.unpack(raw_data)
                        if not pkt: 
                            print("Failed to unpack received packet.") 
                            continue

                        if pkt.flags & FLAG_FIN:
                            self.end_time_transfer = time.time() # Mark end time for throughput
                            print("FIN packet is received")
                            
                            # Inlined _send_fin_ack_server
                            fin_ack_resp = DRTPPacket(ack_num=pkt.seq_num, flags=FLAG_FIN | FLAG_ACK)
                            try:
                                self.sock.sendto(fin_ack_resp.pack(), self.client_addr)
                                print("FIN ACK packet is sent")
                            except socket.error as e_fin_ack: 
                                print(f"Server: Error sending FIN-ACK: {e_fin_ack}")
                            
                            self.connection_active = False # End of connection
                            break # Exit receiving loop

                        if self.discard_seq is not None and pkt.seq_num == self.discard_seq and \
                           not self.discard_seq_triggered:
                            print(f"Simulating discard of packet seq={pkt.seq_num}") 
                            self.discard_seq_triggered = True # Only discard once
                            continue # Skip processing this packet

                        if pkt.seq_num == self.expected_seq_num:
                            log_message_ts(f"packet {pkt.seq_num} is received")
                            file_out.write(pkt.data)
                            self.total_bytes_received_payload += len(pkt.data)
                            self.total_bytes_received_with_header += len(raw_data)
                            
                            ack_resp = DRTPPacket(ack_num=pkt.seq_num, flags=FLAG_ACK,
                                                  recv_window=RECEIVER_WINDOW_ON_SYN_ACK) # Can keep advertising window
                            self.sock.sendto(ack_resp.pack(), self.client_addr)
                            log_message_ts(f"sending ack for the received {pkt.seq_num}") # Timestamped
                            self.expected_seq_num += 1
                        elif pkt.seq_num < self.expected_seq_num: # Duplicate of an already ACKed packet
                            ack_resp = DRTPPacket(ack_num=pkt.seq_num, flags=FLAG_ACK) 
                            self.sock.sendto(ack_resp.pack(), self.client_addr)
                        else: # Out-of-order packet (pkt.seq_num > self.expected_seq_num)
                            # GBN receiver discards out-of-order packets.
                            # It ACKs the last correctly received in-order packet.
                            print(f"Server: out-of-order packet {pkt.seq_num} (expected {self.expected_seq_num}). Discarding.")
                            if self.expected_seq_num > 1: # If we have received at least one packet
                                ack_resp = DRTPPacket(ack_num=self.expected_seq_num -1 , flags=FLAG_ACK)
                                self.sock.sendto(ack_resp.pack(), self.client_addr)
                    
                    except socket.timeout:
                        print("Server: Timeout waiting for data/FIN.")
                        self.connection_active = False # Assume client has given up or crashed
                        if not self.end_time_transfer and self.start_time_transfer > 0: # If transfer had started
                            self.end_time_transfer = time.time()
                        break # Exit receiving loop
        except IOError as e:
            print(f"Server: File I/O error for '{self.output_filename}'. Error: {e}") 
            self.connection_active = False # Stop if file can't be written
            if not self.end_time_transfer and self.start_time_transfer > 0:
                self.end_time_transfer = time.time()


class DRTPClient:
    """
    Description:
        Implements the DRTP client. Connects to server, sends a file using GBN,
        then tears down connection.
    """
    def __init__(self, s_ip, s_port, file_to_send, win_size):
        """
        Description:
            Initializes the client
        Arguments:
            s_ip: Servers IP address
            s_port: Servers port number
            file_to_send: Path to the local file to send
            win_size: Clients sending window size
        Returns:
            None
        """
        self.server_ip = s_ip
        self.server_port = s_port
        self.filename = file_to_send
        self.window_size_arg = win_size
        self.effective_window_size = win_size 
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_addr = (self.server_ip, self.server_port)
        self.base_seq_num = 1
        self.next_seq_num = 1
        self.sent_packets_buffer = {} 
        self.gbn_timer_start_time = None
        self.file_handle = None
        self.eof_reached = False
        self.connection_established = False
        self.last_fin_seq_num = 0 # To store the sequence number of the FIN packet

    def start(self):
        """
        Description:
            Main client loop: checks file, connects, sends data, tears down
        Arguments:
            None
        Returns:
            None since it orchestrates the client operation
        Error Handling:
            Handles socket errors and general exceptions such as file not found
        """
        try:
            if not os.path.exists(self.filename):
                print(f"Client: File '{self.filename}' not found. Exiting.")
                return
            
            print("Connection Establishment Phase:")
            if not self._establish_connection_client():
                return # Error message handled in _establish_connection_client
            self.connection_established = True
            
            print("Data Transfer:") 
            self.file_handle = open(self.filename, 'rb')
            if os.path.getsize(self.filename) == 0: 
                print(f"Client: File '{self.filename}' is empty.")
                self.eof_reached = True 
            
            self._send_file_data_gbn() 
            
            # Check if all data sent and acknowledged
            if self.eof_reached and self.base_seq_num == self.next_seq_num: 
                print("DATA Finished") 
        
        except FileNotFoundError: 
             print(f"Client: File '{self.filename}' could not be opened. Exiting.")
        except IOError as e:
            print(f"Client: File I/O error with '{self.filename}'. Error: {e}")
        except socket.error as e:
            print(f"Client: Socket error during operation. Error: {e}")
        except Exception as e: 
            print(f"Client: An unexpected error occurred: {e}")
        finally:
            if self.file_handle: 
                self.file_handle.close()
            if self.connection_established: 
                print("Connection Teardown:")
                self._teardown_connection_client()
            if self.sock: 
                self.sock.close()

    def _establish_connection_client(self):
        """
        Description:
            Client-side 3-way handshake. Sends SYN, waits for SYN-ACK, sends ACK.
            Adjusts window size based on server's response.
        Arguments:
            None
        Returns:
            bool: True if successful, False otherwise.
        """
        try:
            syn_pkt = DRTPPacket(flags=FLAG_SYN)
            self.sock.sendto(syn_pkt.pack(), self.server_addr)
            print("SYN packet is sent")

            self.sock.settimeout(CONNECTION_SETUP_TIMEOUT)
            raw_syn_ack, _ = self.sock.recvfrom(PACKET_SIZE)
            syn_ack_pkt = DRTPPacket.unpack(raw_syn_ack)

            if not syn_ack_pkt or not (syn_ack_pkt.flags & FLAG_SYN and syn_ack_pkt.flags & FLAG_ACK):
                print("Connection failed: Invalid SYN-ACK received.") 
                return False
            
            server_rcv_win = syn_ack_pkt.recv_window
            self.effective_window_size = min(self.window_size_arg, server_rcv_win)
            if self.effective_window_size <= 0: 
                self.effective_window_size = 1
            
            print("SYN-ACK packet is received")

            ack_pkt = DRTPPacket(flags=FLAG_ACK) 
            self.sock.sendto(ack_pkt.pack(), self.server_addr)
            print("ACK packet is sent")
            print("Connection established")
            return True
        except socket.timeout:
            print("Connection failed: Timeout waiting for SYN-ACK.") 
            return False
        except socket.error as e:
            print(f"Connection failed: Socket error - {e}")
            return False
        except Exception as e: 
            print(f"Connection failed: Unexpected error - {e}")
            return False

    def _send_file_data_gbn(self):
        """
        Description:
            Sends file data using GBN. Manages window, sends packets, handles ACKs and timeouts.
        Arguments:
            None.
        Returns:
            None.
        """
        while not self.eof_reached or self.base_seq_num < self.next_seq_num:
            while self.next_seq_num < self.base_seq_num + self.effective_window_size and \
                  not self.eof_reached:
                data_payload_chunk = self.file_handle.read(DATA_CHUNK_SIZE)
                if not data_payload_chunk:
                    self.eof_reached = True
                    # No more data to send, just wait for ACKs for outstanding packets
                    if self.base_seq_num == self.next_seq_num: # All sent packets are ACKed
                        return 
                    break # Exit inner send loop
                
                data_pkt_obj = DRTPPacket(seq_num=self.next_seq_num, data_payload=data_payload_chunk)
                data_pkt_bytes = data_pkt_obj.pack()
                self.sent_packets_buffer[self.next_seq_num] = data_pkt_bytes # Buffer for retransmission
                
                try:
                    self.sock.sendto(data_pkt_bytes, self.server_addr)
                except socket.error as e:
                    print(f"Client: Socket error sending packet {self.next_seq_num}: {e}")
                    return # Critical error, stop GBN

                window_log_display_list = sorted([s for s in self.sent_packets_buffer if s >= self.base_seq_num])
                window_log_str = ", ".join(map(str, window_log_display_list))
                log_message_ts(f"packet with seq = {self.next_seq_num} is sent, sliding window = {{{window_log_str}}}")
                
                if self.base_seq_num == self.next_seq_num: # This is the first packet in the window (or window just advanced)
                    self.gbn_timer_start_time = time.time() # Start GBN timer
                self.next_seq_num += 1
            
            if self.eof_reached and self.base_seq_num == self.next_seq_num:
                break # All data sent and acknowledged

            # Wait for ACK or handle timeout
            try:
                current_timeout_val = GBN_TIMEOUT_DURATION
                if self.gbn_timer_start_time: # If timer is running
                    time_passed = time.time() - self.gbn_timer_start_time
                    remaining_on_timer = GBN_TIMEOUT_DURATION - time_passed
                    if remaining_on_timer <= 0: 
                        raise socket.timeout # Timer effectively expired
                    current_timeout_val = remaining_on_timer
                elif not (self.base_seq_num < self.next_seq_num): # No outstanding packets
                    if self.eof_reached: break 
                    continue 

                self.sock.settimeout(current_timeout_val)
                raw_ack, _ = self.sock.recvfrom(HEADER_LENGTH) # ACKs are header-only
                ack_pkt_obj = DRTPPacket.unpack(raw_ack)

                if ack_pkt_obj and (ack_pkt_obj.flags & FLAG_ACK):
                    log_message_ts(f"ACK for packet = {ack_pkt_obj.ack_num} is received") # Timestamped
                    if ack_pkt_obj.ack_num >= self.base_seq_num:
                        # Valid cumulative ACK, slide window
                        for i in range(self.base_seq_num, ack_pkt_obj.ack_num + 1):
                            self.sent_packets_buffer.pop(i, None) # Remove ACKed packets
                        self.base_seq_num = ack_pkt_obj.ack_num + 1
                        
                        if self.base_seq_num == self.next_seq_num: # All outstanding packets ACKed
                            self.gbn_timer_start_time = None # Stop timer
                        else: # Still outstanding packets
                            self.gbn_timer_start_time = time.time() # Restart timer for new base

            except socket.timeout:
                if self.base_seq_num < self.next_seq_num: # If there are unacknowledged packets
                    print("RTO occured")
                    self.gbn_timer_start_time = time.time() # Restart timer
                    # Retransmit all packets in the current window
                    for seq_to_resend in range(self.base_seq_num, self.next_seq_num):
                        if seq_to_resend in self.sent_packets_buffer:
                            bytes_to_resend_pkt = self.sent_packets_buffer[seq_to_resend]
                            try:
                                self.sock.sendto(bytes_to_resend_pkt, self.server_addr)
                            except socket.error as e:
                                print(f"Client: Socket error retransmitting packet {seq_to_resend}: {e}")
                                return # Critical error

    def _teardown_connection_client(self):
        """
        Description:
            Client-side 2-way handshake. Sends FIN, waits for FIN-ACK.
        Arguments:
            None.
        Returns:
            bool: True if successful, False otherwise.
        """
        try:
            self.last_fin_seq_num = self.next_seq_num # FIN uses the next seq num
            fin_pkt_obj = DRTPPacket(seq_num=self.last_fin_seq_num, flags=FLAG_FIN)
            
            self.sock.sendto(fin_pkt_obj.pack(), self.server_addr)
            print("FIN packet is sent")
            self.sock.settimeout(CONNECTION_SETUP_TIMEOUT) 
            raw_fin_ack, _ = self.sock.recvfrom(PACKET_SIZE) 
            fin_ack_pkt_obj = DRTPPacket.unpack(raw_fin_ack)

            if fin_ack_pkt_obj and \
               (fin_ack_pkt_obj.flags & FLAG_FIN) and \
               (fin_ack_pkt_obj.flags & FLAG_ACK) and \
               (fin_ack_pkt_obj.ack_num == self.last_fin_seq_num):
                print("FIN ACK packet is received")
                print("Connection Closes")
                return True
            else:
                print("Connection Closes (FIN-ACK not received or invalid)") 
                return False
        except socket.timeout:
            print("Connection Closes (Timeout waiting for FIN-ACK)")
            return False
        except socket.error as e:
            print(f"Connection Closes (Socket error during teardown: {e})")
            return False
        except Exception as e: 
            print(f"Connection Closes (Unexpected error in teardown: {e})") 
            return False

def check_port_arg_main(port_value_str):
    """
    Description:
        Validates port number for argparse and converts to int checking if it is in range 
    Arguments:
        port_value_str: Port number from command line arguments as a string
        gets converted to int and checked if it is in range
    Returns:
        int port: Validated port number, its for argparse type checking. 
    Error Handling:
        Raises error if invalid value is given or out of range
    """
    try:
        port = int(port_value_str)
        if not (1024 <= port <= 65535):
            raise argparse.ArgumentTypeError(f"Port {port} out of range [1024-65535].")
        return port
    except ValueError: # If int() conversion fails
        raise argparse.ArgumentTypeError(f"Port '{port_value_str}' not a valid integer.")

def main():
    """
    Description:
        main function to run the DRTP application. It sets up the interface,
        parses the CLI arguments, and starts the server or client based on the selected mode
    Arguments:
        None. It uses argparse to handle command-line arguments
    Returns:
        None, since its purpose is to set up and run the application
    Error Handling:
        Handles argument parsing errors
    """
    arg_parser = argparse.ArgumentParser(description="DRTP File Transfer Application.")
    mode_selection_group = arg_parser.add_mutually_exclusive_group(required=True)
    mode_selection_group.add_argument("-s", "--server", action="store_true", help="Server mode.")
    mode_selection_group.add_argument("-c", "--client", action="store_true", help="Client mode.")
    
    arg_parser.add_argument("-i", "--ip", type=str, help="IP address (Server: IP to bind, Client: Server IP).")
    arg_parser.add_argument("-p", "--port", type=check_port_arg_main, default=DEFAULT_PORT, help=f"Port number. Default: {DEFAULT_PORT}.")
    
    arg_parser.add_argument("-f", "--file", type=str, metavar="FILENAME", help="File to send (Client only). E.g., Photo.jpg")
    arg_parser.add_argument("-w", "--window", type=int, default=DEFAULT_WINDOW_SIZE, metavar="SIZE", help=f"Client's sending window size. Default: {DEFAULT_WINDOW_SIZE}.")
    arg_parser.add_argument("-d", "--discard", type=int, metavar="SEQ_NUM", help="Server: seq to discard once for testing.") 

    try:
        cli_args = arg_parser.parse_args()
    except SystemExit: 
        # argparse handles printing errors and exiting, so just return
        return 

    if cli_args.client:
        if cli_args.ip is None: 
            cli_args.ip = "127.0.0.1" # Default server IP for client
        if not cli_args.file: 
            arg_parser.error("-f/--file is required for client mode.") 
        if cli_args.window <= 0: 
            arg_parser.error("-w/--window must be a positive integer.")
    
    if cli_args.server:
        if cli_args.ip is None: 
            cli_args.ip = "0.0.0.0" # Default for server to listen on all interfaces
    
    if cli_args.server:
        drtp_server = DRTPServer(cli_args.ip, cli_args.port, cli_args.discard) 
        drtp_server.start()
    elif cli_args.client:
        drtp_client = DRTPClient(cli_args.ip, cli_args.port, cli_args.file, cli_args.window)
        drtp_client.start()

main()
