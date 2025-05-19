
import argparse
import socket
import struct
import os
import time
from datetime import datetime # For timestamped logs



HEADER_LENGTH = 8 # Bytes for DRTP header
DATA_CHUNK_SIZE = 992 # Bytes for application data
PACKET_SIZE = HEADER_LENGTH + DATA_CHUNK_SIZE  # Total packet size = 1000 bytes
DEFAULT_PORT = 8088 
DEFAULT_WINDOW_SIZE = 3 # Default GBN window size
RECEIVER_WINDOW_ON_SYN_ACK = 15 # #max window size for SYN-ACK
GBN_TIMEOUT_DURATION = 0.4  # 400 ms for GBN timeout
CONNECTION_SETUP_TIMEOUT = 5.0 # 

# DRTP packet flags
FLAG_RST = 1 << 0 
FLAG_ACK = 1 << 1  
FLAG_SYN = 1 << 2  
FLAG_FIN = 1 << 3  


def log_message(message_text):
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


class DRTPPacket:
    """
        Handles DRTP packet creation and parsing.
        Contains methods to pack and unpack packets, and manage header fields.    """
    _header_format_string = '!HHHH' # Network byte order, 4 unsigned shorts (16-bit each)

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
        # make sure the values are within the 16 bit range
        self.seq_num = seq_num & 0xFFFF 
        self.ack_num = ack_num & 0xFFFF
        self.flags = (flags & ~FLAG_RST) & 0xFFFF
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
            packed_header = struct.pack(self._header_format_string,self.seq_num, self.ack_num,self.flags, self.recv_window)
        except struct.error as e:
            log_message(f"Critical Error: Failed to pack DRTP header - {e}")
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
        if len(raw_packet_bytes) < HEADER_LENGTH: #check if the packet is too short
            return None
        try:
            header_tuple = struct.unpack(DRTPPacket._header_format_string,raw_packet_bytes[:HEADER_LENGTH])
        except struct.error as e:
            log_message(f"Warning: Error unpacking DRTP header - {e}. Raw header hex: {raw_packet_bytes[:HEADER_LENGTH].hex()}")
            return None 
        
        data_payload_part = raw_packet_bytes[HEADER_LENGTH:] #data starts after the header
        return DRTPPacket(seq_num=header_tuple[0], ack_num=header_tuple[1],flags=header_tuple[2], recv_window=header_tuple[3],
                          data_payload=data_payload_part)


class DRTPServer:
    """
    Description:
        Implements the DRTP server. listens for the client, receives a file reliably,calculates throughput, then shuts down.
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
        self.expected_seq_num = 1 # Data packets start at sequence 1
        self.client_addr = None
        self.output_filename = "received_file_server.dat" # Default, made specific later
        self.connection_active = False
        self.total_bytes_received_payload = 0
        self.total_bytes_received_with_header = 0
        self.start_time_transfer = 0.0 # For throughput calculation
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
            log_message(f"Server listening on {self.host_ip}:{self.port}")

            if not self._establish_connection_server():
                return # Handshake failed, 

            self._receive_file_data()

        except socket.error as e_sock:
            log_message(f"Server Socket Error: {e_sock}")
        except Exception as e_general:
            log_message(f"Server General Error: {e_general}")
        finally:
            if self.start_time_transfer > 0: # If connection was established
                if self.connection_active and self.end_time_transfer == 0: # If exited without FIN
                    self.end_time_transfer = time.time()
                self._calculate_and_log_throughput()
                log_message("Connection Closes")
            
            if self.sock:
                self.sock.close()
            log_message("Server shut down.")

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
            self.sock.settimeout(None) # Wait indefinitely for initial SYN
            log_message("Server: Waiting for SYN...")
            raw_syn_bytes, client_address_info = self.sock.recvfrom(PACKET_SIZE)
            
            syn_pkt = DRTPPacket.unpack(raw_syn_bytes)
            if not syn_pkt or not (syn_pkt.flags & FLAG_SYN):
                log_message("Server: Bad/No SYN received. Handshake failed.")
                return False
            
            self.client_addr = client_address_info
            log_message("SYN packet is received")

            syn_ack_pkt = DRTPPacket(flags=FLAG_SYN | FLAG_ACK,
                                     recv_window=RECEIVER_WINDOW_ON_SYN_ACK)
            self.sock.sendto(syn_ack_pkt.pack(), self.client_addr)
            log_message("SYN-ACK packet is sent")

            self.sock.settimeout(CONNECTION_SETUP_TIMEOUT)
            raw_ack_bytes, _ = self.sock.recvfrom(PACKET_SIZE)
            ack_pkt = DRTPPacket.unpack(raw_ack_bytes)
            
            if not ack_pkt or not ((ack_pkt.flags & FLAG_ACK) and not (ack_pkt.flags & FLAG_SYN)):
                log_message("Server: Bad/No pure ACK for SYN-ACK. Handshake failed.")
                return False
            
            log_message("ACK packet is received")
            log_message("Connection established")
            
            self.connection_active = True
            self.start_time_transfer = time.time() # Timer for throughput starts after handshake
            return True
        except socket.timeout:
            log_message("Server: Timeout in handshake.")
            return False
        except Exception as e:
            log_message(f"Server: Error in handshake: {e}")
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
        self.output_filename = f"received_file_from_{self.client_addr[0]}_{self.client_addr[1]}.dat"
        try:
            with open(self.output_filename, 'wb') as file_out:
                log_message(f"Server: Receiving data into '{self.output_filename}'")
                while self.connection_active:
                    try:
                        self.sock.settimeout(CONNECTION_SETUP_TIMEOUT * 2) # Timeout for client activity
                        raw_data, sender_addr = self.sock.recvfrom(PACKET_SIZE)
                        
                        if sender_addr != self.client_addr: continue # Ignore other sources

                        pkt = DRTPPacket.unpack(raw_data)
                        if not pkt: continue # Ignore malformed

                        if pkt.flags & FLAG_FIN: # FIN received
                            self.end_time_transfer = time.time()
                            log_message("FIN packet is received")
                            self._send_fin_ack_server(pkt.seq_num)
                            self.connection_active = False
                            break

                        # Discard test
                        if self.discard_seq is not None and pkt.seq_num == self.discard_seq and \
                           not self.discard_seq_triggered:
                            log_message(f"Simulating discard of packet seq={pkt.seq_num}")
                            self.discard_seq_triggered = True
                            continue

                        # GBN logic
                        if pkt.seq_num == self.expected_seq_num:
                            log_message(f"packet {pkt.seq_num} is received")
                            file_out.write(pkt.data)
                            self.total_bytes_received_payload += len(pkt.data)
                            self.total_bytes_received_with_header += len(raw_data)

                            ack_resp = DRTPPacket(ack_num=pkt.seq_num, flags=FLAG_ACK,
                                                  recv_window=RECEIVER_WINDOW_ON_SYN_ACK)
                            self.sock.sendto(ack_resp.pack(), self.client_addr)
                            log_message(f"sending ack for the received {pkt.seq_num}")
                            self.expected_seq_num += 1
                        elif pkt.seq_num < self.expected_seq_num:
                            log_message(f"Duplicate/old packet {pkt.seq_num} (expected {self.expected_seq_num}). Re-ACKing {pkt.seq_num}.")
                            ack_resp = DRTPPacket(ack_num=pkt.seq_num, flags=FLAG_ACK)
                            self.sock.sendto(ack_resp.pack(), self.client_addr)
                        else: # Out-of-order: pkt.seq_num > self.expected_seq_num
                            log_message(f"out-of-order packet {pkt.seq_num} (expected {self.expected_seq_num}). Discarding.")
                            # As per assignment, "not acknowledge anything". Example output for -d matches this.

                    except socket.timeout:
                        log_message("Server: Timeout waiting for data/FIN.")
                        self.connection_active = False
                        if not self.end_time_transfer and self.start_time_transfer > 0:
                            self.end_time_transfer = time.time()
                        break
                    except Exception as e_loop:
                        log_message(f"Server: Error in data receive loop: {e_loop}")
                        pass # Try to continue for minor errors
        except IOError as e_io:
            log_message(f"Server: File I/O error for '{self.output_filename}': {e_io}")
            self.connection_active = False
            if not self.end_time_transfer and self.start_time_transfer > 0:
                self.end_time_transfer = time.time()
        log_message(f"Server: Data reception ended. Output: '{self.output_filename}'.")

    def _send_fin_ack_server(self, client_fin_seq_num):
        """
        Description:
            sends FIN-ACK in response to clients FIN.
        Arguments:
            client_fin_seq_num : Sequence number of the client's FIN to acknowledge
        Returns:
            None, since it manages the sending of the packet.
        """
        fin_ack_resp = DRTPPacket(ack_num=client_fin_seq_num, flags=FLAG_FIN | FLAG_ACK)
        try:
            self.sock.sendto(fin_ack_resp.pack(), self.client_addr)
            log_message("FIN ACK packet is sent")
        except socket.error as e_finack_send:
            log_message(f"Server: Error sending FIN-ACK: {e_finack_send}")

    def _calculate_and_log_throughput(self):
        """
        Description:
            Calculates and logs throughput based on received bytes and transfer duration.
        Arguments:
            None
        Returns:
            None, Prints result to console.
        """
        if self.start_time_transfer > 0 and self.end_time_transfer > self.start_time_transfer and \
           self.total_bytes_received_with_header > 0:
            duration = self.end_time_transfer - self.start_time_transfer
            if duration <= 0:
                log_message("Throughput: Invalid duration.")
                return
            # Mbps = (Total Bytes * 8 bits/byte) / (Duration_sec * 1,000,000 bits/Mbps)
            throughput_mbps = (self.total_bytes_received_with_header * 8) / (duration * 1000000.0)
            log_message(f"The throughput is {throughput_mbps:.2f} Mbps")
            log_message(f"(Debug Info: Payload={self.total_bytes_received_payload}B, "
                        f"TotalDRTP={self.total_bytes_received_with_header}B, Time={duration:.2f}s)")
        elif self.start_time_transfer > 0:
            log_message("Throughput: Not enough data or valid duration.")
        else:
            log_message("Throughput: Skipped (connection not fully made).")


class DRTPClient:
    """
    Description:
        Implements the DRTP client. Connects to server, sends a file reliably using GBN,
        then tears down connection.
    """
    def __init__(self, s_ip, s_port, file_to_send, win_size):
        """
        Description:
            Initializes the client.
        Arguments:
            s_ip: Servers IP address.
            s_port: Servers port number.
            file_to_send: Path to the local file to send.
            win_size: Client's sending window size (N for GBN).
        Returns:
            None. Why?: Constructor.
        """
        self.server_ip = s_ip
        self.server_port = s_port
        self.filename = file_to_send
        self.window_size_arg = win_size
        self.effective_window_size = win_size # Adjusted later by server's advertisement

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_addr = (self.server_ip, self.server_port)

        self.base_seq_num = 1 # Oldest unACKed packet
        self.next_seq_num = 1 # Next new packet to send
        self.sent_packets_buffer = {} # Stores {seq: packed_bytes} for retransmission
        self.gbn_timer_start_time = None # For GBN_TIMEOUT_DURATION
        
        self.file_handle = None
        self.eof_reached = False
        self.connection_established = False
        self.last_fin_seq_num = 0

    def start(self):
        """
        Description:
            Main client loop: checks file, connects, sends data, tears down.
        Arguments:
            None.
        Use of other input and output parameters in the function:
            Calls internal methods for different phases. Handles major exceptions.
        Returns:
            None. Why?: Orchestrates client operation.
        """
        try:
            if not os.path.exists(self.filename):
                log_message(f"Client: File '{self.filename}' not found. Exiting.")
                return
            
            log_message("Connection Establishment Phase:")
            if not self._establish_connection_client():
                return # _establish_connection_client logs "Connection failed"
            self.connection_established = True

            log_message("Data Transfer:")
            self.file_handle = open(self.filename, 'rb')
            if os.path.getsize(self.filename) == 0:
                log_message(f"Client: File '{self.filename}' is empty. Will send FIN.")
                self.eof_reached = True
            
            self._send_file_data_gbn()

            if self.eof_reached and self.base_seq_num == self.next_seq_num:
                 log_message("DATA Finished")

        except Exception as e: # Catch-all for unexpected issues
            log_message(f"Client General Error: {e}")
        finally:
            if self.file_handle: self.file_handle.close()
            if self.connection_established:
                log_message("Connection Teardown:")
                self._teardown_connection_client()
            # "Connection Closes" is logged by teardown or after "Connection failed"
            if self.sock: self.sock.close()

    def _establish_connection_client(self):
        """
        Description:
            Client-side 3-way handshake. Sends SYN, waits for SYN-ACK, sends ACK.
            Adjusts window size based on server's response.
        Arguments:
            None.
        Use of other input and output parameters in the function:
            Uses self.sock, self.server_addr, DRTPPacket, flag constants, timeout.
            Updates self.effective_window_size.
        Returns:
            bool: True if successful, False otherwise.
                  Why?: To signal if data transfer can proceed.
        """
        try:
            syn_pkt = DRTPPacket(flags=FLAG_SYN)
            self.sock.sendto(syn_pkt.pack(), self.server_addr)
            log_message("SYN packet is sent")

            self.sock.settimeout(CONNECTION_SETUP_TIMEOUT)
            raw_syn_ack, _ = self.sock.recvfrom(PACKET_SIZE)
            syn_ack_pkt = DRTPPacket.unpack(raw_syn_ack)

            if not syn_ack_pkt or not (syn_ack_pkt.flags & FLAG_SYN and syn_ack_pkt.flags & FLAG_ACK):
                log_message("Client: Invalid SYN-ACK from server.")
                log_message("Connection failed")
                return False
            
            server_rcv_win = syn_ack_pkt.recv_window
            self.effective_window_size = min(self.window_size_arg, server_rcv_win)
            if self.effective_window_size <= 0: self.effective_window_size = 1 # Min 1
            
            log_message(f"Client: Server rcv_win={server_rcv_win}. Effective send_win={self.effective_window_size}.")
            log_message("SYN-ACK packet is received")

            ack_pkt = DRTPPacket(flags=FLAG_ACK) # Pure ACK
            self.sock.sendto(ack_pkt.pack(), self.server_addr)
            log_message("ACK packet is sent")
            log_message("Connection established")
            return True
        except socket.timeout:
            log_message("Client: Timeout waiting for SYN-ACK.")
            log_message("Connection failed")
            return False
        except Exception as e:
            log_message(f"Client: Error in handshake: {e}")
            log_message("Connection failed")
            return False

    def _send_file_data_gbn(self):
        """
        Description:
            Sends file data using GBN. Manages window, sends packets, handles ACKs and timeouts.
        Arguments:
            None.
        Use of other input and output parameters in the function:
            Uses self.file_handle, GBN state vars (base, next_seq, buffer, timer), timeouts.
        Returns:
            None. Why?: Manages data sending state and side effects.
        """
        while not self.eof_reached or self.base_seq_num < self.next_seq_num:
            # Send new packets if window allows
            while self.next_seq_num < self.base_seq_num + self.effective_window_size and \
                  not self.eof_reached:
                data_payload_chunk = self.file_handle.read(DATA_CHUNK_SIZE)
                if not data_payload_chunk:
                    self.eof_reached = True
                    if self.base_seq_num == self.next_seq_num: return # All sent & ACKed
                    break # EOF, stop sending new, wait for ACKs
                
                data_pkt_obj = DRTPPacket(seq_num=self.next_seq_num, data_payload=data_payload_chunk)
                data_pkt_bytes = data_pkt_obj.pack()
                self.sent_packets_buffer[self.next_seq_num] = data_pkt_bytes
                
                try:
                    self.sock.sendto(data_pkt_bytes, self.server_addr)
                except socket.error as e_send_gbn:
                    log_message(f"Client: Socket error sending packet {self.next_seq_num}: {e_send_gbn}")
                    return # Critical, stop GBN

                window_log = sorted([s for s in self.sent_packets_buffer if s >= self.base_seq_num])
                log_message(f"packet with seq = {self.next_seq_num} is sent, sliding window = {{{', '.join(map(str, window_log))}}}")

                if self.base_seq_num == self.next_seq_num: # Timer for oldest packet in window
                    self.gbn_timer_start_time = time.time()
                self.next_seq_num += 1
            
            if self.eof_reached and self.base_seq_num == self.next_seq_num: break # All done

            # Wait for ACKs or RTO
            try:
                current_timeout_val = GBN_TIMEOUT_DURATION
                if self.gbn_timer_start_time:
                    time_passed = time.time() - self.gbn_timer_start_time
                    remaining_on_timer = GBN_TIMEOUT_DURATION - time_passed
                    if remaining_on_timer <= 0: raise socket.timeout
                    current_timeout_val = remaining_on_timer
                elif not (self.base_seq_num < self.next_seq_num): # No packets in flight
                    if self.eof_reached: break
                    continue 

                self.sock.settimeout(current_timeout_val)
                raw_ack, _ = self.sock.recvfrom(HEADER_LENGTH) # ACKs are header-only
                ack_pkt_obj = DRTPPacket.unpack(raw_ack)

                if ack_pkt_obj and (ack_pkt_obj.flags & FLAG_ACK):
                    log_message(f"ACK for packet = {ack_pkt_obj.ack_num} is received")
                    if ack_pkt_obj.ack_num >= self.base_seq_num: # Cumulative ACK
                        for i in range(self.base_seq_num, ack_pkt_obj.ack_num + 1):
                            self.sent_packets_buffer.pop(i, None)
                        self.base_seq_num = ack_pkt_obj.ack_num + 1
                        
                        if self.base_seq_num == self.next_seq_num: # All outstanding ACKed
                            self.gbn_timer_start_time = None # Stop timer
                        else:
                            self.gbn_timer_start_time = time.time() # Restart for new base
            except socket.timeout: # GBN RTO
                if self.base_seq_num < self.next_seq_num: # If packets are outstanding
                    log_message("RTO occured")
                    self.gbn_timer_start_time = time.time() # Restart timer
                    for seq_to_resend in range(self.base_seq_num, self.next_seq_num):
                        if seq_to_resend in self.sent_packets_buffer:
                            bytes_to_resend_pkt = self.sent_packets_buffer[seq_to_resend]
                            try:
                                self.sock.sendto(bytes_to_resend_pkt, self.server_addr)
                                log_message(f"retransmitting packet with seq =  {seq_to_resend}")
                            except socket.error as e_resend_rto:
                                log_message(f"Client: Socket error re-sending {seq_to_resend} on RTO: {e_resend_rto}")
                                return # Critical
            except Exception as e_ack_loop:
                log_message(f"Client: Error in ACK loop: {e_ack_loop}")

    def _teardown_connection_client(self):
        """
        Description:
            Client-side 2-way handshake. Sends FIN, waits for FIN-ACK. Retries FIN on timeout.
        Arguments:
            None.
        Use of other input and output parameters in the function:
            Uses self.sock, self.server_addr, DRTPPacket, flag constants, timeout.
            Manages self.last_fin_seq_num.
        Returns:
            bool: True if successful, False otherwise.
                  Why?: To indicate if connection closed gracefully.
        """
        try:
            self.last_fin_seq_num = self.next_seq_num # FIN uses next available seq num
            fin_pkt_obj = DRTPPacket(seq_num=self.last_fin_seq_num, flags=FLAG_FIN)
            
            max_fin_attempts = 3
            for attempt_num in range(max_fin_attempts):
                try:
                    self.sock.sendto(fin_pkt_obj.pack(), self.server_addr)
                    if attempt_num == 0: # Log "FIN packet is sent" only on first try to match example
                        log_message("FIN packet is sent") # Assignment example has "FIN packet packet is sent" - assuming typo

                    self.sock.settimeout(CONNECTION_SETUP_TIMEOUT)
                    raw_fin_ack, _ = self.sock.recvfrom(PACKET_SIZE)
                    fin_ack_pkt_obj = DRTPPacket.unpack(raw_fin_ack)

                    if fin_ack_pkt_obj and (fin_ack_pkt_obj.flags & FLAG_FIN) and \
                       (fin_ack_pkt_obj.flags & FLAG_ACK) and \
                       (fin_ack_pkt_obj.ack_num == self.last_fin_seq_num):
                        log_message("FIN ACK packet is received")
                        log_message("Connection Closes")
                        return True
                    else:
                        log_message(f"Client: Invalid FIN-ACK (attempt {attempt_num + 1}).")
                except socket.timeout:
                    log_message(f"Client: Timeout waiting for FIN-ACK (attempt {attempt_num + 1}).")
                except Exception as e_fin_loop:
                    log_message(f"Client: Error in FIN-ACK loop (attempt {attempt_num + 1}): {e_fin_loop}")
                
                if attempt_num == max_fin_attempts - 1: # Last attempt
                    log_message("Client: Max FIN retries reached.")
                    break
            
            log_message("Connection Closes (FIN-ACK not confirmed)")
            return False
        except Exception as e_teardown_main:
            log_message(f"Client: Error during teardown start: {e_teardown_main}")
            log_message("Connection Closes")
            return False

def check_port_arg_main(port_value_str):
    """
    Description:
        Validates port number for argparse. Integer, in range [1024, 65535].
    Arguments:
        port_value_str (str): Port number from command line.
    Use of other input and output parameters in the function:
        Converts to int.
    Returns:
        int: Validated port number.
        Why?: For argparse type checking. Raises error if invalid.
    """
    try:
        port = int(port_value_str)
        if not (1024 <= port <= 65535):
            raise argparse.ArgumentTypeError(f"Port {port} out of range [1024-65535].")
        return port
    except ValueError:
        raise argparse.ArgumentTypeError(f"Port '{port_value_str}' not a valid integer.")

def main():
    """
    Description:
        Parses CLI args, then starts DRTP client or server.
    Arguments:
        None (uses sys.argv).
    Use of other input and output parameters in the function:
        Uses argparse, DRTPClient/Server classes.
    Returns:
        None. Why?: Main application driver.
    """
    # Setting up the command-line argument parser
    arg_parser = argparse.ArgumentParser(
        description="DRTP File Transfer Application (DATA2410).",
        epilog="Example Client: python3 application.py -c -f Photo.jpg -i 10.0.1.2 -p 8088 -w 5\n"
               "Example Server: python3 application.py -s -i 10.0.1.2 -p 8088 -d 8",
        formatter_class=argparse.RawTextHelpFormatter # For better epilog formatting
    )
    # Group for mutually exclusive server/client mode selection
    mode_selection_group = arg_parser.add_mutually_exclusive_group(required=True)
    mode_selection_group.add_argument("-s", "--server", action="store_true", help="Run in server mode.")
    mode_selection_group.add_argument("-c", "--client", action="store_true", help="Run in client mode.")

    # Common arguments
    arg_parser.add_argument("-i", "--ip", type=str,
                            help="IP address. Server: bind IP (default 0.0.0.0). Client: server IP (default 127.0.0.1).")
    arg_parser.add_argument("-p", "--port", type=check_port_arg_main, default=DEFAULT_PORT,
                            help=f"Port number (1024-65535). Default: {DEFAULT_PORT}.")
    # Client-specific arguments
    arg_parser.add_argument("-f", "--file", type=str, metavar="FILENAME",
                            help="File to transfer (Client mode only, required).")
    arg_parser.add_argument("-w", "--window", type=int, default=DEFAULT_WINDOW_SIZE, metavar="SIZE",
                            help=f"Client sending window size (packets, >0). Default: {DEFAULT_WINDOW_SIZE}.")
    # Server-specific arguments
    arg_parser.add_argument("-d", "--discard", type=int, metavar="SEQ_NUM",
                            help="Server: sequence number of a packet to discard once for testing.")

    try:
        cli_args = arg_parser.parse_args()
    except SystemExit: # Argparse handles errors like -h or bad arguments by exiting
        return # Allow argparse to terminate gracefully

    # Post-parsing validation and default IP setting
    if cli_args.client:
        if cli_args.ip is None: cli_args.ip = "127.0.0.1" # Default client connects to localhost
        if not cli_args.file:
            arg_parser.error("Client mode requires -f/--file argument.") # Exits
        if cli_args.window <= 0:
            arg_parser.error("Window size (-w) must be a positive integer.") # Exits
        if cli_args.discard is not None:
            print("Note: -d/--discard argument is ignored by the client.")
    
    if cli_args.server:
        if cli_args.ip is None: cli_args.ip = "0.0.0.0" # Default server listens on all interfaces
        if cli_args.file:
            print("Note: -f/--file argument is ignored by the server.")
        # -w is a client sender concept, server advertises its own fixed receiver window.

    # Launch the application based on the selected mode
    if cli_args.server:
        drtp_server = DRTPServer(cli_args.ip, cli_args.port, cli_args.discard)
        drtp_server.start()
    elif cli_args.client:
        drtp_client = DRTPClient(cli_args.ip, cli_args.port, cli_args.file, cli_args.window)
        drtp_client.start()
    # No else needed as the mode group is required by argparse.

# Direct call to main_logic() when the script is executed.
main()
