import argparse  # For parsing command-line arguments
import socket    # For network communication using UDP sockets
import struct    # For packing and unpacking binary data (DRTP header)
import time      # For handling timeouts and measuring duration for throughput
import os        # For file system operations (checking file existence, size)
import sys       # For system-specific parameters and functions (e.g., sys.exit)
from datetime import datetime # For generating timestamped log messages

# --- DRTP Protocol Constants ---
# These constants define the structure and parameters of the DRTP protocol.

#: int: Length of the DRTP header in bytes.
# The header consists of: Seq (2B), Ack (2B), Flags (2B), RecvWin (2B) = 8 bytes.
HEADER_LENGTH = 8

#: int: Size of the application data chunk in bytes for each DRTP data packet.
# As specified in the assignment details.
DATA_CHUNK_SIZE = 992

#: int: Total nominal size of a DRTP packet that carries data (Header + Data).
PACKET_SIZE = HEADER_LENGTH + DATA_CHUNK_SIZE  # 8 + 992 = 1000 bytes

# --- Application Behavior Constants ---
#: int: Default port number used if no port is specified by the user.
DEFAULT_PORT = 8088
#: int: Default sliding window size for the client (sender) if not specified.
DEFAULT_WINDOW_SIZE = 3
#: int: Receiver window size advertised by the server in its SYN-ACK packet.
# This value is fixed as per the assignment's connection establishment details.
RECEIVER_WINDOW_ON_SYN_ACK = 15
#: float: Timeout duration in seconds for the Go-Back-N (GBN) retransmission timer.
# If an ACK is not received for the base of the GBN window within this time, retransmission occurs.
# Assignment specifies 400 milliseconds.
GBN_TIMEOUT_DURATION = 0.4
#: float: Timeout duration in seconds for control packets during connection setup (e.g., waiting for SYN-ACK)
# and connection teardown (e.g., waiting for FIN-ACK).
# Based on the assignment example "What if the server is not running or responding?".
CONNECTION_SETUP_TIMEOUT = 5.0

# DRTP Flags (as bitmasks for the 16-bit 'Flags' field of the header)
# The assignment specifies the format: | (12 unused bits) | F | S | A | R |
# This means R is bit 0, A is bit 1, S is bit 2, F is bit 3 (from right, LSB).
#: int: Bitmask for the Reset (RST) flag. Unused in this assignment (always set to 0).
FLAG_RST = 1 << 0  # Value: 1
#: int: Bitmask for the Acknowledgment (ACK) flag. Used to acknowledge received packets.
FLAG_ACK = 1 << 1  # Value: 2
#: int: Bitmask for the Synchronization (SYN) flag. Used to initiate a connection.
FLAG_SYN = 1 << 2  # Value: 4
#: int: Bitmask for the Finish (FIN) flag. Used to terminate a connection.
FLAG_FIN = 1 << 3  # Value: 8

# --- Utility Functions ---
def log_message(message_text):
    """
    Description:
        This function prints a log message to the standard console output.
        Each message is automatically prefixed with a current timestamp in HH:MM:SS.ffffff format,
        which matches the assignment's specified output style for logging events.
    Arguments:
        message_text (str): The string message that needs to be logged to the console.
    Use of other input and output parameters in the function:
        - It calls `datetime.now()` from the `datetime` module to get the precise current system time.
        - It uses an f-string and the `strftime` method to format the timestamp and the `message_text` together.
        - The formatted output is sent to the `print()` function, which directs it to standard output (the console).
    Returns:
        None.
        Why?: The function's primary purpose is to perform an action (printing to the console for logging)
              rather than to compute and return a value. This is typical for logging utility functions.
    """
    # Get the current time.
    current_time = datetime.now()
    # Format the time as HH:MM:SS.microseconds.
    timestamp_str = current_time.strftime('%H:%M:%S.%f')
    # Print the formatted log message.
    print(f"{timestamp_str} -- {message_text}")

# --- DRTPPacket Class ---
class DRTPPacket:
    """
    Description:
        Represents a DRTP packet, providing methods for packing its fields into a byte string
        for network transmission and for unpacking a received byte string back into its
        constituent header fields and data payload. This class encapsulates the DRTP
        header structure as defined by the assignment.

    Header format (8 bytes total):
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Sequence Number (16b) |  Acknowledgment Num (16b) |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Flags (16b)           |  Receiver Window (16b)    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |               Application DATA (992 bytes)    |
    |                  ...                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    # The 'struct' module format string for the DRTP header.
    # '!' = Network byte order (big-endian).
    # 'H' = Unsigned short integer (16 bits / 2 bytes).
    # Four 'H's for: Sequence Number, Acknowledgment Number, Flags, Receiver Window.
    _header_format_string = '!HHHH'

    def __init__(self, seq_num=0, ack_num=0, flags=0, recv_window=0, data_payload=b''):
        """
        Description:
            Constructor for the DRTPPacket class. Initializes a new DRTP packet object
            with the specified header field values and data payload.
        Arguments:
            seq_num (int, optional): The sequence number for this packet (0-65535). Defaults to 0.
            ack_num (int, optional): The acknowledgment number (0-65535). Defaults to 0.
            flags (int, optional): Integer representing the combined DRTP flags (0-65535). Defaults to 0.
                                   Individual flags (FLAG_SYN, FLAG_ACK, etc.) should be bitwise ORed
                                   to form this value. The RST flag bit should always be 0.
            recv_window (int, optional): The receiver window size being advertised (0-65535). Defaults to 0.
            data_payload (bytes, optional): The application data for this packet. Defaults to an empty byte string (b''),
                                         suitable for control packets (e.g., pure ACKs, SYN, FIN).
        Use of other input and output parameters in the function:
            - Input parameters are masked with 0xFFFF to ensure they fit within their 16-bit fields,
              preventing overflow errors during packing.
            - The RST flag (bit 0) is explicitly ensured to be 0 in the flags field, as per assignment note.
        Returns:
            None.
            Why?: Standard Python constructor behavior; it initializes the instance (self).
        """
        # Ensure values fit within 16 bits (0-65535) by masking.
        self.seq_num = seq_num & 0xFFFF
        self.ack_num = ack_num & 0xFFFF
        # Ensure RST flag (bit 0) is 0, then mask to 16 bits.
        # (flags & ~FLAG_RST) clears the RST bit if it was somehow set, then apply other flags.
        # However, the problem states "we'll set the value to 0", implying it's the responsibility
        # of the flag construction logic. Here, we just ensure the overall flags value is 16-bit.
        # A simpler way if flags are constructed carefully: self.flags = flags & 0xFFFF
        # For safety, if RST must be zero:
        self.flags = (flags & 0xFFFE) & 0xFFFF # Clears bit 0 (FLAG_RST) then ensures 16-bit
        # Or, if assuming flags are passed correctly with RST=0:
        # self.flags = flags & 0xFFFF

        self.recv_window = recv_window & 0xFFFF
        self.data = data_payload # Data payload is not part of the fixed-size header packing.

    def pack(self):
        """
        Description:
            Packs the DRTPPacket instance's header fields into a byte string and appends
            the data payload. This creates the raw binary representation of the packet
            suitable for network transmission.
        Arguments:
            None (operates on the instance's attributes: self.seq_num, self.ack_num, etc.).
        Use of other input and output parameters in the function:
            - self._header_format_string (class attribute): Specifies the format for `struct.pack`.
            - The instance's header attributes (seq_num, ack_num, flags, recv_window) are packed.
            - self.data (instance attribute) is appended to the packed header.
        Returns:
            bytes: A byte string representing the complete DRTP packet (header + data).
                   Why?: This is the format required for sending data over UDP sockets.
        """
        try:
            # Pack the header fields into a byte string.
            packed_header = struct.pack(self._header_format_string,
                                        self.seq_num,
                                        self.ack_num,
                                        self.flags,
                                        self.recv_window)
        except struct.error as e:
            # This error is unlikely if attributes are correctly masked in __init__,
            # but it's good practice for robustness.
            log_message(f"Error packing DRTP header: {e}. Fields: Seq={self.seq_num}, Ack={self.ack_num}, Flags={self.flags}, Win={self.recv_window}")
            raise # Re-raise the exception as this is a critical failure.

        # Concatenate the packed header with the data payload.
        return packed_header + self.data

    @staticmethod
    def unpack(raw_packet_bytes):
        """
        Description:
            A static method that takes a raw byte string (typically received from the network)
            and attempts to parse it into a DRTPPacket object. It unpacks the header fields
            and separates the data payload.
        Arguments:
            raw_packet_bytes (bytes): The raw byte string to be unpacked.
        Use of other input and output parameters in the function:
            - HEADER_LENGTH (global constant): Used to check if `raw_packet_bytes` is long enough
              and to slice the header part.
            - DRTPPacket._header_format_string (class attribute): Used by `struct.unpack`.
        Returns:
            DRTPPacket or None:
                - A new DRTPPacket instance populated with the unpacked header fields and data
                  if parsing is successful.
                  Why?: Provides a convenient object-oriented way to access packet components.
                - None if `raw_packet_bytes` is too short to contain a valid header or if unpacking fails.
                  Why?: Signals to the caller that the received bytes do not form a valid DRTP packet.
        """
        # Check if the received bytes are at least as long as the defined header.
        if len(raw_packet_bytes) < HEADER_LENGTH:
            # log_message(f"DEBUG: unpack received packet too short: {len(raw_packet_bytes)} bytes") # Optional debug
            return None # Not enough data for a header.

        try:
            # Unpack the header portion of the byte string.
            header_tuple = struct.unpack(DRTPPacket._header_format_string,
                                         raw_packet_bytes[:HEADER_LENGTH])
        except struct.error as e:
            # This could happen if the packet is corrupted, despite correct length.
            log_message(f"Error unpacking DRTP header from bytes: {e}. Bytes: {raw_packet_bytes[:HEADER_LENGTH].hex()}")
            return None # Parsing failed.

        # The remainder of the packet is the data payload.
        data_payload_part = raw_packet_bytes[HEADER_LENGTH:]
        
        # Create and return a new DRTPPacket object using the unpacked values.
        # header_tuple contains (seq_num, ack_num, flags, recv_window)
        return DRTPPacket(seq_num=header_tuple[0],
                          ack_num=header_tuple[1],
                          flags=header_tuple[2],
                          recv_window=header_tuple[3],
                          data_payload=data_payload_part)

    def __repr__(self):
        """
        Description:
            Provides a developer-friendly string representation of the DRTPPacket object,
            useful for debugging and logging.
        Arguments:
            None (operates on the instance's attributes).
        Use of other input and output parameters in the function:
            Accesses self.seq_num, self.ack_num, self.flags, self.recv_window, and len(self.data).
            Uses global flag constants (FLAG_SYN, etc.) to create a readable flags string.
        Returns:
            str: A string summarizing the packet's contents.
                 Why?: Aids in understanding the state of a packet object during development.
        """
        active_flags_list = []
        if self.flags & FLAG_SYN: active_flags_list.append("SYN")
        if self.flags & FLAG_ACK: active_flags_list.append("ACK")
        if self.flags & FLAG_FIN: active_flags_list.append("FIN")
        # RST flag is not used by application, but can be shown if set.
        # if self.flags & FLAG_RST: active_flags_list.append("RST")
        
        flags_string = ",".join(active_flags_list) if active_flags_list else "None"
        
        return (f"DRTPPacket(Seq={self.seq_num}, Ack={self.ack_num}, "
                f"Flags=[{flags_string}] (Val=0x{self.flags:04X}), RecvWin={self.recv_window}, DataLen={len(self.data)})")

# --- DRTPServer Class ---
class DRTPServer:
    """
    Description:
        This class implements the server-side logic for the DATA2410 Reliable Transport Protocol (DRTP).
        The server listens for a single client connection on a specified UDP port. Upon connection,
        it reliably receives a file using the Go-Back-N (GBN) protocol, saves it to disk,
        calculates the transfer throughput, and then terminates. It handles one client session per execution.
    """
    def __init__(self, server_ip_address, server_port_number, sequence_to_discard=None):
        """
        Description:
            This is the constructor for the DRTPServer class. It initializes the server's
            state, including network parameters, GBN variables, and the UDP socket.
        Arguments:
            server_ip_address (str): The IP address that the server will bind its UDP socket to.
                                     Using '0.0.0.0' allows listening on all available network interfaces.
            server_port_number (int): The port number on which the server will listen for incoming DRTP packets.
            sequence_to_discard (int, optional): If provided, this is the sequence number of a data packet
                                                 that the server should intentionally discard ONCE during data reception.
                                                 This is used for testing the client's retransmission mechanism.
                                                 Defaults to None, meaning no packets are intentionally discarded.
        Use of other input and output parameters in the function:
            - self.host_ip, self.port, self.discard_seq: Store the input arguments.
            - self.sock: A UDP socket (`socket.SOCK_DGRAM`) is created but not yet bound.
            - self.expected_seq_num: Initialized to 1, as data packet sequence numbers start from 1.
            - self.client_addr: Will store the (IP, port) of the connected client after handshake.
            - self.output_filename: A default name for the received file.
            - self.connection_active: A boolean flag indicating if a DRTP connection is established.
            - Throughput metrics (total_bytes_*, start_time, end_time) are initialized to zero/default.
        Returns:
            None.
            Why?: Constructors in Python implicitly return the newly created instance (self); they don't
                  have an explicit return statement for a value.
        """
        self.host_ip = server_ip_address
        self.port = server_port_number
        self.discard_seq = sequence_to_discard
        self.discard_seq_triggered = False

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.expected_seq_num = 1
        self.client_addr = None
        self.output_filename = "received_file_server_default.dat" # Will be made more specific later
        self.connection_active = False
        self.total_bytes_received_payload = 0
        self.total_bytes_received_with_header = 0 # As per FAQ Q6, for throughput
        self.start_time = 0.0
        self.end_time = 0.0

    def start(self):
        """
        Description:
            This is the main entry point to run the DRTP server. It performs the necessary steps:
            binding the socket to the specified IP and port, attempting to establish a connection
            with a client, receiving file data if the connection is successful, and then cleaning up
            by calculating throughput and closing the socket. The server is designed to handle
            one client session and then exit.
        Arguments:
            None.
        Use of other input and output parameters in the function:
            - self.sock: The server's UDP socket is bound using `self.host_ip` and `self.port`.
            - Internal methods `_establish_connection()` and `_receive_data()` are called to manage
              the connection lifecycle and data transfer.
            - Exception handling: Catches common socket errors and general exceptions to provide
              log messages and ensure graceful shutdown (socket closure).
        Returns:
            None.
            Why?: This method orchestrates the server's operation; its results are primarily side effects
                  like network communication, file writing, and console logging.
        """
        try:
            self.sock.bind((self.host_ip, self.port))
            log_message(f"Server listening on {self.host_ip}:{self.port}")

            if not self._establish_connection():
                # _establish_connection logs specific failure reasons.
                # The assignment output for SYN timeout doesn't show "Connection Closes",
                # so we just return if handshake fails.
                return

            self._receive_data()

        except socket.error as sock_err:
            log_message(f"Server Socket Error: {sock_err}")
        except Exception as general_err:
            log_message(f"Server General Error: {general_err}")
            # import traceback; traceback.print_exc() # For debugging
        finally:
            # Calculate throughput and log "Connection Closes" if the connection
            # at least reached the point where self.start_time was set (after handshake).
            if self.start_time > 0:
                if self.connection_active and self.end_time == 0: # If data loop exited without FIN
                    self.end_time = time.time() # Mark current time as end for duration calculation
                
                self._calculate_and_display_throughput()
                log_message("Connection Closes") # This matches example output timing for successful/terminated transfers.
            
            if self.sock:
                self.sock.close()
            log_message("Server shut down.")

    def _establish_connection(self):
        """
        Description:
            This private method handles the server-side of the DRTP 3-way handshake.
            It waits for a SYN packet from a client, responds with a SYN-ACK packet,
            and then waits for the client's final ACK packet to confirm the connection.
        Arguments:
            None.
        Use of other input and output parameters in the function:
            - self.sock: The server's UDP socket, used for receiving and sending handshake packets.
            - DRTPPacket class: For packing outgoing SYN-ACK and unpacking incoming SYN/ACK.
            - FLAG_SYN, FLAG_ACK (global constants): Used to check and set flags in packets.
            - RECEIVER_WINDOW_ON_SYN_ACK (global constant): Advertised in the SYN-ACK.
            - CONNECTION_SETUP_TIMEOUT (global constant): Used for socket timeouts when waiting for client responses.
            - On successful handshake:
                - self.client_addr is set to the (IP, port) of the connected client.
                - self.connection_active is set to True.
                - self.start_time is set (as per FAQ, timer starts after handshake for throughput).
        Returns:
            bool: True if the 3-way handshake completes successfully.
                  False if any step fails (e.g., timeout, incorrect packet received).
                  Why?: Indicates to the caller (`start` method) if it's safe to proceed to the data transfer phase.
        """
        try:
            self.sock.settimeout(None) # Wait indefinitely for the first SYN
            log_message("Server: Waiting for SYN...")
            raw_syn_bytes, client_address = self.sock.recvfrom(PACKET_SIZE) # Use PACKET_SIZE as max buffer
            
            syn_packet = DRTPPacket.unpack(raw_syn_bytes)
            if not syn_packet or not (syn_packet.flags & FLAG_SYN):
                log_message("Server: Received non-SYN or malformed packet during SYN phase. Handshake failed.")
                return False
            
            self.client_addr = client_address
            log_message("SYN packet is received") # Matches assignment output

            # Send SYN-ACK
            # Seq/Ack numbers for control packets are 0 as per simplified handshake (FAQ Q1)
            syn_ack_response = DRTPPacket(seq_num=0, ack_num=0,
                                          flags=FLAG_SYN | FLAG_ACK,
                                          recv_window=RECEIVER_WINDOW_ON_SYN_ACK)
            self.sock.sendto(syn_ack_response.pack(), self.client_addr)
            log_message("SYN-ACK packet is sent") # Matches assignment output

            # Wait for client's final ACK
            self.sock.settimeout(CONNECTION_SETUP_TIMEOUT)
            raw_final_ack_bytes, _ = self.sock.recvfrom(PACKET_SIZE) # Expect header-only packet

            final_ack_packet = DRTPPacket.unpack(raw_final_ack_bytes)
            if not final_ack_packet:
                log_message("Server: Received malformed final ACK packet. Handshake failed.")
                return False
            
            # A "pure" ACK has ACK flag set, and SYN flag NOT set.
            is_valid_final_ack = (final_ack_packet.flags & FLAG_ACK) and \
                                 not (final_ack_packet.flags & FLAG_SYN)
            if not is_valid_final_ack:
                log_message("Server: Did not receive a pure ACK for SYN-ACK (e.g., SYN flag also set or ACK missing). Handshake failed.")
                return False
            
            log_message("ACK packet is received") # Matches assignment output
            log_message("Connection established") # Matches assignment output
            
            self.connection_active = True
            self.start_time = time.time() # Start throughput timer (FAQ Q7)
            return True

        except socket.timeout:
            log_message("Server: Timeout during connection establishment phase.")
            return False
        except Exception as e:
            log_message(f"Server: An unexpected error occurred during connection establishment: {e}")
            return False

    def _receive_data(self):
        """
        Description:
            This private method is responsible for the server's data reception phase.
            It continuously listens for incoming DRTP data packets from the connected client,
            processes them according to Go-Back-N (GBN) receiver rules (checking sequence numbers,
            handling discards for testing, writing in-order data to a file, sending ACKs),
            and also watches for a FIN packet to initiate connection teardown.
        Arguments:
            None.
        Use of other input and output parameters in the function:
            - self.sock: The server's UDP socket used for receiving packets.
            - self.client_addr: The address of the connected client, to ensure packets are from the correct source.
            - self.expected_seq_num: Tracks the sequence number of the next data packet the server expects to receive.
            - self.discard_seq, self.discard_seq_triggered: Used for the packet discard testing feature.
            - self.output_filename: The name of the file where received data is written.
            - self.total_bytes_received_*: Metrics updated for throughput calculation.
            - self.connection_active: Flag that controls the main receiving loop. Set to False upon FIN or error.
            - self.end_time: Timestamp set when a FIN is received or an error terminates data reception.
            - DRTPPacket class: For unpacking received packets and packing ACKs.
            - FLAG_FIN, FLAG_ACK (global constants): Used for checking/setting packet flags.
            - CONNECTION_SETUP_TIMEOUT: Used for socket timeout during data reception loop to prevent indefinite blocking.
        Returns:
            None.
            Why?: Its primary role is to process incoming data and manage state, with side effects
                  like file writing and sending ACKs. It doesn't compute a value to return directly.
        """
        self.output_filename = f"received_file_from_{self.client_addr[0]}_{self.client_addr[1]}.dat"
        
        try:
            with open(self.output_filename, 'wb') as output_file:
                log_message(f"Server: Receiving data, will be saved to '{self.output_filename}'")
                
                while self.connection_active:
                    try:
                        self.sock.settimeout(CONNECTION_SETUP_TIMEOUT * 2) # e.g., 10s for client activity
                        
                        raw_bytes, sender_addr = self.sock.recvfrom(PACKET_SIZE)
                        
                        if sender_addr != self.client_addr:
                            log_message(f"Server: Ignored packet from unexpected source {sender_addr}.")
                            continue

                        packet = DRTPPacket.unpack(raw_bytes)
                        if not packet:
                            log_message("Server: Received malformed packet during data phase. Ignoring.")
                            continue

                        # Handle FIN for connection teardown first
                        if packet.flags & FLAG_FIN:
                            self.end_time = time.time() # Stop throughput timer (FAQ Q7)
                            log_message("FIN packet is received") # Matches assignment
                            self._send_fin_ack(packet.seq_num) # Ack the FIN using its sequence number
                            self.connection_active = False # Signal to stop receiving loop
                            break # Exit while loop

                        # Handle data packet
                        # Discard logic for testing
                        if self.discard_seq is not None and \
                           packet.seq_num == self.discard_seq and \
                           not self.discard_seq_triggered:
                            log_message(f"Simulating discard of packet with seq = {packet.seq_num} (due to -d {self.discard_seq}).")
                            self.discard_seq_triggered = True
                            continue # Do not process or ACK this packet

                        # GBN Receiver Logic
                        if packet.seq_num == self.expected_seq_num:
                            log_message(f"packet {packet.seq_num} is received") # Matches assignment
                            output_file.write(packet.data)
                            self.total_bytes_received_payload += len(packet.data)
                            self.total_bytes_received_with_header += len(raw_bytes) # Header + Data (FAQ Q6)

                            # Send ACK for this in-order packet
                            ack_response = DRTPPacket(seq_num=0, # Seq for ACK packet itself
                                                      ack_num=packet.seq_num, # Acking this data packet's seq
                                                      flags=FLAG_ACK,
                                                      recv_window=RECEIVER_WINDOW_ON_SYN_ACK) # Can re-advertise
                            self.sock.sendto(ack_response.pack(), self.client_addr)
                            log_message(f"sending ack for the received {packet.seq_num}") # Matches assignment
                            self.expected_seq_num += 1
                        
                        elif packet.seq_num < self.expected_seq_num:
                            # Duplicate of an already acknowledged packet
                            log_message(f"Duplicate/old packet {packet.seq_num} received (expected {self.expected_seq_num}). Re-sending ACK for {packet.seq_num}.")
                            ack_response = DRTPPacket(ack_num=packet.seq_num, flags=FLAG_ACK)
                            self.sock.sendto(ack_response.pack(), self.client_addr)
                        
                        else: # Out-of-order: packet.seq_num > self.expected_seq_num
                            # Assignment: "DRTP receiver should in such cases not acknowledge anything and may discard these packets."
                            # Example output for -d shows server logging "out-of-order packet X is received" and then
                            # eventually receiving the missing packet and ACKing it. It does not show duplicate ACKs for
                            # the last in-order packet in that specific -d example.
                            log_message(f"out-of-order packet {packet.seq_num} is received, expected {self.expected_seq_num}. Discarding.")
                            # To strictly follow "not acknowledge anything": do nothing more here.
                            # If an optimization was desired (send duplicate ACK for expected_seq_num - 1), it would go here.
                            # Based on example, we just log and discard.

                    except socket.timeout:
                        log_message("Server: Timeout waiting for data or FIN. Assuming client issue.")
                        self.connection_active = False
                        if not self.end_time and self.start_time > 0: self.end_time = time.time()
                        break 
                    except Exception as e_inner:
                        log_message(f"Server: Error during packet processing in data loop: {e_inner}")
                        # Potentially continue, or if severe, set connection_active = False
                        pass

        except IOError as file_err:
            log_message(f"Server: File I/O error with '{self.output_filename}': {file_err}")
            self.connection_active = False # Cannot continue if file writing fails
            if not self.end_time and self.start_time > 0: self.end_time = time.time()
        
        log_message(f"Server: Data reception phase ended. Output file: '{self.output_filename}'.")


    def _send_fin_ack(self, client_fin_seq):
        """
        Description:
            This private method constructs and sends a FIN-ACK packet to the client.
            This is done when the server receives a FIN packet from the client, indicating
            the client has finished sending data and wishes to close the connection.
        Arguments:
            client_fin_seq (int): The sequence number that was in the FIN packet received
                                  from the client. This sequence number is acknowledged by
                                  the server's FIN-ACK.
        Use of other input and output parameters in the function:
            - self.sock: The server's UDP socket, used for sending the FIN-ACK.
            - self.client_addr: The address of the client to send the FIN-ACK to.
            - DRTPPacket class: Used to construct the FIN-ACK packet.
            - FLAG_FIN, FLAG_ACK (global constants): These flags are set in the outgoing packet.
        Returns:
            None.
            Why?: The function's purpose is to send a packet, which is a side effect.
                  It doesn't compute a value to be returned to its caller within the server.
        """
        fin_ack_response = DRTPPacket(seq_num=0, # Server's seq for its FIN-ACK (can be 0)
                                      ack_num=client_fin_seq, # Acknowledging client's FIN seq
                                      flags=FLAG_FIN | FLAG_ACK,
                                      recv_window=0) # Window not relevant in FIN-ACK
        try:
            self.sock.sendto(fin_ack_response.pack(), self.client_addr)
            log_message("FIN ACK packet is sent") # Matches assignment output
        except socket.error as sock_err_finack:
            log_message(f"Server: Socket error sending FIN-ACK: {sock_err_finack}")

    def _calculate_and_display_throughput(self):
        """
        Description:
            This private method calculates the throughput of the file transfer from the server's perspective.
            Throughput is defined as the total number of bytes received (including DRTP headers for data packets)
            divided by the duration of the data transfer phase. The result is displayed in Megabits per second (Mbps).
        Arguments:
            None.
        Use of other input and output parameters in the function:
            - self.start_time (float): Timestamp taken after successful connection establishment.
            - self.end_time (float): Timestamp taken when the client's FIN packet is received (or transfer ends due to error).
            - self.total_bytes_received_with_header (int): Total bytes (DRTP header + data) of all correctly received data packets.
            - The calculation adheres to the assignment's definition: 1 MB = 1000 KB, 1 KB = 1000 Bytes.
        Returns:
            None.
            Why?: The function's purpose is to calculate and print the throughput result to the console,
                  which is a side effect. It does not return a value.
        """
        if self.start_time > 0 and self.end_time > self.start_time and self.total_bytes_received_with_header > 0:
            duration = self.end_time - self.start_time
            if duration <= 0: # Should ideally not happen if end_time > start_time
                log_message("Throughput calculation error: Duration is not positive.")
                return

            # Total bits = total bytes * 8
            # Mbps = (Total bits) / (duration_seconds * 1,000,000)
            throughput_mbps = (self.total_bytes_received_with_header * 8) / (duration * 1000000.0)
            log_message(f"The throughput is {throughput_mbps:.2f} Mbps") # Matches assignment
            log_message(f"(INFO: Payload bytes: {self.total_bytes_received_payload}, "
                        f"Total DRTP packet bytes: {self.total_bytes_received_with_header}, Duration: {duration:.2f}s)")
        elif self.start_time > 0:
            log_message("Throughput calculation: Insufficient data or invalid duration.")
        else:
            log_message("Throughput calculation skipped: Connection not fully established.")


# --- DRTPClient Class ---
class DRTPClient:
    """
    Description:
        This class implements the client-side logic for the DATA2410 Reliable Transport Protocol (DRTP).
        The client initiates a connection to a DRTP server, reliably transmits a specified local file
        using the Go-Back-N (GBN) protocol, and then properly terminates the connection.
    """
    def __init__(self, target_server_ip, target_server_port, local_filename, client_window_size):
        """
        Description:
            This is the constructor for the DRTPClient class. It initializes the client's
            state, including server address details, the file to be transferred, GBN parameters
            (like window size), and the UDP socket.
        Arguments:
            target_server_ip (str): The IP address of the DRTP server to connect to.
            target_server_port (int): The port number on which the DRTP server is listening.
            local_filename (str): The path to the local file that the client will read and send to the server.
            client_window_size (int): The sender's (client's) desired window size for GBN, specified via command-line.
                                      The actual operational window size might be smaller, capped by the server's
                                      advertised receiver window.
        Use of other input and output parameters in the function:
            - self.server_ip, self.server_port, self.filename, self.window_size_arg: Store input arguments.
            - self.effective_window_size: Initialized with `client_window_size`, will be updated after handshake.
            - self.sock: A UDP socket (`socket.SOCK_DGRAM`) is created.
            - self.server_addr: A tuple `(target_server_ip, target_server_port)` for `sendto` calls.
            - GBN state variables (self.base_seq_num, self.next_seq_num, self.sent_packets_buffer,
              self.gbn_timer_start_time) are initialized for the data transfer phase.
            - self.file_handle, self.eof_reached, self.connection_established, self.last_fin_seq_num:
              Initialized to their default states.
        Returns:
            None.
            Why?: Standard Python constructor behavior.
        """
        self.server_ip = target_server_ip
        self.server_port = target_server_port
        self.filename = local_filename
        self.window_size_arg = client_window_size
        self.effective_window_size = client_window_size # Will be min(arg, server_adv_win)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_addr = (self.server_ip, self.server_port)

        self.base_seq_num = 1
        self.next_seq_num = 1
        self.sent_packets_buffer = {} # {seq_num: DRTPPacket_object_packed_bytes}
        self.gbn_timer_start_time = None
        
        self.file_handle = None
        self.eof_reached = False
        self.connection_established = False
        self.last_fin_seq_num = 0 # Seq num used for client's FIN

    def start(self):
        """
        Description:
            This is the main entry point to run the DRTP client. It orchestrates the client's
            operations: checking for the existence of the file to be sent, establishing a
            connection with the server, transferring the file data reliably, and finally,
            tearing down the connection.
        Arguments:
            None.
        Use of other input and output parameters in the function:
            - self.filename: Path to the file; its existence is checked.
            - Internal methods `_establish_connection()`, `_send_data_gbn()`, and
              `_teardown_connection()` are called in sequence.
            - Exception handling: Catches common errors like `FileNotFoundError`, socket errors,
              and general exceptions to provide log messages and ensure the socket is closed.
        Returns:
            None.
            Why?: The method's purpose is to execute the client's lifecycle, with outcomes
                  being network communication, file reading, and console logging.
        """
        try:
            if not os.path.exists(self.filename):
                log_message(f"Client: Error - Source file '{self.filename}' not found. Cannot start.")
                return
            
            log_message("Connection Establishment Phase:")
            if not self._establish_connection():
                # _establish_connection logs "Connection failed" as per example.
                return 
            self.connection_established = True

            log_message("Data Transfer:")
            self.file_handle = open(self.filename, 'rb')
            if os.path.getsize(self.filename) == 0:
                log_message(f"Client: File '{self.filename}' is empty. No data packets to send.")
                self.eof_reached = True
            
            self._send_data_gbn()

            # Log "DATA Finished" when all data is sent AND acknowledged, or if file was empty.
            if self.eof_reached and self.base_seq_num == self.next_seq_num:
                 log_message("DATA Finished") # Matches assignment output

        except FileNotFoundError: # Should be caught by os.path.exists, but as a fallback
            log_message(f"Client: File '{self.filename}' not found (unexpectedly after initial check).")
        except socket.error as se:
            log_message(f"Client Socket Error: {se}")
            # "Connection failed" might have already been logged if error was during setup.
        except Exception as e:
            log_message(f"Client General Error: {e}")
            # import traceback; traceback.print_exc() # For debugging
        finally:
            if self.file_handle:
                self.file_handle.close()
            
            if self.connection_established:
                log_message("Connection Teardown:")
                self._teardown_connection()
            else:
                # If connection failed at setup, "Connection failed" was logged.
                # The example for SYN timeout doesn't show "Connection Closes",
                # but for consistency if start() is exited, we might need a general close message.
                # Let's assume "Connection failed" is sufficient for setup failures.
                # If start() completes (even if teardown fails), "Connection Closes" is part of teardown.
                pass # "Connection failed" already logged by _establish_connection

            if self.sock: # Ensure socket is closed
                self.sock.close()
            # "Connection Closes" is typically logged by _teardown_connection or after setup failure.

    def _establish_connection(self):
        """
        Description:
            This private method handles the client-side of the DRTP 3-way handshake.
            It sends a SYN packet to the server, waits for a SYN-ACK response, and upon
            receiving a valid SYN-ACK, it sends a final ACK to confirm the connection.
            It also processes the receiver window advertised by the server.
        Arguments:
            None.
        Use of other input and output parameters in the function:
            - self.sock: The client's UDP socket for sending/receiving handshake packets.
            - self.server_addr: The (IP, port) tuple of the DRTP server.
            - DRTPPacket class: For packing outgoing SYN/ACK and unpacking incoming SYN-ACK.
            - FLAG_SYN, FLAG_ACK (global constants): For setting/checking flags.
            - CONNECTION_SETUP_TIMEOUT (global constant): For socket timeout when waiting for SYN-ACK.
            - On successful handshake:
                - self.effective_window_size is updated based on `min(self.window_size_arg, server_advertised_window)`.
        Returns:
            bool: True if connection established, False otherwise.
                  Why?: To signal to the `start()` method whether it's okay to proceed to data transfer.
        """
        try:
            # 1. Send SYN
            syn_packet_obj = DRTPPacket(seq_num=0, ack_num=0, flags=FLAG_SYN)
            self.sock.sendto(syn_packet_obj.pack(), self.server_addr)
            log_message("SYN packet is sent") # Matches assignment

            # 2. Wait for SYN-ACK
            self.sock.settimeout(CONNECTION_SETUP_TIMEOUT) # As per "server not responding" example
            raw_syn_ack_bytes, _ = self.sock.recvfrom(PACKET_SIZE) # SYN-ACK is header-only

            syn_ack_packet_obj = DRTPPacket.unpack(raw_syn_ack_bytes)
            if not syn_ack_packet_obj:
                log_message("Client: Received malformed SYN-ACK. Handshake failed.")
                log_message("Connection failed") # Matches assignment
                return False
            
            if not (syn_ack_packet_obj.flags & FLAG_SYN and syn_ack_packet_obj.flags & FLAG_ACK):
                log_message("Client: Received packet is not a valid SYN-ACK. Handshake failed.")
                log_message("Connection failed") # Matches assignment
                return False
            
            server_adv_win = syn_ack_packet_obj.recv_window
            self.effective_window_size = min(self.window_size_arg, server_adv_win)
            if self.effective_window_size <= 0: # Must be at least 1
                log_message(f"Warning: Effective window size became {self.effective_window_size} (arg: {self.window_size_arg}, server: {server_adv_win}). Setting to 1.")
                self.effective_window_size = 1
            
            log_message(f"Client: Server advertised receiver window: {server_adv_win}. Effective sending window: {self.effective_window_size}.")
            log_message("SYN-ACK packet is received") # Matches assignment

            # 3. Send ACK for SYN-ACK
            final_ack_obj = DRTPPacket(seq_num=0, ack_num=0, flags=FLAG_ACK) # Pure ACK
            self.sock.sendto(final_ack_obj.pack(), self.server_addr)
            log_message("ACK packet is sent") # Matches assignment
            log_message("Connection established") # Matches assignment
            return True

        except socket.timeout:
            log_message("Client: Timeout waiting for SYN-ACK from server.")
            log_message("Connection failed") # Matches assignment
            return False
        except Exception as e:
            log_message(f"Client: Error during connection establishment: {e}")
            log_message("Connection failed") # Matches assignment
            return False

    def _send_data_gbn(self):
        """
        Description:
            This private method implements the core Go-Back-N (GBN) sending logic for the client.
            It reads data from the file in chunks, creates DRTP data packets, sends them within
            the constraints of the effective sending window, manages a retransmission timer for the
            oldest unacknowledged packet, processes incoming ACKs to slide the window, and handles
            timeouts by retransmitting the current window of packets.
        Arguments:
            None.
        Use of other input and output parameters in the function:
            - self.file_handle: Used to read data chunks from the file.
            - self.eof_reached: Flag set to True when the end of the file is reached.
            - GBN state: self.base_seq_num, self.next_seq_num, self.effective_window_size,
              self.sent_packets_buffer (stores bytes of sent packets for retransmission),
              self.gbn_timer_start_time.
            - self.sock: Client's UDP socket for sending data packets and receiving ACKs.
            - self.server_addr: Destination for data packets.
            - DRTPPacket class and global constants: DATA_CHUNK_SIZE, FLAG_ACK.
            - GBN_TIMEOUT_DURATION (global constant): Used for the retransmission timer.
        Returns:
            None.
            Why?: This method's role is to manage the data transfer process, which involves side effects
                  (network sending/receiving, logging) rather than returning a computed value.
                  It continues until all file data is successfully acknowledged or an unrecoverable error occurs.
        """
        while not self.eof_reached or self.base_seq_num < self.next_seq_num:
            # Send new packets if window allows and data is available
            while self.next_seq_num < self.base_seq_num + self.effective_window_size and \
                  not self.eof_reached:
                
                data_chunk = self.file_handle.read(DATA_CHUNK_SIZE)
                if not data_chunk:
                    self.eof_reached = True
                    if self.base_seq_num == self.next_seq_num: # All sent packets are acked
                        return # EOF and no outstanding packets, GBN data phase done.
                    break # EOF reached, stop sending new packets, wait for ACKs for outstanding ones.

                # Create and send data packet
                # Data packets have flags=0, ack_num=0, recv_window=0 from client perspective
                packet_obj_to_send = DRTPPacket(seq_num=self.next_seq_num, data_payload=data_chunk)
                packed_bytes_to_send = packet_obj_to_send.pack()
                self.sent_packets_buffer[self.next_seq_num] = packed_bytes_to_send # Store bytes for retransmission
                
                try:
                    self.sock.sendto(packed_bytes_to_send, self.server_addr)
                except socket.error as se_send:
                    log_message(f"Client: Socket error sending packet {self.next_seq_num}: {se_send}")
                    return # Critical error, stop GBN

                current_window_seqs = sorted([s for s in self.sent_packets_buffer if s >= self.base_seq_num])
                log_message(f"packet with seq = {self.next_seq_num} is sent, sliding window = {{{', '.join(map(str, current_window_seqs))}}}")

                if self.base_seq_num == self.next_seq_num: # Timer starts for the first packet in window
                    self.gbn_timer_start_time = time.time()
                self.next_seq_num += 1
            
            if self.eof_reached and self.base_seq_num == self.next_seq_num:
                break # All data sent and acknowledged

            # Wait for ACKs or handle timeout
            try:
                sock_recv_timeout = GBN_TIMEOUT_DURATION
                if self.gbn_timer_start_time:
                    elapsed = time.time() - self.gbn_timer_start_time
                    remaining = GBN_TIMEOUT_DURATION - elapsed
                    if remaining <= 0:
                        raise socket.timeout # Timer conceptually expired
                    sock_recv_timeout = remaining
                elif not (self.base_seq_num < self.next_seq_num): # No packets in flight
                    if self.eof_reached: break
                    continue # Go back to try sending more

                self.sock.settimeout(sock_recv_timeout)
                raw_ack_bytes, _ = self.sock.recvfrom(HEADER_LENGTH) # ACKs are header-only

                ack_packet_obj = DRTPPacket.unpack(raw_ack_bytes)
                if not ack_packet_obj:
                    log_message("Client: Received malformed ACK. Ignoring.")
                    continue

                if ack_packet_obj.flags & FLAG_ACK:
                    log_message(f"ACK for packet = {ack_packet_obj.ack_num} is received") # Matches assignment
                    if ack_packet_obj.ack_num >= self.base_seq_num: # Cumulative ACK
                        for i in range(self.base_seq_num, ack_packet_obj.ack_num + 1):
                            self.sent_packets_buffer.pop(i, None) # Remove from buffer
                        self.base_seq_num = ack_packet_obj.ack_num + 1
                        
                        if self.base_seq_num == self.next_seq_num: # All outstanding ACKed
                            self.gbn_timer_start_time = None # Stop timer
                        else:
                            self.gbn_timer_start_time = time.time() # Restart timer for new base
            
            except socket.timeout: # GBN RTO
                if self.base_seq_num < self.next_seq_num: # If there are outstanding packets
                    log_message("RTO occured") # Matches assignment
                    self.gbn_timer_start_time = time.time() # Restart timer
                    for seq_resend in range(self.base_seq_num, self.next_seq_num):
                        if seq_resend in self.sent_packets_buffer:
                            bytes_to_resend = self.sent_packets_buffer[seq_resend]
                            try:
                                self.sock.sendto(bytes_to_resend, self.server_addr)
                                log_message(f"retransmitting packet with seq =  {seq_resend}") # Matches assignment
                            except socket.error as se_resend_rto:
                                log_message(f"Client: Socket error re-sending packet {seq_resend} on RTO: {se_resend_rto}")
                                return # Critical, stop GBN
            
            except Exception as e_ack:
                log_message(f"Client: Error receiving/processing ACK: {e_ack}")
                # Let GBN timer handle if ACKs stop coming

    def _teardown_connection(self):
        """
        Description:
            This private method handles the client-side of the DRTP 2-way handshake to terminate
            an established connection. It sends a FIN packet to the server and waits for a
            FIN-ACK response. It implements a retry mechanism for sending the FIN if the
            FIN-ACK is not received promptly.
        Arguments:
            None.
        Use of other input and output parameters in the function:
            - self.sock: The client's UDP socket.
            - self.server_addr: The (IP, port) of the server.
            - self.next_seq_num: Used as the sequence number for the FIN packet (self.last_fin_seq_num).
            - DRTPPacket class and FLAG_FIN, FLAG_ACK constants.
            - CONNECTION_SETUP_TIMEOUT (global constant): Used for socket timeout when waiting for FIN-ACK.
        Returns:
            bool: True if teardown was successful (FIN-ACK received and validated), False otherwise.
                  Why?: To indicate whether the connection was closed gracefully from DRTP's perspective.
        """
        try:
            # FIN packet's sequence number can be the next available one.
            self.last_fin_seq_num = self.next_seq_num
            
            fin_packet_obj = DRTPPacket(seq_num=self.last_fin_seq_num, flags=FLAG_FIN)
            
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    self.sock.sendto(fin_packet_obj.pack(), self.server_addr)
                    # Log "FIN packet is sent" only once as per example, or on first attempt.
                    # The assignment example output for client shows "FIN packet packet is sent" (typo likely means "FIN packet is sent")
                    if attempt == 0:
                        log_message("FIN packet is sent") # Or "FIN packet packet is sent" to match example typo

                    self.sock.settimeout(CONNECTION_SETUP_TIMEOUT)
                    raw_fin_ack_bytes, _ = self.sock.recvfrom(PACKET_SIZE) # FIN-ACK is header-only

                    fin_ack_obj = DRTPPacket.unpack(raw_fin_ack_bytes)
                    if not fin_ack_obj:
                        log_message(f"Client: Malformed FIN-ACK received (attempt {attempt + 1}).")
                        if attempt == max_retries - 1: break # Last attempt failed
                        continue

                    is_valid_fin_ack = (fin_ack_obj.flags & FLAG_FIN) and \
                                       (fin_ack_obj.flags & FLAG_ACK) and \
                                       (fin_ack_obj.ack_num == self.last_fin_seq_num)
                    
                    if is_valid_fin_ack:
                        log_message("FIN ACK packet is received") # Matches assignment
                        log_message("Connection Closes")         # Matches assignment
                        return True # Successful teardown
                    else:
                        log_message(f"Client: Invalid FIN-ACK received (attempt {attempt + 1}). Flags=0x{fin_ack_obj.flags:X}, AckN={fin_ack_obj.ack_num}, ExpAckN={self.last_fin_seq_num}")
                        # Fall through to retry if attempts remain

                except socket.timeout:
                    log_message(f"Client: Timeout waiting for FIN-ACK (attempt {attempt + 1}).")
                    # Loop will resend FIN if attempts remain
                except Exception as e_fin_recv_loop:
                    log_message(f"Client: Error in FIN-ACK loop (attempt {attempt + 1}): {e_fin_recv_loop}")
                
                if attempt == max_retries - 1: # After last attempt
                    log_message("Client: Max retries for FIN-ACK reached.")
                    break 

            # If loop finishes without returning True
            log_message("Connection Closes (FIN-ACK not confirmed after retries)")
            return False

        except Exception as e_teardown:
            log_message(f"Client: Error during connection teardown initiation: {e_teardown}")
            log_message("Connection Closes") # Ensure this is logged
            return False

# --- Argument Parsing and Main Execution ---
def check_port_arg(port_str_val):
    """
    Description:
        Custom type validation function for argparse, specifically for port numbers.
        It ensures the provided port is an integer and within the valid range [1024, 65535].
    Arguments:
        port_str_val (str): The port number as a string from the command line.
    Use of other input and output parameters in the function:
        Attempts to convert `port_str_val` to `int`.
    Returns:
        int: The validated port number if valid.
        Why?: To be used by argparse as the parsed value for the port argument.
        Raises argparse.ArgumentTypeError: If validation fails, argparse handles the error message.
    """
    try:
        port_int = int(port_str_val)
        if not (1024 <= port_int <= 65535):
            raise argparse.ArgumentTypeError(f"Port number {port_int} must be between 1024 and 65535.")
        return port_int
    except ValueError:
        raise argparse.ArgumentTypeError(f"Port '{port_str_val}' is not a valid integer.")

def main():
    """
    Description:
        Main function to drive the DRTP application. It parses command-line arguments
        to determine mode (client/server) and other parameters, then instantiates and
        starts the appropriate DRTPClient or DRTPServer object.
    Arguments:
        None (implicitly uses sys.argv for command-line arguments).
    Use of other input and output parameters in the function:
        - argparse module: To define and parse command-line arguments.
        - check_port_arg: Custom type for port validation.
        - Global constants: DEFAULT_PORT, DEFAULT_WINDOW_SIZE.
        - Instantiates DRTPClient or DRTPServer with parsed arguments.
    Returns:
        None.
        Why?: Orchestrates the application launch; does not compute a return value.
              Exits with status codes on argument errors.
    """
    parser = argparse.ArgumentParser(
        description="DRTP (DATA2410 Reliable Transport Protocol) File Transfer Application.",
        epilog="Example Client: python3 application.py -c -f Photo.jpg -i 10.0.1.2 -p 8088 -w 5\n"
               "Example Server: python3 application.py -s -i 10.0.1.2 -p 8088 -d 8",
        formatter_class=argparse.RawTextHelpFormatter
    )
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("-s", "--server", action="store_true", help="Run in server mode.")
    mode_group.add_argument("-c", "--client", action="store_true", help="Run in client mode.")

    parser.add_argument("-i", "--ip", type=str,
                        help="IP address. Server: IP to bind (default: 0.0.0.0). Client: Server's IP (default: 127.0.0.1).")
    parser.add_argument("-p", "--port", type=check_port_arg, default=DEFAULT_PORT,
                        help=f"Port number (1024-65535). Default: {DEFAULT_PORT}.")
    parser.add_argument("-f", "--file", type=str, metavar="FILENAME",
                        help="File to transfer (Client mode only, required).")
    parser.add_argument("-w", "--window", type=int, default=DEFAULT_WINDOW_SIZE, metavar="SIZE",
                        help=f"Client's sending window size (packets, >0). Default: {DEFAULT_WINDOW_SIZE}.")
    parser.add_argument("-d", "--discard", type=int, metavar="SEQ_NUM",
                        help="Server: sequence number of a packet to discard once for testing.")

    try:
        args = parser.parse_args()
    except SystemExit as e: # Argparse exits on error or -h
        sys.exit(e.code)


    # Post-parsing validation and default setting
    if args.client:
        if args.ip is None: args.ip = "127.0.0.1" # Default client IP
        if not args.file:
            parser.error("argument -f/--file is required in client mode.")
        if args.window <= 0:
            parser.error("argument -w/--window: must be a positive integer.")
        if args.discard is not None:
            print("Warning: -d/--discard argument is ignored in client mode.")
    
    if args.server:
        if args.ip is None: args.ip = "0.0.0.0" # Default server IP
        if args.file:
            print("Warning: -f/--file argument is ignored in server mode.")
        # No specific validation for -w for server as it's not directly used by server logic for its operation.

    # Launch based on mode
    if args.server:
        server = DRTPServer(args.ip, args.port, args.discard)
        server.start()
    elif args.client:
        client = DRTPClient(args.ip, args.port, args.file, args.window)
        client.start()
    # else: Should be caught by argparse's required group

if __name__ == "__main__":
    main()
