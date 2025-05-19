import argparse
import socket
import struct
import os
import sys
import time # Keep time import
from datetime import datetime # For timestamped logs

# --- DRTP Protocol Constants ---
HEADER_LENGTH = 8 
DATA_CHUNK_SIZE = 992 
PACKET_SIZE = HEADER_LENGTH + DATA_CHUNK_SIZE

# --- Application Behavior Constants ---
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

# --- Utility Functions ---
def log_message(message_text):
    """
    Description: Prints log message with timestamp.
    Arguments: message_text (str): Message to log.
    Returns: None. Why?: Logging.
    """
    timestamp_str = datetime.now().strftime('%H:%M:%S.%f')
    print(f"{timestamp_str} -- {message_text}")

# --- DRTPPacket Class ---
class DRTPPacket:
    """
    Description: Handles DRTP packet packing/unpacking (8-byte header).
    """
    _header_format_string = '!HHHH' 

    def __init__(self, seq_num=0, ack_num=0, flags=0, recv_window=0, data_payload=b''):
        """
        Description: Initializes DRTPPacket.
        Arguments: seq (int), ack (int), flags (int), win (int), data (bytes).
        Returns: None. Why?: Constructor.
        """
        self.seq_num = seq_num & 0xFFFF
        self.ack_num = ack_num & 0xFFFF
        self.flags = (flags & ~FLAG_RST) & 0xFFFF 
        self.recv_window = recv_window & 0xFFFF
        self.data = data_payload

    def pack(self):
        """
        Description: Packs header and data to bytes.
        Arguments: None.
        Returns: bytes: Packet. Why?: For UDP send.
        """
        try:
            packed_header = struct.pack(self._header_format_string,
                                        self.seq_num, self.ack_num,
                                        self.flags, self.recv_window)
        except struct.error as e:
            log_message(f"Error: Pack failed - {e}") # Minimal error log
            raise 
        return packed_header + self.data

    @staticmethod
    def unpack(raw_packet_bytes):
        """
        Description: Parses raw bytes to DRTPPacket.
        Arguments: raw_packet_bytes (bytes).
        Returns: DRTPPacket or None. Why?: Packet object or parse fail.
        """
        if len(raw_packet_bytes) < HEADER_LENGTH:
            return None 
        try:
            header_tuple = struct.unpack(DRTPPacket._header_format_string,
                                         raw_packet_bytes[:HEADER_LENGTH])
        except struct.error:
            return None # Minimal fail, no log needed here for compactness
        
        data_payload_part = raw_packet_bytes[HEADER_LENGTH:]
        return DRTPPacket(seq_num=header_tuple[0], ack_num=header_tuple[1],
                          flags=header_tuple[2], recv_window=header_tuple[3],
                          data_payload=data_payload_part)

# --- DRTPServer Class ---
class DRTPServer:
    """
    Description: Implements DRTP server.
    """
    def __init__(self, ip_addr, port_num, discard_packet_seq=None):
        """
        Description: Initializes server.
        Arguments: ip (str), port (int), discard_seq (int, opt).
        Returns: None. Why?: Constructor.
        """
        self.host_ip = ip_addr
        self.port = port_num
        self.discard_seq = discard_packet_seq
        self.discard_seq_triggered = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.expected_seq_num = 1
        self.client_addr = None
        self.output_filename = "received_file.dat" # Simpler fixed name
        self.connection_active = False
        self.total_bytes_received_payload = 0
        self.total_bytes_received_with_header = 0
        self.start_time_transfer = 0.0
        self.end_time_transfer = 0.0

    def start(self):
        """
        Description: Main server loop.
        Arguments: None.
        Returns: None. Why?: Orchestrates.
        """
        try:
            self.sock.bind((self.host_ip, self.port))
            log_message(f"Server listening on {self.host_ip}:{self.port}")
            if not self._establish_connection_server():
                return
            self._receive_file_data()
        except socket.error as e_sock:
            log_message(f"Server Socket Err: {e_sock}") # Slightly more compact
        except Exception as e_general:
            log_message(f"Server General Err: {e_general}")
        finally:
            if self.start_time_transfer > 0:
                if self.connection_active and self.end_time_transfer == 0:
                    self.end_time_transfer = time.time()
                self._calculate_and_log_throughput()
                log_message("Connection Closes")
            if self.sock:
                self.sock.close()
            log_message("Server shut down.")

    def _establish_connection_server(self):
        """
        Description: Server 3-way handshake.
        Arguments: None.
        Returns: bool: True if success. Why?: To proceed.
        """
        try:
            self.sock.settimeout(None) 
            log_message("Server: Waiting for SYN...")
            raw_syn, client_address_info = self.sock.recvfrom(PACKET_SIZE)
            syn_pkt = DRTPPacket.unpack(raw_syn)
            if not syn_pkt or not (syn_pkt.flags & FLAG_SYN):
                return False 
            self.client_addr = client_address_info
            log_message("SYN packet is received")

            syn_ack_pkt = DRTPPacket(flags=FLAG_SYN | FLAG_ACK,
                                     recv_window=RECEIVER_WINDOW_ON_SYN_ACK)
            self.sock.sendto(syn_ack_pkt.pack(), self.client_addr)
            log_message("SYN-ACK packet is sent")

            self.sock.settimeout(CONNECTION_SETUP_TIMEOUT)
            raw_ack, _ = self.sock.recvfrom(PACKET_SIZE)
            ack_pkt = DRTPPacket.unpack(raw_ack)
            if not ack_pkt or not ((ack_pkt.flags & FLAG_ACK) and not (ack_pkt.flags & FLAG_SYN)):
                return False
            log_message("ACK packet is received")
            log_message("Connection established")
            self.connection_active = True
            self.start_time_transfer = time.time()
            return True
        except socket.timeout:
            log_message("Server: Timeout in handshake.") 
            return False
        except Exception: 
            return False

    def _receive_file_data(self):
        """
        Description: Receives file via GBN.
        Arguments: None.
        Returns: None. Why?: Manages reception.
        """
        try:
            with open(self.output_filename, 'wb') as file_out:
                # log_message(f"Server: Receiving data into '{self.output_filename}'") # Can be removed
                while self.connection_active:
                    try:
                        self.sock.settimeout(CONNECTION_SETUP_TIMEOUT * 2)
                        raw_data, sender_addr = self.sock.recvfrom(PACKET_SIZE)
                        if sender_addr != self.client_addr: continue
                        pkt = DRTPPacket.unpack(raw_data)
                        if not pkt: continue

                        if pkt.flags & FLAG_FIN:
                            self.end_time_transfer = time.time()
                            log_message("FIN packet is received")
                            self._send_fin_ack_server(pkt.seq_num)
                            self.connection_active = False
                            break

                        if self.discard_seq is not None and pkt.seq_num == self.discard_seq and \
                           not self.discard_seq_triggered:
                            log_message(f"Simulating discard of packet seq={pkt.seq_num}")
                            self.discard_seq_triggered = True
                            continue

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
                            ack_resp = DRTPPacket(ack_num=pkt.seq_num, flags=FLAG_ACK) 
                            self.sock.sendto(ack_resp.pack(), self.client_addr)
                        else: 
                            log_message(f"out-of-order packet {pkt.seq_num} (expected {self.expected_seq_num}). Discarding.")
                    except socket.timeout:
                        log_message("Server: Timeout waiting for data/FIN.")
                        self.connection_active = False
                        if not self.end_time_transfer and self.start_time_transfer > 0:
                            self.end_time_transfer = time.time()
                        break
                    except Exception: 
                        pass 
        except IOError:
            log_message(f"Server: File I/O error for '{self.output_filename}'.") 
            self.connection_active = False
            if not self.end_time_transfer and self.start_time_transfer > 0:
                self.end_time_transfer = time.time()
        # log_message(f"Server: Data reception ended.") # Can be removed

    def _send_fin_ack_server(self, client_fin_seq_num):
        """
        Description: Sends FIN-ACK.
        Arguments: client_fin_seq_num (int).
        Returns: None. Why?: Sends packet.
        """
        fin_ack_resp = DRTPPacket(ack_num=client_fin_seq_num, flags=FLAG_FIN | FLAG_ACK)
        try:
            self.sock.sendto(fin_ack_resp.pack(), self.client_addr)
            log_message("FIN ACK packet is sent")
        except socket.error: 
            pass

    def _calculate_and_log_throughput(self):
        """
        Description: Calculates and logs throughput.
        Arguments: None.
        Returns: None. Why?: Prints result.
        """
        if self.start_time_transfer > 0 and self.end_time_transfer > self.start_time_transfer and \
           self.total_bytes_received_with_header > 0:
            duration = self.end_time_transfer - self.start_time_transfer
            if duration <= 0: return 
            throughput_mbps = (self.total_bytes_received_with_header * 8) / (duration * 1000000.0)
            log_message(f"The throughput is {throughput_mbps:.2f} Mbps")
            # The (Debug Info: ...) line is now removed.
        elif self.start_time_transfer > 0:
            log_message("Throughput: Not enough data or valid duration.")
        # Else: No log if connection didn't even start transfer phase

# --- DRTPClient Class ---
class DRTPClient:
    """
    Description: Implements DRTP client.
    """
    def __init__(self, s_ip, s_port, file_to_send, win_size):
        """
        Description: Initializes client.
        Arguments: s_ip (str), s_port (int), file (str), win (int).
        Returns: None. Why?: Constructor.
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
        self.last_fin_seq_num = 0

    def start(self):
        """
        Description: Main client loop.
        Arguments: None.
        Returns: None. Why?: Orchestrates.
        """
        try:
            if not os.path.exists(self.filename):
                log_message(f"Client: File '{self.filename}' not found. Exiting.")
                return
            log_message("Connection Establishment Phase:")
            if not self._establish_connection_client():
                return
            self.connection_established = True
            log_message("Data Transfer:")
            self.file_handle = open(self.filename, 'rb')
            if os.path.getsize(self.filename) == 0:
                log_message(f"Client: File '{self.filename}' is empty.")
                self.eof_reached = True
            self._send_file_data_gbn()
            if self.eof_reached and self.base_seq_num == self.next_seq_num:
                 log_message("DATA Finished")
        except Exception: 
            pass
        finally:
            if self.file_handle: self.file_handle.close()
            if self.connection_established:
                log_message("Connection Teardown:")
                self._teardown_connection_client()
            if self.sock: self.sock.close()

    def _establish_connection_client(self):
        """
        Description: Client 3-way handshake.
        Arguments: None.
        Returns: bool: True if success. Why?: To proceed.
        """
        try:
            syn_pkt = DRTPPacket(flags=FLAG_SYN)
            self.sock.sendto(syn_pkt.pack(), self.server_addr)
            log_message("SYN packet is sent")

            self.sock.settimeout(CONNECTION_SETUP_TIMEOUT)
            raw_syn_ack, _ = self.sock.recvfrom(PACKET_SIZE)
            syn_ack_pkt = DRTPPacket.unpack(raw_syn_ack)

            if not syn_ack_pkt or not (syn_ack_pkt.flags & FLAG_SYN and syn_ack_pkt.flags & FLAG_ACK):
                log_message("Connection failed") 
                return False
            
            server_rcv_win = syn_ack_pkt.recv_window
            self.effective_window_size = min(self.window_size_arg, server_rcv_win)
            if self.effective_window_size <= 0: self.effective_window_size = 1 
            
            log_message("SYN-ACK packet is received") # Keep essential handshake logs

            ack_pkt = DRTPPacket(flags=FLAG_ACK) 
            self.sock.sendto(ack_pkt.pack(), self.server_addr)
            log_message("ACK packet is sent")
            log_message("Connection established")
            return True
        except socket.timeout:
            log_message("Connection failed") 
            return False
        except Exception:
            log_message("Connection failed") 
            return False

    def _send_file_data_gbn(self):
        """
        Description: Sends file data via GBN.
        Arguments: None.
        Returns: None. Why?: Manages sending.
        """
        while not self.eof_reached or self.base_seq_num < self.next_seq_num:
            while self.next_seq_num < self.base_seq_num + self.effective_window_size and \
                  not self.eof_reached:
                data_payload_chunk = self.file_handle.read(DATA_CHUNK_SIZE)
                if not data_payload_chunk:
                    self.eof_reached = True
                    if self.base_seq_num == self.next_seq_num: return
                    break
                data_pkt_obj = DRTPPacket(seq_num=self.next_seq_num, data_payload=data_payload_chunk)
                data_pkt_bytes = data_pkt_obj.pack()
                self.sent_packets_buffer[self.next_seq_num] = data_pkt_bytes
                try:
                    self.sock.sendto(data_pkt_bytes, self.server_addr)
                except socket.error: return 

                window_log = sorted([s for s in self.sent_packets_buffer if s >= self.base_seq_num])
                log_message(f"packet with seq = {self.next_seq_num} is sent, sliding window = {{{', '.join(map(str, window_log))}}}")
                if self.base_seq_num == self.next_seq_num:
                    self.gbn_timer_start_time = time.time()
                self.next_seq_num += 1
            
            if self.eof_reached and self.base_seq_num == self.next_seq_num: break

            try:
                current_timeout_val = GBN_TIMEOUT_DURATION
                if self.gbn_timer_start_time:
                    time_passed = time.time() - self.gbn_timer_start_time
                    remaining_on_timer = GBN_TIMEOUT_DURATION - time_passed
                    if remaining_on_timer <= 0: raise socket.timeout
                    current_timeout_val = remaining_on_timer
                elif not (self.base_seq_num < self.next_seq_num):
                    if self.eof_reached: break
                    continue 
                self.sock.settimeout(current_timeout_val)
                raw_ack, _ = self.sock.recvfrom(HEADER_LENGTH)
                ack_pkt_obj = DRTPPacket.unpack(raw_ack)
                if ack_pkt_obj and (ack_pkt_obj.flags & FLAG_ACK):
                    log_message(f"ACK for packet = {ack_pkt_obj.ack_num} is received")
                    if ack_pkt_obj.ack_num >= self.base_seq_num:
                        for i in range(self.base_seq_num, ack_pkt_obj.ack_num + 1):
                            self.sent_packets_buffer.pop(i, None)
                        self.base_seq_num = ack_pkt_obj.ack_num + 1
                        if self.base_seq_num == self.next_seq_num:
                            self.gbn_timer_start_time = None
                        else:
                            self.gbn_timer_start_time = time.time()
            except socket.timeout:
                if self.base_seq_num < self.next_seq_num:
                    log_message("RTO occured")
                    self.gbn_timer_start_time = time.time()
                    for seq_to_resend in range(self.base_seq_num, self.next_seq_num):
                        if seq_to_resend in self.sent_packets_buffer:
                            bytes_to_resend_pkt = self.sent_packets_buffer[seq_to_resend]
                            try:
                                self.sock.sendto(bytes_to_resend_pkt, self.server_addr)
                                log_message(f"retransmitting packet with seq =  {seq_to_resend}")
                            except socket.error: return 
            except Exception: 
                pass

    def _teardown_connection_client(self):
        """
        Description: Client 2-way handshake.
        Arguments: None.
        Returns: bool: True if success. Why?: Graceful close.
        """
        try:
            self.last_fin_seq_num = self.next_seq_num
            fin_pkt_obj = DRTPPacket(seq_num=self.last_fin_seq_num, flags=FLAG_FIN)
            max_fin_attempts = 3
            for attempt_num in range(max_fin_attempts):
                try:
                    self.sock.sendto(fin_pkt_obj.pack(), self.server_addr)
                    if attempt_num == 0:
                        log_message("FIN packet is sent")
                    self.sock.settimeout(CONNECTION_SETUP_TIMEOUT)
                    raw_fin_ack, _ = self.sock.recvfrom(PACKET_SIZE)
                    fin_ack_pkt_obj = DRTPPacket.unpack(raw_fin_ack)
                    if fin_ack_pkt_obj and (fin_ack_pkt_obj.flags & FLAG_FIN) and \
                       (fin_ack_pkt_obj.flags & FLAG_ACK) and \
                       (fin_ack_pkt_obj.ack_num == self.last_fin_seq_num):
                        log_message("FIN ACK packet is received")
                        log_message("Connection Closes")
                        return True
                except socket.timeout:
                    if attempt_num == max_fin_attempts -1 : log_message("Client: Max FIN retries reached.")
                except Exception: 
                    pass
                if attempt_num == max_fin_attempts - 1: break
            log_message("Connection Closes (FIN-ACK not confirmed)")
            return False
        except Exception:
            log_message("Connection Closes") 
            return False

def check_port_arg_main(port_value_str):
    """
    Description: Validates port for argparse.
    Arguments: port_value_str (str).
    Returns: int: Valid port. Why?: For argparse.
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
    Description: Parses CLI args, starts client/server.
    Arguments: None.
    Returns: None. Why?: Main driver.
    """
    arg_parser = argparse.ArgumentParser(description="DRTP File Transfer Application.")
    mode_selection_group = arg_parser.add_mutually_exclusive_group(required=True)
    mode_selection_group.add_argument("-s", "--server", action="store_true", help="Server mode.")
    mode_selection_group.add_argument("-c", "--client", action="store_true", help="Client mode.")
    arg_parser.add_argument("-i", "--ip", type=str, help="IP address.")
    arg_parser.add_argument("-p", "--port", type=check_port_arg_main, default=DEFAULT_PORT, help=f"Port. Default: {DEFAULT_PORT}.")
    arg_parser.add_argument("-f", "--file", type=str, metavar="FILENAME", help="File (Client only).")
    arg_parser.add_argument("-w", "--window", type=int, default=DEFAULT_WINDOW_SIZE, metavar="SIZE", help=f"Window size. Default: {DEFAULT_WINDOW_SIZE}.")
    arg_parser.add_argument("-d", "--discard", type=int, metavar="SEQ_NUM", help="Server: seq to discard.")

    try:
        cli_args = arg_parser.parse_args()
    except SystemExit: return

    if cli_args.client:
        if cli_args.ip is None: cli_args.ip = "127.0.0.1"
        if not cli_args.file: arg_parser.error("-f/--file required for client.")
        if cli_args.window <= 0: arg_parser.error("-w/--window must be > 0.")
    if cli_args.server:
        if cli_args.ip is None: cli_args.ip = "0.0.0.0"

    if cli_args.server:
        drtp_server = DRTPServer(cli_args.ip, cli_args.port, cli_args.discard)
        drtp_server.start()
    elif cli_args.client:
        drtp_client = DRTPClient(cli_args.ip, cli_args.port, cli_args.file, cli_args.window)
        drtp_client.start()

main()
