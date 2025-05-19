import argparse
import socket
import struct
import os # for file ops
import time
from datetime import datetime

header_length = 8 # len of header
data_chunk_size = 992 # data chunk
packet_size = header_length + data_chunk_size # total packet size
default_port = 8088 # default port if not specified
default_win_size = 3 # default window
receive_win_on_syn_ack = 15 # server advertised window
gbn_timeout = 0.4 # 400 ms for gbn
connection_timeout = 5.0 # 5s for connection establishment
flag_rst = 1 << 0 # reset flag
flag_ack = 1 << 1 # ACK flag
flag_syn = 1 << 2 # SYN flag
flag_fin = 1 << 3 # FIN flag

def log_message_ts(message_text): # For messages that need a timestamp as per example given on github
    timestamp_str = datetime.now().strftime('%H:%M:%S.%f') # get current time formatted
    print(f"{timestamp_str} -- {message_text}")

class DRTPPacket:
    _header_format_string = '!HHHH' # format for struct packing
    def __init__(self, seq_num=0, ack_num=0, flags=0, recv_window=0, data_payload=b''):
        self.seq_num = seq_num & 0xFFFF
        self.ack_num = ack_num & 0xFFFF
        self.flags = (flags & ~flag_rst) & 0xFFFF
        self.recv_window = recv_window & 0xFFFF
        self.data = data_payload

    def pack(self):
        try:
            packed_header = struct.pack(self._header_format_string, self.seq_num, self.ack_num, self.flags, self.recv_window)
        except struct.error as e:
            print(f"Error: Pack failed - {e}")
            raise
        return packed_header + self.data

    @staticmethod
    def unpack(raw_packet_bytes):
        if len(raw_packet_bytes) < header_length:
            print("Packet too short to unpack.")
            return None
        try:
            header_tuple = struct.unpack(DRTPPacket._header_format_string, raw_packet_bytes[:header_length])
        except struct.error:
            return None
        data_payload_part = raw_packet_bytes[header_length:]
        return DRTPPacket(seq_num=header_tuple[0], ack_num=header_tuple[1], flags=header_tuple[2], recv_window=header_tuple[3], data_payload=data_payload_part)

class DRTPServer:
    def __init__(self, ip_addr, port_num, discard_packet_seq=None):
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
        try:
            self.sock.bind((self.host_ip, self.port))
            print(f"Server listening on {self.host_ip}:{self.port}")
            if not self._establish_connection_server():
                return
            self._receive_file_data()
        except socket.error as e_sock:
            print(f"Server Socket Err: {e_sock}")
        finally:
            if self.start_time_transfer > 0:
                if self.connection_active and self.end_time_transfer == 0:
                    self.end_time_transfer = time.time()
                if self.end_time_transfer > self.start_time_transfer and self.total_bytes_received_with_header > 0:
                    duration = self.end_time_transfer - self.start_time_transfer
                    if duration > 0:
                        throughput_mbps = (self.total_bytes_received_with_header * 8) / (duration * 1000000.0)
                        print(f"The throughput is {throughput_mbps:.2f} Mbps")
                elif self.total_bytes_received_with_header == 0 and self.connection_active:
                    print("Throughput: No data received for calculation.")
                print("Connection Closes")
            if self.sock:
                self.sock.close()
            print("Server shut down.")

    def _establish_connection_server(self):
        try:
            self.sock.settimeout(None)
            raw_syn, client_address_info = self.sock.recvfrom(packet_size)
            syn_pkt = DRTPPacket.unpack(raw_syn)
            if not syn_pkt or not (syn_pkt.flags & flag_syn):
                print("Did not receive a valid SYN packet.")
                return False
            self.client_addr = client_address_info
            print("SYN packet is received")

            syn_ack_pkt = DRTPPacket(flags=flag_syn | flag_ack, recv_window=receive_win_on_syn_ack)
            self.sock.sendto(syn_ack_pkt.pack(), self.client_addr)
            print("SYN-ACK packet is sent")

            self.sock.settimeout(connection_timeout)
            raw_ack, _ = self.sock.recvfrom(packet_size)
            ack_pkt = DRTPPacket.unpack(raw_ack)
            if not ack_pkt or not ((ack_pkt.flags & flag_ack) and not (ack_pkt.flags & flag_syn)):
                print("Did not receive a valid ACK for SYN-ACK.")
                return False
            print("ACK packet is received")
            print("Connection established")
            self.connection_active = True
            self.start_time_transfer = time.time()
            return True
        except socket.timeout:
            print("Server: Timeout in handshake.")
            return False

    def _receive_file_data(self):
        try:
            with open(self.output_filename, 'wb') as file_out:
                while self.connection_active:
                    try:
                        self.sock.settimeout(gbn_timeout * 5)
                        raw_data, sender_addr = self.sock.recvfrom(packet_size)
                        if sender_addr != self.client_addr:
                            continue
                        pkt = DRTPPacket.unpack(raw_data)
                        if not pkt:
                            print("Failed to unpack received packet.")
                            continue
                        if pkt.flags & flag_fin:
                            self.end_time_transfer = time.time()
                            print("FIN packet is received")
                            fin_ack_resp = DRTPPacket(ack_num=pkt.seq_num, flags=flag_fin | flag_ack)
                            self.sock.sendto(fin_ack_resp.pack(), self.client_addr)
                            print("FIN ACK packet is sent")
                            self.connection_active = False
                            break
                        if self.discard_seq is not None and pkt.seq_num == self.discard_seq and not self.discard_seq_triggered:
                            print(f"Simulating discard of packet seq={pkt.seq_num}")
                            self.discard_seq_triggered = True
                            continue
                        if pkt.seq_num == self.expected_seq_num:
                            log_message_ts(f"packet {pkt.seq_num} is received")
                            file_out.write(pkt.data)
                            self.total_bytes_received_payload += len(pkt.data)
                            self.total_bytes_received_with_header += len(raw_data)
                            ack_resp = DRTPPacket(ack_num=pkt.seq_num, flags=flag_ack, recv_window=receive_win_on_syn_ack)
                            self.sock.sendto(ack_resp.pack(), self.client_addr)
                            log_message_ts(f"sending ack for the received {pkt.seq_num}")
                            self.expected_seq_num += 1
                        elif pkt.seq_num < self.expected_seq_num:
                            ack_resp = DRTPPacket(ack_num=pkt.seq_num, flags=flag_ack)
                            self.sock.sendto(ack_resp.pack(), self.client_addr)
                        else:
                            print(f"Server: out-of-order packet {pkt.seq_num} (expected {self.expected_seq_num}). Discarding.")
                            if self.expected_seq_num > 1:
                                ack_resp = DRTPPacket(ack_num=self.expected_seq_num - 1, flags=flag_ack)
                                self.sock.sendto(ack_resp.pack(), self.client_addr)
                    except socket.timeout:
                        print("Server: Timeout waiting for data/FIN.")
                        self.connection_active = False
                        if not self.end_time_transfer and self.start_time_transfer > 0:
                            self.end_time_transfer = time.time()
                        break
        except IOError as e:
            print(f"Server: File I/O error for '{self.output_filename}'. Error: {e}")
            self.connection_active = False

class DRTPClient:
    def __init__(self, s_ip, s_port, file_to_send, win_size):
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
        try:
            if not os.path.exists(self.filename):
                print(f"Client: File '{self.filename}' not found. Exiting.")
                return
            print("Connection Establishment Phase:")
            if not self._establish_connection_client():
                return
            self.connection_established = True
            print("Data Transfer:")
            self.file_handle = open(self.filename, 'rb')
            if os.path.getsize(self.filename) == 0:
                print(f"Client: File '{self.filename}' is empty.")
                self.eof_reached = True
            self._send_file_data_gbn()
            if self.eof_reached and self.base_seq_num == self.next_seq_num:
                print("DATA Finished")
        except FileNotFoundError:
            print(f"Client: File '{self.filename}' could not be opened. Exiting.")
        finally:
            if self.file_handle:
                self.file_handle.close()
            if self.connection_established:
                print("Connection Teardown:")
                self._teardown_connection_client()
            if self.sock:
                self.sock.close()

    def _establish_connection_client(self):
        try:
            syn_pkt = DRTPPacket(flags=flag_syn)
            self.sock.sendto(syn_pkt.pack(), self.server_addr)
            print("SYN packet is sent")
            self.sock.settimeout(connection_timeout)
            raw_syn_ack, _ = self.sock.recvfrom(packet_size)
            syn_ack_pkt = DRTPPacket.unpack(raw_syn_ack)
            if not syn_ack_pkt or not (syn_ack_pkt.flags & flag_syn and syn_ack_pkt.flags & flag_ack):
                print("Connection failed: Invalid SYN-ACK received.")
                return False
            server_rcv_win = syn_ack_pkt.recv_window
            self.effective_window_size = min(self.window_size_arg, server_rcv_win)
            if self.effective_window_size <= 0:
                self.effective_window_size = 1
            print("SYN-ACK packet is received")
            ack_pkt = DRTPPacket(flags=flag_ack)
            self.sock.sendto(ack_pkt.pack(), self.server_addr)
            print("ACK packet is sent")
            print("Connection established")
            return True
        except socket.timeout:
            print("Connection failed: Timeout waiting for SYN-ACK.")
            return False

    def _send_file_data_gbn(self):
        while not self.eof_reached or self.base_seq_num < self.next_seq_num:
            while self.next_seq_num < self.base_seq_num + self.effective_window_size and not self.eof_reached:
                data_payload_chunk = self.file_handle.read(data_chunk_size)
                if not data_payload_chunk:
                    self.eof_reached = True
                    if self.base_seq_num == self.next_seq_num:
                        return
                    break
                data_pkt_obj = DRTPPacket(seq_num=self.next_seq_num, data_payload=data_payload_chunk)
                data_pkt_bytes = data_pkt_obj.pack()
                self.sent_packets_buffer[self.next_seq_num] = data_pkt_bytes
                try:
                    self.sock.sendto(data_pkt_bytes, self.server_addr)
                except socket.error as e:
                    print(f"Client: Socket error sending packet {self.next_seq_num}: {e}")
                    return
                window_log_display_list = sorted([s for s in self.sent_packets_buffer if s >= self.base_seq_num])
                window_log_str = ", ".join(map(str, window_log_display_list))
                log_message_ts(f"packet with seq = {self.next_seq_num} is sent, sliding window = {{{window_log_str}}}")
                if self.base_seq_num == self.next_seq_num:
                    self.gbn_timer_start_time = time.time()
                self.next_seq_num += 1
            if self.eof_reached and self.base_seq_num == self.next_seq_num:
                break
            try:
                current_timeout_val = gbn_timeout
                if self.gbn_timer_start_time:
                    time_passed = time.time() - self.gbn_timer_start_time
                    remaining_on_timer = gbn_timeout - time_passed
                    if remaining_on_timer <= 0:
                        raise socket.timeout
                    current_timeout_val = remaining_on_timer
                elif not (self.base_seq_num < self.next_seq_num):
                    if self.eof_reached:
                        break
                    continue
                self.sock.settimeout(current_timeout_val)
                raw_ack, _ = self.sock.recvfrom(header_length)
                ack_pkt_obj = DRTPPacket.unpack(raw_ack)
                if ack_pkt_obj and (ack_pkt_obj.flags & flag_ack):
                    log_message_ts(f"ACK for packet = {ack_pkt_obj.ack_num} is received")
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
                    print("RTO occured")
                    self.gbn_timer_start_time = time.time()
                    for seq_to_resend in range(self.base_seq_num, self.next_seq_num):
                        if seq_to_resend in self.sent_packets_buffer:
                            bytes_to_resend_pkt = self.sent_packets_buffer[seq_to_resend]
                            self.sock.sendto(bytes_to_resend_pkt, self.server_addr)

    def _teardown_connection_client(self):
        try:
            self.last_fin_seq_num = self.next_seq_num
            fin_pkt_obj = DRTPPacket(seq_num=self.last_fin_seq_num, flags=flag_fin)
            self.sock.sendto(fin_pkt_obj.pack(), self.server_addr)
            print("FIN packet is sent")
            self.sock.settimeout(connection_timeout)
            raw_fin_ack, _ = self.sock.recvfrom(packet_size)
            fin_ack_pkt_obj = DRTPPacket.unpack(raw_fin_ack)
            if fin_ack_pkt_obj and (fin_ack_pkt_obj.flags & flag_fin) and (fin_ack_pkt_obj.flags & flag_ack) and (fin_ack_pkt_obj.ack_num == self.last_fin_seq_num):
                print("FIN ACK packet is received")
                print("Connection Closes")
                return True
            else:
                print("Connection Closes (FIN-ACK not received or invalid)")
                return False
        except socket.timeout:
            print("Connection Closes (Timeout waiting for FIN-ACK)")
            return False

def check_port_arg(port_value_str):
    try:
        port = int(port_value_str)
        if not (1024 <= port <= 65535):
            raise argparse.ArgumentTypeError(f"Port {port} out of range [1024-65535].")
        return port
    except ValueError:
        raise argparse.ArgumentTypeError(f"Port '{port_value_str}' not a valid integer.")

def main():
    arg_parser = argparse.ArgumentParser(description="DRTP File Transfer Application.")
    mode_selection_group = arg_parser.add_mutually_exclusive_group(required=True)
    mode_selection_group.add_argument("-s", "--server", action="store_true", help="Server mode.")
    mode_selection_group.add_argument("-c", "--client", action="store_true", help="Client mode.")
    arg_parser.add_argument("-i", "--ip", type=str, help="IP address")
    arg_parser.add_argument("-p", "--port", type=check_port_arg, default=default_port, help=f"Port number. Default: {default_port}.")
    arg_parser.add_argument("-f", "--file", type=str, metavar="FILENAME", help="File to send (Client only)")
    arg_parser.add_argument("-w", "--window", type=int, default=default_win_size, metavar="SIZE", help=f"Client's sending window size. Default: {default_win_size}.")
    arg_parser.add_argument("-d", "--discard", type=int, metavar="SEQ_NUM", help="Server: seq to discard once for testing.")
    try:
        cli_args = arg_parser.parse_args()
    except SystemExit:
        return
    if cli_args.client:
        if cli_args.ip is None:
            cli_args.ip = "127.0.0.1"
        if not cli_args.file:
            arg_parser.error("-f/--file is required for client mode.")
        if cli_args.window <= 0:
            arg_parser.error("-w/--window must be a positive integer.")
    if cli_args.server:
        if cli_args.ip is None:
            cli_args.ip = "0.0.0.0"
    if cli_args.server:
        drtp_server = DRTPServer(cli_args.ip, cli_args.port, cli_args.discard)
        drtp_server.start()
    elif cli_args.client:
        drtp_client = DRTPClient(cli_args.ip, cli_args.port, cli_args.file, cli_args.window)
        drtp_client.start()

main()
