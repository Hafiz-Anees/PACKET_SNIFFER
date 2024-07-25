from PyQt5 import QtWidgets, QtCore, QtGui
from scapy.all import sniff, Packet
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.tls.record import TLS
import sys
import psutil

# displaying traffic sniffer window

class SnifferWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.sniffer_thread = SnifferThread()
        self.sniffer_thread.packet_received.connect(self.display_packet)
        self.sniffer_thread.sniffing_stopped.connect(self.display_total_packets)
        self.captured_packets = []

    def initUI(self):
        self.layout = QtWidgets.QVBoxLayout()

        # Create table for packets
        self.packet_table = QtWidgets.QTableWidget()
        self.packet_table.setColumnCount(6)
        self.packet_table.setHorizontalHeaderLabels(["Source MAC", "Destination MAC", "Source IP", "Destination IP", "Protocol", "Length"])

        self.start_button = QtWidgets.QPushButton("START SNIFFING")
        self.stop_button = QtWidgets.QPushButton("STOP SNIFFING")
        self.view_headers_button = QtWidgets.QPushButton("HEADER DETAIL")
        self.view_headers_button.setEnabled(False)

        # Search bar for filtering protocols
        self.filter_input = QtWidgets.QLineEdit()
        self.filter_input.setPlaceholderText("FILTER ANY PROTOCOL")
        self.filter_input.textChanged.connect(self.filter_packets)

        self.layout.addWidget(self.packet_table)
        self.layout.addWidget(self.filter_input)
        self.layout.addWidget(self.start_button)
        self.layout.addWidget(self.stop_button)
        self.layout.addWidget(self.view_headers_button)

        self.setLayout(self.layout)

        self.start_button.clicked.connect(self.start_sniffing)
        self.stop_button.clicked.connect(self.stop_sniffing)
        self.view_headers_button.clicked.connect(self.view_headers)

        self.setWindowTitle("PACKET SNIFFER TOOLS (CAPITAL UNIVERSITY OF SCIENCE AND TECHNOLOGY)")
        self.setGeometry(300, 300, 900, 400)

    def start_sniffing(self):
        self.packet_table.setRowCount(0)
        self.captured_packets = []
        self.view_headers_button.setEnabled(False)
        self.sniffer_thread.start()

    def stop_sniffing(self):
        self.sniffer_thread.sniffing = False
        self.view_headers_button.setEnabled(True)

    @QtCore.pyqtSlot(tuple)
    def display_packet(self, packet_info):
        row_position = self.packet_table.rowCount()
        self.packet_table.insertRow(row_position)
        for col, info in enumerate(packet_info[:-2]):
            item = QtWidgets.QTableWidgetItem(info)
            self.packet_table.setItem(row_position, col, item)
            protocol = packet_info[4]
            # if protocol in ["TCP", "UDP", "ARP", "ICMP"]:
            #     item.setBackground(QtGui.QColor(160,200,230))

            if protocol == "TCP":
                item.setBackground(QtGui.QColor(160,200,230))
            elif protocol == "UDP":
                item.setBackground(QtGui.QColor(200,160,200))
            elif protocol == "ARP":
                item.setBackground(QtGui.QColor(255,255,255))
            elif protocol == "ICMP":
                item.setBackground(QtGui.QColor(255,255,255))
            elif protocol == "HTTP":
                item.setBackground(QtGui.QColor(0, 255, 0))
            elif protocol == "HTTPS":
                item.setBackground(QtGui.QColor(0, 0,255))
            elif protocol == "FTP":
                item.setBackground(QtGui.QColor(255, 255, 0))
        self.packet_table.setItem(row_position, 5, QtWidgets.QTableWidgetItem(packet_info[-2]))
        self.captured_packets.append(packet_info)

    @QtCore.pyqtSlot(int)
    def display_total_packets(self, total_packets):
        QtWidgets.QMessageBox.information(self, "Sniffing Stopped", f"Total Packets: {total_packets}")

    def view_headers(self):
        headers_window = HeadersWindow(self.captured_packets)
        headers_window.exec_()

    def filter_packets(self):
        filter_text = self.filter_input.text().upper()
        for i in range(self.packet_table.rowCount()):
            item = self.packet_table.item(i, 4)  # Protocol column
            self.packet_table.setRowHidden(i, filter_text not in item.text())


# displaying header detail header window 

class HeadersWindow(QtWidgets.QDialog):
    def __init__(self, packets):
        super().__init__()
        self.packets = packets
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Packet Headers")
        self.setGeometry(300, 300, 800, 400)

        self.layout = QtWidgets.QVBoxLayout()

        self.header_table = QtWidgets.QTableWidget()
        self.header_table.setColumnCount(10)
        self.header_table.setHorizontalHeaderLabels(["Protocol", "Source MAC", "Destination MAC", "Source IP", "Destination IP", "Seq Number", "Ack Number", "Length", "Source Port", "Destination Port"])

        self.layout.addWidget(self.header_table)
        self.setLayout(self.layout)

        self.display_headers()

    # header detail
    def display_headers(self):
        for packet_info in self.packets:
            protocol, src_mac, dst_mac, src_ip, dst_ip, seq_num, ack_num, length, src_port, dst_port = packet_info[4], packet_info[0], packet_info[1], packet_info[2], packet_info[3], 'N/A', 'N/A', packet_info[5], 'N/A', 'N/A'

            if protocol == "TCP":
                seq_num = str(packet_info[6][TCP].seq)
                ack_num = str(packet_info[6][TCP].ack)
                src_port = str(packet_info[6][TCP].sport)
                dst_port = str(packet_info[6][TCP].dport)
            elif protocol == "UDP":
                src_port = str(packet_info[6][UDP].sport)
                dst_port = str(packet_info[6][UDP].dport)
            elif protocol == "ARP":
                seq_num = 'N/A'
                ack_num = 'N/A'
            elif protocol == "ICMP":
                seq_num = 'N/A'
                ack_num = 'N/A'

            row_position = self.header_table.rowCount()
            self.header_table.insertRow(row_position)
            for col, info in enumerate([protocol, src_mac, dst_mac, src_ip, dst_ip, seq_num, ack_num, length, src_port, dst_port]):
                item = QtWidgets.QTableWidgetItem(info)
                self.header_table.setItem(row_position, col, item)
                if protocol in ("TCP", "UDP", "ARP", "ICMP"):
                    item.setBackground(QtGui.QColor(255, 255, 255))
                elif protocol == "HTTP":
                    item.setBackground(QtGui.QColor(0, 255, 0))
                elif protocol == "HTTPS":
                    item.setBackground(QtGui.QColor(0, 0, 255))
                elif protocol == "FTP":
                    item.setBackground(QtGui.QColor(255, 255, 0))

# main code to sniffed packets

class SnifferThread(QtCore.QThread):
    packet_received = QtCore.pyqtSignal(tuple)
    sniffing_stopped = QtCore.pyqtSignal(int)

    def __init__(self):
        super().__init__()
        self.sniffing = True
        self.packet_count = 0
        self.interface = self.get_wifi_interface()

    def get_wifi_interface(self):
        interfaces = psutil.net_if_addrs()
        for interface in interfaces:
            if 'wlan' in interface.lower() or 'wi-fi' in interface.lower():  # Adjust according to your OS conventions for wifi interfaces
                return interface
        return None

    def run(self):
        self.sniffing = True
        self.packet_count = 0
        sniff(prn=self.process_packet, iface=self.interface, stop_filter=self.stop_sniffing)
        self.sniffing_stopped.emit(self.packet_count)

    def process_packet(self, packet: Packet):
        self.packet_count += 1
        src_mac, dst_mac, src_ip, dst_ip, proto, length = self.extract_packet_info(packet)
        packet_info = (src_mac, dst_mac, src_ip, dst_ip, proto, str(length), packet)
        self.packet_received.emit(packet_info)

    def extract_packet_info(self, packet: Packet):
        src_mac = dst_mac = src_ip = dst_ip = proto = 'N/A'
        length = len(packet)

        if packet.haslayer(Ether):
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst

        if packet.haslayer('IP'):
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            proto = packet['IP'].proto

        if packet.haslayer(TCP):
            proto = 'TCP'
            if packet.haslayer(HTTPRequest):
                proto = 'HTTP'
            elif packet.haslayer(TLS):
                proto = 'HTTPS'
            elif packet[TCP].sport == 21 or packet[TCP].dport == 21:
                proto = 'FTP-CONTROL'
            elif packet[TCP].sport == 20 or packet[TCP].dport == 20:
                proto = 'FTP-DATA'
        elif packet.haslayer(UDP):
            proto = 'UDP'
        elif packet.haslayer(ARP):
            src_ip = packet['ARP'].psrc
            dst_ip = packet['ARP'].pdst
            proto = 'ARP'
        elif packet.haslayer(ICMP):
            proto = 'ICMP'

        return src_mac, dst_mac, src_ip, dst_ip, proto, length

    def stop_sniffing(self, packet: Packet):
        return not self.sniffing


def main():
    app = QtWidgets.QApplication(sys.argv)
    window = SnifferWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
