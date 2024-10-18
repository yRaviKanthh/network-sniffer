from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP
import tkinter as tk
from tkinter import scrolledtext, messagebox
import tkinter.font as tkFont
import matplotlib.pyplot as plt
from collections import Counter
import threading
import requests
import json

# List to store captured packets
packets = []
protocol_count = Counter()  # Dictionary to store protocol counts
packet_sizes = []  # List to store packet sizes


# Function to process each packet
def packet_handler(packet):
    packets.append(packet)
    packet_sizes.append(len(packet))  # Capture packet size

    # Count protocol types
    if packet.haslayer(TCP):
        protocol_count['TCP'] += 1
    elif packet.haslayer(UDP):
        protocol_count['UDP'] += 1
    elif packet.haslayer(ICMP):
        protocol_count['ICMP'] += 1
    else:
        protocol_count['Other'] += 1

    # Display packet summary in the text box
    output_text.insert(tk.END, packet.summary() + '\n')

    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        output_text.insert(tk.END, f"Source: {src}, Destination: {dst}\n")

        # Perform GeoIP lookup and display
        geoip_info = geoip_lookup(src)
        if geoip_info:
            output_text.insert(tk.END, f"Source Location: {geoip_info['country']}, {geoip_info['city']}\n")

        geoip_info = geoip_lookup(dst)
        if geoip_info:
            output_text.insert(tk.END, f"Destination Location: {geoip_info['country']}, {geoip_info['city']}\n\n")

    # Automatically scroll to the end of the text area
    output_text.see(tk.END)


# Function to perform GeoIP lookup
def geoip_lookup(ip_address):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        geo_data = response.json()
        if geo_data['status'] == 'success':
            return {'country': geo_data['country'], 'city': geo_data['city']}
        else:
            return None
    except Exception as e:
        return None


# Function to start sniffing packets
def start_sniffing():
    # Clear previous packets
    packets.clear()
    output_text.delete(1.0, tk.END)  # Clear the text area before sniffing

    try:
        count = int(packet_count_entry.get())
        filter_text = filter_entry.get().strip()

        sniff(prn=packet_handler, count=count, filter=filter_text)  # Capture specified packets
        wrpcap("captured_packets.pcap", packets)  # Save captured packets to a file

        messagebox.showinfo("Info",
                            f"Sniffing completed! {count} packets captured. Packets saved to 'captured_packets.pcap'")
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid number of packets to capture.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")


# Function to plot packet size distribution
def plot_packet_size_distribution():
    if packet_sizes:
        plt.figure(figsize=(6, 4))
        plt.hist(packet_sizes, bins=20, color='blue', edgecolor='black')
        plt.title('Packet Size Distribution')
        plt.xlabel('Packet Size (bytes)')
        plt.ylabel('Frequency')
        plt.show()


# Function to plot protocol breakdown
def plot_protocol_breakdown():
    if len(protocol_count) > 0:
        labels, sizes = zip(*protocol_count.items())
        plt.figure(figsize=(5, 5))
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
        plt.title("Protocol Breakdown")
        plt.show()


# Create the main window
window = tk.Tk()
window.title("Innovative Network Sniffer")

# Set the window size (not full screen)
window.geometry("800x600")  # Set the desired window size

# Create a font for the text area
font_style = tkFont.Font(family="Helvetica", size=12)  # Increased font size

# Create a frame for the input fields
frame = tk.Frame(window, bg="#1e1e1e")
frame.pack(padx=20, pady=20, fill=tk.X)

# Create a scrolled text area for displaying packet summaries
output_text = scrolledtext.ScrolledText(window, wrap=tk.WORD, width=100, height=30, font=font_style, bg="#f4f4f4",
                                        fg="#333", insertbackground='black')
output_text.pack(padx=10, pady=(0, 10), fill=tk.BOTH, expand=True)  # Make it responsive

# Packet count entry
packet_count_label = tk.Label(frame, text="Number of Packets to Capture:", font=("Helvetica", 12), bg="#1e1e1e",
                              fg="#ffffff")
packet_count_label.grid(row=0, column=0, sticky="w", padx=5, pady=5)

packet_count_entry = tk.Entry(frame, font=("Helvetica", 12))
packet_count_entry.grid(row=0, column=1, padx=5, pady=5)

# Filter entry
filter_label = tk.Label(frame, text="Packet Filter (e.g., udp, tcp):", font=("Helvetica", 12), bg="#1e1e1e",
                        fg="#ffffff")
filter_label.grid(row=1, column=0, sticky="w", padx=5, pady=5)

filter_entry = tk.Entry(frame, font=("Helvetica", 12))
filter_entry.grid(row=1, column=1, padx=5, pady=5)

# Create a stylish button to start sniffing
start_button = tk.Button(window, text="Start Sniffing", command=start_sniffing, bg="#4CAF50", fg="white",
                         font=("Helvetica", 12), borderwidth=2, relief="flat", padx=20, pady=10)
start_button.pack(side=tk.BOTTOM, pady=20)

# Button to show protocol breakdown
plot_button = tk.Button(window, text="Show Protocol Breakdown", command=plot_protocol_breakdown, bg="#4CAF50", fg="white",
                        font=("Helvetica", 12), borderwidth=2, relief="flat", padx=20, pady=10)
plot_button.pack(side=tk.BOTTOM, pady=10)

# Button to show packet size distribution
size_button = tk.Button(window, text="Show Packet Size Distribution", command=plot_packet_size_distribution, bg="#4CAF50", fg="white",
                        font=("Helvetica", 12), borderwidth=2, relief="flat", padx=20, pady=10)
size_button.pack(side=tk.BOTTOM, pady=10)

# Add a title above the text area
title_label = tk.Label(window, text="Captured Packet Details", font=("Helvetica", 16), bg="#1e1e1e", fg="#ffffff")
title_label.pack(pady=10)

# Run the GUI event loop
window.configure(bg="#1e1e1e")  # Set background color for the main window
window.mainloop()
