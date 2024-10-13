from scapy.all import rdpcap, UDP
import matplotlib.pyplot as plt
from collections import defaultdict
import struct
from tqdm import tqdm
import logging
import numpy as np
from matplotlib.widgets import Button

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def is_rtp_packet(packet):
    if UDP in packet and len(packet[UDP].payload) >= 12:
        payload = bytes(packet[UDP].payload)
        version = (payload[0] >> 6) & 0x03
        payload_type = payload[1] & 0x7F
        return version == 2 and (payload_type == 101)  # RTP version should be 2 and payload type 101
    return False

def analyze_rtp_packets(pcap_file):
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        logging.error(f"Error reading pcap file: {e}")
        return {}

    frame_data = defaultdict(list)
    current_frame_start = defaultdict(float)
    current_frame_size = defaultdict(int)

    for packet in tqdm(packets, desc="Analyzing packets", unit="packet"):
        try:
            if is_rtp_packet(packet):
                payload = bytes(packet[UDP].payload)
                
                timestamp = float(packet.time)
                ssrc = struct.unpack('!I', payload[8:12])[0]
                marker = (payload[1] >> 7) & 0x01
                packet_size = len(packet[UDP].payload)

                if not current_frame_start[ssrc]:
                    current_frame_start[ssrc] = timestamp

                current_frame_size[ssrc] += packet_size

                if marker == 1:
                    frame_data[ssrc].append((current_frame_start[ssrc], current_frame_size[ssrc]))
                    current_frame_start[ssrc] = 0
                    current_frame_size[ssrc] = 0

        except Exception as e:
            logging.warning(f"Error processing packet: {e}")
            continue

    return frame_data

def plot_frame_capture_times(frame_data):
    if not frame_data:
        logging.error("No frame data to plot.")
        return

    fig, ax = plt.subplots(figsize=(15, 10))
    colors = plt.cm.rainbow(np.linspace(0, 1, len(frame_data)))

    for (ssrc, frames), color in zip(frame_data.items(), colors):
        times, sizes = zip(*frames)
        ax.scatter(times, sizes, c=[color], label=f'SSRC {ssrc}', alpha=0.6)

    ax.set_xlabel('Capture Time (seconds)')
    ax.set_ylabel('Frame Size (bytes)')
    ax.set_title('Video Frame Capture Times and Sizes')
    ax.legend()
    ax.grid(True)

    # Store the original view limits
    original_xlim = ax.get_xlim()
    original_ylim = ax.get_ylim()

    # Add a reset button
    reset_ax = plt.axes([0.8, 0.02, 0.1, 0.04])
    reset_button = Button(reset_ax, 'Reset View')

    def reset_view(event):
        ax.set_xlim(original_xlim)
        ax.set_ylim(original_ylim)
        plt.draw()

    reset_button.on_clicked(reset_view)

    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    pcap_file = "20mbps_pacing_endure.pcap"
    logging.info("Starting RTP packet analysis...")
    frame_data = analyze_rtp_packets(pcap_file)
    if frame_data:
        logging.info("Analysis complete. Plotting results...")
        plot_frame_capture_times(frame_data)
        logging.info("Plot displayed. Analysis finished.")
    else:
        logging.error("Analysis failed or no data to plot.")