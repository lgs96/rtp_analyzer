# RTP Packet Analyzer

This project provides a Python script for analyzing RTP (Real-time Transport Protocol) packets from a pcap file. It focuses on extracting video frame information and visualizing the capture times and sizes of frames.

## Features

- Reads and processes RTP packets from a pcap file
- Identifies video frames based on RTP marker bits
- Calculates frame sizes by aggregating packet sizes
- Generates an interactive scatter plot of frame capture times vs. frame sizes
- Supports multiple SSRC streams with color-coding
- Provides zoom, pan, and reset view functionalities for the plot

## Requirements

- Python 3.6+
- scapy
- matplotlib
- tqdm
- numpy

You can install the required packages using pip:

```
pip install scapy matplotlib tqdm numpy
```

## Usage

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/rtp-packet-analyzer.git
   cd rtp-packet-analyzer
   ```

2. Place your pcap file in the same directory as the script, or update the `pcap_file` variable in the script with the path to your pcap file.

3. Run the script:
   ```
   python offline_rtp_analyzer.py
   ```

4. The script will process the pcap file and display an interactive scatter plot.

## Interacting with the Plot

- Use the navigation toolbar at the bottom of the plot window for zooming and panning.
- Click the 'Reset View' button to return to the original view.
- Hover over points to see exact values.
- Use the legend to toggle visibility of different SSRC streams.

## Understanding the Output

- Each point on the scatter plot represents a video frame.
- The x-axis shows the capture time of the first packet of each frame.
- The y-axis shows the total size of each frame in bytes.
- Different colors represent different SSRC streams.

## Limitations

- The script assumes RTP packets with payload type 101. Modify the `is_rtp_packet` function if your packets use a different payload type.
- Large pcap files may require significant processing time and memory.

## Contributing

Contributions to improve the script or add new features are welcome. Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
