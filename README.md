# PCAP to CSV Converter

## Description

This tool converts PCAP (Packet Capture) files to CSV (Comma-Separated Values) format, allowing for easy analysis of network traffic data in AI applications or data analysis tools. It extracts all available fields from each packet in the PCAP file and organizes them into a comprehensive CSV output.

## Features

- Converts PCAP files to CSV format
- Extracts all available fields from each packet
- Maintains consistent field ordering in the output
- Provides progress updates during conversion
- Easy-to-use command-line interface

## Requirements

- Python 3.6+
- pyshark
- tshark (Wireshark command-line interface)

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/Halcy0nic/pcap2csv.git
   cd pcap2csv
   ```

2. Install the required Python packages:
   ```
   pip install pyshark
   ```

3. Ensure tshark is installed on your system. It comes with Wireshark, or you can install it separately.

## Usage

Run the script from the command line with the following syntax:

```
python pcap_to_csv.py <input_pcap_file> <output_csv_file>
```

Example:
```
python pcap_to_csv.py capture.pcap output.csv
```

## Output

The script will create a CSV file with the following characteristics:

- Each row represents a packet from the PCAP file
- Columns include all fields extracted from the packets
- The first column, 'layers', lists the protocol layers present in each packet
- Subsequent columns are named in the format `layer_name.field_name`

## Limitations

- Large PCAP files may require significant memory and processing time
- The tool attempts to extract all fields, which may result in a very wide CSV file

## Contributing

Contributions, issues, and feature requests are welcome.

## License

[MIT](https://choosealicense.com/licenses/mit/)
