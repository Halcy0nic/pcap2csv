import pyshark
import csv
import argparse
from collections import OrderedDict

def extract_fields(packet):
    """Extract all fields from a packet."""
    fields = OrderedDict()
    
    # Extract layer names
    layer_names = [layer.layer_name for layer in packet.layers]
    fields['layers'] = ':'.join(layer_names)
    
    # Extract fields from each layer
    for layer in packet.layers:
        for field_name in layer.field_names:
            try:
                field_value = getattr(layer, field_name)
                fields[f"{layer.layer_name}.{field_name}"] = field_value
            except AttributeError:
                # Skip fields that can't be accessed
                pass
    
    return fields

def pcap_to_csv(input_file, output_file):
    """Convert PCAP file to CSV."""
    # Open the PCAP file
    capture = pyshark.FileCapture(input_file)
    
    all_fields = set()
    packets_data = []

    # First pass: collect all possible fields
    for packet_number, packet in enumerate(capture, start=1):
        fields = extract_fields(packet)
        all_fields.update(fields.keys())
        packets_data.append(fields)
        
        if packet_number % 100 == 0:
            print(f"Processed {packet_number} packets (first pass)")

    # Sort the fields to ensure consistent order
    fieldnames = sorted(list(all_fields))

    # Write to CSV
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for packet_number, packet_fields in enumerate(packets_data, start=1):
            # Fill in missing fields with empty strings
            row = {field: packet_fields.get(field, '') for field in fieldnames}
            writer.writerow(row)
            
            if packet_number % 100 == 0:
                print(f"Wrote {packet_number} packets to CSV")

    print(f"Conversion complete. Output saved to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert PCAP to CSV")
    parser.add_argument("input", help="Input PCAP file")
    parser.add_argument("output", help="Output CSV file")
    args = parser.parse_args()

    pcap_to_csv(args.input, args.output)

