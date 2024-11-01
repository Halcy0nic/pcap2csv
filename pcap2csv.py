import pyshark
import pandas as pd
import csv
import argparse
from collections import OrderedDict

def extract_fields(packet):
    """Extract all fields from a packet."""
    fields = OrderedDict()

    # Sets layers to extract from
    layers = [packet.frame_info]
    layers.extend(packet.layers)

    # Extract fields from each layer
    for layer in layers:
        for field_name in layer.field_names:
            try:
                field_value = getattr(layer, field_name)
                fields[f"{layer.layer_name}.{field_name}"] = field_value
            except AttributeError:
                # Skip fields that can't be accessed
                pass
    
    return fields

def pcap_to_dataframe(input_file):
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
            print(f"Processed {packet_number} packets")

    # Sort the fields to ensure consistent order
    fieldnames = sorted(list(all_fields))

    # Create DataFrame
    df = pd.DataFrame(packets_data)

    # Reorder columns to match fieldnames
    df = df.reindex(columns=fieldnames)

    # Fill NaN values with empty strings
    df = df.fillna('')

    return df;

def remove_duplicate_columns(df):
    # Transpose the DataFrame to make columns into rows
    transposed_df = df.T

    # Drop duplicate rows (which are originally columns in the original DataFrame)
    unique_transposed_df = transposed_df.drop_duplicates()

    # Transpose back to get the DataFrame with duplicate columns removed
    unique_df = unique_transposed_df.T

    print("Removed duplicate fields")
    return unique_df

def dataframe_to_csv(df, output_file):
    """Save DataFrame to CSV file."""
    df.to_csv(output_file, index=False)
    print(f"Conversion complete. Output saved to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert PCAP to CSV")
    parser.add_argument("input", help="Input PCAP file")
    parser.add_argument("output", help="Output CSV file")
    args = parser.parse_args()

    df = pcap_to_dataframe(args.input)
    df = remove_duplicate_columns(df)
    dataframe_to_csv(df, args.output)

