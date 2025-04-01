import re
from datetime import datetime
import json
import os

# Function to parse a timestamp from a log line
def parse_timestamp(line):
    match = re.search(r"\[(\d{2}:\d{2}:\d{2}\.\d{3})\]", line)
    if match:
        return datetime.strptime(match.group(1), "%H:%M:%S.%f")
    return None

# Function to process log files for varbloom counter extraction
def process_varbloom_log_file(file_path):
    results = []
    earliest_timestamp = None  # Track the earliest timestamp
    current_register = 2  # Start with register 0
    curr_reg_bloom_0_size = 0
    curr_reg_bloom_1_size = 0
    last_line_was_reset = False
    with open(file_path, "r") as file:
        lines = file.readlines()
        for i in range(len(lines)):
            # Match the first register update
            match_reg_0 = re.search(
                r"\[(\d{2}:\d{2}:\d{2}\.\d{3})\].*Wrote register 'SwitchIngress\.reg_bloom_0_size'.*value (\d+)", 
                lines[i]
            )
            if match_reg_0:
                last_line_was_reset = False
                timestamp = datetime.strptime(match_reg_0.group(1), "%H:%M:%S.%f")
                if earliest_timestamp is None:
                    earliest_timestamp = timestamp  # Set the earliest timestamp
                reg_bloom_0_size = int(match_reg_0.group(2))
                
                abs_timestamp = int((timestamp - earliest_timestamp).total_seconds() * 1e9)
                
                # Append the tuple (absolute timestamp, reg_bloom_0_size, reg_bloom_1_size)
                results.append((abs_timestamp, reg_bloom_0_size, curr_reg_bloom_1_size))
                curr_reg_bloom_0_size = reg_bloom_0_size
                
            match_reg_1 = re.search(
                r"\[(\d{2}:\d{2}:\d{2}\.\d{3})\].*Wrote register 'SwitchIngress\.reg_bloom_1_size'.*value (\d+)", 
                lines[i]
            )
            if match_reg_1:
                last_line_was_reset = False
                timestamp = datetime.strptime(match_reg_1.group(1), "%H:%M:%S.%f")
                if earliest_timestamp is None:
                    earliest_timestamp = timestamp 
                reg_bloom_1_size = int(match_reg_1.group(2))
                
                # Convert timestamps to nanoseconds from the earliest timestamp
                # abs_timestamp_0 = int((timestamp_0 - earliest_timestamp).total_seconds() * 1e9)
                abs_timestamp = int((timestamp - earliest_timestamp).total_seconds() * 1e9)
                
                # Append the tuple (absolute timestamp, reg_bloom_0_size, reg_bloom_1_size)
                results.append((abs_timestamp, curr_reg_bloom_0_size, reg_bloom_1_size))
                curr_reg_bloom_1_size = reg_bloom_1_size

            # Match bm_register_reset events
            match_reset = re.search(
                r"\[(\d{2}:\d{2}:\d{2}\.\d{3})\].*bm_register_reset", 
                lines[i]
            )
            if match_reset:
                if last_line_was_reset:
                    timestamp_reset = datetime.strptime(match_reset.group(1), "%H:%M:%S.%f")
                    if earliest_timestamp is None:
                        earliest_timestamp = timestamp_reset  # Set the earliest timestamp
                    
                    # Convert timestamp to nanoseconds from the earliest timestamp
                    abs_timestamp_reset = int((timestamp_reset - earliest_timestamp).total_seconds() * 1e9)
                    
                    # Simulate resetting the current register
                    if current_register == 0 or current_register == 1:
                        curr_reg_bloom_0_size = 0
                    else:
                        curr_reg_bloom_1_size = 0
                        
                    results.append((abs_timestamp_reset, curr_reg_bloom_0_size, curr_reg_bloom_1_size))  # Reset reg_bloom_0_size

                else:
                    last_line_was_reset = True
                current_register = (current_register + 1) % 4

    return results

# Function to process log files for cuckoo filter extraction
def process_cuckoo_log_file(file_path):
    results = []
    earliest_timestamp = None  # Track the earliest timestamp
    accumulated_sum = 0  # Start with 0 elements in the cuckoo filter
    line_count = 0  # Track the number of lines processed
    add_matches = 0  # Count matches for insert success
    remove_matches = 0  # Count matches for delete success

    with open(file_path, "r") as file:
        lines = file.readlines()
        for line in lines:
            line_count += 1

            # Match +1 case
            match_add = re.search(
                r"\[(\d{2}:\d{2}:\d{2}\.\d{3})\].*meta\.cuckoo_insert_success = 1", 
                line
            )
            if match_add:
                add_matches += 1
                timestamp_add = datetime.strptime(match_add.group(1), "%H:%M:%S.%f")
                if earliest_timestamp is None:
                    earliest_timestamp = timestamp_add  # Set the earliest timestamp
                accumulated_sum += 1
                abs_timestamp_add = int((timestamp_add - earliest_timestamp).total_seconds() * 1e9)
                results.append((abs_timestamp_add, accumulated_sum))
                continue

            # Match -1 case
            match_remove = re.search(
                r"\[(\d{2}:\d{2}:\d{2}\.\d{3})\].*meta\.cuckoo_delete_success = 1", 
                line
            )
            if match_remove:
                remove_matches += 1
                timestamp_remove = datetime.strptime(match_remove.group(1), "%H:%M:%S.%f")
                if earliest_timestamp is None:
                    earliest_timestamp = timestamp_remove  # Set the earliest timestamp
                accumulated_sum -= 1
                abs_timestamp_remove = int((timestamp_remove - earliest_timestamp).total_seconds() * 1e9)
                results.append((abs_timestamp_remove, accumulated_sum))

            # Debug: Print progress every 1 million lines
            if line_count % 1_000_000 == 0:
                relative_start_time = (
                    (timestamp_add - earliest_timestamp).total_seconds()
                    if earliest_timestamp and match_add
                    else 0
                )
                print(f"Processed {line_count} lines... Matches: +1={add_matches}, -1={remove_matches}, Relative Start Time: {relative_start_time:.3f}s")

        # Debug: Print total lines processed and matches
        print(f"Finished processing {line_count} lines. Total Matches: +1={add_matches}, -1={remove_matches}")
    return results

# Function to save results to a JSON file
def save_results_to_json(data, filename):
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results/")
    with open(f"{output_dir}{filename}", "w") as json_file:
        json.dump(data, json_file, indent=4, default=str)

# Main function to process all log files
def main():
    
    # Get the base directory of the current script
    base_dir = os.path.dirname(os.path.abspath(__file__))

    # Define relative paths to the log files
    relative_log_files = [
        "results/filter_elements_varbloom_results.txt"
    ]

    # Convert relative paths to absolute paths
    varbloom_log_files = [os.path.join(base_dir, rel_path) for rel_path in relative_log_files]
    # Process varbloom results
    varbloom_results = []
    for log_file in varbloom_log_files:
        varbloom_results.extend(process_varbloom_log_file(log_file))
    
    # Sort varbloom results by timestamp
    varbloom_results.sort(key=lambda x: x[0])
    
    # Format varbloom results for JSON
    formatted_varbloom_results = [
        {
            "timestamp_ns": timestamp,  # Update key to reflect nanoseconds
            "reg_bloom_0_size": reg_bloom_0_size,
            "reg_bloom_1_size": reg_bloom_1_size
        }
        for timestamp, reg_bloom_0_size, reg_bloom_1_size in varbloom_results
    ]
    # print(formatted_varbloom_results)
    # Save varbloom results to JSON
    save_results_to_json(formatted_varbloom_results, "fel-varbloom_results.json")

    # Define relative paths to the cuckoo log files
    relative_cuckoo_log_files = [
        "results/filter_elements_cuckoo_results.txt"
    ]

    # Convert relative paths to absolute paths
    cuckoo_log_files = [os.path.join(base_dir, rel_path) for rel_path in relative_cuckoo_log_files]
    # Process cuckoo filter results
    cuckoo_results = []
    for log_file in cuckoo_log_files:
        cuckoo_results.extend(process_cuckoo_log_file(log_file))
    
    # Sort cuckoo results by timestamp
    cuckoo_results.sort(key=lambda x: x[0])
    
    # Format cuckoo results for JSON
    formatted_cuckoo_results = [
        {
            "timestamp_ns": timestamp,  # Timestamp in nanoseconds
            "n_elements": accumulated_sum
        }
        for timestamp, accumulated_sum in cuckoo_results
    ]
    # Save cuckoo results to JSON
    save_results_to_json(formatted_cuckoo_results, "fel-cuckoo_results.json")

if __name__ == "__main__":
    main()
