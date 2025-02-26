import pandas as pd

def load_logs(file_path):
    """
    Load and parse security log files.
    Supports space-separated and CSV log formats.
    """
    try:
        # Try loading as CSV
        df = pd.read_csv(file_path)
        
        # If only one column exists, it means parsing failed
        if df.shape[1] == 1:
            raise ValueError("Incorrect format detected, trying space-separated parsing...")

    except:
        # If CSV fails, try space-separated format
        df = pd.read_csv(file_path, delimiter=r'\s+', header=None, 
                         names=['timestamp', 'src_ip', 'dest_ip', 'protocol', 'status'],
                         engine='python')

    print("✅ Log Data Loaded Successfully:")
    print(df.head())  # Display first few rows
    return df

# Test the function
if __name__ == "__main__":
    logs = load_logs("logs/sample_log.log")
