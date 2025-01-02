import hashlib
import tkinter as tk
from tkinter import filedialog

def compute_sha256(file_path):
    """Compute  the SHA-256 hash of the file at the given path."""
    hash_sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
    except FileNotFoundError:
        return "Error: File not found."
    except Exception as e:
        return f"An error occurred: {e}"

def main():
    # Initialize Tkinter root
    root = tk.Tk()
    root.withdraw()  # Hide the root window

    # Open file dialog to select a file
    file_path = filedialog.askopenfilename(title="Select a file to compute SHA-256 hash")

    if file_path:
        result = compute_sha256(file_path)
        # Write the result to 'hash.txt'
        try:
            with open('hash.txt', 'w') as output_file:
                output_file.write(f"File selected: {file_path}\n")
                output_file.write(f"SHA-256 hash: {result}\n")
            print("Hash has been written to 'hash.txt'.")
        except Exception as e:
            print(f"An error occurred while writing to 'hash.txt': {e}")
    else:
        print("No file selected.")

if __name__ == "__main__":
    main()
