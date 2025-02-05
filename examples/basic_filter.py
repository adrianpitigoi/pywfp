"""
Example usage of PyWFP package
"""

from pywfp import PyWFP
from pprint import pprint
import ctypes
import sys


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def main():
    # Check for admin privileges
    if not is_admin():
        print("This script requires administrator privileges.")
        print("Please run this script as administrator.")
        sys.exit(1)

    # Create PyWFP instance
    pywfp = PyWFP()

    # Example filter string
    filter_string = (
        "outbound and tcp and remoteaddr == 192.168.1.3-192.168.1.4 " "and tcp.dstport == 8123 and action == block"
    )

    try:
        # Use context manager to handle WFP engine session
        with pywfp.session():
            # Add the filter
            filter_name = "PyWFP Block Filter"
            pywfp.add_filter(filter_string, filter_name=filter_name, weight=1000)

            # List existing filters
            filters = pywfp.list_filters()
            print(f"Found {len(filters)} WFP filters")

            # Find our specific filter
            if filter := pywfp.get_filter(filter_name):
                print(f"Found filter: {filter}")
                pprint(filter)

            # Keep the filter active until interrupted
            print("Press Ctrl+C to exit and remove the filter")
            try:
                while True:
                    input()
            except KeyboardInterrupt:
                print("Received Ctrl+C, cleaning up")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
