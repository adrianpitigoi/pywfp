# PyWFP

PyWFP is a Python interface for working with Windows Filtering Platform (WFP), allowing creation of network traffic filters using a similar Windivert-style syntax.

> **Note:** PyWFP requires administrator privileges to run. Running without admin rights will result in a `WFPError` with code `0x00000005` (Access Denied).

## Installation

```bash
pip install pywfp
```

## Usage

```python
from pywfp import PyWFP
from pprint import pprint


def main():
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
```

## Supported Filters

PyWFP supports a variety of filter conditions that can be combined using logical AND operations. Here are the supported filter types:

### Basic Filter Syntax
```python
"outbound and tcp and remoteaddr == 192.168.1.3-192.168.1.4 and tcp.dstport == 8123 and action == allow"
```

### Supported Conditions
| Field            | Description                                      | Example Values                     |
|------------------|--------------------------------------------------|------------------------------------|
| inbound/outbound | Direction of traffic                            | `inbound`, `outbound`              |
| tcp/udp/icmp     | Protocol type                                   | `tcp`, `udp`, `icmp`               |
| remoteaddr       | Remote IP address (supports ranges)            | `192.168.1.1`, `10.0.0.1-10.0.0.255` |
| localaddr        | Local IP address (supports ranges)             | `127.0.0.1`, `192.168.1.1-192.168.1.255` |
| tcp.dstport      | TCP destination port                            | `80`, `443`                        |
| tcp.srcport      | TCP source port                                 | `5000`, `8080`                     |
| udp.dstport      | UDP destination port                            | `53`, `123`                        |
| udp.srcport      | UDP source port                                 | `5000`, `8080`                     |
| action           | Filter action (allow/block)                     | `allow`, `block`                   |

### IP Address Ranges
You can specify IP ranges using hyphen notation:
```python
"remoteaddr == 192.168.1.1-192.168.1.255"
```

### Multiple Conditions
Combine conditions using AND:
```python
"outbound and tcp and remoteaddr == 192.168.1.1 and tcp.dstport == 80"
```

## Filter Management
```python
# You can set the weight of the filter to determine its priority. If weight is not specified, the highest priority will be given.
pywfp.add_filter("inbound and udp", filter_name="Block UDP", weight=500)

# List all filters
for filter in pywfp.list_filters():
    print(filter["name"])
)
# Maybe more to be added here
```