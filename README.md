# PyWFP

PyWFP is a Python interface for working with Windows Filtering Platform (WFP), allowing creation of network traffic filters using a similar Windivert-style syntax.

## Installation

```bash
pip install pywfp
```

## Usage

```python
from pywfp import PyWFP
from pprint import pprint

def main():
    pywfp = PyWFP()
    filter_string = (
        "outbound and tcp and remoteaddr == 192.168.1.3-192.168.1.4 "
        "and tcp.dstport == 8123 and action == allow"
    )

    with pywfp.session():  # Context manager for session handling
        pywfp.add_filter(filter_string, filter_name="Example Filter", weight=1000)
        
        # List and inspect filters
        if filter := pywfp.get_filter("Example Filter"):
            pprint(filter)

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
# You can set the weight of the filter to determine its priority
pywfp.add_filter("inbound and udp", filter_name="Block UDP", weight=500)

# List all filters
for filter in pywfp.list_filters():
    print(filter["name"])
)
# Maybe more to be added here
```