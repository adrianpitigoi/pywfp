"""
Contains the classes to build a WFP filter from Windivert-style conditions.
Also defines a mapping from many Windivert field names to WFP condition keys.
"""

from typing import List, Union
import uuid
import ctypes
import socket
import struct
from win32more import Guid
from win32more.Windows.Win32.NetworkManagement.WindowsFilteringPlatform import (
    FWPM_FILTER0,
    FWPM_FILTER_CONDITION0,
    FWP_ACTION_BLOCK,
    FWPM_FILTER_FLAG_NONE,
    FWP_MATCH_EQUAL,
    FWPM_CONDITION_IP_REMOTE_ADDRESS,
    FWPM_CONDITION_IP_REMOTE_PORT,
    FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_LOCAL_ADDRESS,
    FWPM_CONDITION_IP_LOCAL_PORT,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWP_ACTION_PERMIT,
)
from win32more.Windows.Win32.NetworkManagement.WindowsFilteringPlatform import (
    FWP_UINT64,
    FWP_UINT32,
    FWP_UINT16,
    FWP_UINT8,
    FWP_RANGE_TYPE,
    FWP_MATCH_RANGE,
    FWP_RANGE0,
)
import logging

# Create a logger specific to this module
logger = logging.getLogger(__name__)


class WfpCondition:
    def __init__(self, field_key, value, value_type, match_type=FWP_MATCH_EQUAL):
        logger.debug(f"Creating WfpCondition: field={field_key}, value={value}, type={value_type}")
        self.field_key = field_key
        self.value = value
        self.value_type = value_type
        self.match_type = match_type
        self._range_val_ref = None  # For holding onto temporary range memory

    def to_fwpm_filter_condition(self):
        logger.debug(f"Converting condition to FWPM_FILTER_CONDITION0: {self.field_key}")
        cond = FWPM_FILTER_CONDITION0()
        cond.fieldKey = self.field_key
        cond.matchType = self.match_type

        if self.match_type == FWP_MATCH_RANGE:
            cond.conditionValue.type = FWP_RANGE_TYPE
            range_val = FWP_RANGE0()
            low_val, high_val = self.value

            # Set up the low-range value
            range_val.valueLow.type = self.value_type
            if self.value_type == FWP_UINT32:
                range_val.valueLow.uint32 = low_val
            elif self.value_type == FWP_UINT16:
                range_val.valueLow.uint16 = low_val
            elif self.value_type == FWP_UINT8:
                range_val.valueLow.uint8 = low_val
            else:
                raise ValueError("Unsupported value type for low range")

            # Set up the high-range value
            range_val.valueHigh.type = self.value_type
            if self.value_type == FWP_UINT32:
                range_val.valueHigh.uint32 = high_val
            elif self.value_type == FWP_UINT16:
                range_val.valueHigh.uint16 = high_val
            elif self.value_type == FWP_UINT8:
                range_val.valueHigh.uint8 = high_val
            else:
                raise ValueError("Unsupported value type for high range")

            # Allocate and store the pointer:
            ptr = ctypes.pointer(range_val)
            cond.conditionValue.rangeValue = ptr
            # Retain a reference to ensure that 'range_val' remains alive
            self._range_val_ref = ptr
        else:
            cond.conditionValue.type = self.value_type
            if self.value_type == FWP_UINT16:
                cond.conditionValue.uint16 = self.value
            elif self.value_type == FWP_UINT8:
                cond.conditionValue.uint8 = self.value
            elif self.value_type == FWP_UINT32:
                cond.conditionValue.uint32 = self.value
            else:
                raise ValueError("Unsupported value type")
        return cond


class WfpFilter:
    def __init__(self, name, description, layer, sublayer, action=FWP_ACTION_BLOCK):
        logger.debug(f"Creating WfpFilter: name={name}, layer={layer}")
        self.name = name
        self.description = description
        self.layer = layer
        self.sublayer = sublayer
        self.action = FWP_ACTION_PERMIT if action == "allow" else FWP_ACTION_BLOCK
        self.filterKey = uuid.uuid4()
        self.conditions: List[WfpCondition] = []
        self.weight = 0  # FWP_EMPTY

    def add_condition(self, condition: WfpCondition):
        logger.debug(f"Adding condition to filter: {condition.field_key}")
        self.conditions.append(condition)

    def to_fwpm_filter(self, weight):
        logger.debug(f"Converting WfpFilter to FWPM_FILTER0: {self.name}")
        fw_filter = FWPM_FILTER0()
        fw_filter.filterKey = Guid(str(self.filterKey))
        fw_filter.displayData.name = self.name
        fw_filter.displayData.description = self.description
        fw_filter.flags = FWPM_FILTER_FLAG_NONE
        fw_filter.layerKey = self.layer
        fw_filter.subLayerKey = self.sublayer
        fw_filter.action.type = self.action
        fw_filter.weight.type = FWP_UINT64
        fw_filter.weight.uint64 = ctypes.pointer(ctypes.c_ulonglong(weight))
        fw_filter.numFilterConditions = len(self.conditions)
        ConditionsArrayType = FWPM_FILTER_CONDITION0 * len(self.conditions)
        conditions_array = ConditionsArrayType()
        for i, cond in enumerate(self.conditions):
            conditions_array[i] = cond.to_fwpm_filter_condition()
        fw_filter.filterCondition = ctypes.cast(conditions_array, ctypes.POINTER(FWPM_FILTER_CONDITION0))
        return fw_filter


def ip_value_to_uint32(ip_value: str) -> Union[int, tuple[int, int]]:
    """Convert IP value to integer or tuple of integers if it's a range"""
    if "-" in ip_value:
        # Handle as range
        start_ip, end_ip = ip_value.split("-")
        start_int = struct.unpack("!I", socket.inet_aton(start_ip.strip()))[0]
        end_int = struct.unpack("!I", socket.inet_aton(end_ip.strip()))[0]
        return (start_int, end_int)
    else:
        # Handle as single IP
        return struct.unpack("!I", socket.inet_aton(ip_value))[0]


# Mapping dictionary:
# Each key is a lower-case Windivert field name.
# The tuple is (WFP condition key, expected value type, transformation function)
# Transformation functions convert the string value to the appropriate Python type.
WINDIVERT_TO_WFP_MAPPING = {
    "outbound": (FWPM_LAYER_ALE_AUTH_CONNECT_V4, None, lambda v: None),
    "inbound": (FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, None, lambda v: None),
    "tcp": (FWPM_CONDITION_IP_PROTOCOL, FWP_UINT8, lambda v: 6),
    "udp": (FWPM_CONDITION_IP_PROTOCOL, FWP_UINT8, lambda v: 17),
    "icmp": (FWPM_CONDITION_IP_PROTOCOL, FWP_UINT8, lambda v: 1),
    "icmpv6": (FWPM_CONDITION_IP_PROTOCOL, FWP_UINT8, lambda v: 58),
    "ip.protocol": (FWPM_CONDITION_IP_PROTOCOL, FWP_UINT8, lambda v: int(v, 0)),
    "tcp.srcport": (FWPM_CONDITION_IP_LOCAL_PORT, FWP_UINT16, int),
    "tcp.dstport": (FWPM_CONDITION_IP_REMOTE_PORT, FWP_UINT16, int),
    "udp.srcport": (FWPM_CONDITION_IP_LOCAL_PORT, FWP_UINT16, int),
    "udp.dstport": (FWPM_CONDITION_IP_REMOTE_PORT, FWP_UINT16, int),
    "localaddr": (
        FWPM_CONDITION_IP_LOCAL_ADDRESS,
        FWP_UINT32,
        ip_value_to_uint32,
    ),
    "remoteaddr": (
        FWPM_CONDITION_IP_REMOTE_ADDRESS,
        FWP_UINT32,
        ip_value_to_uint32,
    ),
}
