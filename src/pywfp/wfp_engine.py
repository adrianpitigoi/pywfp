"""
A helper class for opening the Windows Filtering Platform engine,
starting transactions, adding filters, and closing the engine.
"""

import ctypes
import logging

from win32more.Windows.Win32.Foundation import HANDLE
from win32more.Windows.Win32.NetworkManagement.WindowsFilteringPlatform import (
    FWPM_FILTER0,
    FWPM_FILTER_CONDITION0,
    FWPM_SESSION0,
    FWPM_SESSION_FLAG_DYNAMIC,
    FwpmEngineClose0,
    FwpmEngineOpen0,
    FwpmFilterAdd0,
    FwpmFilterCreateEnumHandle0,
    FwpmFilterDestroyEnumHandle0,
    FwpmFilterEnum0,
    FwpmFreeMemory0,
    FwpmTransactionBegin0,
    FwpmTransactionCommit0,
)
import win32more.Windows.Win32.NetworkManagement.WindowsFilteringPlatform as wfp

from .wfp_filter import WfpFilter


RPC_C_AUTHN_WINNT = 10


logger = logging.getLogger(__name__)


# Helper function to get the match type name from win32more enums
def get_match_type_name(value: int) -> str:
    """
    Iterates over attributes in the wfp module looking for ones with the prefix "FWP_MATCH_"
    whose value matches the provided `value`. Returns the enum name if found or "UNKNOWN".
    """
    for attr in dir(wfp):
        if attr.startswith("FWP_MATCH_"):
            try:
                if getattr(wfp, attr) == value:
                    return attr
            except Exception:
                continue
    return "UNKNOWN"


# Helper function to get the condition value type name from win32more enums
def get_condition_value_type_name(value: int) -> str:
    """
    Iterates over a fixed list of expected condition value type names defined in win32more.
    Returns the matching enum name or "UNKNOWN" if not found.
    """
    expected_types = [
        "FWP_EMPTY",
        "FWP_UINT8",
        "FWP_UINT16",
        "FWP_UINT32",
        "FWP_UINT64",
        "FWP_INT8",
        "FWP_INT16",
        "FWP_INT32",
        "FWP_INT64",
        "FWP_FLOAT",
        "FWP_DOUBLE",
        "FWP_BYTE_ARRAY16_TYPE",
        "FWP_BYTE_BLOB_TYPE",
        "FWP_SID",
        "FWP_SECURITY_DESCRIPTOR_TYPE",
        "FWP_TOKEN_INFORMATION_TYPE",
        "FWP_TOKEN_ACCESS_INFORMATION_TYPE",
        "FWP_UNICODE_STRING_TYPE",
        "FWP_BYTE_ARRAY6_TYPE",
        "FWP_V4_ADDR_MASK",
        "FWP_V6_ADDR_MASK",
        "FWP_RANGE_TYPE",
        "FWP_DATA_TYPE_MAX",
    ]
    for type_name in expected_types:
        try:
            if getattr(wfp, type_name) == value:
                return type_name
        except Exception:
            continue
    return "UNKNOWN"


class WfpEngine:
    def __init__(self):
        logger.debug("Initializing WfpEngine")
        self.engine_handle = HANDLE()
        self.PAGE_SIZE = 100

    def open(self, session_name: str = "DynamicSession", flags: int = FWPM_SESSION_FLAG_DYNAMIC):
        logger.info("Opening WFP engine")
        session = FWPM_SESSION0()
        session.displayData.name = session_name
        session.flags = flags
        hr = FwpmEngineOpen0(
            None,
            RPC_C_AUTHN_WINNT,
            None,
            ctypes.pointer(session),
            ctypes.byref(self.engine_handle),
        )
        if hr != 0:
            logger.error(f"Failed to open WFP engine: 0x{hr:08x}")
            raise Exception(f"FwpmEngineOpen0 failed: 0x{hr:08x}")
        logger.info("WFP engine opened successfully")

    def close(self):
        logger.info("Closing WFP engine")
        FwpmEngineClose0(self.engine_handle)
        logger.debug("WFP engine closed")

    def add_filter(self, wfp_filter: WfpFilter, filter_name: str, filter_description: str, weight: int):
        """
        Add a new WFP filter.

        Args:
            wfp_filter: The WfpFilter object to add
            filter_name: Name for the filter
            filter_description: Description for the filter
        """
        logger.info("Adding new WFP filter")
        hr = FwpmTransactionBegin0(self.engine_handle, 0)
        if hr != 0:
            logger.error(f"Transaction begin failed: 0x{hr:08x}")
            raise Exception(f"FwpmTransactionBegin0 failed: 0x{hr:08x}")

        if weight is None:
            weight = (2**64) - 1  # Max uint64, highest filter priority
        fw_filter = wfp_filter.to_fwpm_filter(weight)

        # Set the filter name and description
        fw_filter.displayData.name = filter_name
        fw_filter.displayData.description = filter_description

        hr = FwpmFilterAdd0(self.engine_handle, ctypes.pointer(fw_filter), None, None)
        if hr != 0:
            logger.error(f"Filter add failed: 0x{hr:08x}")
            raise Exception(f"FwpmFilterAdd0 failed: 0x{hr:08x}")

        hr = FwpmTransactionCommit0(self.engine_handle)
        if hr != 0:
            logger.error(f"Transaction commit failed: 0x{hr:08x}")
            raise Exception(f"FwpmTransactionCommit0 failed: 0x{hr:08x}")

        logger.info("Filter added successfully")

    def list_filters(self):
        """
        Lists all WFP filters currently installed in the system.
        Returns a list of filter dictionaries.
        """
        enum_handle = HANDLE()
        filters = []

        logger.debug("Creating enum handle...")
        # Create enum handle
        hr = FwpmFilterCreateEnumHandle0(self.engine_handle, None, ctypes.byref(enum_handle))
        if hr != 0:
            raise Exception(f"FwpmFilterCreateEnumHandle0 failed: 0x{hr:08x}")

        try:
            logger.debug("Starting filter enumeration...")
            while True:
                page = self._get_filter_page(enum_handle)
                if not page:  # Empty page means we're done
                    logger.debug("No more filters to enumerate")
                    break
                logger.debug(f"Found {len(page)} filters in this page")
                filters.extend(page)

        finally:
            logger.debug("Destroying enum handle...")
            FwpmFilterDestroyEnumHandle0(self.engine_handle, enum_handle)

        logger.debug(f"Total filters found: {len(filters)}")
        return filters

    def _get_filter_page(self, enum_handle):
        """
        Gets a single page of filters.
        Returns a list of filter dictionaries or None if no more filters.
        """
        num_entries = ctypes.c_uint32()
        entries_ptr = ctypes.POINTER(ctypes.POINTER(FWPM_FILTER0))()

        # Get next batch of filters
        hr = FwpmFilterEnum0(
            self.engine_handle,
            enum_handle,
            self.PAGE_SIZE,
            ctypes.byref(entries_ptr),
            ctypes.byref(num_entries),
        )

        if hr != 0:
            # Check if this is just the end of enumeration
            if hr == 0x80320003:  # FWP_E_NO_MORE_ELEMENTS
                return None
            raise Exception(f"FwpmFilterEnum0 failed: 0x{hr:08x}")

        if num_entries.value == 0:
            return None

        try:
            page = []
            logger.debug(f"Processing {num_entries.value} filters")
            # Access the array of filter pointers
            filters_array = ctypes.cast(
                entries_ptr, ctypes.POINTER(ctypes.POINTER(FWPM_FILTER0) * num_entries.value)
            ).contents

            for i in range(num_entries.value):
                try:
                    filter_info = filters_array[i].contents
                    filter_dict = {
                        "filter_id": filter_info.filterId,
                        "flags": filter_info.flags,
                    }

                    # Process display data
                    if hasattr(filter_info, "displayData") and filter_info.displayData:
                        filter_dict["name"] = filter_info.displayData.name or ""
                        filter_dict["description"] = filter_info.displayData.description or ""
                    else:
                        filter_dict["name"] = ""
                        filter_dict["description"] = ""

                    # Process layer key
                    filter_dict["layer_key"] = str(filter_info.layerKey) if hasattr(filter_info, "layerKey") else ""

                    # Process weight
                    filter_dict["weight"] = None
                    if hasattr(filter_info, "effectiveWeight") and filter_info.effectiveWeight:
                        if filter_info.effectiveWeight.type == 6:  # FWP_UINT64
                            filter_dict["weight"] = filter_info.effectiveWeight.uint64
                        elif filter_info.effectiveWeight.type == 4:  # FWP_UINT32
                            filter_dict["weight"] = filter_info.effectiveWeight.uint32

                    # Process conditions with human-readable enum names from win32more
                    filter_dict["num_conditions"] = getattr(filter_info, "numFilterConditions", 0)
                    filter_dict["conditions"] = []
                    if filter_info.numFilterConditions > 0 and filter_info.filterCondition:
                        conditions_array = ctypes.cast(
                            filter_info.filterCondition,
                            ctypes.POINTER(FWPM_FILTER_CONDITION0 * filter_info.numFilterConditions),
                        ).contents

                        for j in range(filter_info.numFilterConditions):
                            condition = conditions_array[j]

                            condition_dict = {
                                "field_key": str(condition.fieldKey),
                                "match_type": condition.matchType,
                                "match_type_name": get_match_type_name(condition.matchType),
                                "condition_value": {
                                    "type": condition.conditionValue.type,
                                    "type_name": get_condition_value_type_name(condition.conditionValue.type),
                                },
                            }

                            # Extract the actual value based on the type using match/case
                            if condition.conditionValue.type == wfp.FWP_UINT8:
                                condition_dict["condition_value"]["value"] = condition.conditionValue.uint8
                            elif condition.conditionValue.type == wfp.FWP_UINT16:
                                condition_dict["condition_value"]["value"] = condition.conditionValue.uint16
                            elif condition.conditionValue.type == wfp.FWP_UINT32:
                                condition_dict["condition_value"]["value"] = condition.conditionValue.uint32
                            elif condition.conditionValue.type == wfp.FWP_UINT64:
                                condition_dict["condition_value"]["value"] = condition.conditionValue.uint64
                            elif condition.conditionValue.type == wfp.FWP_INT8:
                                condition_dict["condition_value"]["value"] = condition.conditionValue.int8
                            elif condition.conditionValue.type == wfp.FWP_INT16:
                                condition_dict["condition_value"]["value"] = condition.conditionValue.int16
                            elif condition.conditionValue.type == wfp.FWP_INT32:
                                condition_dict["condition_value"]["value"] = condition.conditionValue.int32
                            elif condition.conditionValue.type == wfp.FWP_INT64:
                                condition_dict["condition_value"]["value"] = condition.conditionValue.int64
                            elif condition.conditionValue.type == wfp.FWP_FLOAT:
                                condition_dict["condition_value"]["value"] = condition.conditionValue.float32
                            elif condition.conditionValue.type == wfp.FWP_DOUBLE:
                                condition_dict["condition_value"]["value"] = condition.conditionValue.double64
                            elif condition.conditionValue.type == wfp.FWP_BYTE_ARRAY16_TYPE:
                                bytes_array = condition.conditionValue.byteArray16
                                condition_dict["condition_value"]["value"] = [b for b in bytes_array]
                            elif condition.conditionValue.type == wfp.FWP_BYTE_BLOB_TYPE:
                                if condition.conditionValue.byteBlob:
                                    blob = condition.conditionValue.byteBlob.contents
                                    condition_dict["condition_value"]["value"] = bytes(blob.data[: blob.size])
                            elif condition.conditionValue.type == wfp.FWP_UNICODE_STRING_TYPE:
                                condition_dict["condition_value"]["value"] = (
                                    condition.conditionValue.unicodeString or ""
                                )
                            elif condition.conditionValue.type == wfp.FWP_RANGE_TYPE:
                                range_value = condition.conditionValue.rangeValue.contents

                                # Handle the low value
                                low_value = None
                                if range_value.valueLow.type == wfp.FWP_UINT32:  # IPv4 address
                                    ip_int = range_value.valueLow.uint32
                                    low_value = f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"
                                elif range_value.valueLow.type == wfp.FWP_BYTE_ARRAY16_TYPE:  # IPv6 address
                                    bytes_array = range_value.valueLow.byteArray16
                                    try:
                                        # Convert to bytes and then to hex string
                                        raw_bytes = bytes(bytes_array)[:16]  # Limit to 16 bytes
                                        hex_pairs = []
                                        for i in range(0, len(raw_bytes), 2):
                                            if i + 1 < len(raw_bytes):
                                                hex_pairs.append(f"{raw_bytes[i]:02x}{raw_bytes[i+1]:02x}")
                                        low_value = ":".join(hex_pairs) if hex_pairs else None
                                    except Exception as e:
                                        logger.error(f"Error processing IPv6 low value: {e}")
                                        low_value = None

                                # Handle the high value
                                high_value = None
                                if range_value.valueHigh.type == wfp.FWP_UINT32:  # IPv4 address
                                    ip_int = range_value.valueHigh.uint32
                                    high_value = f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"
                                elif range_value.valueHigh.type == wfp.FWP_BYTE_ARRAY16_TYPE:  # IPv6 address
                                    bytes_array = range_value.valueHigh.byteArray16
                                    try:
                                        # Convert to bytes and then to hex string
                                        raw_bytes = bytes(bytes_array)[:16]  # Limit to 16 bytes
                                        hex_pairs = []
                                        for i in range(0, len(raw_bytes), 2):
                                            if i + 1 < len(raw_bytes):
                                                hex_pairs.append(f"{raw_bytes[i]:02x}{raw_bytes[i+1]:02x}")
                                        high_value = ":".join(hex_pairs) if hex_pairs else None
                                    except Exception as e:
                                        logger.error(f"Error processing IPv6 high value: {e}")
                                        high_value = None

                                condition_dict["condition_value"]["value"] = {"low": low_value, "high": high_value}
                            else:  # Default case
                                condition_dict["condition_value"]["value"] = "Unsupported value type"

                            filter_dict["conditions"].append(condition_dict)

                    # Process provider key
                    filter_dict["provider_key"] = (
                        str(filter_info.providerKey)
                        if hasattr(filter_info, "providerKey") and filter_info.providerKey
                        else None
                    )

                    # Process sublayer key
                    filter_dict["sublayer_key"] = (
                        str(filter_info.subLayerKey) if hasattr(filter_info, "subLayerKey") else ""
                    )

                    # Process action type
                    filter_dict["action_type"] = (
                        filter_info.action.type
                        if hasattr(filter_info, "action") and hasattr(filter_info.action, "type")
                        else None
                    )

                    page.append(filter_dict)

                except Exception as e:
                    logger.exception(f"Error processing filter {i}: {str(e)}")
                    continue

            return page

        finally:
            # Cast the pointer to void pointer before freeing
            void_ptr = ctypes.cast(entries_ptr, ctypes.c_void_p)
            FwpmFreeMemory0(void_ptr)
