import pytest
from pywfp.wfp_filter import WfpFilter, WfpCondition, ip_value_to_uint32
from win32more.Windows.Win32.NetworkManagement.WindowsFilteringPlatform import (
    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_SUBLAYER_UNIVERSAL,
    FWP_MATCH_EQUAL,
    FWP_MATCH_RANGE,
    FWP_UINT32,
    FWPM_CONDITION_IP_REMOTE_PORT,
)


class TestWfpFilter:
    @pytest.fixture
    def basic_filter(self):
        return WfpFilter(
            name="Test Filter",
            description="Test Description",
            layer=FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            sublayer=FWPM_SUBLAYER_UNIVERSAL,
        )

    def test_filter_creation(self, basic_filter):
        assert basic_filter.name == "Test Filter"
        assert basic_filter.description == "Test Description"
        assert basic_filter.conditions == []

    def test_add_condition(self, basic_filter):
        condition = WfpCondition(
            field_key=FWPM_CONDITION_IP_REMOTE_PORT,
            value=80,
            value_type=FWP_UINT32,
            match_type=FWP_MATCH_EQUAL,
        )
        basic_filter.add_condition(condition)

        assert len(basic_filter.conditions) == 1
        assert basic_filter.conditions[0] == condition

    def test_to_fwpm_filter(self, basic_filter):
        fwpm_filter = basic_filter.to_fwpm_filter(1000)

        assert fwpm_filter.displayData.name == "Test Filter"
        assert fwpm_filter.displayData.description == "Test Description"
        assert fwpm_filter.layerKey == FWPM_LAYER_ALE_AUTH_CONNECT_V4


class TestWfpCondition:
    def test_basic_condition(self):
        condition = WfpCondition(field_key=FWPM_CONDITION_IP_REMOTE_PORT, value=80, value_type=FWP_UINT32)
        fwpm_condition = condition.to_fwpm_filter_condition()

        assert fwpm_condition.fieldKey == FWPM_CONDITION_IP_REMOTE_PORT
        assert fwpm_condition.matchType == FWP_MATCH_EQUAL

    def test_range_condition(self):
        condition = WfpCondition(
            field_key=FWPM_CONDITION_IP_REMOTE_PORT, value=(1, 100), value_type=FWP_UINT32, match_type=FWP_MATCH_RANGE
        )
        fwpm_condition = condition.to_fwpm_filter_condition()

        assert fwpm_condition.fieldKey == FWPM_CONDITION_IP_REMOTE_PORT
        assert fwpm_condition.matchType == FWP_MATCH_RANGE


class TestIpValueConversion:
    def test_single_ip(self):
        result = ip_value_to_uint32("192.168.1.1")
        assert isinstance(result, int)

    def test_ip_range(self):
        result = ip_value_to_uint32("192.168.1.1-192.168.1.255")
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_invalid_ip(self):
        with pytest.raises(OSError):
            ip_value_to_uint32("invalid.ip.address")
