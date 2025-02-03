import pytest
from pywfp.filter_builder import build_wfp_filter_from_expression
from win32more.Windows.Win32.NetworkManagement.WindowsFilteringPlatform import (
    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWP_ACTION_BLOCK,
    FWP_ACTION_PERMIT,
    FWP_MATCH_RANGE,
)


class TestFilterBuilder:
    def test_basic_outbound_filter(self):
        filter_string = "outbound and tcp"
        wfp_filter = build_wfp_filter_from_expression(filter_string)

        assert wfp_filter.layer == FWPM_LAYER_ALE_AUTH_CONNECT_V4
        assert wfp_filter.action == FWP_ACTION_BLOCK
        assert len(wfp_filter.conditions) == 1  # Only TCP condition, outbound is handled by layer

    def test_inbound_filter(self):
        filter_string = "inbound and tcp"
        wfp_filter = build_wfp_filter_from_expression(filter_string)

        assert wfp_filter.layer == FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
        assert len(wfp_filter.conditions) == 1

    def test_ip_range_filter(self):
        filter_string = "outbound and remoteaddr == 192.168.1.1-192.168.1.255"
        wfp_filter = build_wfp_filter_from_expression(filter_string)

        assert len(wfp_filter.conditions) == 1
        condition = wfp_filter.conditions[0]
        assert condition.match_type == FWP_MATCH_RANGE

    def test_action_allow(self):
        filter_string = "outbound and tcp and action == allow"
        wfp_filter = build_wfp_filter_from_expression(filter_string)

        assert wfp_filter.action == FWP_ACTION_PERMIT

    def test_invalid_filter(self):
        with pytest.raises(ValueError):
            build_wfp_filter_from_expression("invalid filter")

    @pytest.mark.parametrize(
        "port_filter,expected_port",
        [
            ("tcp.dstport == 80", 80),
            ("tcp.srcport == 443", 443),
            ("udp.dstport == 53", 53),
            ("udp.srcport == 1234", 1234),
        ],
    )
    def test_port_filters(self, port_filter, expected_port):
        filter_string = f"outbound and {port_filter}"
        wfp_filter = build_wfp_filter_from_expression(filter_string)

        assert len(wfp_filter.conditions) == 1
        condition = wfp_filter.conditions[0]
        assert condition.value == expected_port
