import pytest
from pywfp.filter_parser import FilterParser, FilterExpression, Token
from pywfp.filter_parser import TOKEN_IDENTIFIER, TOKEN_OPERATOR, TOKEN_NUMBER


class TestFilterParser:
    def test_basic_filter_parsing(self):
        filter_str = "outbound and tcp and remoteaddr == 192.168.1.1"
        expr = FilterParser.parse(filter_str)
        conditions = expr.flatten()

        assert len(conditions) == 3
        assert conditions[0].field == "outbound"
        assert conditions[1].field == "tcp"
        assert conditions[2].field == "remoteaddr"
        assert conditions[2].value == "192.168.1.1"

    def test_invalid_filter_syntax(self):
        with pytest.raises(ValueError):
            FilterParser.parse("outbound or invalid syntax")

    def test_ip_range_parsing(self):
        filter_str = "remoteaddr == 192.168.1.1-192.168.1.255"
        expr = FilterParser.parse(filter_str)
        conditions = expr.flatten()

        assert len(conditions) == 1
        assert conditions[0].field == "remoteaddr"
        assert conditions[0].value == "192.168.1.1-192.168.1.255"
