import pytest
from unittest.mock import Mock, patch
from pywfp import PyWFP, WFPError


class TestPyWFP:
    @pytest.fixture
    def pywfp(self):
        return PyWFP(session_name="TestSession")

    def test_initialization(self):
        pywfp = PyWFP("CustomSession")
        assert pywfp.session_name == "CustomSession"

    @patch("pywfp.core.WfpEngine")
    def test_session_context_manager(self, mock_engine):
        pywfp = PyWFP()
        with pywfp.session():
            mock_engine.return_value.open.assert_called_once()
        mock_engine.return_value.close.assert_called_once()

    @patch("pywfp.core.build_wfp_filter_from_expression")
    def test_add_filter_success(self, mock_builder, pywfp):
        filter_string = "outbound and tcp"
        mock_filter = Mock()
        mock_builder.return_value = mock_filter

        with patch.object(pywfp._engine, "add_filter") as mock_add:
            pywfp.add_filter(filter_string, "Test Filter", "Test Description", 1000)
            mock_builder.assert_called_once_with(filter_string)
            mock_add.assert_called_once_with(mock_filter, "Test Filter", "Test Description", 1000)

    def test_add_filter_failure(self, pywfp):
        with pytest.raises(WFPError):
            with patch.object(pywfp._engine, "add_filter", side_effect=Exception("Test error")):
                pywfp.add_filter("outbound and tcp")

    @patch("pywfp.core.WfpEngine.list_filters")
    def test_list_filters(self, mock_list, pywfp):
        mock_filters = [{"name": "Test Filter"}]
        mock_list.return_value = mock_filters

        filters = pywfp.list_filters()
        assert filters == mock_filters
        mock_list.assert_called_once()

    def test_get_filter(self, pywfp):
        mock_filters = [{"name": "Test Filter 1"}, {"name": "Test Filter 2"}]
        with patch.object(pywfp, "list_filters", return_value=mock_filters):
            filter = pywfp.get_filter("Test Filter 1")
            assert filter == mock_filters[0]

            filter = pywfp.get_filter("Non-existent Filter")
            assert filter is None

    @pytest.mark.parametrize(
        "filter_string,expected",
        [
            ("outbound and tcp", True),
            ("inbound and udp and remoteaddr == 192.168.1.1", True),
            ("invalid syntax", False),
        ],
    )
    def test_validate_filter(self, filter_string, expected):
        assert PyWFP.validate_filter(filter_string) == expected
