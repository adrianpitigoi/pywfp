import ctypes
import pytest
from unittest.mock import Mock, patch
from pywfp.wfp_engine import WfpEngine, get_match_type_name, get_condition_value_type_name


class TestWfpEngine:
    @pytest.fixture
    def engine(self):
        return WfpEngine()

    @patch("pywfp.wfp_engine.FwpmEngineOpen0")
    def test_engine_open(self, mock_open, engine):
        mock_open.return_value = 0

        engine.open("TestSession")
        mock_open.assert_called_once()

    @patch("pywfp.wfp_engine.FwpmEngineClose0")
    def test_engine_close(self, mock_close, engine):
        engine.close()
        mock_close.assert_called_once()

    @patch("pywfp.wfp_engine.FwpmFilterAdd0")
    @patch("pywfp.wfp_engine.FwpmTransactionBegin0")
    @patch("pywfp.wfp_engine.FwpmTransactionCommit0")
    @patch("pywfp.wfp_engine.FwpmEngineOpen0")
    def test_add_filter(self, mock_open, mock_commit, mock_begin, mock_add, engine):
        # Configure mock for engine open
        mock_open.return_value = 0
        engine.open("TestSession")  # Initialize the engine first

        # Define fake ctypes structure for the filter
        class FakeDisplayData:
            def __init__(self):
                self.name = None
                self.description = None

        class FakeFWPMFilter(ctypes.Structure):
            _fields_ = []  # No field definitions needed for this dummy

            def __init__(self):
                super().__init__()
                self.displayData = FakeDisplayData()

        # Create a fake filter instance (ctypes structure) for testing
        fake_filter_instance = FakeFWPMFilter()

        # Create a mock filter whose to_fwpm_filter method returns our fake instance
        mock_filter = Mock()
        mock_filter.to_fwpm_filter.return_value = fake_filter_instance

        # Configure return values for the WFP functions
        mock_begin.return_value = 0
        mock_add.return_value = 0
        mock_commit.return_value = 0

        # Call add_filter which internally will call ctypes.pointer() on our fake ctypes instance
        engine.add_filter(mock_filter, "Test Filter", "Test Description", 1000)

        # Verify the mock filter's to_fwpm_filter was called with correct weight
        mock_filter.to_fwpm_filter.assert_called_once_with(1000)

        # Verify the display data was set correctly on our fake ctypes filter
        assert fake_filter_instance.displayData.name == "Test Filter"
        assert fake_filter_instance.displayData.description == "Test Description"

        # Verify the WFP function calls
        mock_begin.assert_called_once()
        mock_add.assert_called_once()
        mock_commit.assert_called_once()

    def test_get_match_type_name(self):
        assert "FWP_MATCH_EQUAL" in get_match_type_name(0)
        assert "UNKNOWN" == get_match_type_name(-1)

    def test_get_condition_value_type_name(self):
        assert "FWP_UINT32" in get_condition_value_type_name(3)
        assert "UNKNOWN" == get_condition_value_type_name(-1)

    @patch("pywfp.wfp_engine.FwpmFilterCreateEnumHandle0")
    @patch("pywfp.wfp_engine.FwpmFilterEnum0")
    @patch("pywfp.wfp_engine.FwpmFilterDestroyEnumHandle0")
    def test_list_filters(self, mock_destroy, mock_enum, mock_create, engine):
        # Set FwpmFilterCreateEnumHandle0 to return success (0)
        mock_create.return_value = 0
        mock_enum.return_value = 0  # already set to simulate enumeration success

        filters = engine.list_filters()

        mock_create.assert_called_once()
        mock_enum.assert_called()
        mock_destroy.assert_called_once()

    @patch("pywfp.wfp_engine.FwpmEngineOpen0")
    def test_engine_open_failure(self, mock_open, engine):
        # Configure mock to return an error code
        mock_open.return_value = 0x80320001  # Some error code

        with pytest.raises(Exception) as exc_info:
            engine.open("TestSession")

        assert "FwpmEngineOpen0 failed" in str(exc_info.value)
        mock_open.assert_called_once()
