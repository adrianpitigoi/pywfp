import pytest
import ctypes
import socket
import time
import threading
import http.server
import socketserver
from contextlib import contextmanager
from pywfp import PyWFP


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


@contextmanager
def tcp_server(port):
    """Creates a temporary TCP server for testing"""

    class Handler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            # Suppress log messages
            pass

    server = socketserver.TCPServer(("", port), Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def can_connect(host, port, timeout=1):
    """Test if we can establish a TCP connection"""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except (socket.timeout, ConnectionRefusedError, PermissionError):
        return False


@pytest.mark.integration
@pytest.mark.skipif(not is_admin(), reason="Integration tests require admin privileges")
class TestIntegration:
    @pytest.fixture
    def pywfp(self):
        return PyWFP()

    @pytest.mark.integration
    def test_tcp_block_filter(self, pywfp):
        """Test blocking TCP connections to a specific port"""
        TEST_PORT = 8080

        # Start a test server
        with tcp_server(TEST_PORT):
            # Verify connection works before filter
            assert can_connect("127.0.0.1", TEST_PORT), "Should connect before filter"

            # Add blocking filter
            filter_string = (
                f"outbound and tcp and remoteaddr == 127.0.0.1 and tcp.dstport == {TEST_PORT} and action == block"
            )
            filter_name = "Integration Test TCP Block"

            with pywfp.session():
                try:
                    # Add the blocking filter
                    pywfp.add_filter(filter_string, filter_name=filter_name)

                    # Verify filter exists
                    filter = pywfp.get_filter(filter_name)
                    assert filter is not None, "Filter should exist"

                    # Try to connect - should fail
                    assert not can_connect("127.0.0.1", TEST_PORT), "Connection should be blocked"

                finally:
                    # Filter will be automatically removed when session ends
                    pass

            # Verify connection works after filter is removed
            assert can_connect("127.0.0.1", TEST_PORT), "Should connect after filter removal"

    @pytest.mark.integration
    def test_multiple_filters(self, pywfp):
        """Test adding multiple filters with different weights"""
        TEST_PORT = 8081

        with tcp_server(TEST_PORT):
            with pywfp.session():
                try:
                    # Add allow filter with higher weight (takes precedence)
                    allow_filter = (
                        f"outbound and tcp and remoteaddr == 127.0.0.1 and "
                        f"tcp.dstport == {TEST_PORT} and action == allow"
                    )
                    pywfp.add_filter(allow_filter, filter_name="Allow Filter", weight=2000)

                    # Add block filter with lower weight
                    block_filter = (
                        f"outbound and tcp and remoteaddr == 127.0.0.1 and "
                        f"tcp.dstport == {TEST_PORT} and action == block"
                    )
                    pywfp.add_filter(block_filter, filter_name="Block Filter", weight=1000)

                    # Verify filters exist
                    filters = pywfp.list_filters()
                    assert len([f for f in filters if f["name"] in ["Allow Filter", "Block Filter"]]) == 2

                    # Connection should work because allow filter has higher weight
                    assert can_connect("127.0.0.1", TEST_PORT), "Connection should be allowed due to filter weight"

                finally:
                    pass

    @pytest.mark.integration
    def test_ip_range_filter(self, pywfp):
        """Test filtering IP ranges"""
        TEST_PORT = 8082

        with tcp_server(TEST_PORT):
            with pywfp.session():
                try:
                    # Block entire subnet
                    filter_string = (
                        "outbound and tcp and " "remoteaddr == 127.0.0.1-127.0.0.255 and " "action == block"
                    )
                    pywfp.add_filter(filter_string, filter_name="IP Range Block")

                    # Try connections to different IPs in range
                    assert not can_connect("127.0.0.1", TEST_PORT), "Connection to 127.0.0.1 should be blocked"

                finally:
                    pass

    @pytest.mark.integration
    def test_filter_removal_on_session_end(self, pywfp):
        """Test that filters are properly cleaned up when session ends"""
        filter_name = "Cleanup Test Filter"

        # Add filter in a session
        with pywfp.session():
            pywfp.add_filter("outbound and tcp", filter_name=filter_name)

            # Verify filter exists
            filter = pywfp.get_filter(filter_name)
            assert filter is not None, "Filter should exist during session"

        # Start new session to check if filter was removed
        with pywfp.session():
            filter = pywfp.get_filter(filter_name)
            assert filter is None, "Filter should be removed after session end"

    @pytest.mark.integration
    @pytest.mark.parametrize("protocol", ["tcp", "udp"])
    def test_protocol_filters(self, pywfp, protocol):
        """Test filtering different protocols"""
        TEST_PORT = 8083

        with pywfp.session():
            filter_string = f"outbound and {protocol} and " f"remoteaddr == 127.0.0.1 and action == block"
            pywfp.add_filter(filter_string, filter_name=f"{protocol.upper()} Block Test")

            if protocol == "tcp":
                assert not can_connect("127.0.0.1", TEST_PORT), "TCP connection should be blocked"
            else:
                # For UDP, we could add UDP-specific tests here
                pass
