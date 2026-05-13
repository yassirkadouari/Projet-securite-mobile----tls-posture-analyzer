from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation
from sslyze.scanner.scan_command_attempt import ScanCommandAttemptStatusEnum

def test_scan():
    location = ServerNetworkLocation(hostname="google.com")
    scanner = Scanner()
    request = ServerScanRequest(
        server_location=location
    )
    scanner.queue_scans([request])
    for result in scanner.get_results():
        print(result.connectivity_status)
        
test_scan()
