"""
Test suite for Email Gateway and MDM Connectors API endpoints
Tests for iteration 31: Email Gateway, MDM Platform Connectors, and CSPM auth
"""
import pytest
import requests
import os
import json

# Get the backend URL from environment
BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')
if not BASE_URL:
    BASE_URL = "https://seraph-security.preview.emergentagent.com"

# Test credentials
TEST_EMAIL = "test@seraph.ai"
TEST_PASSWORD = "test123456"


class TestAuthentication:
    """Authentication tests - get token for protected endpoints"""
    
    @pytest.fixture(scope="class")
    def auth_token(self):
        """Get authentication token"""
        response = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={"email": TEST_EMAIL, "password": TEST_PASSWORD}
        )
        assert response.status_code == 200, f"Login failed: {response.text}"
        data = response.json()
        return data.get("access_token")
    
    @pytest.fixture(scope="class")
    def auth_headers(self, auth_token):
        """Get auth headers for requests"""
        return {"Authorization": f"Bearer {auth_token}"}
    
    def test_login(self):
        """Test login endpoint works"""
        response = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={"email": TEST_EMAIL, "password": TEST_PASSWORD}
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        print(f"Login successful, got token")


class TestEmailGatewayEndpoints:
    """Email Gateway API tests - SMTP gateway management"""
    
    @pytest.fixture(scope="class")
    def auth_headers(self):
        """Get auth headers"""
        response = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={"email": TEST_EMAIL, "password": TEST_PASSWORD}
        )
        if response.status_code != 200:
            pytest.skip("Login failed - skipping email gateway tests")
        return {"Authorization": f"Bearer {response.json()['access_token']}"}
    
    def test_gateway_stats(self, auth_headers):
        """Test GET /api/email-gateway/stats - gateway statistics"""
        response = requests.get(
            f"{BASE_URL}/api/email-gateway/stats",
            headers=auth_headers
        )
        assert response.status_code == 200, f"Stats endpoint failed: {response.status_code} - {response.text}"
        data = response.json()
        
        # Verify expected stats fields
        expected_fields = ["total_processed", "accepted", "rejected", "quarantined", "mode"]
        for field in expected_fields:
            assert field in data, f"Missing field: {field}"
        
        print(f"Gateway stats: processed={data['total_processed']}, mode={data['mode']}")
    
    def test_gateway_quarantine(self, auth_headers):
        """Test GET /api/email-gateway/quarantine - quarantine list"""
        response = requests.get(
            f"{BASE_URL}/api/email-gateway/quarantine",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        
        assert "quarantine" in data
        assert "count" in data
        assert isinstance(data["quarantine"], list)
        
        print(f"Quarantine: {data['count']} messages")
    
    def test_gateway_blocklist_get(self, auth_headers):
        """Test GET /api/email-gateway/blocklist - blocklist retrieval"""
        response = requests.get(
            f"{BASE_URL}/api/email-gateway/blocklist",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        
        expected_lists = ["sender_blocklist", "domain_blocklist", "ip_blocklist"]
        for list_name in expected_lists:
            assert list_name in data, f"Missing blocklist: {list_name}"
        
        print(f"Blocklists retrieved: senders={len(data['sender_blocklist'])}, domains={len(data['domain_blocklist'])}, IPs={len(data['ip_blocklist'])}")
    
    def test_gateway_allowlist_get(self, auth_headers):
        """Test GET /api/email-gateway/allowlist - allowlist retrieval"""
        response = requests.get(
            f"{BASE_URL}/api/email-gateway/allowlist",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        
        expected_lists = ["sender_allowlist", "domain_allowlist", "ip_allowlist"]
        for list_name in expected_lists:
            assert list_name in data, f"Missing allowlist: {list_name}"
        
        print(f"Allowlists retrieved successfully")
    
    def test_gateway_policies(self, auth_headers):
        """Test GET /api/email-gateway/policies - policy retrieval"""
        response = requests.get(
            f"{BASE_URL}/api/email-gateway/policies",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        
        assert "policies" in data
        assert isinstance(data["policies"], dict)
        
        # Default policy should exist
        if "default" in data["policies"]:
            default_policy = data["policies"]["default"]
            print(f"Default policy settings: {list(default_policy.keys())}")
        
        print(f"Policies retrieved: {list(data['policies'].keys())}")
    
    def test_gateway_blocklist_add_remove(self, auth_headers):
        """Test POST/DELETE /api/email-gateway/blocklist - add and remove from blocklist"""
        # Add to blocklist
        test_sender = "test_blocked@malicious-domain.com"
        response = requests.post(
            f"{BASE_URL}/api/email-gateway/blocklist",
            headers=auth_headers,
            json={"value": test_sender, "list_type": "sender"}
        )
        assert response.status_code == 200, f"Add to blocklist failed: {response.text}"
        
        # Verify it was added
        response = requests.get(
            f"{BASE_URL}/api/email-gateway/blocklist",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert test_sender in data["sender_blocklist"], "Sender not added to blocklist"
        
        # Remove from blocklist
        response = requests.delete(
            f"{BASE_URL}/api/email-gateway/blocklist",
            headers=auth_headers,
            params={"value": test_sender, "list_type": "sender"}
        )
        assert response.status_code == 200, f"Remove from blocklist failed: {response.text}"
        
        print("Blocklist add/remove working correctly")
    
    def test_gateway_allowlist_add(self, auth_headers):
        """Test POST /api/email-gateway/allowlist - add to allowlist"""
        test_sender = "trusted@allowed-domain.com"
        response = requests.post(
            f"{BASE_URL}/api/email-gateway/allowlist",
            headers=auth_headers,
            json={"value": test_sender, "list_type": "sender"}
        )
        assert response.status_code == 200, f"Add to allowlist failed: {response.text}"
        
        # Verify it was added
        response = requests.get(
            f"{BASE_URL}/api/email-gateway/allowlist",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert test_sender in data["sender_allowlist"], "Sender not added to allowlist"
        
        print("Allowlist add working correctly")
    
    def test_gateway_process_email(self, auth_headers):
        """Test POST /api/email-gateway/process - process test email"""
        test_email = {
            "envelope_from": "sender@test.com",
            "envelope_to": ["recipient@company.com"],
            "subject": "Test Email Subject",
            "body": "This is a test email body for gateway processing.",
            "client_ip": "192.168.1.100"
        }
        
        response = requests.post(
            f"{BASE_URL}/api/email-gateway/process",
            headers=auth_headers,
            json=test_email
        )
        assert response.status_code == 200, f"Process email failed: {response.text}"
        data = response.json()
        
        # Verify decision fields
        assert "action" in data, "Missing action in response"
        assert "threat_score" in data, "Missing threat_score in response"
        assert "reason" in data, "Missing reason in response"
        
        print(f"Email processed: action={data['action']}, threat_score={data['threat_score']}, reason={data['reason']}")
    
    def test_gateway_requires_auth(self):
        """Test that email gateway endpoints require authentication"""
        # Try accessing without token
        response = requests.get(f"{BASE_URL}/api/email-gateway/stats")
        assert response.status_code in [401, 403], f"Endpoint should require auth, got {response.status_code}"
        print("Email gateway correctly requires authentication")


class TestMDMConnectorsEndpoints:
    """MDM Connectors API tests - Mobile Device Management integration"""
    
    @pytest.fixture(scope="class")
    def auth_headers(self):
        """Get auth headers"""
        response = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={"email": TEST_EMAIL, "password": TEST_PASSWORD}
        )
        if response.status_code != 200:
            pytest.skip("Login failed - skipping MDM connector tests")
        return {"Authorization": f"Bearer {response.json()['access_token']}"}
    
    def test_mdm_status(self, auth_headers):
        """Test GET /api/mdm/status - MDM connector status"""
        response = requests.get(
            f"{BASE_URL}/api/mdm/status",
            headers=auth_headers
        )
        assert response.status_code == 200, f"MDM status failed: {response.status_code} - {response.text}"
        data = response.json()
        
        assert "connectors" in data, "Missing connectors field"
        assert "total_devices" in data, "Missing total_devices field"
        
        print(f"MDM status: {len(data['connectors'])} connectors, {data['total_devices']} devices")
    
    def test_mdm_devices(self, auth_headers):
        """Test GET /api/mdm/devices - list managed devices"""
        response = requests.get(
            f"{BASE_URL}/api/mdm/devices",
            headers=auth_headers
        )
        assert response.status_code == 200, f"MDM devices failed: {response.text}"
        data = response.json()
        
        assert "devices" in data, "Missing devices field"
        assert "count" in data, "Missing count field"
        assert isinstance(data["devices"], list)
        
        print(f"MDM devices: {data['count']} devices")
    
    def test_mdm_policies(self, auth_headers):
        """Test GET /api/mdm/policies - list compliance policies"""
        response = requests.get(
            f"{BASE_URL}/api/mdm/policies",
            headers=auth_headers
        )
        assert response.status_code == 200, f"MDM policies failed: {response.text}"
        data = response.json()
        
        assert "policies" in data, "Missing policies field"
        assert "count" in data, "Missing count field"
        assert isinstance(data["policies"], list)
        
        print(f"MDM policies: {data['count']} policies")
    
    def test_mdm_platforms(self, auth_headers):
        """Test GET /api/mdm/platforms - list supported MDM platforms"""
        response = requests.get(
            f"{BASE_URL}/api/mdm/platforms",
            headers=auth_headers
        )
        assert response.status_code == 200, f"MDM platforms failed: {response.text}"
        data = response.json()
        
        assert "platforms" in data, "Missing platforms field"
        
        # Verify expected platforms are listed
        platforms = data["platforms"]
        platform_ids = [p["id"] for p in platforms]
        expected_platforms = ["intune", "jamf"]  # At least these should exist
        
        for platform in expected_platforms:
            assert platform in platform_ids, f"Missing expected platform: {platform}"
        
        # Each platform should have required fields
        for platform in platforms:
            assert "id" in platform, "Platform missing id"
            assert "name" in platform, "Platform missing name"
            assert "config_required" in platform, "Platform missing config_required"
        
        print(f"MDM platforms supported: {platform_ids}")
    
    def test_mdm_add_connector(self, auth_headers):
        """Test POST /api/mdm/connectors - add MDM connector"""
        test_connector = {
            "name": "test-intune-connector",
            "platform": "intune",
            "config": {
                "tenant_id": "test-tenant-123",
                "client_id": "test-client-456",
                "client_secret": "test-secret-789"
            }
        }
        
        response = requests.post(
            f"{BASE_URL}/api/mdm/connectors",
            headers=auth_headers,
            json=test_connector
        )
        assert response.status_code == 200, f"Add connector failed: {response.text}"
        data = response.json()
        
        assert "message" in data or "platform" in data, "Missing response confirmation"
        print(f"MDM connector added successfully")
        
        # Clean up - remove the test connector
        delete_response = requests.delete(
            f"{BASE_URL}/api/mdm/connectors/{test_connector['name']}",
            headers=auth_headers
        )
        # OK if delete works or returns not found (already cleaned up)
        assert delete_response.status_code in [200, 404], f"Cleanup failed: {delete_response.text}"
    
    def test_mdm_sync(self, auth_headers):
        """Test POST /api/mdm/sync - initiate device sync"""
        response = requests.post(
            f"{BASE_URL}/api/mdm/sync",
            headers=auth_headers
        )
        # May return 200 even if no connectors configured
        assert response.status_code == 200, f"MDM sync failed: {response.text}"
        data = response.json()
        
        assert "message" in data or "status" in data, "Missing sync status"
        print(f"MDM sync response: {data}")
    
    def test_mdm_connect_all(self, auth_headers):
        """Test POST /api/mdm/connect-all - connect all platforms"""
        response = requests.post(
            f"{BASE_URL}/api/mdm/connect-all",
            headers=auth_headers
        )
        assert response.status_code == 200, f"Connect all failed: {response.text}"
        data = response.json()
        
        assert "results" in data, "Missing results field"
        print(f"MDM connect-all response: {data}")
    
    def test_mdm_requires_auth(self):
        """Test that MDM endpoints require authentication"""
        response = requests.get(f"{BASE_URL}/api/mdm/status")
        assert response.status_code in [401, 403], f"Endpoint should require auth, got {response.status_code}"
        print("MDM endpoints correctly require authentication")


class TestCSPMAuthentication:
    """CSPM endpoint authentication tests - verify /api/v1/cspm/scan requires auth"""
    
    @pytest.fixture(scope="class")
    def auth_headers(self):
        """Get auth headers"""
        response = requests.post(
            f"{BASE_URL}/api/auth/login",
            json={"email": TEST_EMAIL, "password": TEST_PASSWORD}
        )
        if response.status_code != 200:
            pytest.skip("Login failed - skipping CSPM tests")
        return {"Authorization": f"Bearer {response.json()['access_token']}"}
    
    def test_cspm_scan_requires_auth(self):
        """Test POST /api/v1/cspm/scan requires authentication"""
        # Try to start a scan without authentication
        response = requests.post(
            f"{BASE_URL}/api/v1/cspm/scan",
            json={}
        )
        assert response.status_code in [401, 403], f"CSPM scan should require auth, got {response.status_code}"
        print("CSPM scan endpoint correctly requires authentication")
    
    def test_cspm_scan_with_auth(self, auth_headers):
        """Test POST /api/v1/cspm/scan works with authentication"""
        response = requests.post(
            f"{BASE_URL}/api/v1/cspm/scan",
            headers=auth_headers,
            json={}
        )
        # Should return 200 (even if not_configured)
        assert response.status_code == 200, f"CSPM scan with auth failed: {response.text}"
        data = response.json()
        
        # Verify response structure
        assert "status" in data, "Missing status field"
        print(f"CSPM scan response: status={data['status']}")
    
    def test_cspm_providers_list(self, auth_headers):
        """Test GET /api/v1/cspm/providers - list configured providers"""
        response = requests.get(
            f"{BASE_URL}/api/v1/cspm/providers",
            headers=auth_headers
        )
        # Providers endpoint may or may not require auth depending on implementation
        # But should return 200 with auth
        assert response.status_code == 200, f"CSPM providers failed: {response.text}"
        data = response.json()
        
        assert isinstance(data, list), "Expected list of providers"
        print(f"CSPM providers: {len(data)} configured")
    
    def test_cspm_dashboard(self, auth_headers):
        """Test GET /api/v1/cspm/dashboard - CSPM dashboard stats"""
        response = requests.get(
            f"{BASE_URL}/api/v1/cspm/dashboard",
            headers=auth_headers
        )
        # Dashboard may not require auth but should work with auth
        assert response.status_code == 200, f"CSPM dashboard failed: {response.text}"
        data = response.json()
        
        assert "posture" in data, "Missing posture field"
        print(f"CSPM dashboard: posture grade={data['posture'].get('grade', 'N/A')}")
    
    def test_cspm_findings(self, auth_headers):
        """Test GET /api/v1/cspm/findings - list findings"""
        response = requests.get(
            f"{BASE_URL}/api/v1/cspm/findings",
            headers=auth_headers
        )
        assert response.status_code == 200, f"CSPM findings failed: {response.text}"
        data = response.json()
        
        assert "findings" in data, "Missing findings field"
        assert "total" in data, "Missing total field"
        print(f"CSPM findings: {data['total']} total")


class TestEndpointSecurity:
    """Security tests - verify all new endpoints require authentication"""
    
    def test_all_email_gateway_endpoints_require_auth(self):
        """Verify email gateway endpoints are protected"""
        endpoints = [
            ("GET", "/api/email-gateway/stats"),
            ("GET", "/api/email-gateway/quarantine"),
            ("GET", "/api/email-gateway/blocklist"),
            ("GET", "/api/email-gateway/allowlist"),
            ("GET", "/api/email-gateway/policies"),
            ("POST", "/api/email-gateway/blocklist"),
            ("POST", "/api/email-gateway/allowlist"),
            ("POST", "/api/email-gateway/process"),
        ]
        
        for method, endpoint in endpoints:
            if method == "GET":
                response = requests.get(f"{BASE_URL}{endpoint}")
            else:
                response = requests.post(f"{BASE_URL}{endpoint}", json={})
            
            assert response.status_code in [401, 403, 422], \
                f"Endpoint {endpoint} should require auth, got {response.status_code}"
        
        print("All email gateway endpoints correctly require authentication")
    
    def test_all_mdm_endpoints_require_auth(self):
        """Verify MDM connector endpoints are protected"""
        endpoints = [
            ("GET", "/api/mdm/status"),
            ("GET", "/api/mdm/devices"),
            ("GET", "/api/mdm/policies"),
            ("GET", "/api/mdm/platforms"),
            ("POST", "/api/mdm/connectors"),
            ("POST", "/api/mdm/sync"),
            ("POST", "/api/mdm/connect-all"),
        ]
        
        for method, endpoint in endpoints:
            if method == "GET":
                response = requests.get(f"{BASE_URL}{endpoint}")
            else:
                response = requests.post(f"{BASE_URL}{endpoint}", json={})
            
            assert response.status_code in [401, 403, 422], \
                f"Endpoint {endpoint} should require auth, got {response.status_code}"
        
        print("All MDM connector endpoints correctly require authentication")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
