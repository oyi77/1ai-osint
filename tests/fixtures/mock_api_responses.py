"""Mock API responses for testing OSINT modules without hitting real APIs."""

MOCK_HIBP_BREACHES = [
    {
        "Name": "TestBreach2023",
        "Title": "Test Breach",
        "Domain": "testbreach.com",
        "BreachDate": "2023-06-15",
        "AddedDate": "2023-07-01",
        "PwnCount": 50000,
        "Description": "A test breach for unit testing purposes.",
        "DataClasses": ["Email addresses", "Passwords", "Usernames"],
        "IsVerified": True,
    }
]

MOCK_SHODAN_HOST = {
    "ip_str": "192.168.1.1",
    "org": "Test Organization",
    "os": "Linux",
    "ports": [22, 80, 443],
    "vulns": ["CVE-2023-1234"],
    "hostnames": ["test.example.com"],
}

MOCK_GITHUB_SEARCH = {
    "total_count": 2,
    "items": [
        {
            "name": "config.yml",
            "path": "config/config.yml",
            "repository": {"full_name": "test/repo"},
            "html_url": "https://github.com/test/repo/blob/main/config/config.yml",
        },
        {
            "name": ".env.example",
            "path": ".env.example",
            "repository": {"full_name": "test/another-repo"},
            "html_url": "https://github.com/test/another-repo/blob/main/.env.example",
        },
    ],
}

MOCK_GITLEAKS_FINDING = {
    "rule-id": "aws-access-token",
    "description": "AWS Access Token",
    "match": "AKIAIOSFODNN7EXAMPLE",
    "secret": "AKIAIOSFODNN7EXAMPLE",
    "file": "config.js",
    "line": "42",
    "commit": "abc123",
    "author": "Test Author",
    "email": "test@example.com",
    "date": "2023-01-15T10:30:00Z",
}

MOCK_LEAKCHECK_RESPONSE = {
    "success": True,
    "found": 3,
    "result": [
        {
            "email": "test@example.com",
            "password": "redacted",
            "source": "TestBreach1",
        },
        {
            "email": "test@example.com",
            "password": "redacted",
            "source": "TestBreach2",
        },
    ],
}

MOCK_SCYLLA_RESPONSE = {
    "results": [
        {
            "email": "test@example.com",
            "password": "redacted",
            "hash": "abc123def456",
            "source": "TestLeak",
            "domain": "example.com",
        }
    ]
}

MOCK_BREACHDIRECTORY_RESPONSE = {
    "success": True,
    "result": [
        {
            "email": "test@example.com",
            "password": "redacted",
            "hash": "abc123",
            "sources": ["TestBreach"],
        }
    ]
}


def get_mock_response(service: str, query: str = "") -> dict:
    """
    Get a mock response for a given service.

    Args:
        service: Service name (hibp, shodan, github, gitleaks, leakcheck, etc.)
        query: The query (unused, but available for dynamic responses)
    Returns:
        Mock response dict
    """
    mocks = {
        "hibp": MOCK_HIBP_BREACHES,
        "shodan": MOCK_SHODAN_HOST,
        "github": MOCK_GITHUB_SEARCH,
        "gitleaks": [MOCK_GITLEAKS_FINDING],
        "leakcheck": MOCK_LEAKCHECK_RESPONSE,
        "scylla": MOCK_SCYLLA_RESPONSE,
        "breachdirectory": MOCK_BREACHDIRECTORY_RESPONSE,
    }
    return mocks.get(service, {"error": f"No mock for service: {service}"})
