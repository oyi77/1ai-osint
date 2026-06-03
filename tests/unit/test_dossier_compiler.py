from unittest.mock import MagicMock
from src.modules.deep_scan.dossier_compiler import DossierCompiler
from src.modules.free_intel.github_intel import GitHubProfile
from src.modules.free_intel.gravatar_intel import GravatarProfile
from src.modules.free_intel.google_dork_intel import DorkResult


def test_compile_with_github():
    compiler = DossierCompiler()
    gh = GitHubProfile(
        username="testuser",
        full_name="Test User",
        email="test@example.com",
        company="@TestCo",
        location="Jakarta, Indonesia",
        bio="Developer",
        blog="https://test.com",
        twitter_username="testuser",
        avatar_url="https://avatar.com/1.jpg",
        public_repos=10,
        followers=50,
        commit_emails=["real@company.com"],
    )
    dossier = compiler.compile("Test User", github_profiles=[gh])
    assert dossier.full_name == "Test User"
    assert any(e.address == "test@example.com" for e in dossier.emails)
    assert any(e.address == "real@company.com" for e in dossier.emails)
    assert dossier.current_employer == "TestCo"
    assert "Jakarta, Indonesia" in dossier.known_locations
    assert any(a.platform == "github" for a in dossier.social_accounts)
    assert any(a.platform == "twitter" for a in dossier.social_accounts)
    assert "https://avatar.com/1.jpg" in dossier.profile_pictures
    assert "https://test.com" in dossier.websites


def test_compile_with_dorks():
    compiler = DossierCompiler()
    dr = DorkResult(
        query="Test User",
        extracted_emails=["found@email.com"],
        extracted_phones=["+6281234567890"],
        linkedin_urls=["https://linkedin.com/in/testuser"],
    )
    dossier = compiler.compile("Test User", dork_results=[dr])
    assert any(e.address == "found@email.com" for e in dossier.emails)
    assert any(p.number == "+6281234567890" for p in dossier.phones)
    assert any(a.platform == "linkedin" for a in dossier.social_accounts)


def test_compile_intelligence_gaps():
    compiler = DossierCompiler()
    dossier = compiler.compile("Unknown Person")
    assert len(dossier.intelligence_gaps) > 0
    assert dossier.confidence_score == 0.0


def test_compile_confidence_score():
    compiler = DossierCompiler()
    gh = GitHubProfile(
        username="user",
        email="a@b.com",
        company="Co",
        location="City",
        avatar_url="https://pic.jpg",
        blog="https://blog.com",
    )
    dossier = compiler.compile("User", github_profiles=[gh])
    assert dossier.confidence_score > 0.0


def test_deduplication():
    compiler = DossierCompiler()
    gh = GitHubProfile(
        username="u", email="same@email.com", commit_emails=["same@email.com"]
    )
    dossier = compiler.compile("User", github_profiles=[gh])
    email_count = sum(1 for e in dossier.emails if e.address == "same@email.com")
    assert email_count == 1  # Should not duplicate


def test_compile_with_gravatar():
    compiler = DossierCompiler()
    grav = GravatarProfile(
        email_hash="hash",
        display_name="Gravatar Display Name",
        profile_url="https://gravatar.com/displayname",
        photo_url="https://gravatar.com/pic.jpg",
        about_me="Bio",
        current_location="Bandung, Indonesia",
        verified_accounts=[
            {
                "domain": "facebook",
                "url": "https://facebook.com/user",
                "username": "user",
            }
        ],
    )
    dossier = compiler.compile("User", gravatar_profiles=[grav])
    assert "Gravatar Display Name" in dossier.aliases
    assert "https://gravatar.com/pic.jpg" in dossier.profile_pictures
    assert "Bandung, Indonesia" in dossier.known_locations
    assert any(a.platform == "facebook" for a in dossier.social_accounts)
    assert "Gravatar" in dossier.data_sources_used


def test_compile_with_messaging():
    compiler = DossierCompiler()
    # Mocking messaging presence result
    mr = MagicMock()
    mr.phone_number = "0812345678"
    mr.whatsapp_registered = True

    # 1. No existing phone in dossier
    dossier1 = compiler.compile("User", messaging_results=[mr])
    assert any(
        p.number == "0812345678" and p.whatsapp_registered is True
        for p in dossier1.phones
    )

    # 2. Existing phone in dossier (from dorks)
    dr = DorkResult(query="User", extracted_phones=["0812345678"])
    dossier2 = compiler.compile("User", dork_results=[dr], messaging_results=[mr])
    assert len(dossier2.phones) == 1
    assert dossier2.phones[0].number == "0812345678"
    assert dossier2.phones[0].whatsapp_registered is True


def test_compile_with_bts():
    compiler = DossierCompiler()
    # Mocking BTS phone analysis result
    bt = MagicMock()
    bt.phone_number = "0812345678"
    bt.operator = "Telkomsel"

    # Existing phone in dossier
    dr = DorkResult(query="User", extracted_phones=["0812345678"])
    dossier = compiler.compile("User", dork_results=[dr], bts_results=[bt])
    assert len(dossier.phones) == 1
    assert dossier.phones[0].number == "0812345678"
    assert dossier.phones[0].operator == "Telkomsel"


def test_compile_with_hibp():
    compiler = DossierCompiler()
    # Mocking BreachRecord
    b = MagicMock()
    b.name = "Tokopedia"
    b.data_classes = ["Email", "Password"]

    dossier = compiler.compile("User", hibp_results=[[b]])
    assert "Tokopedia" in dossier.breached_services
    assert "Email" in dossier.exposed_data_types
    assert "Password" in dossier.exposed_data_types


def test_compile_with_social_findings():
    compiler = DossierCompiler()
    # Mocking findings
    f1 = MagicMock()
    f1.raw_data = {
        "type": "github",
        "profile": {
            "email": "direct@example.com",
            "company": "@DirectCo",
            "location": "Surabaya, Indonesia",
        },
    }

    f2 = MagicMock()
    f2.raw_data = {
        "type": "social_account",
        "platform": "instagram",
        "url": "https://instagram.com/directuser",
        "username": "directuser",
        "source": "sherlock",
    }

    dossier = compiler.compile("User", social_findings=[f1, f2])
    assert any(e.address == "direct@example.com" for e in dossier.emails)
    assert dossier.current_employer == "DirectCo"
    assert "Surabaya, Indonesia" in dossier.known_locations
    assert any(
        a.platform == "instagram" and a.username == "directuser"
        for a in dossier.social_accounts
    )
    assert "External Open-Source Tools" in dossier.data_sources_used


def test_export_dossier_html():
    from src.modules.deep_scan.exports.dossier_html import export_dossier_html

    compiler = DossierCompiler()
    # Create a dummy dossier with typical data to trigger all branches in HTML template
    gh = GitHubProfile(
        username="testuser",
        full_name="Test User",
        email="test@example.com",
        company="@TestCo",
        location="Jakarta, Indonesia",
        bio="Developer",
        avatar_url="https://avatar.com/1.jpg",
        public_repos=10,
    )
    b = MagicMock()
    b.name = "Tokopedia"
    b.data_classes = ["Email"]

    dossier = compiler.compile("Test User", github_profiles=[gh], hibp_results=[[b]])
    html = export_dossier_html(dossier)

    assert "Test User" in html
    assert "test@example.com" in html
    assert "TestCo" in html
    assert "Jakarta, Indonesia" in html
    assert "Tokopedia" in html
    assert "dossier-" in html
