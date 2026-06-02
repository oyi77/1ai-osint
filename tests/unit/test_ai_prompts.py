"""Tests for AI prompt templates — entity_extraction and false_positive_filter."""


from src.ai.prompts.entity_extraction import ENTITY_EXTRACTION_PROMPT
from src.ai.prompts.false_positive_filter import FALSE_POSITIVE_PROMPT


# --- Entity Extraction Prompt ---

class TestEntityExtractionPrompt:
    """Tests for the ENTITY_EXTRACTION_PROMPT template."""

    def test_prompt_is_nonempty_string(self):
        assert isinstance(ENTITY_EXTRACTION_PROMPT, str)
        assert len(ENTITY_EXTRACTION_PROMPT) > 100

    def test_prompt_contains_entity_types(self):
        expected_types = [
            "email", "phone", "username", "domain", "ip",
            "url", "hash", "name", "organization", "address",
        ]
        for etype in expected_types:
            assert etype in ENTITY_EXTRACTION_PROMPT, f"Missing entity type: {etype}"

    def test_prompt_contains_json_format(self):
        assert '"entities"' in ENTITY_EXTRACTION_PROMPT
        assert '"entity_type"' in ENTITY_EXTRACTION_PROMPT
        assert '"value"' in ENTITY_EXTRACTION_PROMPT
        assert '"confidence"' in ENTITY_EXTRACTION_PROMPT
        assert '"summary"' in ENTITY_EXTRACTION_PROMPT

    def test_prompt_contains_context_field(self):
        assert '"context"' in ENTITY_EXTRACTION_PROMPT

    def test_prompt_contains_confidence_threshold(self):
        assert "0.3" in ENTITY_EXTRACTION_PROMPT

    def test_prompt_contains_rules(self):
        assert "Rules:" in ENTITY_EXTRACTION_PROMPT or "Rules" in ENTITY_EXTRACTION_PROMPT

    def test_prompt_mentions_json_response(self):
        assert "JSON" in ENTITY_EXTRACTION_PROMPT

    def test_prompt_mentions_lowercase_normalization(self):
        assert "lowercase" in ENTITY_EXTRACTION_PROMPT.lower()

    def test_prompt_not_fabricate_rule(self):
        assert "NOT" in ENTITY_EXTRACTION_PROMPT or "not" in ENTITY_EXTRACTION_PROMPT
        assert "fabricate" in ENTITY_EXTRACTION_PROMPT.lower()


# --- False Positive Filter Prompt ---

class TestFalsePositivePrompt:
    """Tests for the FALSE_POSITIVE_PROMPT template."""

    def test_prompt_is_nonempty_string(self):
        assert isinstance(FALSE_POSITIVE_PROMPT, str)
        assert len(FALSE_POSITIVE_PROMPT) > 100

    def test_prompt_contains_assessment_fields(self):
        assert '"finding_id"' in FALSE_POSITIVE_PROMPT
        assert '"is_false_positive"' in FALSE_POSITIVE_PROMPT
        assert '"confidence"' in FALSE_POSITIVE_PROMPT
        assert '"reasoning"' in FALSE_POSITIVE_PROMPT
        assert '"adjusted_severity"' in FALSE_POSITIVE_PROMPT

    def test_prompt_contains_json_format(self):
        assert '"assessments"' in FALSE_POSITIVE_PROMPT
        assert '"summary"' in FALSE_POSITIVE_PROMPT

    def test_prompt_mentions_false_positive_indicators(self):
        assert "false positive" in FALSE_POSITIVE_PROMPT.lower()

    def test_prompt_contains_test_data_indicators(self):
        assert "test@example.com" in FALSE_POSITIVE_PROMPT
        assert "example.com" in FALSE_POSITIVE_PROMPT

    def test_prompt_contains_placeholder_indicators(self):
        assert "placeholder" in FALSE_POSITIVE_PROMPT.lower() or "null" in FALSE_POSITIVE_PROMPT.lower()

    def test_prompt_contains_outdated_data_indicator(self):
        assert "2010" in FALSE_POSITIVE_PROMPT or "outdated" in FALSE_POSITIVE_PROMPT.lower()

    def test_prompt_mentions_duplicate_findings(self):
        assert "duplicate" in FALSE_POSITIVE_PROMPT.lower()

    def test_prompt_mentions_confidence_range(self):
        assert "0.0" in FALSE_POSITIVE_PROMPT
        assert "1.0" in FALSE_POSITIVE_PROMPT

    def test_prompt_not_empty_after_strip(self):
        assert len(FALSE_POSITIVE_PROMPT.strip()) > 0
