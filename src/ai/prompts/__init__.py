"""Prompt templates for AI-powered OSINT analysis."""

from src.ai.prompts.behavioral_analysis import BEHAVIORAL_ANALYSIS_PROMPT
from src.ai.prompts.entity_extraction import ENTITY_EXTRACTION_PROMPT
from src.ai.prompts.false_positive_filter import FALSE_POSITIVE_PROMPT

__all__ = [
    "ENTITY_EXTRACTION_PROMPT",
    "FALSE_POSITIVE_PROMPT",
    "BEHAVIORAL_ANALYSIS_PROMPT",
]
