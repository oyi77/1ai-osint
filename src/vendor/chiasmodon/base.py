from typing import Any, Dict


class OSINTTool:
    """
    Base interface for all OSINT tool wrappers.
    Each OSINT tool should implement this interface.
    """

    name: str

    def search(self, query: str, **kwargs) -> Dict[str, Any]:
        """
        Perform a search query using the OSINT tool.
        Args:
            query (str): The search query.
            **kwargs: Additional tool-specific options.
        Returns:
            Dict[str, Any]: The search results.
        """
        raise NotImplementedError

    def scan(self, query: str, **kwargs) -> Dict[str, Any]:
        """
        Perform a scan operation using the OSINT tool.
        Args:
            query (str): The scan target.
            **kwargs: Additional tool-specific options.
        Returns:
            Dict[str, Any]: The scan results.
        """
        raise NotImplementedError

    def analyze(self, data: Any, **kwargs) -> Dict[str, Any]:
        """
        Analyze OSINT data using AI/ML or advanced heuristics.
        """
        raise NotImplementedError

    def learn(self, feedback: Any, **kwargs) -> None:
        """
        Self-learning: update internal models or heuristics based on feedback or new data.
        """
        raise NotImplementedError
