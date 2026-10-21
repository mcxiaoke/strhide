try:
    from .api import StegoEvaluator, generate_markdown_report
except (ImportError, ValueError):
    from api import StegoEvaluator, generate_markdown_report

__all__ = ["StegoEvaluator", "generate_markdown_report"]
__version__ = "1.0.0"

