"""Workers: ingestion pipeline and NATS consumer."""
from .pipeline import IngestionPipeline

__all__ = ["IngestionPipeline"]
