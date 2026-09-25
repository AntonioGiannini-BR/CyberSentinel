from pathlib import Path
from typing import Any

from src import db


class AnalysisRepository:
    def __init__(self, database_path: Path):
        self.database_path = database_path

    def save(
        self,
        filename: str,
        stored_path: Path,
        report_path: Path,
        result: dict[str, Any],
    ) -> int:
        return db.save_analysis(
            self.database_path,
            filename,
            stored_path,
            report_path,
            result,
        )

    def list(self, limit: int = 50, query: str = ""):
        return db.list_analyses(
            self.database_path,
            limit=limit,
            query=query,
        )

    def get(self, analysis_id: int):
        return db.get_analysis(self.database_path, analysis_id)

    def delete(self, analysis_id: int) -> bool:
        return db.delete_analysis(self.database_path, analysis_id)

    def dashboard_stats(self) -> dict[str, Any]:
        return db.dashboard_stats(self.database_path)