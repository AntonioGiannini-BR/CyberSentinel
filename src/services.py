from pathlib import Path

from werkzeug.datastructures import FileStorage

from src.analyzer import analyze_events, parse_log_file, save_report
from src.config import Config
from src.db import save_analysis
from src.security import safe_upload_name, validate_upload


class AnalysisService:
    def __init__(self, config: Config):
        self.config = config

    def analyze(
        self,
        uploaded_file: FileStorage,
        threshold: int = 5,
    ) -> tuple[int, dict]:
        # Valida o arquivo recebido.
        data = validate_upload(
            uploaded_file,
            self.config.allowed_extensions,
            self.config.max_upload_bytes,
        )

        # Salva o arquivo com um nome seguro.
        stored_name = safe_upload_name(uploaded_file.filename)
        stored_path = self.config.uploads_dir / stored_name
        stored_path.write_bytes(data)

        # Interpreta os eventos e identifica padrões suspeitos.
        events = parse_log_file(stored_path)
        result = analyze_events(
            events,
            brute_force_threshold=threshold,
        )

        # Gera o relatório JSON.
        report_path = save_report(
            result,
            self.config.reports_dir,
            prefix=Path(stored_name).stem,
        )

        # Registra a análise no banco.
        analysis_id = save_analysis(
            self.config.database_path,
            uploaded_file.filename,
            stored_path,
            report_path,
            result,
        )

        return analysis_id, result