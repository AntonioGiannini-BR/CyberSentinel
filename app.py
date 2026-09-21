from __future__ import annotations

import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None

from flask import Flask, jsonify, render_template, request, redirect, session, url_for, flash, send_file
from werkzeug.security import check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

from src.analyzer import analyze_events, parse_log_file, save_report
from src.config import Config
from src.db import get_analysis, init_db, list_analyses, save_analysis, delete_analysis, dashboard_stats
from src.security import csrf_token, login_required, safe_upload_name, validate_csrf, validate_upload


def create_app(config: Config | None = None) -> Flask:
    cfg = config or Config.from_env()
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=cfg.secret_key,
        MAX_CONTENT_LENGTH=cfg.max_upload_bytes,
        SESSION_COOKIE_HTTPONLY=cfg.session_cookie_http_only,
        SESSION_COOKIE_SAMESITE=cfg.session_cookie_samesite,
        SESSION_COOKIE_SECURE=cfg.session_cookie_secure,
    )
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    for directory in (cfg.uploads_dir, cfg.reports_dir, cfg.audit_log_path.parent):
        directory.mkdir(parents=True, exist_ok=True)
    init_db(cfg.database_path)
    _configure_logging(app, cfg.audit_log_path)

    @app.context_processor
    def inject_csrf():
        return {'csrf_token': csrf_token}

    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self'; img-src 'self' data:; script-src 'self'"
        return response

    @app.get('/health')
    def health():
        return jsonify({'status': 'ok'})

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            validate_csrf()
            username = request.form.get('username', '')
            password = request.form.get('password', '')
            if username == cfg.username and check_password_hash(cfg.password_hash, password):
                session.clear()
                session['authenticated'] = True
                session['username'] = username
                app.logger.info('login_success username=%s ip=%s', username, request.remote_addr)
                return redirect(request.args.get('next') or url_for('dashboard'))
            app.logger.warning('login_failed username=%s ip=%s', username, request.remote_addr)
            flash('Invalid credentials.', 'error')
        return render_template('login.html')

    @app.post('/logout')
    @login_required
    def logout():
        validate_csrf()
        app.logger.info('logout username=%s ip=%s', session.get('username'), request.remote_addr)
        session.clear()
        return redirect(url_for('login'))

    @app.get('/')
    @login_required
    def dashboard():
        rows = list_analyses(cfg.database_path, limit=10)
        latest = rows[0] if rows else None
        result = json.loads(latest['result_json']) if latest else None
        stats = dashboard_stats(cfg.database_path)
        return render_template('dashboard.html', latest=latest, result=result, analyses=rows, stats=stats)

    @app.post('/upload')
    @login_required
    def upload_log():
        validate_csrf()
        try:
            uploaded_file = request.files.get('log_file')
            threshold = max(1, min(int(request.form.get('threshold', '5')), 50))
            data = validate_upload(uploaded_file, cfg.allowed_extensions, cfg.max_upload_bytes)  # type: ignore[arg-type]
            stored_name = safe_upload_name(uploaded_file.filename)  # type: ignore[union-attr]
            stored_path = cfg.uploads_dir / stored_name
            stored_path.write_bytes(data)
            events = parse_log_file(stored_path)
            result = analyze_events(events, brute_force_threshold=threshold)
            report_path = save_report(result, cfg.reports_dir, prefix=Path(stored_name).stem)
            analysis_id = save_analysis(cfg.database_path, uploaded_file.filename, stored_path, report_path, result)  # type: ignore[union-attr]
            app.logger.info('analysis_created id=%s file=%s user=%s ip=%s', analysis_id, uploaded_file.filename, session.get('username'), request.remote_addr)  # type: ignore[union-attr]
            flash('Log analyzed successfully.', 'success')
            return redirect(url_for('analysis_detail', analysis_id=analysis_id))
        except (ValueError, OSError) as exc:
            app.logger.warning('upload_rejected reason=%s ip=%s', exc, request.remote_addr)
            flash(str(exc), 'error')
            return redirect(url_for('dashboard'))

    @app.get('/history')
    @login_required
    def history():
        query = request.args.get('q', '').strip()[:100]
        return render_template('history.html', analyses=list_analyses(cfg.database_path, limit=100, query=query), query=query)

    @app.get('/analysis/<int:analysis_id>')
    @login_required
    def analysis_detail(analysis_id: int):
        row = get_analysis(cfg.database_path, analysis_id)
        if row is None:
            return render_template('error.html', message='Analysis not found.'), 404
        return render_template('analysis_detail.html', analysis=row, result=json.loads(row['result_json']))

    @app.get('/analysis/<int:analysis_id>/report')
    @login_required
    def download_report(analysis_id: int):
        row = get_analysis(cfg.database_path, analysis_id)
        if row is None:
            return render_template('error.html', message='Analysis not found.'), 404
        path = Path(row['report_path']).resolve()
        reports_root = cfg.reports_dir.resolve()
        if reports_root not in path.parents or not path.is_file():
            return render_template('error.html', message='Report file is unavailable.'), 404
        return send_file(path, as_attachment=True, download_name=f'cybersentinel-analysis-{analysis_id}.json')

    @app.post('/analysis/<int:analysis_id>/delete')
    @login_required
    def remove_analysis(analysis_id: int):
        validate_csrf()
        row = get_analysis(cfg.database_path, analysis_id)
        if row is None:
            return render_template('error.html', message='Analysis not found.'), 404
        for key, root in [('stored_path', cfg.uploads_dir), ('report_path', cfg.reports_dir)]:
            path = Path(row[key]).resolve()
            if root.resolve() in path.parents and path.is_file():
                path.unlink(missing_ok=True)
        delete_analysis(cfg.database_path, analysis_id)
        flash('Análise removida com segurança.', 'success')
        return redirect(url_for('history'))

    @app.post('/api/analyze')
    @login_required
    def api_analyze():
        validate_csrf()
        uploaded_file = request.files.get('log_file')
        threshold = max(1, min(int(request.form.get('threshold', '5')), 50))
        data = validate_upload(uploaded_file, cfg.allowed_extensions, cfg.max_upload_bytes)  # type: ignore[arg-type]
        stored_name = safe_upload_name(uploaded_file.filename)  # type: ignore[union-attr]
        stored_path = cfg.uploads_dir / stored_name
        stored_path.write_bytes(data)
        events = parse_log_file(stored_path)
        result = analyze_events(events, brute_force_threshold=threshold)
        report_path = save_report(result, cfg.reports_dir, prefix=Path(stored_name).stem)
        analysis_id = save_analysis(cfg.database_path, uploaded_file.filename, stored_path, report_path, result)  # type: ignore[union-attr]
        return jsonify({'analysis_id': analysis_id, 'result': result})

    @app.errorhandler(413)
    def file_too_large(_):
        return render_template('error.html', message='Uploaded file is too large.'), 413

    @app.errorhandler(400)
    def bad_request(_):
        return render_template('error.html', message='Invalid request.'), 400

    return app


def _configure_logging(app: Flask, audit_log_path: Path) -> None:
    handler = RotatingFileHandler(audit_log_path, maxBytes=1_000_000, backupCount=5)
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    app.logger.setLevel(logging.INFO)
    app.logger.addHandler(handler)


if __name__ == '__main__':
    # Local execution: load .env automatically so `python app.py` uses the same
    # credentials configured for the project.
    if load_dotenv is not None:
        load_dotenv()

    cfg = Config.from_env()
    create_app(cfg).run(host='127.0.0.1', port=5000, debug=False)
