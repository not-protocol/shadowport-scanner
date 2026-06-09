# ShadowPort Scanner v2.1.0 — Production Checklist

> All items must be verified before a release is tagged.
> Run `pytest tests/ -v --tb=short` and confirm all pass.

---

## 1. Known Bugs Fixed

| # | Bug | Fix | Verified |
|---|---|---|---|
| 1 | `table scans has no column named partial` | Full schema rewrite in `db/database.py` with all columns defined. Migration adds missing columns via `PRAGMA table_info` + `ALTER TABLE`. | ⬜ |
| 2 | Excel file not created or updated on exit | `log_scan_to_excel()` called immediately after every scan. Never on exit. | ⬜ |
| 3 | SQL injection via f-string queries | All queries use parameterized `?` placeholders. Zero f-string SQL. | ⬜ |
| 4 | Missing try/except on conn.execute() | All DB operations wrapped in `_get_conn()` context manager with rollback on exception. | ⬜ |
| 5 | Connection never closed on exception | `@contextmanager` with `finally: conn.close()` on every connection. | ⬜ |
| 6 | CTRL+C crash with traceback | `KeyboardInterrupt` caught at every input prompt and scan stage in `main.py`. | ⬜ |
| 7 | Progress bar hangs at 97-99% | `ScanProgress.stop(state=)` always terminates: done / timeout / cancel / error. | ⬜ |
| 8 | Nmap errors shown as raw tracebacks | All `nmap.PortScannerError` and generic exceptions caught, converted to user-readable messages. | ⬜ |
| 9 | Race condition on Excel file (concurrent scans) | `threading.Lock()` (`_excel_lock`) wraps every Excel read/write operation. | ⬜ |
| 10 | Scan# auto-increment off-by-one | `_next_scan_number()` counts existing data rows (excluding header): `max(ws.max_row - 1, 0) + 1`. | ⬜ |

---

## 2. Schema Migration

- [ ] `migrate_schema()` runs on every startup via `init_db()`
- [ ] `PRAGMA table_info(scans)` correctly detects all existing columns
- [ ] Missing columns added via `ALTER TABLE scans ADD COLUMN ...`
- [ ] Migration is idempotent — safe to run multiple times
- [ ] `schema_meta` table records current schema version
- [ ] Test: `test_migrate_adds_missing_columns` passes

---

## 3. Excel Logging

- [ ] `Log/` directory auto-created if missing
- [ ] New file created with styled header row (bold, navy fill)
- [ ] Existing file: row appended, header not duplicated
- [ ] `Scan #` increments correctly from existing row count
- [ ] `PermissionError` retried 3× with 1s delay
- [ ] `openpyxl wb.save()` called before `wb.close()`
- [ ] `threading.Lock()` prevents concurrent write corruption
- [ ] Returns `(True, message)` on success, `(False, message)` on failure
- [ ] Tests: all `test_excel_logger.py` tests pass

---

## 4. Input Validation

- [ ] `validate_target()` returns `ValidationResult(valid, reason)`
- [ ] Shell metacharacters (`;`, `&`, `|`, `` ` ``, `$`, `(`, `)`) rejected
- [ ] Unicode input rejected
- [ ] Partial IPs (`192.168`, `192.168.1`) rejected
- [ ] Out-of-range octets (`999.999.999.999`, `256.0.0.1`) rejected
- [ ] CIDR prefix range enforced (0–32)
- [ ] Single words and garbage strings rejected
- [ ] Spaces in target rejected
- [ ] `subprocess` never called with `shell=True`
- [ ] Tests: all `test_validation.py` tests pass

---

## 5. Privilege Checks

- [ ] `is_root()` called before every SYN (`-sS`) and OS detection (`-O`) scan
- [ ] Non-root user attempting privileged scan receives clear error message
- [ ] `sudo` is never auto-invoked programmatically
- [ ] Warning shown at startup if not root, with option to continue
- [ ] Root-required modes clearly marked in menu with `[root]` tag

---

## 6. Thread Safety

- [ ] All scan worker threads use `app.call_from_thread()` for Textual UI updates
- [ ] No direct widget mutation from background threads
- [ ] `LiveEventsLog._lock` (threading.Lock) guards `_seen_keys` set
- [ ] `_db_lock` (threading.Lock) guards all SQLite operations
- [ ] `_excel_lock` (threading.Lock) guards all Excel operations
- [ ] `LiveEventsLog` MAX_EVENTS = 100 cap enforced
- [ ] Banner grabbing timeout: max 5s per host (TIMEOUT = 5 in `banner_grabber.py`)

---

## 7. Dual-Write Consistency

- [ ] `save_scan()` (SQLite) called immediately after scan
- [ ] `log_scan_to_excel()` called immediately after scan (same code path)
- [ ] `audit_log_consistency()` runs on startup as background health check
- [ ] Discrepancies logged as warnings at startup
- [ ] Both writes succeed or failure is reported separately

---

## 8. Export Functionality

- [ ] TXT export: generates correctly, includes partial flag if applicable
- [ ] JSON export: valid JSON, includes meta and scan data
- [ ] XML export: valid XML structure
- [ ] HTML export: renders in browser, includes risk bar
- [ ] All formats: `PermissionError` caught with fix instruction shown
- [ ] Reports saved to `reports/` directory (auto-created)
- [ ] Reports `chmod 644` after write

---

## 9. Plugin Isolation

- [ ] Plugins loaded via `importlib` dynamic import
- [ ] Failed plugin import skipped with warning — does not crash app
- [ ] Each plugin runs in try/except — plugin crash does not crash app
- [ ] Plugin output captured and displayed, not executed
- [ ] Plugin log written to `plugins_log` SQLite table via `log_plugin_run()`

---

## 10. Error Logging

- [ ] `Log/error.log` created automatically on first error
- [ ] Every caught exception logged with: timestamp, target, mode, error, stack trace
- [ ] `log_error()` itself never raises (wrapped in bare `except`)
- [ ] Error log never shown to user unless they open it manually
- [ ] Startup errors (DB init, plugin load, audit) logged silently

---

## 11. Graceful CTRL+C

- [ ] CTRL+C at target input prompt: returns to loop
- [ ] CTRL+C at mode selection: returns to target prompt
- [ ] CTRL+C during scan: scan cancelled, partial results shown if available
- [ ] CTRL+C at save prompt: skipped cleanly
- [ ] CTRL+C at plugin menu: returns to main loop
- [ ] Top-level `try/except KeyboardInterrupt` in `main()` as final safety net
- [ ] No traceback ever shown on CTRL+C

---

## 12. Test Coverage

```bash
pytest tests/ -v --tb=short
```

| Test File | Tests | Coverage Area |
|---|---|---|
| `test_validation.py` | 30+ | All valid, invalid, injection, unicode inputs |
| `test_database.py` | 20+ | save_scan, history, migration, SQL injection safety |
| `test_excel_logger.py` | 15+ | New file, append, auto-increment, missing dir |
| `test_change_detector.py` | 9 | New/closed ports, unchanged, missing scans |
| `test_service_kb.py` | 7 | Known ports, fallback, formatting |

---

## Release Gate

v2.1.0 cannot be tagged unless **all boxes above are checked** and:

```
pytest tests/ -v --tb=short
```

Reports zero failures.

---

*ShadowPort Scanner — Use only on systems you own or are authorized to test.*
