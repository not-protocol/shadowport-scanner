## [2.4.0] - 2026-06-25

### Added
- Packet capture via TShark (`core/capture_engine.py`): start/stop a live capture on a chosen interface, with optional BPF filter and duration, run in a background thread so the TUI never blocks.
- New sidebar item **Capture**, between Plugins and Reports (`CaptureView` in `main.py`, following the same in-file widget pattern as `PluginView`/`DashboardView`).
- `captures` table in the SQLite database (`id`, `timestamp`, `interface`, `bpf_filter`, `display_filter`, `duration_seconds`, `packet_count`, `file_path`, `status`), with a `timestamp` index. Schema bumped to version 5 (`config/settings.py`). Migrated automatically by the existing `migrate_schema()`/`init_db()` — no separate migration script needed.
- `db.database.log_capture()` / `get_capture_history()`, following the file's existing `_db_lock` + `_conn()` context-manager convention exactly.
- `ConfigManager` (`config/config_manager.py`) — persistent JSON config at `~/.shadowport/config.json` with atomic writes (tmp file + `os.replace`). Defaults sourced from `config/settings.py` (`DEFAULT_THEME`, `DEFAULT_CAPTURE_INTERFACE`, `DEFAULT_CAPTURE_FILTER`, `DEFAULT_CAPTURE_DURATION`) rather than duplicated.
- `ThemeManager` (`ui/theme_manager.py`) — wraps the existing `ShadowPortApp._apply_theme()` with a read-on-startup / write-on-switch persistence layer, without duplicating the CSS-variable mutation logic.
- `CAPTURES_DIR` setting (`Log/captures/`, created with `mode=0o700`).

### Fixed
- **Theme selection not persisting across restarts.** The v2.3 theme button handler called `self._apply_theme(theme_key)` directly, which only ever mutated `self.styles.__dict__` in memory and never wrote the choice anywhere durable. The handler now calls `self.theme_manager.switch(theme_key)`, which applies the theme via the same `_apply_theme()` and persists the choice via `ConfigManager`. `_apply_theme()` gained an optional `silent` parameter so startup restoration doesn't pop a "Theme: ..." toast before the user has done anything.
- `ConfigManager.load()` recovers gracefully from a corrupted `config.json` (invalid JSON) by resetting to defaults instead of crashing app startup.

### Security
- Packet capture uses `subprocess` in list-form only (`shell=False`) throughout; the BPF filter is always passed as a separate argv element, never shell-interpolated.
- Interface names are validated against `^[a-zA-Z0-9_:.-]{1,15}$` (covers interface aliases like `eth0:1`) before reaching any subprocess call, both in `CaptureEngine.__init__` and at the UI layer.
- Capture output directory (`Log/captures/`) is created with `mode=0o700`.
- `db.log_capture()` uses parameterised `?` queries exclusively, matching every other write path in `db/database.py`. Verified against a live SQL-injection probe in `tests/test_database_capture.py`.
- Non-root capture documented via `setcap cap_net_raw,cap_net_admin+eip` on `dumpcap`, rather than running ShadowPort as root.
- Re-verified `tools/reserved_attr_guard.py` against the v2.4-modified `main.py` — no new attribute collides with Textual's reserved internal names.

### Dependencies
- Added `pytest-mock>=3.12.0` and `pytest-asyncio>=0.23.0` for the v2.4 test suite.
- TShark remains an OS-level dependency, installed separately from Python packages (no new mandatory PyPI dependency).

### Tests
- `tests/test_capture_engine.py` — 15 cases covering validation, command construction, ring-buffer flags, tshark-availability checks, the double-start guard (using a realistically slow mock process to avoid a false pass), event callbacks on failure, and the terminate/wait/kill stop sequence.
- `tests/test_config_manager.py` — 7 cases covering defaults sourced from `config/settings.py`, corrupt-JSON recovery, atomic save (no leftover `.tmp` files), and round-trips.
- `tests/test_theme_manager.py` — 7 cases covering startup restoration (silent), manual switching (toasts + persists), invalid-key handling, and label lookup.
- `tests/test_database_capture.py` — 9 cases covering insert/query, ordering, limits, `pathlib.Path` filepath coercion, a live SQL-injection probe, `get_stats()` integration, and migrating a simulated real v2.3 database forward to v2.5 schema.
