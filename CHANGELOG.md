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

## [2.4.1] - 2026-06-26

### Changed — Wireshark-style Capture UI
- Rebuilt the Capture page filter row from a single free-text BPF box into
  structured fields: Interface select, Protocol select (Any/TCP/UDP/DNS/
  HTTP/HTTPS/ICMP), Port input, and IP/host input. `CaptureView.build_bpf_filter()`
  translates these into a real BPF expression (e.g. picking "DNS" with no
  port maps to `udp port 53`, the actual underlying primitive — `dns` is not
  itself a BPF keyword). A live preview line shows the generated filter
  before you start a capture.
- Packet list grid is now genuinely populated after each capture (previously
  `add_packet_row()` existed but was never called) — `ShadowPortApp._load_packet_rows()`
  runs `tshark -r <file> -T fields ...` on a background thread and streams
  rows back via `call_from_thread`, matching every other worker in this file.
- Packet rows are colored by protocol (TCP/UDP/DNS/HTTP/TLS/ICMP/ARP), each
  built as a `rich.text.Text` object per cell — matching Textual's documented
  `DataTable` per-cell-styling mechanism (there is no CSS-level per-row hook).
- Added a packet **detail pane** below the grid: clicking a row (`cursor_type="row"`,
  `on_data_table_row_selected`) shows its full Time/Source/Destination/Protocol/
  Length/Info in an expanded view, looked up by row key rather than re-parsing
  the (now color-styled) displayed cell text.
- Port/IP fields are validated with the same discipline as
  `core.scanner_engine.validate_target` (shell-metacharacter and non-ASCII
  rejection), scoped to what a BPF `host`/`port` filter actually accepts.
- Protocol/port/IP/duration are now persisted via `ConfigManager` (new keys:
  `capture_protocol`, `capture_port`, `capture_ip`) and restored into the
  filter row on next launch — previously these fields were write-only in
  config and never read back to pre-fill the UI.
- Reorganized the filter row into two stacked rows (filter fields, then
  duration+controls) instead of cramming 7 widgets into one row — at a
  minimum 80-column terminal the single-row version left ~0 width for the
  busiest field.

### Fixed
- The original v2.4.0 Capture page CSS had no sizing rules at all for its
  input row, so the filter `Input`'s default greedy width pushed the
  Start/Stop buttons off-screen on most terminals. Every widget in both new
  rows now has an explicit width (fixed for selects/buttons, `1fr` only for
  the IP field, which benefits most from the room).
- Start/Stop button visibility now actually toggles based on capture state
  (`_toggle_capture_buttons`), matching the existing `_toggle_scan_buttons`
  pattern — previously both buttons were always visible regardless of
  whether a capture was running.

### Dependencies
- Added `rich>=13.6.0` explicitly to `requirements.txt`. It was always a
  transitive dependency of `textual`, but v2.4.1 imports `rich.text.Text`
  directly for the colored packet cells, so it's now declared rather than
  relied on implicitly.

### Tests
- `tests/test_capture_view_filters.py` — 27 cases covering `build_bpf_filter`
  (11), `validate_ip_field` (8), `validate_port_field` (8), and
  `_color_for_protocol` (5). Since `CaptureView` subclasses Textual's
  `Vertical` and importing it requires `textual`, these tests extract the
  literal method source from `main.py` via `ast` and `exec` it against a
  lightweight fake `self.query_one(...)` harness — testing the exact bytes
  shipped, not a hand-copied reimplementation, while staying runnable
  without `textual` installed.
- `tests/test_config_manager.py` — added `test_structured_capture_fields_roundtrip`
  and extended `test_defaults_match_settings` to cover the three new
  `capture_protocol`/`capture_port`/`capture_ip` keys.

## [2.4.2] - 2026-06-27

### Fixed — Capture page crash on startup
- **`InvalidSelectValueError: Illegal select value 'any'.`** Textual's
  `Select` widget takes options as `(label, value)` tuples — the displayed
  text first, the actual stored value second. `CaptureView.PROTOCOL_OPTIONS`
  was built backwards as `(value, label)` (e.g. `("any", "Any")`), so the
  constructor's `value="any"` was checked against the *labels*
  (`"Any"`, `"TCP"`, ...) instead of the values, and never matched — crashing
  on mount every time. Swapped to `("Any", "any")`, `("TCP", "tcp")`, etc.
- Same backwards-tuple mistake existed in `_load_capture_interfaces()`'s
  worker (`interfaces.append((name, stripped))` — bare interface name first,
  full description second). This didn't crash immediately because the
  *initial* hardcoded list (`[("eth0","eth0"), ...]`) has identical
  label/value strings, masking the bug — but once real `tshark -D` output
  populated the dropdown, `Select.value` would have returned the full
  description string (e.g. `"eth0 (Ethernet)"`) instead of the bare
  interface name, which would then fail `CaptureEngine`'s interface
  allow-list regex. Swapped to `(stripped, name)`.
- `CaptureView.prefill()`'s `valid_keys = {key for key, _ in PROTOCOL_OPTIONS}`
  unpacked the wrong tuple position after the first fix above — it would
  have collected the capitalized *labels* instead of the lowercase *values*,
  silently breaking saved-protocol restoration on startup (no crash, just
  a feature regression). Fixed to unpack the value: `{value for _, value in
  PROTOCOL_OPTIONS}`.
- Audited every other `Select(...)`/`set_options(...)` call site in
  `main.py` (`mode-select`, `plugin-select`) — both were already correct in
  the original v2.3 codebase (`(label, value)` order); the bug was isolated
  to the three spots above, all introduced in the v2.4 Capture rebuild.
