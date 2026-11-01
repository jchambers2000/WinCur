"""PySide6 interface for WinCur's modern native Windows desktop experience."""

from __future__ import annotations

import html
import json
import logging
import os
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from PySide6.QtCore import QDate, QEvent, QObject, QPoint, QRect, Qt, QThread, QTimer, QUrl, Signal, QStandardPaths
from PySide6.QtGui import QBrush, QColor, QDesktopServices, QFont, QLinearGradient, QPainter, QPen, QPolygon, QTextOption
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QButtonGroup, QCheckBox, QComboBox, QDateEdit, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QFrame, QGridLayout, QHBoxLayout, QHeaderView, QInputDialog,
    QLabel, QMainWindow, QMessageBox, QPushButton, QScrollArea, QSizePolicy, QSpacerItem, QSplitter, QStackedWidget, QStyle, QTabWidget, QToolTip,
    QTableWidget, QTableWidgetItem, QTextBrowser, QTextEdit, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget)

from . import APP_VERSION
from .build_info import build_identifier
from .branding import HeaderLogo, PortraitEasterEggDialog, load_application_icon, load_portrait
from .checks import run_all_checks
from .action_history import load_action_history, save_action_record
from .hardening import ACTIONS, HardeningEngine, WindowsHardeningBackend, rollback_record_eligibility
from .baselines import BaselineStore, SecurityBaseline
from .baseline_comparison import (EVIDENCE_ONLY, IMPROVEMENT, NEWLY_ASSESSABLE, NO_LONGER_ASSESSABLE,
    NOT_COMPARABLE, REGRESSION, UNCHANGED, BaselineComparison, compare_to_baseline)
from .drift import compare_assessments
from .history_analysis import aggregate_trend_points, build_trend_presentation, filter_history, history_point, latest_saved_timestamp
from .models import (ActionAvailability, ActionOutcome, ActionPreview, ActionRecord, AssessmentEnvelope,
                     AssessmentScore, CheckResult, CheckStatus, ScanRecord)
from .privileges import is_administrator, launch_elevated_helper, pending_output_path
from .presentation import sanitize_display_text
from .reporting import assessment_report_filename, clear_history, default_history_path, delete_history_indices, export_html, load_history, save_history, unique_report_path
from .scoring import load_scoring_config, load_selected_profile, save_selected_profile, score_results
from .theme import AppearanceMode, ThemeManager, ThemeTokens
from .storage import atomic_write_json

LOGGER = logging.getLogger("wincur.ui")


class LayoutStateStore:
    """Small, failure-tolerant store for user-adjusted splitter proportions."""

    def __init__(self, path: Path) -> None:
        self.path = path
        try:
            payload = json.loads(path.read_text(encoding="utf-8")); self.data = payload if isinstance(payload, dict) else {}
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            self.data = {}

    def sizes(self, key: str, fallback: list[int]) -> list[int]:
        candidate = self.data.get(key)
        if not isinstance(candidate, list) or len(candidate) != len(fallback): return fallback
        if not all(isinstance(value, int) and 0 <= value <= 100_000 for value in candidate) or sum(candidate) <= 0: return fallback
        return candidate

    def save(self, splitters: dict[str, QSplitter]) -> None:
        payload = {}
        for key, splitter in splitters.items():
            if splitter.count() <= 1: continue
            persistent = getattr(splitter, "persistent_sizes", None)
            value = persistent() if callable(persistent) else splitter.sizes()
            if value: payload[key] = value
        try:
            atomic_write_json(self.path, payload, indent=2)
        except OSError:
            LOGGER.exception("Workspace layout preference could not be saved")


class CoordinatedTableWidget(QTableWidget):
    empty_space_clicked = Signal()

    def viewportEvent(self, event) -> bool:  # noqa: N802
        if event.type() == QEvent.Type.MouseButtonPress and not self.indexAt(event.position().toPoint()).isValid():
            self.clearSelection(); self.empty_space_clicked.emit(); self.setFocus(Qt.FocusReason.MouseFocusReason); event.accept(); return True
        return super().viewportEvent(event)

    def mousePressEvent(self, event) -> None:  # noqa: N802
        if not self.indexAt(event.position().toPoint()).isValid():
            self.clearSelection(); self.empty_space_clicked.emit(); self.setFocus(Qt.FocusReason.MouseFocusReason); event.accept(); return
        super().mousePressEvent(event)


class CoordinatedTreeWidget(QTreeWidget):
    empty_space_clicked = Signal()

    def viewportEvent(self, event) -> bool:  # noqa: N802
        if event.type() == QEvent.Type.MouseButtonPress and not self.indexAt(event.position().toPoint()).isValid():
            self.clearSelection(); self.empty_space_clicked.emit(); self.setFocus(Qt.FocusReason.MouseFocusReason); event.accept(); return True
        return super().viewportEvent(event)

    def mousePressEvent(self, event) -> None:  # noqa: N802
        if not self.indexAt(event.position().toPoint()).isValid():
            self.clearSelection(); self.empty_space_clicked.emit(); self.setFocus(Qt.FocusReason.MouseFocusReason); event.accept(); return
        super().mousePressEvent(event)


class ItemViewSelectionCoordinator(QObject):
    """Coordinate only WinCur data views; checkbox state remains independent."""

    def __init__(self, parent: QObject) -> None:
        super().__init__(parent); self.views: list[QAbstractItemView] = []; self._neutral: set[QObject] = set(); self._syncing = False

    def register(self, view: QAbstractItemView) -> None:
        if view in self.views: return
        self.views.append(view)
        view.selectionModel().selectionChanged.connect(lambda selected, _deselected, source=view: self._selection_changed(source, selected))
        if hasattr(view, "empty_space_clicked"): view.empty_space_clicked.connect(self.clear_visual_selection)

    def _selection_changed(self, source: QAbstractItemView, selected) -> None:
        if self._syncing or selected.isEmpty(): return
        self._syncing = True
        try:
            for view in self.views:
                if view is not source: view.clearSelection()
        finally:
            self._syncing = False

    def clear_visual_selection(self) -> None:
        self._syncing = True
        try:
            for view in self.views: view.clearSelection()
        finally:
            self._syncing = False

    def register_neutral(self, widget: QWidget) -> None:
        self._neutral.add(widget); widget.installEventFilter(self)

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:  # noqa: N802
        if watched in self._neutral and event.type() == QEvent.Type.MouseButtonPress: self.clear_visual_selection()
        return False


def windows_description() -> str:
    if sys.platform == "win32":
        version = sys.getwindowsversion()
        release = "11" if version.build >= 22000 else "10"
        edition = platform.win32_edition() if hasattr(platform, "win32_edition") else ""
        return f"Windows {release} {edition} (build {version.build})".replace("  ", " ")
    return platform.platform()


def friendly_timestamp(value: object) -> str:
    """Format an ISO timestamp in the user's local timezone without altering storage."""
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        if parsed.tzinfo is None: parsed = parsed.replace(tzinfo=timezone.utc)
        local = parsed.astimezone()
        return local.strftime("%b %d, %I:%M %p")
    except (TypeError, ValueError, OverflowError):
        return "Unknown date/time"


def timestamp_tooltip(value: object) -> str:
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00")); parsed = parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
        local = parsed.astimezone(); zone = local.tzname() or local.strftime("UTC%z")
        return f"Stored UTC: {parsed.astimezone(timezone.utc).isoformat()}\nLocal: {local.strftime('%b %d, %Y %I:%M:%S %p')} {zone} ({local.strftime('%z')})"
    except (TypeError, ValueError, OverflowError): return f"Stored timestamp: {value}"


def evidence_preview(value: object, limit: int = 96) -> str:
    compact = " ".join(sanitize_display_text(value or "Unavailable").split())
    return compact if len(compact) <= limit else compact[:limit - 1].rstrip() + "…"


def combo_data_index(combo: QComboBox, value: object) -> int:
    """Find arbitrary Python item data without QVariant tuple conversion quirks."""
    return next((index for index in range(combo.count()) if combo.itemData(index) == value), -1)


def html_sections(sections: list[tuple[str, object]]) -> str:
    return "".join(f"<p><b>{html.escape(sanitize_display_text(title))}</b><br>{html.escape(sanitize_display_text(text))}</p>" for title, text in sections)


class ScanWorker(QObject):
    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, config: dict, profile: str, privilege: str,
                 check_runner: Callable = run_all_checks, score_runner: Callable = score_results) -> None:
        super().__init__()
        self.config = config; self.profile = profile; self.privilege = privilege
        self.check_runner = check_runner; self.score_runner = score_runner

    def run(self) -> None:
        try:
            findings = self.check_runner(self.config)
            assessment = self.score_runner(findings, self.config, self.profile)
            self.finished.emit(AssessmentEnvelope.create(findings, assessment, self.privilege))
        except Exception as exc:
            LOGGER.exception("Read-only scan failed")
            self.failed.emit(str(exc))


class HistoryWorker(QObject):
    finished = Signal(str)

    def __init__(self, record: ScanRecord, history_path: Path | None = None) -> None:
        super().__init__(); self.record = record; self.history_path = history_path

    def run(self) -> None:
        try:
            save_history(self.record, self.history_path); self.finished.emit("")
        except Exception as exc:
            LOGGER.exception("Assessment history could not be saved")
            self.finished.emit(str(exc))


class PreviewWorker(QObject):
    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, action_id: str | None = None) -> None:
        super().__init__(); self.action_id = action_id

    def run(self) -> None:
        try:
            engine = HardeningEngine(WindowsHardeningBackend())
            ids = [self.action_id] if self.action_id else list(ACTIONS)
            self.finished.emit([engine.preview(action_id) for action_id in ids])
        except Exception as exc:
            self.failed.emit(str(exc))


class ModernHeader(QWidget):
    def __init__(self, theme_manager: ThemeManager, portrait=None, click_window_ms: int = 2000) -> None:
        super().__init__(); self.tokens = theme_manager.tokens; theme_manager.theme_changed.connect(self.set_tokens)
        self.setFixedHeight(68); self._portrait = load_portrait() if portrait is None else portrait; self.easter_dialog = None
        self.logo = HeaderLogo(self._portrait, click_window_ms, self); self.logo.move(14, 10); self.logo.triggered.connect(self._show_easter_egg)

    def _show_easter_egg(self) -> None:
        if self._portrait.isNull(): return
        if self.easter_dialog is not None and self.easter_dialog.isVisible(): return
        self.logo.reset_sequence(); dialog = PortraitEasterEggDialog(self._portrait, self.window()); self.easter_dialog = dialog
        dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True); dialog.finished.connect(self._easter_egg_closed); dialog.show(); dialog.raise_(); dialog.activateWindow()

    def _easter_egg_closed(self, _result: int) -> None:
        self.logo.reset_sequence(); self.easter_dialog = None

    def set_tokens(self, tokens: ThemeTokens) -> None:
        self.tokens = tokens; self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        gradient = QLinearGradient(0, 0, self.width(), 0)
        t = self.tokens
        gradient.setColorAt(0, QColor(t.header_bottom)); gradient.setColorAt(.55, QColor(t.header_mid)); gradient.setColorAt(1, QColor(t.header_top))
        painter.fillRect(self.rect(), gradient)
        painter.setPen(QPen(QColor(t.header_border), 1)); painter.drawLine(0, self.height() - 1, self.width(), self.height() - 1)
        painter.setPen(QColor(t.nav_selected_text)); painter.setFont(QFont("Segoe UI", 20, QFont.Weight.DemiBold)); painter.drawText(70, 31, "WinCur")
        painter.setFont(QFont("Segoe UI", 9)); painter.setPen(QColor(t.header_subtitle)); painter.drawText(72, 51, "Windows security, made understandable")


class MetricPanel(QFrame):
    def __init__(self, title: str, description: str = "") -> None:
        super().__init__(); self.setObjectName("metricPanel")
        layout = QVBoxLayout(self); layout.setContentsMargins(15, 12, 15, 12); layout.setSpacing(3)
        label = QLabel(title); label.setObjectName("metricTitle")
        self.value = QLabel("--"); self.value.setObjectName("metricValue")
        layout.addWidget(label); layout.addWidget(self.value)
        self.description = QLabel(description); self.description.setObjectName("metricDescription"); self.description.setWordWrap(True); layout.addWidget(self.description)


class ResponsiveSplitter(QSplitter):
    """Switch between side-by-side and stacked content without losing user sizing."""

    def __init__(self, breakpoint: int = 1100, parent: QWidget | None = None) -> None:
        super().__init__(Qt.Orientation.Horizontal, parent); self.breakpoint = breakpoint; self.wide_breakpoint = breakpoint + 80; self._changing = False
        self._saved_sizes = {Qt.Orientation.Horizontal: [650, 350], Qt.Orientation.Vertical: [220, 330]}
        self._minimum_primary = {Qt.Orientation.Horizontal: [650, 350], Qt.Orientation.Vertical: [210, 300]}
        self.setChildrenCollapsible(False); self.splitterMoved.connect(self._remember_sizes)

    @staticmethod
    def _valid_sizes(value, fallback: list[int]) -> list[int]:
        if not isinstance(value, list) or len(value) != len(fallback): return list(fallback)
        if not all(isinstance(item, int) and 0 <= item <= 100_000 for item in value) or sum(value) <= 0: return list(fallback)
        return list(value)

    def restore_persistent_sizes(self, value, horizontal_fallback: list[int]) -> None:
        horizontal = horizontal_fallback; vertical = self._saved_sizes[Qt.Orientation.Vertical]
        if isinstance(value, dict):
            horizontal = self._valid_sizes(value.get("horizontal"), horizontal_fallback)
            vertical = self._valid_sizes(value.get("vertical"), vertical)
        else:
            horizontal = self._valid_sizes(value, horizontal_fallback)  # legacy list format
        self._saved_sizes = {Qt.Orientation.Horizontal: horizontal, Qt.Orientation.Vertical: vertical}
        self._changing = True; self._apply_saved_sizes(); self._changing = False

    def persistent_sizes(self) -> dict[str, list[int]]:
        if sum(self.sizes()) > 0: self._saved_sizes[self.orientation()] = self.sizes()
        return {"horizontal": list(self._saved_sizes[Qt.Orientation.Horizontal]), "vertical": list(self._saved_sizes[Qt.Orientation.Vertical])}

    def _normalized_sizes(self, values: list[int], total: int, orientation: Qt.Orientation) -> list[int]:
        available = max(2, total - self.handleWidth())
        first_min, second_min = self._minimum_primary[orientation]
        if available < first_min + second_min:
            first_min = max(1, round(available * first_min / (first_min + second_min))); second_min = max(1, available - first_min)
        ratio = values[0] / max(1, sum(values)); first = round(available * ratio)
        first = max(first_min, min(first, available - second_min)); return [first, max(1, available - first)]

    def _apply_saved_sizes(self) -> None:
        total = self.width() if self.orientation() == Qt.Orientation.Horizontal else self.height()
        values = self._saved_sizes[self.orientation()]
        self.setSizes(self._normalized_sizes(values, total, self.orientation()) if total > self.handleWidth() else values)

    def _remember_sizes(self, *_args) -> None:
        if not self._changing and sum(self.sizes()) > 0: self._saved_sizes[self.orientation()] = self.sizes()

    def update_for_width(self, width: int | None = None) -> None:
        available = self.width() if width is None else width; current = self.orientation()
        target = Qt.Orientation.Vertical if current == Qt.Orientation.Horizontal and available < self.breakpoint else Qt.Orientation.Horizontal if current == Qt.Orientation.Vertical and available > self.wide_breakpoint else current
        if target == current:
            if any(size <= 0 for size in self.sizes()): self._apply_saved_sizes()
            return
        self._changing = True; self.setOrientation(target); self._apply_saved_sizes(); self._changing = False

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event); self.update_for_width(event.size().width())


def segmented_bar(labels: tuple[str, ...], callback: Callable[[int], None], parent: QObject) -> tuple[QWidget, QButtonGroup, list[QPushButton]]:
    container = QWidget(); container.setObjectName("segmentBar"); layout = QHBoxLayout(container); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(4)
    group = QButtonGroup(parent); group.setExclusive(True); buttons: list[QPushButton] = []
    for index, label in enumerate(labels):
        button = QPushButton(label); button.setObjectName("segmentButton"); button.setCheckable(True); button.setMinimumHeight(36); button.setMinimumWidth(button.fontMetrics().horizontalAdvance(label) + 40); button.setSizePolicy(QSizePolicy.Policy.MinimumExpanding, QSizePolicy.Policy.Fixed); button.clicked.connect(lambda checked=False, value=index: callback(value)); group.addButton(button, index); buttons.append(button); layout.addWidget(button)
    buttons[0].setChecked(True); layout.addStretch(1); return container, group, buttons


class TrendChart(QWidget):
    """Dependency-free, single-metric chart with strictly comparable series."""

    point_selected = Signal(object)

    def __init__(self, theme_manager: ThemeManager) -> None:
        super().__init__(); self.tokens = theme_manager.tokens; self.points = []; self.metric_name = "score"; self.connect_points = True; self.hit_points: list[tuple[QPoint, object]] = []; self.selected_point = None; self.keyboard_index = -1
        theme_manager.theme_changed.connect(self.set_tokens); self.setMinimumHeight(190); self.setMouseTracking(True); self.setFocusPolicy(Qt.FocusPolicy.StrongFocus); self.setToolTip("Hover or select a representative daily assessment.")

    def set_tokens(self, tokens: ThemeTokens) -> None:
        self.tokens = tokens; self.update()

    def set_points(self, points: list) -> None:
        self.points = points
        if self.selected_point not in points: self.selected_point = None; self.keyboard_index = -1
        self.update()

    def set_metric(self, metric: str) -> None:
        if metric not in ("score", "coverage"): raise ValueError(f"Unsupported trend metric: {metric}")
        self.metric_name = metric; self.selected_point = None; self.keyboard_index = -1; self.update()

    def set_connect_points(self, enabled: bool) -> None:
        self.connect_points = enabled; self.update()

    def select_point(self, point: object) -> None:
        if point not in self.points: return
        self.selected_point = point; self.keyboard_index = self.points.index(point); self.point_selected.emit(point); self.update()

    def _nearest(self, position: QPoint):
        candidates = [(abs(position.x() - location.x()) ** 2 + abs(position.y() - location.y()) ** 2, point) for location, point in self.hit_points]
        if not candidates: return None
        distance, point = min(candidates, key=lambda item: item[0]); return point if distance <= 144 else None

    def _tooltip(self, point) -> str:
        value = getattr(point, self.metric_name); label = "Score" if self.metric_name == "score" else "Coverage"
        return f"{friendly_timestamp(point.record.get('timestamp_utc'))}\n{label}: {'Unavailable' if value is None else f'{value:.1f}%'}\n{point.privilege} · {point.profile} profile"

    def mouseMoveEvent(self, event) -> None:  # noqa: N802
        point = self._nearest(event.position().toPoint())
        if point: QToolTip.showText(event.globalPosition().toPoint(), self._tooltip(point), self)
        else: QToolTip.hideText()

    def mousePressEvent(self, event) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton:
            point = self._nearest(event.position().toPoint())
            self.setFocus()
            if point: self.select_point(point)
            event.accept(); return
        super().mousePressEvent(event)

    def keyPressEvent(self, event) -> None:  # noqa: N802
        selectable = [point for point in self.points if point.timestamp and getattr(point, self.metric_name) is not None]
        if selectable and event.key() in (Qt.Key.Key_Left, Qt.Key.Key_Right):
            step = -1 if event.key() == Qt.Key.Key_Left else 1; self.keyboard_index = (self.keyboard_index + step) % len(selectable); self.select_point(selectable[self.keyboard_index]); return
        if self.selected_point and event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter, Qt.Key.Key_Space): self.point_selected.emit(self.selected_point); return
        super().keyPressEvent(event)

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self); painter.setRenderHint(QPainter.RenderHint.Antialiasing); self.hit_points = []
        t = self.tokens; painter.fillRect(self.rect(), QColor(t.input)); painter.setPen(QPen(QColor(t.border), 1)); painter.drawRoundedRect(self.rect().adjusted(0, 0, -1, -1), 7, 7)
        area = self.rect().adjusted(48, 34, -22, -38)
        if area.width() < 20 or area.height() < 20: return
        painter.setFont(QFont("Segoe UI", 8))
        for value in (0, 25, 50, 75, 100):
            y = area.bottom() - round(area.height() * value / 100)
            painter.setPen(QPen(QColor(t.border), 1, Qt.PenStyle.DotLine)); painter.drawLine(area.left(), y, area.right(), y)
            painter.setPen(QColor(t.muted_text)); painter.drawText(5, y + 4, f"{value}%")
        valid = [point for point in self.points if point.timestamp and getattr(point, self.metric_name) is not None]
        if not valid:
            label = "score" if self.metric_name == "score" else "coverage"; painter.setPen(QColor(t.muted_text)); painter.drawText(area, Qt.AlignmentFlag.AlignCenter, f"No {label} history matches these filters."); return
        start = min(point.timestamp for point in valid); end = max(point.timestamp for point in valid); raw_span = (end - start).total_seconds(); span = max(raw_span, 1.0)
        x_for = lambda point: area.center().x() if raw_span == 0 else area.left() + round(area.width() * (point.timestamp - start).total_seconds() / span)
        y_for = lambda value: area.bottom() - round(area.height() * max(0.0, min(100.0, value)) / 100)
        groups = {}
        for point in valid: groups.setdefault(point.trend_series_key, []).append(point)
        series_colors = [t.heading, t.success, t.warning, t.informational, t.high]
        for key in sorted(groups, key=str):
            points = sorted(groups[key], key=lambda point: point.timestamp); color_index = sum(ord(character) for character in "|".join(key)) % len(series_colors); pen = QPen(QColor(series_colors[color_index]), 2)
            painter.setPen(pen)
            if self.connect_points:
                for left, right in zip(points, points[1:]): painter.drawLine(x_for(left), y_for(getattr(left, self.metric_name)), x_for(right), y_for(getattr(right, self.metric_name)))
            painter.setBrush(pen.color())
            for point in points:
                position = QPoint(x_for(point), y_for(getattr(point, self.metric_name))); self.hit_points.append((position, point)); selected = point is self.selected_point
                painter.setPen(QPen(QColor(t.selection if selected else pen.color()), 3 if selected else 2))
                if point.privilege.casefold().startswith("admin"): painter.drawRoundedRect(QRect(position.x() - 5, position.y() - 5, 10, 10), 2, 2)
                else: painter.drawEllipse(position, 5, 5)
        label_format = "%b %d" if raw_span <= 86400 * 120 else "%b %Y"
        painter.setPen(QColor(t.muted_text)); painter.drawText(area.left(), self.height() - 12, start.astimezone().strftime(label_format))
        if raw_span > 86400: painter.drawText(area.center().x() - 28, self.height() - 12, (start + (end - start) / 2).astimezone().strftime(label_format))
        if raw_span > 0: painter.drawText(area.right() - 55, self.height() - 12, end.astimezone().strftime(label_format))
        label = "Configuration-hardening score" if self.metric_name == "score" else "Assessment coverage"
        painter.setPen(QPen(QColor(t.heading), 2)); painter.drawLine(area.left(), 16, area.left() + 24, 16); painter.setPen(QColor(t.text)); painter.drawText(area.left() + 30, 20, label)
        painter.setPen(QColor(t.muted_text)); painter.drawText(area.right() - 205, 20, "○ Standard    □ Administrator")
        if self.hasFocus():
            painter.setBrush(Qt.BrushStyle.NoBrush); painter.setPen(QPen(QColor(t.selection), 1, Qt.PenStyle.DotLine)); painter.drawRoundedRect(self.rect().adjusted(3, 3, -4, -4), 6, 6)


class WinCurWindow(QMainWindow):
    assessment_displayed = Signal(object)

    def __init__(self, theme_manager: ThemeManager | None = None, scan_worker_factory: Callable | None = None,
                 baseline_path: Path | None = None, history_path: Path | None = None, layout_path: Path | None = None) -> None:
        super().__init__()
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        self.theme_manager = theme_manager or ThemeManager(parent=self)
        self.history_path = history_path
        preference_root = self.theme_manager.preference_path.parent
        self.layout_store = LayoutStateStore(layout_path or preference_root / "ui_layout.json"); self.layout_splitters: dict[str, QSplitter] = {}
        self.scan_worker_factory = scan_worker_factory or (lambda config, profile, privilege: ScanWorker(config, profile, privilege))
        self.config = load_scoring_config(); self.findings: list[CheckResult] = []
        self.history_records: list[dict] = []; self.action_history_records: list[dict] = []; self.findings_center_rows: list[dict] = []
        self.baseline_store = BaselineStore(baseline_path); self.baseline_collection = self.baseline_store.load(); self.latest_baseline_comparison: BaselineComparison | None = None
        self.baseline_dialog: QDialog | None = None
        self.selected_profile = load_selected_profile(self.config)
        self.application_privilege = "Administrator" if is_administrator() else "Standard"
        self.current_record: ScanRecord | None = None; self.scan_thread: QThread | None = None; self.worker: ScanWorker | None = None
        self.history_thread: QThread | None = None; self.history_worker: HistoryWorker | None = None
        self.pending_history_records: list[ScanRecord] = []
        self.previews: list[ActionPreview] = []; self.preview_thread: QThread | None = None; self.preview_worker: PreviewWorker | None = None; self.preview_request_ids: list[str] = []
        self.validated_preview: ActionPreview | None = None; self.preview_mode = "all"; self.preview_repeat_reasons: dict[str, str] = {}
        self.preview_expiry_timer = QTimer(self); self.preview_expiry_timer.setSingleShot(True); self.preview_expiry_timer.timeout.connect(self._expire_validated_preview)
        self.pending_path: Path | None = None; self.pending_kind = ""; self.pending_action_id = ""; self.pending_started = 0.0; self.action_busy = False; self.score_before_action: float | None = None
        self.helper_timer = QTimer(self); self.helper_timer.setInterval(500); self.helper_timer.timeout.connect(self._poll_helper)
        self.windows_name = windows_description(); self.computer_name = os.environ.get("COMPUTERNAME", platform.node() or "Unknown")
        self.setWindowTitle(f"WinCur {APP_VERSION} - Windows Security Assessment"); self.setMinimumSize(900, 640); self.resize(1180, 800)
        application_icon = load_application_icon()
        if not application_icon.isNull(): self.setWindowIcon(application_icon)
        self._build_ui(); self.selection_coordinator = ItemViewSelectionCoordinator(self)
        for view in [*self.findChildren(QTableWidget), *self.findChildren(QTreeWidget)]: self.selection_coordinator.register(view)
        for widget in (self.content_widget, self.page_heading, self.page_subtitle): self.selection_coordinator.register_neutral(widget)
        self.theme_manager.theme_changed.connect(self._theme_changed); self.theme_manager.apply(); self._update_history()

    def _build_ui(self) -> None:
        root = QWidget(); self.setCentralWidget(root)
        outer = QVBoxLayout(root); outer.setContentsMargins(0, 0, 0, 0); outer.setSpacing(0); self.header = ModernHeader(self.theme_manager); outer.addWidget(self.header)
        body = QHBoxLayout(); body.setContentsMargins(0, 0, 0, 0); body.setSpacing(0); outer.addLayout(body, 1)
        sidebar = QFrame(); self.sidebar_widget = sidebar; sidebar.setObjectName("sidebar"); sidebar.setFixedWidth(224)
        side = QVBoxLayout(sidebar); side.setContentsMargins(12, 18, 12, 14); side.setSpacing(7)
        title = QLabel("Navigation"); title.setObjectName("navTitle"); side.addWidget(title)
        self.nav_group = QButtonGroup(self); self.nav_group.setExclusive(True); self.nav_buttons = []
        nav_items = (("Overview", QStyle.StandardPixmap.SP_ComputerIcon), ("Security Issues", QStyle.StandardPixmap.SP_MessageBoxWarning), ("Activity", QStyle.StandardPixmap.SP_FileDialogDetailedView), ("Settings", QStyle.StandardPixmap.SP_FileDialogContentsView))
        for index, (label, icon) in enumerate(nav_items):
            button = QPushButton(label); button.setIcon(self.style().standardIcon(icon)); button.setObjectName("navButton"); button.setCheckable(True); button.setAutoExclusive(True); button.setMinimumHeight(42); button.clicked.connect(lambda checked=False, page=index: self._set_page(page)); self.nav_group.addButton(button, index); self.nav_buttons.append(button); side.addWidget(button)
        self.nav_buttons[0].setChecked(True)
        side.addSpacerItem(QSpacerItem(1, 1, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))
        safety = QLabel(f"SAFE OPERATION\nAssessments are read-only. WinCur {APP_VERSION} applies only one previewed action after confirmation and UAC."); safety.setWordWrap(True); safety.setObjectName("safetyLabel"); side.addWidget(safety)
        body.addWidget(sidebar)

        content = QWidget(); self.content_widget = content; content.setObjectName("content"); layout = QVBoxLayout(content); layout.setContentsMargins(24, 18, 24, 20); layout.setSpacing(10)
        top = QVBoxLayout(); top.setSpacing(2); self.page_heading = QLabel("Overview"); self.page_heading.setObjectName("heading"); top.addWidget(self.page_heading); self.page_subtitle = QLabel("Current security assessment and recommended next steps."); self.page_subtitle.setObjectName("intro"); self.page_subtitle.setWordWrap(True); top.addWidget(self.page_subtitle); layout.addLayout(top)
        self.pages = QStackedWidget(); self.pages.addWidget(self._scrollable_page(self._dashboard_page())); self.pages.addWidget(self._security_issues_page()); self.pages.addWidget(self._activity_page()); self.pages.addWidget(self._scrollable_page(self._settings_page())); layout.addWidget(self.pages, 1); body.addWidget(content, 1)
        for table in self.findChildren(QTableWidget):
            table.setAlternatingRowColors(False); table.setShowGrid(False); table.setWordWrap(False); table.setTextElideMode(Qt.TextElideMode.ElideRight); table.verticalHeader().setDefaultSectionSize(30); table.verticalHeader().setMinimumSectionSize(26)
        for tree in self.findChildren(QTreeWidget): tree.setAlternatingRowColors(False); tree.setUniformRowHeights(True); tree.setTextElideMode(Qt.TextElideMode.ElideRight)
        self._refresh_baseline_ui()

    def _register_splitter(self, key: str, splitter: QSplitter, defaults: list[int]) -> QSplitter:
        splitter.setChildrenCollapsible(False); splitter.setHandleWidth(5)
        if isinstance(splitter, ResponsiveSplitter): splitter.restore_persistent_sizes(self.layout_store.data.get(key), defaults)
        else: splitter.setSizes(self.layout_store.sizes(key, defaults))
        self.layout_splitters[key] = splitter
        return splitter

    @staticmethod
    def _scrollable_page(widget: QWidget) -> QScrollArea:
        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setFrameShape(QFrame.Shape.NoFrame); scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff); scroll.setWidget(widget); return scroll

    def _dashboard_page(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(10)
        header = QHBoxLayout(); heading_box = QVBoxLayout(); title = QLabel("Your PC Security"); title.setObjectName("pageTitle"); heading_box.addWidget(title)
        intro = QLabel("Review important Windows security settings and decide what to address next. Assessments are read-only."); intro.setObjectName("intro"); intro.setWordWrap(True); heading_box.addWidget(intro); header.addLayout(heading_box, 1)
        self.scan_button = QPushButton("Scan PC"); self.scan_button.setObjectName("scanButton"); self.scan_button.setMinimumWidth(112); self.scan_button.clicked.connect(self.start_scan); header.addWidget(self.scan_button)
        elevated = self.application_privilege == "Administrator"
        self.elevated_button = QPushButton("Already Running as Administrator" if elevated else "Scan as Administrator"); self.elevated_button.setObjectName("secondaryButton"); self.elevated_button.setToolTip("WinCur is already running with administrator privileges; a second elevated scan is unnecessary." if elevated else "Run the same read-only assessment with administrator visibility after an explicit UAC prompt."); self.elevated_button.setEnabled(not elevated); self.elevated_button.clicked.connect(self._run_elevated_scan); header.addWidget(self.elevated_button)
        self.administrator_mode_label = QLabel("Administrator Mode"); self.administrator_mode_label.setObjectName("modeLabel"); self.administrator_mode_label.setVisible(elevated); self.administrator_mode_label.setToolTip("WinCur is already running with administrator privileges."); header.addWidget(self.administrator_mode_label)
        self.export_button = QPushButton("Export Report"); self.export_button.setObjectName("secondaryButton"); self.export_button.setEnabled(False); self.export_button.clicked.connect(self.export_report); header.addWidget(self.export_button); layout.addLayout(header)

        self.overview_status_label = QLabel("Scan required"); self.overview_status_label.setObjectName("detailTitle"); layout.addWidget(self.overview_status_label)
        self.overview_explanation_label = QLabel("Run an assessment to review selected configuration-hardening checks. A score is not a guarantee of protection."); self.overview_explanation_label.setWordWrap(True); self.overview_explanation_label.setObjectName("intro"); layout.addWidget(self.overview_explanation_label)
        metrics = QHBoxLayout(); metrics.setSpacing(10)
        self.score_panel = MetricPanel("Configuration-hardening score", "Selected hardening checks—not overall device security.")
        self.coverage_panel = MetricPanel("Assessment coverage", "How much of the selected assessment could be evaluated.")
        self.findings_panel = MetricPanel("Security findings", "Confirmed failures are separate from checks needing more assessment.")
        for panel in (self.score_panel, self.coverage_panel, self.findings_panel): panel.setMinimumWidth(190); metrics.addWidget(panel, 1)
        layout.addLayout(metrics)

        info = QFrame(); info.setObjectName("infoPanel"); info_layout = QGridLayout(info); info_layout.setContentsMargins(14, 9, 14, 9); info_layout.setHorizontalSpacing(18); info_layout.setVerticalSpacing(4)
        self.assessment_timestamp_label = QLabel("Last assessment: None"); self.assessment_timestamp_label.setObjectName("infoValue"); info_layout.addWidget(self.assessment_timestamp_label, 0, 0)
        self.assessment_privilege_label = QLabel("Assessment privilege: None"); self.assessment_privilege_label.setObjectName("infoValue"); info_layout.addWidget(self.assessment_privilege_label, 0, 1)
        self.assessment_profile_label = QLabel(f"Profile: {self.selected_profile}"); self.assessment_profile_label.setObjectName("infoValue"); info_layout.addWidget(self.assessment_profile_label, 0, 2)
        self.assessment_freshness_label = QLabel("Freshness: No assessment"); self.assessment_freshness_label.setObjectName("infoValue"); info_layout.addWidget(self.assessment_freshness_label, 1, 0)
        self.assessment_source_label = QLabel("Assessment state: None"); self.assessment_source_label.setObjectName("infoValue"); self.assessment_source_label.setWordWrap(True); info_layout.addWidget(self.assessment_source_label, 1, 1)
        self.app_privilege_label = QLabel(f"Application privilege: {self.application_privilege}"); self.app_privilege_label.setObjectName("modeLabel"); info_layout.addWidget(self.app_privilege_label, 1, 2)
        self.scan_message = QLabel("Ready to scan"); self.scan_message.setObjectName("scanMessage"); self.scan_message.setWordWrap(True); info_layout.addWidget(self.scan_message, 2, 0, 1, 3)
        for column in range(3): info_layout.setColumnStretch(column, 1)
        layout.addWidget(info)
        self.dashboard_baseline_panel = QFrame(); self.dashboard_baseline_panel.setObjectName("infoPanel"); baseline_layout = QHBoxLayout(self.dashboard_baseline_panel); baseline_layout.setContentsMargins(10, 6, 10, 6); self.dashboard_baseline_label = QLabel("No saved snapshot is active. A snapshot lets future scans be compared with a reference you choose."); self.dashboard_baseline_label.setTextFormat(Qt.TextFormat.PlainText); self.dashboard_baseline_label.setObjectName("infoValue"); self.dashboard_baseline_label.setWordWrap(True); baseline_layout.addWidget(self.dashboard_baseline_label, 1); self.manage_baselines_button = QPushButton("Manage Saved Snapshots…"); self.manage_baselines_button.setObjectName("secondaryButton"); self.manage_baselines_button.setToolTip("Create, select, rename, delete, or compare saved assessment snapshots."); self.manage_baselines_button.clicked.connect(self._open_saved_snapshots); baseline_layout.addWidget(self.manage_baselines_button); layout.addWidget(self.dashboard_baseline_panel)
        issues_header = QHBoxLayout(); issue_title = QLabel("Priority issues"); issue_title.setObjectName("detailTitle"); issues_header.addWidget(issue_title); issues_header.addStretch(1); view_all = QPushButton("View all issues"); view_all.setObjectName("secondaryButton"); view_all.clicked.connect(lambda: self._open_security_issues(0)); issues_header.addWidget(view_all); layout.addLayout(issues_header)
        self.dashboard_findings = CoordinatedTreeWidget(); self.dashboard_findings.setHeaderLabels(["Finding", "Why it needs attention", "Severity"]); self.dashboard_findings.setRootIsDecorated(False); self.dashboard_findings.setMinimumHeight(110); self.dashboard_findings.setMaximumHeight(172); self.dashboard_findings.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents); self.dashboard_findings.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch); self.dashboard_findings.header().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents); self.dashboard_findings.itemDoubleClicked.connect(lambda *_: self._open_security_issues(0)); layout.addWidget(self.dashboard_findings)
        self.category_toggle_button = QPushButton("Show Category Summary"); self.category_toggle_button.setObjectName("xpButton"); self.category_toggle_button.clicked.connect(self._toggle_category_summary); layout.addWidget(self.category_toggle_button, 0, Qt.AlignmentFlag.AlignLeft)
        self.category_summary_widget = self._summary_tab(); self.category_summary_widget.setVisible(False); self.category_summary_widget.setMaximumHeight(245); layout.addWidget(self.category_summary_widget)
        layout.addStretch(1)
        return page

    def _set_page(self, index: int) -> None:
        if not 0 <= index < self.pages.count(): return
        titles = ("Overview", "Security Issues", "Activity", "Settings"); subtitles = ("Current security assessment and recommended next steps.", "Review findings and explicitly previewed fixes.", "Review previous security assessments and hardening activity.", "Manage appearance, assessment depth, local data, and application information.")
        self.pages.setCurrentIndex(index); self.nav_buttons[index].setChecked(True); self.page_heading.setText(titles[index]); self.page_subtitle.setText(subtitles[index])
        if hasattr(self, "selection_coordinator"): self.selection_coordinator.clear_visual_selection()

    def mousePressEvent(self, event) -> None:  # noqa: N802
        if hasattr(self, "selection_coordinator"): self.selection_coordinator.clear_visual_selection()
        super().mousePressEvent(event)

    def _show_settings(self) -> None:
        dialog = QDialog(self); dialog.setWindowTitle("WinCur Settings and About"); dialog.setMinimumWidth(430); layout = QVBoxLayout(dialog)
        form = QFormLayout(); appearance = QComboBox(); appearance.addItems([mode.value for mode in AppearanceMode]); appearance.setCurrentText(self.theme_manager.mode.value); appearance.currentTextChanged.connect(self._appearance_changed); form.addRow("Appearance:", appearance); layout.addLayout(form)
        policy = self.config.get("policy_version", self.config.get("methodology_version", "Unversioned")); about = QLabel(f"WinCur {APP_VERSION}\nBuild: {build_identifier()}\nWindows Security Assessment\n\nRead-only assessment and saved-assessment comparison.\nScoring policy: {policy}\nSaved snapshots are references, not proof of security. Changes are observed only when assessments are compared."); about.setWordWrap(True); about.setObjectName("methodology"); layout.addWidget(about)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close); buttons.rejected.connect(dialog.reject); buttons.accepted.connect(dialog.accept); layout.addWidget(buttons); dialog.exec()

    def _appearance_changed(self, value: str) -> None:
        self.theme_manager.set_mode(AppearanceMode(value))
        if hasattr(self, "appearance_combo") and self.appearance_combo.currentText() != value:
            self.appearance_combo.blockSignals(True); self.appearance_combo.setCurrentText(value); self.appearance_combo.blockSignals(False)

    def _show_about(self) -> None:
        policy = self.config.get("policy_version", self.config.get("methodology_version", "Unversioned"))
        QMessageBox.about(self, "About WinCur", f"WinCur {APP_VERSION} — Windows Security Assessment\nBuild: {build_identifier()}\n\nRead-only assessment and saved-assessment comparison. Saved snapshots are references, not proof of security. Changes are observed only when assessments are compared.\nScoring policy version: {policy}")

    def _security_issues_page(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(9)
        intro = QLabel("Start with confirmed issues. Open the safeguarded fix workspace only when you need it."); intro.setObjectName("intro"); intro.setWordWrap(True); layout.addWidget(intro)
        bar, self.issues_view_group, self.issues_view_buttons = segmented_bar(("Current checklist", "Fix workspace"), self._set_issues_view, self); layout.addWidget(bar)
        self.issues_pages = QStackedWidget(); self.current_issues_scroll = self._scrollable_page(self._findings_tab()); self.issues_pages.addWidget(self.current_issues_scroll); self.issues_pages.addWidget(self._hardening_tab()); layout.addWidget(self.issues_pages, 1); return page

    def _activity_page(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(9)
        bar, self.activity_view_group, self.activity_view_buttons = segmented_bar(("Scan History", "Hardening Audit"), self._set_activity_view, self); layout.addWidget(bar)
        self.activity_pages = QStackedWidget(); self.activity_pages.addWidget(self._history_tab()); self.activity_pages.addWidget(self._action_history_tab()); layout.addWidget(self.activity_pages, 1); return page

    def _settings_page(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(12)
        appearance_box = QFrame(); appearance_box.setObjectName("infoPanel"); appearance_layout = QVBoxLayout(appearance_box); appearance_title = QLabel("Appearance"); appearance_title.setObjectName("detailTitle"); appearance_layout.addWidget(appearance_title); appearance_form = QFormLayout(); self.appearance_combo = QComboBox(); self.appearance_combo.setObjectName("appearanceCombo"); self.appearance_combo.addItems([AppearanceMode.SYSTEM.value, AppearanceMode.LIGHT.value, AppearanceMode.DARK.value]); self.appearance_combo.setCurrentText(self.theme_manager.mode.value); self.appearance_combo.setToolTip("Choose Light, Dark, or follow Windows."); self.appearance_combo.currentTextChanged.connect(self._appearance_changed); appearance_form.addRow("Theme:", self.appearance_combo); appearance_layout.addLayout(appearance_form); layout.addWidget(appearance_box)

        assessment_box = QFrame(); assessment_box.setObjectName("infoPanel"); assessment_layout = QVBoxLayout(assessment_box); assessment_title = QLabel("Security assessments"); assessment_title.setObjectName("detailTitle"); assessment_layout.addWidget(assessment_title); assessment_form = QFormLayout(); self.profile_combo = QComboBox(); self.profile_combo.setObjectName("profileCombo"); self.profile_combo.addItems(list(self.config.get("profiles", {}))); self.profile_combo.setCurrentText(self.selected_profile); self.profile_combo.setToolTip("Changes score interpretation only; it does not run checks or modify Windows."); self.profile_combo.currentTextChanged.connect(self._profile_changed); assessment_form.addRow("Assessment depth:", self.profile_combo); assessment_layout.addLayout(assessment_form)
        self.profile_explanation_label = QLabel(); self.profile_explanation_label.setObjectName("intro"); self.profile_explanation_label.setWordWrap(True); assessment_layout.addWidget(self.profile_explanation_label); self._update_profile_explanation(self.selected_profile)
        scan_explanation = QLabel(f"Standard scans are recommended for routine use. Administrator scans are also read-only, require an explicit UAC choice, and may assess settings unavailable to a Standard scan. Scoring policy: {self.config.get('policy_version', 'Unversioned')}."); scan_explanation.setObjectName("infoValue"); scan_explanation.setWordWrap(True); assessment_layout.addWidget(scan_explanation); layout.addWidget(assessment_box)

        data_box = QFrame(); data_box.setObjectName("infoPanel"); data_layout = QVBoxLayout(data_box); data_title = QLabel("History and data"); data_title.setObjectName("detailTitle"); data_layout.addWidget(data_title); data_text = QLabel("Assessments, preserved snapshot files, reports, preferences, and hardening audit records stay local to this PC."); data_text.setObjectName("intro"); data_text.setWordWrap(True); data_layout.addWidget(data_text); data_buttons = QHBoxLayout(); self.manage_history_settings_button = QPushButton("Manage Scan History"); self.manage_history_settings_button.setObjectName("secondaryButton"); self.manage_history_settings_button.clicked.connect(self._open_history_management); data_buttons.addWidget(self.manage_history_settings_button); self.open_data_folder_button = QPushButton("Open Data Folder"); self.open_data_folder_button.setObjectName("secondaryButton"); self.open_data_folder_button.clicked.connect(self._open_data_folder); data_buttons.addWidget(self.open_data_folder_button); data_buttons.addStretch(1); data_layout.addLayout(data_buttons); layout.addWidget(data_box)

        about_box = QFrame(); about_box.setObjectName("infoPanel"); about_layout = QVBoxLayout(about_box); about_title = QLabel("About WinCur"); about_title.setObjectName("detailTitle"); about_layout.addWidget(about_title); about = QLabel(f"WinCur {APP_VERSION} — Windows Security Assessment\nBuild: {build_identifier()}\n\nWinCur evaluates selected configuration-hardening settings. Scores and coverage are assessment indicators, not guarantees of security. Scans are read-only. Any supported remediation remains individual, previewed, explicitly confirmed, verified, and subject to existing UAC and policy safeguards."); about.setTextFormat(Qt.TextFormat.PlainText); about.setWordWrap(True); about.setObjectName("infoValue"); about_layout.addWidget(about); layout.addWidget(about_box); layout.addStretch(1); return page

    def _update_profile_explanation(self, profile: str) -> None:
        if not hasattr(self, "profile_explanation_label"): return
        descriptions = {"Standard": "Recommended for most Windows PCs.", "Advanced": "Additional security configuration checks.", "Enterprise": "Organization-focused security assessment."}
        explanation = descriptions.get(profile, "Assessment depth controls how existing findings are scored.")
        self.profile_explanation_label.setText(f"{explanation} Changing assessment depth can change the displayed score and coverage without changing Windows settings.")

    def _open_history_management(self) -> None:
        self._set_page(2); self._set_activity_view(0)

    def _open_data_folder(self) -> None:
        folder = (self.history_path or default_history_path()).parent
        if not folder.exists(): QMessageBox.information(self, "Application data", "The WinCur data folder will be created after data is first saved."); return
        if not QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder))): QMessageBox.warning(self, "Application data", "Windows could not open the WinCur data folder.")

    def _open_security_issues(self, view: int = 0) -> None:
        self._set_page(1); self._set_issues_view(view)

    def _set_issues_view(self, view: int) -> None:
        if view == 2: view = 1  # compatibility for existing internal Fix Workspace callers
        if not 0 <= view < self.issues_pages.count(): view = 0
        self.issues_pages.setCurrentIndex(view); self.issues_view_buttons[view].setChecked(True)

    def _open_saved_snapshots(self) -> None:
        if self.baseline_dialog is None:
            dialog = QDialog(self); dialog.setWindowTitle("Manage Saved Snapshots"); dialog.setModal(True); dialog.setMinimumSize(720, 500); dialog.resize(860, 620)
            layout = QVBoxLayout(dialog); layout.setContentsMargins(14, 14, 14, 12); layout.setSpacing(10)
            self.baseline_scroll = QScrollArea(); self.baseline_scroll.setWidgetResizable(True); self.baseline_scroll.setFrameShape(QFrame.Shape.NoFrame); self.baseline_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff); self.baseline_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded); self.baseline_page = self._baselines_page(); self.baseline_scroll.setWidget(self.baseline_page); layout.addWidget(self.baseline_scroll, 1)
            buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close); buttons.rejected.connect(dialog.reject); buttons.accepted.connect(dialog.accept); layout.addWidget(buttons)
            self.baseline_dialog = dialog
        self.baseline_collection = self.baseline_store.load()
        self._refresh_baseline_ui(); self._update_baseline_for_current()
        self.baseline_advanced_widget.setVisible(False); self.baseline_advanced_button.setText("Show Detailed Comparison")
        self.baseline_scroll.verticalScrollBar().setValue(0)
        self._resize_baseline_dialog(False)
        self.baseline_dialog.exec()

    def _resize_baseline_dialog(self, expanded: bool) -> None:
        if self.baseline_dialog is None: return
        screen = self.baseline_dialog.screen() or QApplication.primaryScreen()
        if screen is None: return
        available = screen.availableGeometry().adjusted(16, 16, -16, -16)
        if available.width() < 320 or available.height() < 320: available = screen.availableGeometry()
        maximum_width = max(320, available.width()); maximum_height = max(320, available.height())
        self.baseline_dialog.setMinimumSize(min(720, maximum_width), min(500, maximum_height))
        self.baseline_dialog.layout().activate(); preferred = self.baseline_dialog.sizeHint()
        page_preferred = self.baseline_page.sizeHint() if expanded and hasattr(self, "baseline_page") else preferred
        desired_width = max(860, preferred.width(), page_preferred.width() + 28) if expanded else 860
        desired_height = max(620, preferred.height(), page_preferred.height() + 80) if expanded else 620
        width = min(maximum_width, max(self.baseline_dialog.minimumWidth(), desired_width)); height = min(maximum_height, max(self.baseline_dialog.minimumHeight(), desired_height))
        self.baseline_dialog.resize(width, height)
        center = available.center(); self.baseline_dialog.move(center.x() - width // 2, center.y() - height // 2)

    def _finish_baseline_expansion(self) -> None:
        self._resize_baseline_dialog(True)
        if hasattr(self, "baseline_scroll"): self.baseline_scroll.ensureWidgetVisible(self.baseline_advanced_widget, 12, 12)

    def _set_activity_view(self, index: int) -> None:
        if not 0 <= index < self.activity_pages.count(): index = 0
        self.activity_pages.setCurrentIndex(index); self.activity_view_buttons[index].setChecked(True)

    def _toggle_category_summary(self) -> None:
        visible = not self.category_summary_widget.isVisible(); self.category_summary_widget.setVisible(visible); self.category_toggle_button.setText("Hide Category Summary" if visible else "Show Category Summary")

    def _findings_page(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(0, 0, 0, 0)
        selector_row = QHBoxLayout(); selector_row.addWidget(QLabel("Finding view:")); self.findings_view_selector = QComboBox(); self.findings_view_selector.addItems(["Current assessment", "Saved finding changes"]); self.findings_view_selector.setMaximumWidth(240); selector_row.addWidget(self.findings_view_selector); selector_row.addStretch(1); layout.addLayout(selector_row)
        self.findings_pages = QStackedWidget(); self.findings_pages.addWidget(self._findings_tab()); self.findings_pages.addWidget(self._findings_center_tab()); self.findings_view_selector.currentIndexChanged.connect(self.findings_pages.setCurrentIndex); layout.addWidget(self.findings_pages, 1); return page

    def _trends_page(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(0, 0, 0, 0)
        bar, self.trends_view_group, self.trends_view_buttons = segmented_bar(("Score and coverage", "Security configuration changes"), self._set_trends_view, self); layout.addWidget(bar)
        self.trends_pages = QStackedWidget(); self.trends_pages.addWidget(self._trends_tab()); self.trends_pages.addWidget(self._drift_tab()); layout.addWidget(self.trends_pages, 1); return page

    def _history_page(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(0, 0, 0, 0)
        bar, self.history_view_group, self.history_view_buttons = segmented_bar(("Assessments", "Hardening audit"), self._set_history_view, self); layout.addWidget(bar)
        self.history_pages = QStackedWidget(); self.history_pages.addWidget(self._history_tab()); self.history_pages.addWidget(self._action_history_tab()); layout.addWidget(self.history_pages, 1); return page

    def _set_trends_view(self, index: int) -> None:
        if hasattr(self, "trends_pages") and 0 <= index < self.trends_pages.count(): self.trends_pages.setCurrentIndex(index); self.trends_view_buttons[index].setChecked(True)

    def _set_history_view(self, index: int) -> None:
        if hasattr(self, "history_pages") and 0 <= index < self.history_pages.count(): self.history_pages.setCurrentIndex(index); self.history_view_buttons[index].setChecked(True)

    def _baselines_page(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(8)
        explanation = QLabel("A saved snapshot records your computer's security settings so future scans can be compared against them."); explanation.setObjectName("intro"); explanation.setWordWrap(True); layout.addWidget(explanation)
        management = QFrame(); management.setObjectName("infoPanel"); grid = QGridLayout(management); grid.setContentsMargins(12, 10, 12, 10); grid.setHorizontalSpacing(8); grid.addWidget(QLabel("Active saved snapshot:"), 0, 0); self.active_baseline_combo = QComboBox(); self.active_baseline_combo.setMinimumWidth(180); self.active_baseline_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed); self.active_baseline_combo.currentIndexChanged.connect(self._active_baseline_changed); grid.addWidget(self.active_baseline_combo, 0, 1, 1, 3)
        self.create_baseline_button = QPushButton("Create Snapshot…"); self.create_baseline_button.setObjectName("scanButton"); self.create_baseline_button.clicked.connect(self._create_baseline); grid.addWidget(self.create_baseline_button, 1, 1)
        self.rename_baseline_button = QPushButton("Rename…"); self.rename_baseline_button.setObjectName("secondaryButton"); self.rename_baseline_button.clicked.connect(self._rename_baseline); grid.addWidget(self.rename_baseline_button, 1, 2)
        self.delete_baseline_button = QPushButton("Delete…"); self.delete_baseline_button.setObjectName("destructiveButton"); self.delete_baseline_button.clicked.connect(self._delete_baseline); grid.addWidget(self.delete_baseline_button, 1, 3)
        self.baseline_metadata = QLabel("No active saved snapshot. A snapshot is a reference, not proof that a device is secure."); self.baseline_metadata.setTextFormat(Qt.TextFormat.PlainText); self.baseline_metadata.setObjectName("infoValue"); self.baseline_metadata.setWordWrap(True); grid.addWidget(self.baseline_metadata, 2, 0, 1, 4); grid.setColumnStretch(1, 1); layout.addWidget(management)
        controls = QGridLayout(); controls.addWidget(QLabel("Assessment to compare:"), 0, 0); self.baseline_assessment_combo = QComboBox(); self.baseline_assessment_combo.setMinimumWidth(180); self.baseline_assessment_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed); self.baseline_assessment_combo.currentIndexChanged.connect(lambda *_: self._invalidate_displayed_baseline_comparison("Assessment selection changed. Choose Compare to generate a matching result.")); controls.addWidget(self.baseline_assessment_combo, 0, 1)
        self.compare_baseline_button = QPushButton("Compare Against Saved Snapshot"); self.compare_baseline_button.setObjectName("secondaryButton"); self.compare_baseline_button.clicked.connect(self._compare_selected_baseline); controls.addWidget(self.compare_baseline_button, 1, 1, Qt.AlignmentFlag.AlignRight); controls.setColumnStretch(1, 1); layout.addLayout(controls)
        self.baseline_compatibility = QLabel("Select an active baseline and an assessment."); self.baseline_compatibility.setTextFormat(Qt.TextFormat.PlainText); self.baseline_compatibility.setObjectName("methodology"); self.baseline_compatibility.setWordWrap(True); layout.addWidget(self.baseline_compatibility)
        summary = QGridLayout(); self.baseline_regressions = MetricPanel("Settings worsened"); self.baseline_improvements = MetricPanel("Settings improved"); self.baseline_unchanged = MetricPanel("No change"); self.baseline_review = MetricPanel("Require review")
        for index, panel in enumerate((self.baseline_regressions, self.baseline_improvements, self.baseline_unchanged, self.baseline_review)): panel.value.setText("0"); summary.addWidget(panel, index // 2, index % 2)
        layout.addLayout(summary)
        self.baseline_advanced_button = QPushButton("Show Detailed Comparison"); self.baseline_advanced_button.setObjectName("xpButton"); self.baseline_advanced_button.clicked.connect(self._toggle_baseline_advanced); layout.addWidget(self.baseline_advanced_button, 0, Qt.AlignmentFlag.AlignLeft)
        splitter = QSplitter(Qt.Orientation.Vertical); splitter.setChildrenCollapsible(False); splitter.setMinimumHeight(340); self.baseline_results_table = CoordinatedTableWidget(0, 6); self.baseline_results_table.setHorizontalHeaderLabels(["Security check", "Category", "Saved snapshot", "Current", "Change", "Severity"]); self.baseline_results_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows); self.baseline_results_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers); self.baseline_results_table.setSortingEnabled(True); self.baseline_results_table.verticalHeader().setVisible(False); self.baseline_results_table.verticalHeader().setDefaultSectionSize(30); self.baseline_results_table.verticalHeader().setMinimumSectionSize(26); self.baseline_results_table.setMinimumHeight(180); self.baseline_results_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for column in range(1, 6): self.baseline_results_table.horizontalHeader().setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        self.baseline_results_table.itemSelectionChanged.connect(self._show_baseline_result); splitter.addWidget(self.baseline_results_table)
        detail = QWidget(); detail_layout = QVBoxLayout(detail); detail_layout.setContentsMargins(0, 6, 0, 0); self.baseline_result_title = QLabel("Select a comparison result."); self.baseline_result_title.setTextFormat(Qt.TextFormat.PlainText); self.baseline_result_title.setWordWrap(True); self.baseline_result_title.setObjectName("detailTitle"); detail_layout.addWidget(self.baseline_result_title); self.baseline_result_details = QTextBrowser(); self.baseline_result_details.setMinimumHeight(80); detail_layout.addWidget(self.baseline_result_details); splitter.addWidget(detail); splitter.setStretchFactor(0, 3); splitter.setStretchFactor(1, 1); self.baseline_comparison_splitter = self._register_splitter("snapshot_comparison", splitter, [300, 150]); self.baseline_advanced_widget = splitter; self.baseline_advanced_widget.setVisible(False); layout.addWidget(splitter, 1); return page

    def _toggle_baseline_advanced(self) -> None:
        visible = self.baseline_advanced_widget.isHidden(); self.baseline_advanced_widget.setVisible(visible)
        if visible:
            self.baseline_advanced_widget.setSizes(self.layout_store.sizes("snapshot_comparison", [300, 150])); QTimer.singleShot(0, self._finish_baseline_expansion)
        else:
            self._resize_baseline_dialog(False); self.baseline_scroll.verticalScrollBar().setValue(0)
        self.baseline_advanced_button.setText("Hide Detailed Comparison" if visible else "Show Detailed Comparison")

    def _refresh_baseline_ui(self) -> None:
        if not hasattr(self, "active_baseline_combo"):
            self._update_dashboard_baseline()
            return
        selected = self.baseline_collection.active_baseline_id; self.active_baseline_combo.blockSignals(True); self.active_baseline_combo.clear(); self.active_baseline_combo.addItem("No active saved snapshot", None)
        for baseline in self.baseline_collection.baselines: self.active_baseline_combo.addItem(baseline.name, baseline.baseline_id)
        row = self.active_baseline_combo.findData(selected); self.active_baseline_combo.setCurrentIndex(row if row >= 0 else 0); self.active_baseline_combo.blockSignals(False)
        active = self.baseline_collection.active; enabled = active is not None; self.rename_baseline_button.setEnabled(enabled); self.delete_baseline_button.setEnabled(enabled)
        if active:
            snapshot = active.assessment_snapshot; assessment = snapshot.get("assessment", {}); score = assessment.get("score"); coverage = assessment.get("coverage")
            self.baseline_metadata.setText(f"{active.name} · Created {friendly_timestamp(active.created_utc)} · Assessment {friendly_timestamp(snapshot.get('timestamp_utc'))}\nProfile {assessment.get('profile', 'Legacy')} · Policy {assessment.get('policy_version', 'Unversioned')} · Privilege {snapshot.get('assessment_privilege', 'Unknown')} · Score {'Not scored' if score is None else f'{float(score):.1f}%'} · Coverage {'Unknown' if coverage is None else f'{float(coverage):.1f}%'}")
            self.baseline_metadata.setToolTip(f"Baseline created:\n{timestamp_tooltip(active.created_utc)}\nAssessment:\n{timestamp_tooltip(snapshot.get('timestamp_utc'))}")
        else: self.baseline_metadata.setText("No active saved snapshot. A snapshot is a reference, not proof that a device is secure.")
        self._refresh_baseline_assessments()
        available = self.baseline_assessment_combo.count() > 0 and isinstance(self.baseline_assessment_combo.currentData(), dict)
        self.create_baseline_button.setEnabled(available); self.compare_baseline_button.setEnabled(enabled and available)
        if self.baseline_collection.warnings: self.baseline_compatibility.setText("Storage warning: " + " ".join(self.baseline_collection.warnings))
        elif not available: self.baseline_compatibility.setText("No current or saved assessment is available. Run a read-only assessment before creating a snapshot.")
        elif not enabled: self.baseline_compatibility.setText("Create a snapshot from the selected assessment, or select an existing snapshot to compare.")
        else: self.baseline_compatibility.setText("Choose an assessment and compare it with the active saved snapshot.")
        self._update_dashboard_baseline()

    def _refresh_baseline_assessments(self) -> None:
        if not hasattr(self, "baseline_assessment_combo"): return
        current_timestamp = self.baseline_assessment_combo.currentData().get("timestamp_utc") if isinstance(self.baseline_assessment_combo.currentData(), dict) else None
        self.baseline_assessment_combo.blockSignals(True); self.baseline_assessment_combo.clear()
        if self.current_record:
            record = self.current_record.to_dict(); self.baseline_assessment_combo.addItem(f"Displayed · {friendly_timestamp(record.get('timestamp_utc'))} · {record.get('assessment_privilege', 'Unknown')}", record); self.baseline_assessment_combo.setItemData(0, timestamp_tooltip(record.get("timestamp_utc")), Qt.ItemDataRole.ToolTipRole)
        for record in reversed(self.history_records):
            assessment = record.get("assessment", {}); score = assessment.get("score"); label = f"{friendly_timestamp(record.get('timestamp_utc'))} · {record.get('assessment_privilege', 'Unknown')} · {'—' if score is None else f'{float(score):.0f}%'}"
            self.baseline_assessment_combo.addItem(label, record); self.baseline_assessment_combo.setItemData(self.baseline_assessment_combo.count() - 1, timestamp_tooltip(record.get("timestamp_utc")), Qt.ItemDataRole.ToolTipRole)
        if current_timestamp:
            for row in range(self.baseline_assessment_combo.count()):
                data = self.baseline_assessment_combo.itemData(row)
                if isinstance(data, dict) and data.get("timestamp_utc") == current_timestamp: self.baseline_assessment_combo.setCurrentIndex(row); break
        self.baseline_assessment_combo.blockSignals(False)
        available = self.baseline_assessment_combo.count() > 0 and isinstance(self.baseline_assessment_combo.currentData(), dict)
        if hasattr(self, "create_baseline_button"):
            self.create_baseline_button.setEnabled(available); self.create_baseline_button.setToolTip("" if available else "Run or open a saved assessment before creating a snapshot.")
        if hasattr(self, "compare_baseline_button"): self.compare_baseline_button.setEnabled(self.baseline_collection.active is not None and available)

    def _active_baseline_changed(self) -> None:
        baseline_id = self.active_baseline_combo.currentData()
        try: self.baseline_store.set_active(self.baseline_collection, baseline_id)
        except (OSError, KeyError) as exc: QMessageBox.warning(self, "Saved Snapshots", f"The active saved snapshot could not be stored: {exc}")
        self._invalidate_displayed_baseline_comparison("Active saved snapshot changed. Previous comparison results were cleared."); self._refresh_baseline_ui(); self._update_baseline_for_current()

    def _create_baseline(self) -> None:
        source = self.baseline_assessment_combo.currentData()
        if not isinstance(source, dict): QMessageBox.information(self, "Create saved snapshot", "Complete or select an assessment first."); return
        name, accepted = QInputDialog.getText(self, "Create Saved Snapshot", "Descriptive snapshot name:")
        if not accepted: return
        try:
            self.baseline_store.create(self.baseline_collection, name, source, activate=True)
        except (OSError, ValueError) as exc: QMessageBox.warning(self, "Create saved snapshot", str(exc)); return
        self._invalidate_displayed_baseline_comparison("Saved snapshot created. Choose an assessment and compare when ready."); self._refresh_baseline_ui(); self._update_baseline_for_current(); self.baseline_compatibility.setText("Saved snapshot created from an immutable assessment. Future scans will not replace it.")

    def _rename_baseline(self) -> None:
        active = self.baseline_collection.active
        if not active: return
        name, accepted = QInputDialog.getText(self, "Rename Saved Snapshot", "Snapshot name:", text=active.name)
        if not accepted: return
        try: self.baseline_store.rename(self.baseline_collection, active.baseline_id, name)
        except (OSError, ValueError, KeyError) as exc: QMessageBox.warning(self, "Rename saved snapshot", str(exc)); return
        self._invalidate_displayed_baseline_comparison("Saved snapshot was renamed. Compare again to refresh this view."); self._refresh_baseline_ui()

    def _delete_baseline(self) -> None:
        active = self.baseline_collection.active
        if not active: return
        confirmation = QMessageBox(self); confirmation.setWindowTitle("Delete Saved Snapshot"); confirmation.setIcon(QMessageBox.Icon.Question); confirmation.setTextFormat(Qt.TextFormat.PlainText); confirmation.setText(f"Delete saved snapshot '{active.name}'?\n\nIts independent assessment data will be removed. Scan history is not affected."); confirmation.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No); confirmation.setDefaultButton(QMessageBox.StandardButton.No)
        if confirmation.exec() != QMessageBox.StandardButton.Yes: return
        try: self.baseline_store.delete(self.baseline_collection, active.baseline_id)
        except (OSError, KeyError) as exc: QMessageBox.warning(self, "Delete saved snapshot", str(exc)); return
        self.latest_baseline_comparison = None; self._invalidate_displayed_baseline_comparison("Saved snapshot deleted. Select another snapshot to compare."); self._refresh_baseline_ui()

    def _invalidate_displayed_baseline_comparison(self, message: str) -> None:
        if not hasattr(self, "baseline_results_table"): return
        self.displayed_baseline_context = None; self.baseline_results_table.clearSelection(); self.baseline_results_table.setRowCount(0); self.baseline_result_title.setText("No comparison result selected."); self.baseline_result_details.clear(); self.baseline_compatibility.setText(message)
        for panel in (self.baseline_regressions, self.baseline_improvements, self.baseline_unchanged, self.baseline_review): panel.value.setText("0")

    def _compare_selected_baseline(self) -> None:
        active = self.baseline_collection.active; current = self.baseline_assessment_combo.currentData()
        if not active or not isinstance(current, dict): self.baseline_compatibility.setText("Select an active baseline and a completed assessment."); return
        comparison = compare_to_baseline(active.assessment_snapshot, current); self._display_baseline_comparison(active, current, comparison)
        if self.current_record and current.get("timestamp_utc") == self.current_record.timestamp_utc: self.latest_baseline_comparison = comparison; self._update_dashboard_baseline(); self._rebuild_current_findings()

    def _display_baseline_comparison(self, baseline: SecurityBaseline, current: dict, comparison: BaselineComparison) -> None:
        self.displayed_baseline_context = (baseline, current, comparison)
        self.baseline_results_table.clearSelection(); self.baseline_result_title.setText("Select a comparison result."); self.baseline_result_details.clear()
        deltas = ""
        if comparison.aggregate_comparable:
            score_delta = "Unavailable" if comparison.score_change is None else f"{comparison.score_change:+.1f} points"; coverage_delta = "Unavailable" if comparison.coverage_change is None else f"{comparison.coverage_change:+.1f} points"; deltas = f" Score change: {score_delta}; coverage change: {coverage_delta}."
        self.baseline_compatibility.setText(f"Compared with saved snapshot '{baseline.name}'. {comparison.compatibility_explanation}{deltas}")
        self.baseline_regressions.value.setText(str(comparison.count(REGRESSION))); self.baseline_improvements.value.setText(str(comparison.count(IMPROVEMENT))); self.baseline_unchanged.value.setText(str(comparison.count(UNCHANGED))); self.baseline_review.value.setText(str(comparison.review_count))
        self.baseline_results_table.setSortingEnabled(False); self.baseline_results_table.setRowCount(len(comparison.results)); t = self.theme_manager.tokens
        for row, result in enumerate(comparison.results):
            values = [result.title, result.category, self._friendly_status(result.baseline_status), self._friendly_status(result.current_status), self._friendly_baseline_classification(result.classification), result.severity]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value); item.setData(Qt.ItemDataRole.UserRole, result); self.baseline_results_table.setItem(row, column, item)
            foreground, background = ((t.failure, t.failure_bg) if result.classification == REGRESSION else (t.success, t.success_bg) if result.classification == IMPROVEMENT else (t.warning, t.warning_bg) if result.classification in (NEWLY_ASSESSABLE, NO_LONGER_ASSESSABLE, EVIDENCE_ONLY, NOT_COMPARABLE) else (t.neutral, t.neutral_bg))
            self.baseline_results_table.item(row, 4).setForeground(QColor(foreground)); self.baseline_results_table.item(row, 4).setBackground(QColor(background))
        self.baseline_results_table.setSortingEnabled(True)
        if comparison.results: self.baseline_results_table.selectRow(0)

    def _show_baseline_result(self) -> None:
        row = self.baseline_results_table.currentRow(); item = self.baseline_results_table.item(row, 0) if row >= 0 else None; result = item.data(Qt.ItemDataRole.UserRole) if item else None
        if not result: return
        self.baseline_result_title.setText(f"{result.title} — {self._friendly_baseline_classification(result.classification)}")
        sections = [("Summary", self._friendly_baseline_classification(result.classification)), ("Treatment", result.treatment), ("Saved snapshot status", result.baseline_status), ("Current status", result.current_status), ("Saved snapshot evidence", result.baseline_evidence), ("Current evidence", result.current_evidence), ("Technical classification", result.classification), ("Explanation and next step", result.explanation)]
        self.baseline_result_details.setHtml(html_sections(sections))

    def _update_baseline_for_current(self) -> None:
        active = self.baseline_collection.active
        if not active or not self.current_record: self.latest_baseline_comparison = None; self._update_dashboard_baseline(); return
        self.latest_baseline_comparison = compare_to_baseline(active.assessment_snapshot, self.current_record.to_dict()); self._update_dashboard_baseline(); self._rebuild_current_findings()

    def _update_dashboard_baseline(self) -> None:
        if not hasattr(self, "dashboard_baseline_label"): return
        active = self.baseline_collection.active; comparison = self.latest_baseline_comparison
        if not active: self.dashboard_baseline_label.setText("No saved snapshot is active. A snapshot lets future scans be compared with a reference you choose."); return
        if not self.current_record: self.dashboard_baseline_label.setText(f"Active saved snapshot: {active.name}. Run or open an assessment to compare it."); return
        if not comparison: self.dashboard_baseline_label.setText(f"Active saved snapshot: {active.name}. No comparison is available."); return
        if not comparison.aggregate_comparable: self.dashboard_baseline_label.setText(f"A reliable comparison with '{active.name}' cannot be made. {comparison.compatibility_explanation}"); return
        regressions = comparison.count(REGRESSION); improvements = comparison.count(IMPROVEMENT); review = comparison.review_count
        first = "No confirmed security settings worsened since your saved snapshot." if regressions == 0 else f"{regressions} security setting(s) worsened since your saved snapshot."
        second = f" {improvements} setting(s) improved. {review} check(s) require additional review."
        if comparison.privilege_difference: second += " Scan privilege differs, so visibility may influence score and coverage changes."
        self.dashboard_baseline_label.setText(first + second)

    def _profile_changed(self, profile: str) -> None:
        if not profile or profile not in self.config.get("profiles", {}): return
        self.selected_profile = profile; self._update_profile_explanation(profile)
        self._invalidate_displayed_baseline_comparison("Assessment profile changed. Previous comparison results were cleared.")
        try: save_selected_profile(profile, self.config)
        except OSError: LOGGER.exception("Assessment profile preference could not be saved")
        if self.current_record and self.findings and not (self.scan_thread and self.scan_thread.isRunning()):
            assessment = score_results(self.findings, self.config, profile)
            historical = "historical" in self.current_record.assessment_source.casefold()
            envelope = AssessmentEnvelope(
                self.findings, assessment, self.current_record.timestamp_utc,
                self.current_record.assessment_privilege,
                "Historical saved assessment re-scored; not a current scan" if historical else "Current assessment re-scored; no new scan",
            )
            self._commit_assessment(envelope, persist_history=False)

    def _theme_changed(self, tokens: ThemeTokens) -> None:
        self.header.set_tokens(tokens)
        for row in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(row); index = item.data(0, Qt.ItemDataRole.UserRole)
            if index is not None and 0 <= int(index) < len(self.findings):
                finding = self.findings[int(index)]; informational = bool(self.current_record and self.current_record.assessment.dispositions.get(finding.check_id) == "Informational"); self._style_finding_item(item, finding.status, informational); self._style_severity(item, 1, "Informational" if informational else finding.severity)
        if self.tree.currentItem(): self._show_finding(self.tree.currentItem(), None)
        for row in range(self.dashboard_findings.topLevelItemCount()):
            item = self.dashboard_findings.topLevelItem(row); index = item.data(0, Qt.ItemDataRole.UserRole)
            if index is not None and 0 <= int(index) < len(self.findings): self._style_severity(item, 2, self.findings[int(index)].severity)
        if hasattr(self, "findings_center_tree"):
            for row in range(self.findings_center_tree.topLevelItemCount()):
                item = self.findings_center_tree.topLevelItem(row); data = item.data(0, Qt.ItemDataRole.UserRole) or {}; finding = data.get("finding", {}); informational = data.get("state") == "Informational"; self._style_severity(item, 3, "Informational" if informational else str(finding.get("severity", "Unknown"))); self._style_status_column(item, 4, str(finding.get("status", "Unknown")), informational)
        if self.action_tree.currentItem(): self._show_action(self.action_tree.currentItem(), None)
        for row in range(self.action_tree.topLevelItemCount()): self._style_severity(self.action_tree.topLevelItem(row), 1, self.action_tree.topLevelItem(row).text(1))
        context = getattr(self, "displayed_baseline_context", None)
        if context: self._display_baseline_comparison(*context)

    def _style_finding_item(self, item: QTreeWidgetItem, status: CheckStatus, informational: bool = False) -> None:
        t = self.theme_manager.tokens
        if informational:
            foreground, background = t.semantic("informational")
        else:
            key = {CheckStatus.PASS: "pass", CheckStatus.FAIL: "fail", CheckStatus.UNKNOWN: "unknown", CheckStatus.NOT_APPLICABLE: "neutral"}[status]
            foreground, background = t.semantic(key)
        item.setForeground(2, QColor(foreground)); item.setBackground(2, QBrush()); font = item.font(2); font.setWeight(QFont.Weight.DemiBold if status == CheckStatus.FAIL else QFont.Weight.Normal); item.setFont(2, font)

    def _style_severity(self, item: QTreeWidgetItem, column: int, severity: str) -> None:
        foreground, background = self.theme_manager.tokens.semantic(severity)
        item.setForeground(column, QColor(foreground)); item.setBackground(column, QBrush()); font = item.font(column); font.setWeight(QFont.Weight.DemiBold if severity.casefold() in ("critical", "high") else QFont.Weight.Normal); item.setFont(column, font)

    def _style_status_column(self, item: QTreeWidgetItem, column: int, status: str, informational: bool = False) -> None:
        key = "informational" if informational else {CheckStatus.PASS.value: "pass", CheckStatus.FAIL.value: "fail", CheckStatus.UNKNOWN.value: "unknown"}.get(status, "neutral")
        foreground, background = self.theme_manager.tokens.semantic(key)
        item.setForeground(column, QColor(foreground)); item.setBackground(column, QBrush()); font = item.font(column); font.setWeight(QFont.Weight.DemiBold if status == CheckStatus.FAIL.value else QFont.Weight.Normal); item.setFont(column, font)

    def _summary_tab(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page)
        self.category_table = CoordinatedTableWidget(0, 8); self.category_table.setHorizontalHeaderLabels(["Category", "Score", "Coverage", "Pass", "Fail", "Unknown", "Info", "N/A"])
        self.category_table.verticalHeader().setVisible(False); self.category_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.category_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col in range(1, 8): self.category_table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self.category_table)
        self.methodology_label = QLabel("Unknown results lower coverage; informational and Not Applicable checks are excluded from the score."); self.methodology_label.setWordWrap(True); self.methodology_label.setObjectName("methodology"); layout.addWidget(self.methodology_label)
        return page

    def _findings_tab(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(8)
        self.findings_splitter = ResponsiveSplitter(1100)
        self.findings_list_panel = QWidget(); self.findings_list_panel.setMinimumWidth(360); self.findings_list_panel.setMinimumHeight(210); self.findings_list_panel.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Expanding)
        list_layout = QVBoxLayout(self.findings_list_panel); list_layout.setContentsMargins(0, 0, 8, 0); list_layout.setSpacing(8)
        filters = QHBoxLayout(); filters.addWidget(QLabel("Show:")); self.current_status_filter = QComboBox(); self.current_status_filter.addItems(["Needs Attention", "All Checks", "Passed", "Could Not Assess"]); filters.addWidget(self.current_status_filter); self.findings_advanced_button = QPushButton("Advanced Filters…"); self.findings_advanced_button.setObjectName("secondaryButton"); self.findings_advanced_button.setCheckable(True); self.findings_advanced_button.clicked.connect(self._toggle_findings_filters); filters.addWidget(self.findings_advanced_button); filters.addStretch(1); list_layout.addLayout(filters)
        self.findings_advanced_filters = QFrame(); self.findings_advanced_filters.setObjectName("filterPanel"); advanced_layout = QGridLayout(self.findings_advanced_filters); advanced_layout.setContentsMargins(10, 8, 10, 8); advanced_layout.setHorizontalSpacing(8); advanced_layout.setVerticalSpacing(7)
        self.finding_category_combo = QComboBox(); self.finding_category_combo.addItem("All categories"); self.finding_severity_combo = QComboBox(); self.finding_severity_combo.addItems(["All severities", "Critical", "High", "Medium", "Low", "Informational"])
        self.baseline_change_filter = QComboBox(); self.baseline_change_filter.addItems(["All changes", "Security setting worsened", "Security setting improved", "No change", "Requires review"]); self.reset_findings_filters_button = QPushButton("Reset Filters"); self.reset_findings_filters_button.setObjectName("secondaryButton"); self.reset_findings_filters_button.clicked.connect(self._reset_findings_filters)
        advanced_layout.addWidget(QLabel("Security category:"), 0, 0); advanced_layout.addWidget(self.finding_category_combo, 0, 1); advanced_layout.addWidget(QLabel("Severity:"), 0, 2); advanced_layout.addWidget(self.finding_severity_combo, 0, 3)
        advanced_layout.addWidget(QLabel("Change since saved snapshot:"), 1, 0); advanced_layout.addWidget(self.baseline_change_filter, 1, 1, 1, 2); advanced_layout.addWidget(self.reset_findings_filters_button, 1, 3); advanced_layout.setColumnStretch(1, 1); advanced_layout.setColumnStretch(3, 1)
        self.findings_advanced_filters.setVisible(False); list_layout.addWidget(self.findings_advanced_filters)
        self.tree = CoordinatedTreeWidget(); self.tree.setHeaderLabels(["Finding", "Severity", "Status", "Summary"]); self.tree.setRootIsDecorated(False); self.tree.setMinimumWidth(0)
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive); self.tree.header().resizeSection(0, 235); self.tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents); self.tree.header().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents); self.tree.header().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.tree.currentItemChanged.connect(self._show_finding); list_layout.addWidget(self.tree, 1); self.findings_splitter.addWidget(self.findings_list_panel)
        self.finding_detail_panel = QWidget(); self.finding_detail_panel.setMinimumWidth(300); self.finding_detail_panel.setMinimumHeight(300); self.finding_detail_panel.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Expanding); detail_layout = QVBoxLayout(self.finding_detail_panel); detail_layout.setContentsMargins(8, 0, 0, 0); detail_layout.setSpacing(6); self.detail_title = QLabel("Select a finding to view details."); self.detail_title.setWordWrap(True); self.detail_title.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred); self.detail_title.setObjectName("detailTitle"); detail_layout.addWidget(self.detail_title)
        self.finding_detail_splitter = QSplitter(Qt.Orientation.Vertical)
        self.details = QTextBrowser(); self.details.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth); self.details.setWordWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere); self.details.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff); self.details.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Expanding); self.finding_detail_splitter.addWidget(self.details)
        self.technical_finding_details = QTextBrowser(); self.technical_finding_details.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth); self.technical_finding_details.setWordWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere); self.technical_finding_details.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff); self.technical_finding_details.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Expanding); self.technical_finding_details.setVisible(False); self.finding_detail_splitter.addWidget(self.technical_finding_details)
        self._register_splitter("finding_details_evidence", self.finding_detail_splitter, [330, 170]); detail_layout.addWidget(self.finding_detail_splitter, 1)
        buttons = QHBoxLayout(); buttons.setSpacing(6); self.finding_technical_button = QPushButton("Show Technical Details"); self.finding_technical_button.setObjectName("xpButton"); self.finding_technical_button.clicked.connect(self._toggle_finding_technical); buttons.addWidget(self.finding_technical_button); self.finding_fix_button = QPushButton("View Available Fix"); self.finding_fix_button.setObjectName("xpButton"); self.finding_fix_button.setEnabled(False); self.finding_fix_button.clicked.connect(self._open_finding_fix); buttons.addWidget(self.finding_fix_button); self.settings_button = QPushButton("Open Windows Settings"); self.settings_button.setObjectName("xpButton"); self.settings_button.setEnabled(False); self.settings_button.clicked.connect(self._open_settings); buttons.addWidget(self.settings_button); detail_layout.addLayout(buttons)
        self.findings_splitter.addWidget(self.finding_detail_panel); self.findings_splitter.setStretchFactor(0, 65); self.findings_splitter.setStretchFactor(1, 35); self._register_splitter("security_issues", self.findings_splitter, [650, 350]); layout.addWidget(self.findings_splitter, 1)
        for control in (self.current_status_filter, self.finding_category_combo, self.finding_severity_combo, self.baseline_change_filter): control.currentTextChanged.connect(self._rebuild_current_findings)
        return page

    def _findings_center_tab(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page)
        note = QLabel("Findings are derived from saved assessments. 'New' means first observed in the newer saved scan, not when Windows changed."); note.setWordWrap(True); note.setObjectName("methodology"); layout.addWidget(note)
        filters = QGridLayout(); self.finding_profile_filter = QComboBox(); self.finding_profile_filter.addItem("All profiles")
        self.finding_category_filter = QComboBox(); self.finding_category_filter.addItem("All categories")
        self.finding_severity_filter = QComboBox(); self.finding_severity_filter.addItem("All severities")
        self.finding_status_filter = QComboBox(); self.finding_status_filter.addItems(["All states", "New finding", "Resolved finding", "Persistent failure", "Newly assessable", "Informational", "Unknown or unavailable"])
        self.finding_result_filter = QComboBox(); self.finding_result_filter.addItems(["All results", "Pass", "Fail", "Unknown", "Not Applicable"])
        for index, (label, control) in enumerate((("Profile:", self.finding_profile_filter), ("Category:", self.finding_category_filter), ("Severity:", self.finding_severity_filter), ("State:", self.finding_status_filter), ("Result:", self.finding_result_filter))):
            row, column = divmod(index, 3); filters.addWidget(QLabel(label), row, column * 2); filters.addWidget(control, row, column * 2 + 1)
            control.currentTextChanged.connect(self._filter_findings_center)
        layout.addLayout(filters)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.findings_center_tree = CoordinatedTreeWidget(); self.findings_center_tree.setHeaderLabels(["State", "Finding", "Category", "Severity", "Result", "Profile", "First observed (local)"]); self.findings_center_tree.setRootIsDecorated(False)
        self.findings_center_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents); self.findings_center_tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for column in range(2, 7): self.findings_center_tree.header().setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        self.findings_center_tree.currentItemChanged.connect(self._show_center_finding); splitter.addWidget(self.findings_center_tree)
        detail = QWidget(); detail_layout = QVBoxLayout(detail); self.center_finding_title = QLabel("Select a saved finding."); self.center_finding_title.setObjectName("detailTitle"); detail_layout.addWidget(self.center_finding_title)
        self.center_finding_details = QTextBrowser(); detail_layout.addWidget(self.center_finding_details)
        self.center_hardening_button = QPushButton("Open Supported Hardening Action"); self.center_hardening_button.setObjectName("xpButton"); self.center_hardening_button.setEnabled(False); self.center_hardening_button.clicked.connect(self._open_center_hardening); detail_layout.addWidget(self.center_hardening_button, 0, Qt.AlignmentFlag.AlignLeft)
        splitter.addWidget(detail); self.findings_center_splitter = self._register_splitter("saved_findings", splitter, [330, 230]); layout.addWidget(splitter); return page

    def _trends_tab(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page); layout.setSpacing(8)
        filters = QGridLayout(); filters.setHorizontalSpacing(8); filters.setVerticalSpacing(7); filters.addWidget(QLabel("Metric:"), 0, 0); metric_box = QWidget(); metric_layout = QHBoxLayout(metric_box); metric_layout.setContentsMargins(0, 0, 0, 0); metric_layout.setSpacing(4); self.trend_metric_group = QButtonGroup(self); self.trend_metric_group.setExclusive(True); self.trend_metric_buttons = []
        for metric, label in (("score", "Score"), ("coverage", "Coverage")):
            button = QPushButton(label); button.setObjectName("segmentButton"); button.setCheckable(True); button.setMinimumHeight(34); button.setProperty("metric", metric); button.clicked.connect(lambda checked=False, value=metric: self._set_trend_metric(value)); self.trend_metric_group.addButton(button); self.trend_metric_buttons.append(button); metric_layout.addWidget(button)
        self.trend_metric_buttons[0].setChecked(True); filters.addWidget(metric_box, 0, 1)
        filters.addWidget(QLabel("Profile:"), 0, 2); self.trend_profile_filter = QComboBox(); self.trend_profile_filter.addItem("All"); filters.addWidget(self.trend_profile_filter, 0, 3)
        filters.addWidget(QLabel("Assessment context:"), 0, 4); self.trend_series_filter = QComboBox(); self.trend_series_filter.addItem("Latest comparable context", "latest"); self.trend_series_filter.addItem("All contexts (inspection only)", "all"); self.trend_series_filter.setMinimumWidth(220); filters.addWidget(self.trend_series_filter, 0, 5)
        self.trend_date_filter = QCheckBox("Filter by date"); self.trend_date_filter.setChecked(False); filters.addWidget(self.trend_date_filter, 1, 0)
        filters.addWidget(QLabel("From:"), 1, 1); self.trend_start = QDateEdit(QDate.currentDate().addDays(-30)); self.trend_start.setCalendarPopup(True); self.trend_start.setDisplayFormat("MMM d, yyyy"); self.trend_start.setAlignment(Qt.AlignmentFlag.AlignCenter); self.trend_start.setMinimumWidth(128); filters.addWidget(self.trend_start, 1, 2)
        filters.addWidget(QLabel("To:"), 1, 3); self.trend_end = QDateEdit(QDate.currentDate()); self.trend_end.setCalendarPopup(True); self.trend_end.setDisplayFormat("MMM d, yyyy"); self.trend_end.setAlignment(Qt.AlignmentFlag.AlignCenter); self.trend_end.setMinimumWidth(128); filters.addWidget(self.trend_end, 1, 4); filters.setColumnStretch(5, 1); layout.addLayout(filters)
        self.trend_start.setEnabled(False); self.trend_end.setEnabled(False)
        metrics = QGridLayout(); metrics.setSpacing(8); self.trend_score_panel = MetricPanel("Latest hardening score", "Configuration checks, not overall device security."); self.trend_coverage_panel = MetricPanel("Latest coverage", "How much of that assessment could be evaluated."); self.trend_count_panel = MetricPanel("Comparable assessments", "Same profile, policy, and privilege context."); self.trend_change_panel = MetricPanel("Change from previous")
        for index, panel in enumerate((self.trend_score_panel, self.trend_coverage_panel, self.trend_count_panel, self.trend_change_panel)): panel.value.setText("—"); metrics.addWidget(panel, index // 2, index % 2)
        layout.addLayout(metrics)
        self.trend_workspace_splitter = QSplitter(Qt.Orientation.Vertical); chart_panel = QWidget(); chart_layout = QVBoxLayout(chart_panel); chart_layout.setContentsMargins(0, 0, 0, 0); chart_layout.setSpacing(8)
        self.trend_adaptive_stack = QStackedWidget(); self.trend_empty_label = QLabel("No saved assessments match this context. Run a read-only assessment or adjust the filters."); self.trend_empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter); self.trend_empty_label.setWordWrap(True); self.trend_empty_label.setObjectName("methodology"); self.trend_adaptive_stack.addWidget(self.trend_empty_label)
        self.trend_single_label = QLabel(); self.trend_single_label.setAlignment(Qt.AlignmentFlag.AlignCenter); self.trend_single_label.setWordWrap(True); self.trend_single_label.setObjectName("methodology"); self.trend_adaptive_stack.addWidget(self.trend_single_label)
        comparison = QFrame(); comparison.setObjectName("infoPanel"); comparison_layout = QHBoxLayout(comparison); self.trend_older_label = QLabel(); self.trend_older_label.setWordWrap(True); self.trend_older_label.setAlignment(Qt.AlignmentFlag.AlignCenter); comparison_layout.addWidget(self.trend_older_label, 1); self.trend_change_arrow = QLabel("→"); self.trend_change_arrow.setObjectName("detailTitle"); comparison_layout.addWidget(self.trend_change_arrow); self.trend_newer_label = QLabel(); self.trend_newer_label.setWordWrap(True); self.trend_newer_label.setAlignment(Qt.AlignmentFlag.AlignCenter); comparison_layout.addWidget(self.trend_newer_label, 1); self.trend_adaptive_stack.addWidget(comparison)
        self.trend_chart = TrendChart(self.theme_manager); self.trend_chart.point_selected.connect(self._trend_point_selected); self.trend_adaptive_stack.addWidget(self.trend_chart); chart_layout.addWidget(self.trend_adaptive_stack, 1)
        self.trend_note = QLabel("No saved assessments yet."); self.trend_note.setTextFormat(Qt.TextFormat.PlainText); self.trend_note.setWordWrap(True); self.trend_note.setObjectName("methodology"); chart_layout.addWidget(self.trend_note)
        selection = QFrame(); selection.setObjectName("infoPanel"); selection_layout = QGridLayout(selection); self.trend_selection_label = QLabel("Select a chart point or table row to inspect a saved assessment."); self.trend_selection_label.setObjectName("infoValue"); self.trend_selection_label.setWordWrap(True); selection_layout.addWidget(self.trend_selection_label, 0, 0, 1, 3)
        self.trend_view_button = QPushButton("View Selected (Historical)"); self.trend_view_button.setObjectName("secondaryButton"); self.trend_view_button.setEnabled(False); self.trend_view_button.clicked.connect(self._view_selected_trend); selection_layout.addWidget(self.trend_view_button, 1, 0)
        self.trend_baseline_button = QPushButton("Create Saved Snapshot…"); self.trend_baseline_button.setObjectName("secondaryButton"); self.trend_baseline_button.setEnabled(False); self.trend_baseline_button.clicked.connect(self._create_baseline_from_selected_trend); selection_layout.addWidget(self.trend_baseline_button, 1, 1)
        selection_layout.addWidget(QLabel("Compare with:"), 2, 0); self.trend_compare_combo = QComboBox(); self.trend_compare_combo.setMinimumWidth(180); selection_layout.addWidget(self.trend_compare_combo, 2, 1); self.trend_compare_button = QPushButton("Compare"); self.trend_compare_button.setObjectName("secondaryButton"); self.trend_compare_button.setEnabled(False); self.trend_compare_button.clicked.connect(self._compare_selected_trend); selection_layout.addWidget(self.trend_compare_button, 2, 2); selection_layout.setColumnStretch(1, 1); chart_layout.addWidget(selection); self.trend_workspace_splitter.addWidget(chart_panel)
        self.trend_table = CoordinatedTableWidget(0, 7); self.trend_table.setHorizontalHeaderLabels(["Local date/time", "Profile", "Privilege", "Score", "Coverage", "Comparable change", "Policy"]); self.trend_table.verticalHeader().setVisible(False); self.trend_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.trend_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows); self.trend_table.cellClicked.connect(self._trend_table_selected)
        self.trend_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for column in range(1, 7): self.trend_table.horizontalHeader().setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        self.trend_workspace_splitter.addWidget(self.trend_table); self._register_splitter("security_trends", self.trend_workspace_splitter, [470, 190]); layout.addWidget(self.trend_workspace_splitter, 1)
        self.trend_profile_filter.currentTextChanged.connect(self._update_trends); self.trend_series_filter.currentIndexChanged.connect(self._update_trends); self.trend_start.dateChanged.connect(self._update_trends); self.trend_end.dateChanged.connect(self._update_trends); self.trend_date_filter.toggled.connect(self._toggle_trend_dates)
        return page

    def _drift_tab(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page)
        controls = QHBoxLayout(); controls.addWidget(QLabel("Older assessment:")); self.drift_older = QComboBox(); controls.addWidget(self.drift_older, 1); controls.addWidget(QLabel("Newer assessment:")); self.drift_newer = QComboBox(); controls.addWidget(self.drift_newer, 1)
        compare = QPushButton("Compare Saved Assessments"); compare.setObjectName("xpButton"); compare.clicked.connect(self._update_drift); controls.addWidget(compare); layout.addLayout(controls)
        self.drift_note = QLabel("Security configuration changes are detected only by comparing saved assessments; WinCur does not continuously monitor Windows."); self.drift_note.setWordWrap(True); self.drift_note.setObjectName("methodology"); layout.addWidget(self.drift_note)
        self.drift_table = CoordinatedTableWidget(0, 9); self.drift_table.setHorizontalHeaderLabels(["Finding", "Transition", "Confidence", "Score treatment", "Severity change", "First observed (local)", "Old evidence", "New evidence", "Category"]); self.drift_table.verticalHeader().setVisible(False); self.drift_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.drift_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch); self.drift_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents); self.drift_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        for column in range(3, 9): self.drift_table.horizontalHeader().setSectionResizeMode(column, QHeaderView.ResizeMode.Stretch if column in (6, 7) else QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self.drift_table); return page

    def _toggle_trend_dates(self, enabled: bool) -> None:
        self.trend_start.setEnabled(enabled); self.trend_end.setEnabled(enabled); self._update_trends()

    def _set_trend_metric(self, metric: str) -> None:
        self.trend_chart.set_metric(metric)
        for button in self.trend_metric_buttons: button.setChecked(button.property("metric") == metric)
        self.selected_trend_point = None; self.trend_selection_label.setText("Select a chart point or table row to inspect a saved assessment."); self.trend_view_button.setEnabled(False); self.trend_baseline_button.setEnabled(False); self.trend_compare_button.setEnabled(False); self.trend_table.clearSelection()
        self._update_trends()

    def _refresh_trend_series_filter(self, points: list, metric: str) -> None:
        selected = self.trend_series_filter.currentData(); representatives = {}
        for point in points:
            if point.timestamp is None or getattr(point, metric) is None: continue
            existing = representatives.get(point.trend_series_key)
            if existing is None or point.timestamp >= existing.timestamp: representatives[point.trend_series_key] = point
        self.trend_series_filter.blockSignals(True); self.trend_series_filter.clear(); self.trend_series_filter.addItem("Latest comparable context", "latest"); self.trend_series_filter.addItem("All contexts (inspection only)", "all")
        for key, point in sorted(representatives.items(), key=lambda item: (item[1].profile, item[1].privilege, item[1].policy_version)):
            label = f"{point.profile} · {point.privilege} · Policy {point.policy_version}"; self.trend_series_filter.addItem(label, key)
        row = combo_data_index(self.trend_series_filter, selected); self.trend_series_filter.setCurrentIndex(row if row >= 0 else 0); self.trend_series_filter.blockSignals(False)

    def _update_trends(self) -> None:
        if not hasattr(self, "trend_chart"): return
        profile = self.trend_profile_filter.currentText() or "All"
        start = self.trend_start.date().toPython() if self.trend_date_filter.isChecked() else None
        end = self.trend_end.date().toPython() if self.trend_date_filter.isChecked() else None
        points = filter_history(self.history_records, profile, start, end); metric = self.trend_chart.metric_name; self._refresh_trend_series_filter(points, metric); series_choice = self.trend_series_filter.currentData()
        usable = [point for point in points if point.timestamp is not None and getattr(point, metric) is not None]
        if series_choice == "latest" and usable:
            latest_key = max(usable, key=lambda point: point.timestamp).trend_series_key; chart_source = [point for point in points if point.trend_series_key == latest_key]
        elif isinstance(series_choice, tuple): chart_source = [point for point in points if point.trend_series_key == series_choice]
        else: chart_source = points
        display_points = chart_source if self.trend_date_filter.isChecked() else chart_source[-10:]
        presentation = build_trend_presentation(display_points, metric, None); score_presentation = build_trend_presentation(display_points, "score", None)
        latest = presentation.latest or score_presentation.latest; self.trend_score_panel.value.setText("—" if latest is None or latest.score is None else f"{latest.score:.1f}%"); self.trend_coverage_panel.value.setText("—" if latest is None or latest.coverage is None else f"{latest.coverage:.1f}%")
        comparable = len(presentation.assessments) if presentation.mode != "incomparable" else 0; self.trend_count_panel.value.setText(str(comparable) if comparable else "—")
        score_change = score_presentation.change; self.trend_change_panel.value.setText("—" if score_change is None else f"{score_change:+.1f}"); self.trend_change_panel.description.setText("Score points; shown only for the same profile, policy, and privilege context." if score_change is not None else "No previous directly comparable scored assessment.")
        mode_index = {"empty": 0, "single": 1, "comparison": 2, "timeline": 3, "chart": 3, "incomparable": 0}[presentation.mode]; self.trend_adaptive_stack.setCurrentIndex(mode_index)
        if presentation.mode == "incomparable": self.trend_empty_label.setText("Multiple incompatible assessment contexts are listed below for inspection. Choose one profile, policy, and privilege context to calculate a trend.")
        elif presentation.mode == "empty": self.trend_empty_label.setText("No scored assessments match this context. Saved records with missing metadata remain available in Scan History.")
        elif presentation.mode == "single":
            point = presentation.latest; value = getattr(point, metric); self.trend_single_label.setText(f"One representative assessment\n{friendly_timestamp(point.record.get('timestamp_utc'))} · {point.profile} · {point.privilege}\n{metric.title()}: {value:.1f}%\nA trend requires another directly comparable assessment on a different date.")
        elif presentation.mode == "comparison":
            older, newer = presentation.daily_points[0], presentation.daily_points[-1]; old_value, new_value = getattr(older, metric), getattr(newer, metric); change = new_value - old_value
            self.trend_older_label.setText(f"Earlier assessment\n{friendly_timestamp(older.record.get('timestamp_utc'))}\n{metric.title()} {old_value:.1f}%")
            self.trend_newer_label.setText(f"Later assessment\n{friendly_timestamp(newer.record.get('timestamp_utc'))}\n{metric.title()} {new_value:.1f}%\nChange {change:+.1f} points")
        chart_points = list(presentation.daily_points); self.trend_chart.set_points(chart_points); self.trend_chart.set_connect_points(presentation.mode == "chart"); self.trend_chart.setMinimumHeight(190); self.trend_chart.setMaximumHeight(300 if presentation.mode == "chart" else 230)
        selected = getattr(self, "selected_trend_point", None)
        if selected not in display_points:
            self.selected_trend_point = None; self.trend_selection_label.setText("Select a chart point or table row to inspect a saved assessment."); self.trend_view_button.setEnabled(False); self.trend_baseline_button.setEnabled(False); self.trend_compare_button.setEnabled(False)
        prior_by_series = {}; changes = {}
        for point in display_points:
            prior = prior_by_series.get(point.trend_series_key); changes[id(point)] = None if prior is None or prior.score is None or point.score is None else point.score - prior.score; prior_by_series[point.trend_series_key] = point
        self.trend_table.setRowCount(len(display_points))
        for row, point in enumerate(reversed(display_points)):
            raw_timestamp = point.record.get("timestamp_utc", "Unknown"); change = changes[id(point)]; values = [friendly_timestamp(raw_timestamp), point.profile, point.privilege, "Not scored" if point.score is None else f"{point.score:.1f}%", "Unknown" if point.coverage is None else f"{point.coverage:.1f}%", "—" if change is None else f"{change:+.1f}", point.policy_version]
            for column, value in enumerate(values):
                item = QTableWidgetItem(sanitize_display_text(value)); self.trend_table.setItem(row, column, item); item.setToolTip(sanitize_display_text(value))
                if column == 0: item.setData(Qt.ItemDataRole.UserRole, point); item.setToolTip(timestamp_tooltip(raw_timestamp))
        available_keys = {point.trend_series_key for point in usable}; missing = sum(point.timestamp is None or getattr(point, metric) is None for point in points); omitted_daily = max(0, len(presentation.assessments) - len(chart_points)); metric_label = "score" if metric == "score" else "coverage"
        notes = [f"Showing {len(display_points)} recent assessment record(s). Visualization mode: {presentation.mode}. {len(chart_points)} representative date(s) are used for {metric_label}."]
        if len(available_keys) > 1: notes.append("Different profiles, scoring policies, and Standard/Administrator privilege contexts are never treated as one comparable trend. A visibility-related score difference is not presented as a security improvement.")
        if omitted_daily: notes.append(f"{omitted_daily} same-day assessment(s) remain available in the table but are omitted from the chart for readability.")
        if missing: notes.append(f"{missing} record(s) lack a usable date or {metric_label} value and appear only in the table.")
        if self.baseline_collection.active: notes.append(f"Active saved snapshot: {self.baseline_collection.active.name} (assessment {friendly_timestamp(self.baseline_collection.active.assessment_snapshot.get('timestamp_utc'))}).")
        self.trend_note.setText(" ".join(notes))

    def _trend_point_selected(self, point) -> None:
        self.selected_trend_point = point
        score = "Not scored" if point.score is None else f"{point.score:.1f}%"; coverage = "Unknown" if point.coverage is None else f"{point.coverage:.1f}%"
        raw_timestamp = point.record.get("timestamp_utc", "Unknown"); self.trend_selection_label.setText(f"{friendly_timestamp(raw_timestamp)} · {point.profile} · {point.privilege}\nScore {score} · Coverage {coverage} · Policy {point.policy_version}"); self.trend_selection_label.setToolTip(timestamp_tooltip(raw_timestamp))
        for row in range(self.trend_table.rowCount()):
            item = self.trend_table.item(row, 0)
            if item and item.data(Qt.ItemDataRole.UserRole) == point: self.trend_table.selectRow(row); self.trend_table.scrollToItem(item); break
        self.trend_view_button.setEnabled(True); self.trend_baseline_button.setEnabled(True)
        selected_index = next((index for index, record in enumerate(self.history_records) if record is point.record), -1)
        other_row = next((row for row in range(self.trend_compare_combo.count()) if self.trend_compare_combo.itemData(row) != selected_index), -1)
        if other_row >= 0: self.trend_compare_combo.setCurrentIndex(other_row)
        self.trend_compare_button.setEnabled(other_row >= 0)

    def _trend_table_selected(self, row: int, column: int) -> None:
        item = self.trend_table.item(row, 0); point = item.data(Qt.ItemDataRole.UserRole) if item else None
        if point in self.trend_chart.points: self.trend_chart.select_point(point)
        elif point:
            # A table row may belong to a comparable series hidden by the
            # default "latest series" view. Select that series so the chart,
            # table, and details continue to describe the same assessment.
            series_row = combo_data_index(self.trend_series_filter, point.trend_series_key)
            if series_row >= 0:
                self.trend_series_filter.setCurrentIndex(series_row)
            if point in self.trend_chart.points: self.trend_chart.select_point(point)
            else:
                # Multiple scans from the same day intentionally collapse to
                # the latest chart point. Keep the exact table row available
                # without pretending that it is the daily representative.
                self.trend_chart.selected_point = None; self.trend_chart.keyboard_index = -1; self.trend_chart.update(); self._trend_point_selected(point)

    def _view_selected_trend(self) -> None:
        point = getattr(self, "selected_trend_point", None)
        if point: self._view_history_record(point.record)

    def _create_baseline_from_selected_trend(self) -> None:
        point = getattr(self, "selected_trend_point", None)
        if not point: return
        self._open_saved_snapshots(); self._refresh_baseline_assessments()
        for row in range(self.baseline_assessment_combo.count()):
            data = self.baseline_assessment_combo.itemData(row)
            if isinstance(data, dict) and data.get("timestamp_utc") == point.record.get("timestamp_utc"): self.baseline_assessment_combo.setCurrentIndex(row); break
        self._create_baseline()

    def _compare_selected_trend(self) -> None:
        point = getattr(self, "selected_trend_point", None); other_index = self.trend_compare_combo.currentData()
        if not point or not isinstance(other_index, int): return
        try: selected_index = next(index for index, record in enumerate(self.history_records) if record is point.record)
        except StopIteration: return
        self.drift_older.setCurrentIndex(self.drift_older.findData(other_index)); self.drift_newer.setCurrentIndex(self.drift_newer.findData(selected_index)); self._update_drift(); self._set_trends_view(1)

    def _refresh_drift_selectors(self) -> None:
        if not hasattr(self, "drift_older"): return
        current_old = self.drift_older.currentData(); current_new = self.drift_newer.currentData()
        for combo in (self.drift_older, self.drift_newer): combo.blockSignals(True); combo.clear()
        for index, record in enumerate(self.history_records):
            point = history_point(record); raw_timestamp = record.get("timestamp_utc", "Unknown"); label = f"{friendly_timestamp(raw_timestamp)} · {point.profile} · {point.privilege}"
            self.drift_older.addItem(label, index); self.drift_newer.addItem(label, index)
            for combo in (self.drift_older, self.drift_newer): combo.setItemData(combo.count() - 1, f"{timestamp_tooltip(raw_timestamp)}\nPolicy: {point.policy_version}", Qt.ItemDataRole.ToolTipRole)
        if self.history_records:
            old_index = current_old if isinstance(current_old, int) and current_old < len(self.history_records) else max(0, len(self.history_records) - 2)
            new_index = current_new if isinstance(current_new, int) and current_new < len(self.history_records) else len(self.history_records) - 1
            self.drift_older.setCurrentIndex(self.drift_older.findData(old_index)); self.drift_newer.setCurrentIndex(self.drift_newer.findData(new_index))
        for combo in (self.drift_older, self.drift_newer): combo.blockSignals(False)
        self._update_drift()

    def _update_drift(self) -> None:
        if not hasattr(self, "drift_table"): return
        old_index = self.drift_older.currentData(); new_index = self.drift_newer.currentData()
        if not isinstance(old_index, int) or not isinstance(new_index, int) or old_index == new_index:
            self.drift_table.setRowCount(0); self.drift_note.setText("Select two different saved assessments. Drift is detected only at scan comparison time, not continuously."); return
        older = self.history_records[old_index]; newer = self.history_records[new_index]
        old_time = history_point(older).timestamp; new_time = history_point(newer).timestamp
        if old_time and new_time and old_time > new_time: older, newer = newer, older
        comparison = compare_assessments(older, newer); score = "Unavailable" if comparison.score_change is None else f"{comparison.score_change:+.1f} points"; coverage = "Unavailable" if comparison.coverage_change is None else f"{comparison.coverage_change:+.1f} points"
        self.drift_note.setText(f"{comparison.comparison_note} Score impact: {score}. Coverage change: {coverage}. 'First observed' is the newer scan time; WinCur does not infer when Windows changed.")
        self.drift_table.setRowCount(len(comparison.changes))
        for row, change in enumerate(comparison.changes):
            values = [change.title, change.classification, change.confidence, change.score_treatment, change.severity_change, friendly_timestamp(change.first_observed_utc), evidence_preview(change.older_evidence, 80), evidence_preview(change.newer_evidence, 80), change.category]
            for column, value in enumerate(values):
                item = QTableWidgetItem(sanitize_display_text(value)); self.drift_table.setItem(row, column, item)
                if column == 5: item.setToolTip(timestamp_tooltip(change.first_observed_utc))
                elif column == 6: item.setToolTip(sanitize_display_text(change.older_evidence))
                elif column == 7: item.setToolTip(sanitize_display_text(change.newer_evidence))

    def _refresh_findings_center(self) -> None:
        if not hasattr(self, "findings_center_tree"): return
        by_profile: dict[str, list[dict]] = {}
        for record in self.history_records: by_profile.setdefault(history_point(record).profile, []).append(record)
        rows = []
        for profile, records in by_profile.items():
            newer = records[-1]; newer_point = history_point(newer)
            older = next((record for record in reversed(records[:-1]) if history_point(record).policy_version == newer_point.policy_version), None)
            old_results = {str(item.get("check_id")): item for item in (older or {}).get("results", []) if isinstance(item, dict)}
            dispositions = newer.get("assessment", {}).get("dispositions", {}) if isinstance(newer.get("assessment"), dict) else {}
            for finding in newer.get("results", []):
                if not isinstance(finding, dict): continue
                check_id = str(finding.get("check_id")); status = str(finding.get("status", "Unknown")); old_status = str(old_results.get(check_id, {}).get("status", "Missing"))
                state = None; confidence = "Observed status"; first_observed = newer.get("timestamp_utc", "Unknown")
                if dispositions.get(check_id) == "Informational": state = "Informational"; confidence = "Excluded from this profile's score"
                elif old_status == "Unknown" and status in ("Pass", "Fail"): state = "Newly assessable"; confidence = "New evidence, not confirmed configuration drift"
                elif status == "Fail":
                    state = "Persistent failure" if old_status == "Fail" else "New finding"
                    confidence = "Confirmed Pass-to-Fail drift" if old_status == "Pass" else "First observed failure"
                    if state == "Persistent failure":
                        for candidate in reversed(records[:-1]):
                            if history_point(candidate).policy_version != newer_point.policy_version: continue
                            candidate_result = next((item for item in candidate.get("results", []) if isinstance(item, dict) and str(item.get("check_id")) == str(finding.get("check_id"))), None)
                            if not candidate_result or candidate_result.get("status") != "Fail": break
                            first_observed = candidate.get("timestamp_utc", first_observed)
                elif status == "Pass" and old_status == "Fail": state = "Resolved finding"; confidence = "Confirmed Fail-to-Pass drift"
                elif status == "Unknown": state = "Unknown or unavailable"
                if state:
                    rows.append({"state": state, "confidence": confidence, "profile": profile, "privilege": newer.get("assessment_privilege", "Unknown"), "timestamp": first_observed, "finding": finding})
        self.findings_center_rows = rows
        profiles = sorted(by_profile); categories = sorted({str(row["finding"].get("category", "Unknown")) for row in rows}); severities = sorted({str(row["finding"].get("severity", "Unknown")) for row in rows})
        for combo, first, values in ((self.finding_profile_filter, "All profiles", profiles), (self.finding_category_filter, "All categories", categories), (self.finding_severity_filter, "All severities", severities)):
            selected = combo.currentText(); combo.blockSignals(True); combo.clear(); combo.addItem(first); combo.addItems(values); combo.setCurrentText(selected if selected in [first, *values] else first); combo.blockSignals(False)
        self._filter_findings_center()

    def _filter_findings_center(self) -> None:
        if not hasattr(self, "findings_center_tree"): return
        profile = self.finding_profile_filter.currentText(); category = self.finding_category_filter.currentText(); severity = self.finding_severity_filter.currentText(); state = self.finding_status_filter.currentText(); result = self.finding_result_filter.currentText()
        visible = [row for row in self.findings_center_rows if (profile == "All profiles" or row["profile"] == profile) and (category == "All categories" or row["finding"].get("category") == category) and (severity == "All severities" or row["finding"].get("severity") == severity) and (state == "All states" or row["state"] == state) and (result == "All results" or row["finding"].get("status") == result)]
        self.findings_center_tree.clear()
        for index, row in enumerate(visible):
            finding = row["finding"]; values = [row["state"], finding.get("title", finding.get("check_id", "Unknown")), finding.get("category", "Unknown"), finding.get("severity", "Unknown"), finding.get("status", "Unknown"), row["profile"], friendly_timestamp(row["timestamp"])]; item = QTreeWidgetItem([sanitize_display_text(value) for value in values]); item.setData(0, Qt.ItemDataRole.UserRole, row); item.setToolTip(6, timestamp_tooltip(row["timestamp"])); self._style_severity(item, 3, "Informational" if row["state"] == "Informational" else str(finding.get("severity", "Unknown"))); self._style_status_column(item, 4, str(finding.get("status", "Unknown")), row["state"] == "Informational"); self.findings_center_tree.addTopLevelItem(item)
        if self.findings_center_tree.topLevelItemCount(): self.findings_center_tree.setCurrentItem(self.findings_center_tree.topLevelItem(0))
        else: self.center_finding_title.setText("No saved findings match these filters."); self.center_finding_details.clear(); self.center_hardening_button.setEnabled(False)

    def _show_center_finding(self, current: QTreeWidgetItem | None, previous: QTreeWidgetItem | None) -> None:
        if not current: return
        row = current.data(0, Qt.ItemDataRole.UserRole); finding = row.get("finding", {}); remediation = finding.get("remediation") or {}
        self.center_finding_title.setText(f"{finding.get('title', finding.get('check_id', 'Finding'))} — {row.get('state')}")
        if finding.get("status") == CheckStatus.PASS.value:
            recommendation = "No action was required when this assessment passed. Continue monitoring through future assessments."
        elif finding.get("status") == CheckStatus.UNKNOWN.value:
            try: recommendation = self._unknown_recommendation(CheckResult.from_dict(finding), str(row.get("privilege", "Unknown")))
            except (KeyError, TypeError, ValueError): recommendation = "Review the saved explanation and technical evidence. This inconclusive result is not a confirmed failure."
        else:
            recommendation = str(remediation.get("summary", "No recommendation is defined."))
        sections = [("Classification", str(row.get("confidence", row.get("state", "Observed")))), ("Saved result", str(finding.get("status", "Unknown"))), ("Evidence", str(finding.get("evidence", "Unavailable"))), ("Explanation", str(finding.get("explanation", "Unavailable"))), ("Recommendation", recommendation)]
        self.center_finding_details.setHtml(html_sections(sections))
        action_id = self._action_for_check(str(finding.get("check_id"))); self.center_hardening_button.setProperty("actionId", action_id); self.center_hardening_button.setEnabled(bool(action_id))

    def _open_center_hardening(self) -> None:
        action_id = self.center_hardening_button.property("actionId")
        if not action_id: return
        self._open_security_issues(2)
        for row in range(self.action_tree.topLevelItemCount()):
            item = self.action_tree.topLevelItem(row)
            if item.data(0, Qt.ItemDataRole.UserRole) == action_id: self.action_tree.setCurrentItem(item); break

    def _history_tab(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page)
        header = QHBoxLayout(); self.history_label = QLabel("No saved assessments yet."); self.history_label.setObjectName("infoValue"); self.history_label.setWordWrap(True); header.addWidget(self.history_label, 1); layout.addLayout(header)
        note = QLabel("Historical assessments are saved locally and never presented as current device state."); note.setObjectName("intro"); layout.addWidget(note)
        tools = QHBoxLayout(); tools.addWidget(QLabel("Profile:")); self.history_profile_filter = QComboBox(); self.history_profile_filter.addItem("All profiles"); tools.addWidget(self.history_profile_filter); self.history_select_all_button = QPushButton("Select all visible"); self.history_select_all_button.setObjectName("secondaryButton"); tools.addWidget(self.history_select_all_button); self.history_deselect_all_button = QPushButton("Deselect all"); self.history_deselect_all_button.setObjectName("secondaryButton"); tools.addWidget(self.history_deselect_all_button); self.history_selection_label = QLabel("0 selected"); self.history_selection_label.setObjectName("infoValue"); tools.addWidget(self.history_selection_label); tools.addStretch(1); layout.addLayout(tools)
        self.history_splitter = QSplitter(Qt.Orientation.Vertical); self.history_table = CoordinatedTableWidget(0, 6); self.history_table.setHorizontalHeaderLabels(["Select", "Scan date/time", "Privilege", "Profile", "Score", "Coverage"])
        self.history_table.verticalHeader().setVisible(False); self.history_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers); self.history_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows); self.history_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection); self.history_table.cellDoubleClicked.connect(lambda *_: self._view_selected_history())
        self.history_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents); self.history_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for column in range(2, 6): self.history_table.horizontalHeader().setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        self.history_splitter.addWidget(self.history_table); self.history_record_details = QTextBrowser(); self.history_record_details.setMinimumHeight(64); self.history_record_details.setHtml("<p>Select an assessment to view its details.</p>"); self.history_splitter.addWidget(self.history_record_details); self._register_splitter("scan_history", self.history_splitter, [440, 105]); layout.addWidget(self.history_splitter, 1)
        buttons = QHBoxLayout(); self.last_assessment_button = QPushButton("Open Assessment"); self.last_assessment_button.setObjectName("secondaryButton"); self.last_assessment_button.setEnabled(False); self.last_assessment_button.clicked.connect(self._view_selected_history); buttons.addWidget(self.last_assessment_button)
        self.delete_history_button = QPushButton("Delete selected scans"); self.delete_history_button.setObjectName("destructiveButton"); self.delete_history_button.setEnabled(False); self.delete_history_button.clicked.connect(self._delete_selected_history); buttons.addWidget(self.delete_history_button)
        self.clear_history_button = QPushButton("Clear all scan history"); self.clear_history_button.setObjectName("destructiveButton"); self.clear_history_button.setEnabled(False); self.clear_history_button.clicked.connect(self._clear_scan_history); buttons.addWidget(self.clear_history_button); buttons.addStretch(1); layout.addLayout(buttons)
        self.history_table.itemSelectionChanged.connect(self._history_selection_changed); self.history_table.itemChanged.connect(self._history_checkbox_changed); self.history_profile_filter.currentTextChanged.connect(self._filter_history_rows); self.history_select_all_button.clicked.connect(self._select_all_visible_history); self.history_deselect_all_button.clicked.connect(self._deselect_all_history); return page

    def _hardening_tab(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page)
        notice = QLabel("Actions are individual and opt-in. Select one, review the exact proposal, and confirm it. WinCur never runs all fixes automatically."); notice.setWordWrap(True); notice.setObjectName("methodology"); layout.addWidget(notice)
        top = QHBoxLayout(); self.preview_button = QPushButton("Refresh Action Previews"); self.preview_button.setObjectName("xpButton"); self.preview_button.clicked.connect(self._refresh_previews); top.addWidget(self.preview_button); top.addStretch(1); layout.addLayout(top)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.action_tree = CoordinatedTreeWidget(); self.action_tree.setHeaderLabels(["Hardening action", "Severity", "State", "Current configuration"]); self.action_tree.setRootIsDecorated(False); self.action_tree.setMinimumHeight(110)
        self.action_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch); self.action_tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents); self.action_tree.header().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents); self.action_tree.header().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.action_tree.currentItemChanged.connect(self._show_action); splitter.addWidget(self.action_tree)
        detail = QWidget(); details = QVBoxLayout(detail); self.action_title = QLabel("No action preview selected"); self.action_title.setObjectName("detailTitle"); details.addWidget(self.action_title)
        self.action_details = QTextBrowser(); self.action_details.setMaximumHeight(110); self.action_details.setHtml("<p>Select an action above, then choose <b>Preview Selected Action</b>. Previewing is read-only and never changes Windows settings.</p>"); details.addWidget(self.action_details)
        self.advanced_details = QTextBrowser(); self.advanced_details.setVisible(False); self.advanced_details.setMaximumHeight(170); details.addWidget(self.advanced_details)
        self.preview_status_panel = QFrame(); self.preview_status_panel.setObjectName("infoPanel"); preview_status_layout = QVBoxLayout(self.preview_status_panel); preview_status_layout.setContentsMargins(10, 7, 10, 7); preview_status_layout.setSpacing(2)
        self.preview_status_title = QLabel("Preview required before applying"); preview_status_font = self.preview_status_title.font(); preview_status_font.setBold(True); self.preview_status_title.setFont(preview_status_font); self.preview_status_title.setObjectName("infoValue"); preview_status_layout.addWidget(self.preview_status_title)
        self.preview_status_text = QLabel("Select an action, then review its proposed changes. No changes will be made during the preview."); self.preview_status_text.setObjectName("intro"); self.preview_status_text.setWordWrap(True); preview_status_layout.addWidget(self.preview_status_text); details.addWidget(self.preview_status_panel)
        buttons = QHBoxLayout(); self.preview_selected_button = QPushButton("Preview Selected Action"); self.preview_selected_button.setObjectName("xpButton"); self.preview_selected_button.clicked.connect(self._preview_selected_action); buttons.addWidget(self.preview_selected_button)
        self.apply_button = QPushButton("Apply Selected Action"); self.apply_button.setObjectName("scanButton"); self.apply_button.setEnabled(False); self.apply_button.setToolTip("Preview this remediation before applying it."); self.apply_button.clicked.connect(self._apply_selected_action); buttons.addWidget(self.apply_button)
        self.advanced_button = QPushButton("Show Advanced Details"); self.advanced_button.setObjectName("xpButton"); self.advanced_button.clicked.connect(self._toggle_advanced); buttons.addWidget(self.advanced_button); buttons.addStretch(1); details.addLayout(buttons)
        splitter.addWidget(detail); self.hardening_splitter = self._register_splitter("hardening_workspace", splitter, [260, 300]); layout.addWidget(splitter)
        for action_id, definition in ACTIONS.items():
            item = QTreeWidgetItem([definition.title, definition.severity, "Refresh required", "Not queried"]); item.setData(0, Qt.ItemDataRole.UserRole, action_id); self._style_severity(item, 1, definition.severity); self.action_tree.addTopLevelItem(item)
        return page

    def _action_history_tab(self) -> QWidget:
        page = QWidget(); layout = QVBoxLayout(page)
        note = QLabel("Rollback always requires selection, confirmation, and UAC. Firewall rollback is intentionally unavailable because it could weaken protection."); note.setWordWrap(True); note.setObjectName("methodology"); layout.addWidget(note)
        self.action_history_table = CoordinatedTableWidget(0, 5); self.action_history_table.setHorizontalHeaderLabels(["Date and time", "Action", "Operation type", "Result", "Verification / rollback"])
        self.action_history_table.verticalHeader().setVisible(False); self.action_history_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers); self.action_history_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows); self.action_history_table.itemSelectionChanged.connect(self._update_rollback_button)
        self.action_history_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents); self.action_history_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch); self.action_history_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents); self.action_history_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents); self.action_history_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.action_history_table)
        self.rollback_button = QPushButton("Rollback Selected Action"); self.rollback_button.setObjectName("xpButton"); self.rollback_button.setEnabled(False); self.rollback_button.setToolTip("Select a valid rollback-eligible audit record."); self.rollback_button.clicked.connect(self._rollback_selected); layout.addWidget(self.rollback_button, 0, Qt.AlignmentFlag.AlignLeft)
        return page

    def _refresh_previews(self) -> None:
        if self.action_busy or (self.preview_thread and self.preview_thread.isRunning()): return
        self.validated_preview = None; self.apply_button.setEnabled(False); self.preview_mode = "all"
        self._mark_previews_pending(list(ACTIONS)); self.preview_button.setEnabled(False); self.preview_button.setText("Reading configuration..."); self._start_preview_worker(None)

    def _preview_selected_action(self) -> None:
        item = self.action_tree.currentItem()
        if not item or self.action_busy or (self.preview_thread and self.preview_thread.isRunning()): return
        self.validated_preview = None; self.apply_button.setEnabled(False); self.preview_mode = "selected"; self.preview_selected_button.setEnabled(False); self.preview_selected_button.setText("Previewing...")
        action_id = str(item.data(0, Qt.ItemDataRole.UserRole)); self._mark_previews_pending([action_id]); self._start_preview_worker(action_id)

    def _mark_previews_pending(self, action_ids: list[str]) -> None:
        requested = set(action_ids); self.preview_request_ids = list(action_ids); self._clear_validated_preview()
        self.previews = [preview for preview in self.previews if preview.action_id not in requested]
        for row in range(self.action_tree.topLevelItemCount()):
            item = self.action_tree.topLevelItem(row)
            if item.data(0, Qt.ItemDataRole.UserRole) in requested:
                item.setText(2, "Reading configuration"); item.setText(3, "Query in progress")
        self._show_action(self.action_tree.currentItem(), None)

    def _clear_validated_preview(self) -> None:
        self.preview_expiry_timer.stop(); self.validated_preview = None; self.apply_button.setEnabled(False); self.apply_button.setToolTip("Preview this remediation before applying it.")

    def _accept_validated_preview(self, preview: ActionPreview) -> None:
        self._clear_validated_preview()
        if preview.availability != ActionAvailability.AVAILABLE: return
        try:
            created = datetime.fromisoformat(preview.created_utc.replace("Z", "+00:00")); created = created.replace(tzinfo=timezone.utc) if created.tzinfo is None else created.astimezone(timezone.utc)
            remaining_ms = min(300000, int((created.timestamp() + 300 - datetime.now(timezone.utc).timestamp()) * 1000))
        except (AttributeError, TypeError, ValueError): remaining_ms = 0
        if remaining_ms <= 0:
            self.preview_repeat_reasons[preview.action_id] = "The preview is missing a current validation timestamp or has expired. Preview this remediation again."
            return
        self.validated_preview = preview; self.preview_repeat_reasons.pop(preview.action_id, None)
        self.preview_expiry_timer.start(remaining_ms)

    def _expire_validated_preview(self) -> None:
        preview = self.validated_preview
        if not preview: return
        self.preview_repeat_reasons[preview.action_id] = "The preview expired. Preview this remediation again so WinCur can revalidate the current configuration."
        self._clear_validated_preview(); self._show_action(self.action_tree.currentItem(), None)

    def _start_preview_worker(self, action_id: str | None) -> None:
        self.preview_thread = QThread(self); self.preview_worker = PreviewWorker(action_id); self.preview_worker.moveToThread(self.preview_thread); self.preview_thread.started.connect(self.preview_worker.run)
        self.preview_worker.finished.connect(self._previews_ready); self.preview_worker.failed.connect(self._previews_failed); self.preview_worker.finished.connect(self.preview_thread.quit); self.preview_worker.failed.connect(self.preview_thread.quit); self.preview_worker.finished.connect(self.preview_worker.deleteLater); self.preview_worker.failed.connect(self.preview_worker.deleteLater); self.preview_thread.finished.connect(self._preview_thread_finished); self.preview_thread.finished.connect(self.preview_thread.deleteLater); self.preview_thread.start()

    def _previews_ready(self, previews: list[ActionPreview]) -> None:
        received = {preview.action_id for preview in previews}
        for preview in previews:
            self.previews = [old for old in self.previews if old.action_id != preview.action_id] + [preview]
            for row in range(self.action_tree.topLevelItemCount()):
                item = self.action_tree.topLevelItem(row)
                if item.data(0, Qt.ItemDataRole.UserRole) == preview.action_id:
                    item.setText(2, preview.availability.value); item.setText(3, preview.current_configuration); break
        for action_id in set(self.preview_request_ids) - received:
            for row in range(self.action_tree.topLevelItemCount()):
                item = self.action_tree.topLevelItem(row)
                if item.data(0, Qt.ItemDataRole.UserRole) == action_id:
                    item.setText(2, "Refresh failed"); item.setText(3, "Configuration unavailable"); break
        self.preview_request_ids = []
        if not self.action_tree.currentItem() and self.action_tree.topLevelItemCount(): self.action_tree.setCurrentItem(self.action_tree.topLevelItem(0))
        if self.preview_mode == "selected" and previews:
            preview = previews[0]
            if preview.availability == ActionAvailability.REQUIRES_ELEVATION:
                QTimer.singleShot(0, lambda action_id=preview.action_id: self._launch_helper("preview", ["--helper-preview", action_id], action_id))
            else:
                self._accept_validated_preview(preview)
        self.preview_button.setEnabled(True); self.preview_button.setText("Refresh Action Previews"); self.preview_selected_button.setEnabled(True); self.preview_selected_button.setText("Preview Selected Action"); self._show_action(self.action_tree.currentItem(), None)

    def _previews_failed(self, message: str) -> None:
        for action_id in self.preview_request_ids:
            for row in range(self.action_tree.topLevelItemCount()):
                item = self.action_tree.topLevelItem(row)
                if item.data(0, Qt.ItemDataRole.UserRole) == action_id:
                    item.setText(2, "Refresh failed"); item.setText(3, "Configuration unavailable"); break
        self.preview_request_ids = []; self._clear_validated_preview(); self._show_action(self.action_tree.currentItem(), None)
        self.preview_button.setEnabled(True); self.preview_button.setText("Refresh Action Previews"); self.preview_selected_button.setEnabled(True); self.preview_selected_button.setText("Preview Selected Action"); QMessageBox.warning(self, "Preview failed", message)

    def _preview_thread_finished(self) -> None: self.preview_thread = None; self.preview_worker = None

    def _selected_preview(self) -> ActionPreview | None:
        item = self.action_tree.currentItem()
        if not item: return None
        action_id = item.data(0, Qt.ItemDataRole.UserRole)
        return next((preview for preview in self.previews if preview.action_id == action_id), None)

    def _show_action(self, current: QTreeWidgetItem | None, previous: QTreeWidgetItem | None) -> None:
        preview = self._selected_preview()
        if not preview:
            self.apply_button.setEnabled(False); self.apply_button.setToolTip("Preview this remediation before applying it."); self.action_title.setText("No action preview selected"); self.action_details.setMaximumHeight(110); self.action_details.setHtml("<p>Select an action above, then choose <b>Preview Selected Action</b>. Previewing is read-only and never changes Windows settings.</p>")
            state = current.text(2) if current else ""
            action_id = str(current.data(0, Qt.ItemDataRole.UserRole)) if current else ""
            if action_id in self.preview_repeat_reasons: self.preview_status_title.setText("Preview required again"); self.preview_status_text.setText(self.preview_repeat_reasons[action_id])
            elif state == "Reading configuration": self.preview_status_title.setText("Preview in progress"); self.preview_status_text.setText("WinCur is reading the current configuration. No changes are being made.")
            elif state == "Refresh failed": self.preview_status_title.setText("Preview failed"); self.preview_status_text.setText("The current configuration could not be read. Refresh or preview this action again; Apply remains unavailable.")
            elif current: self.preview_status_title.setText("Preview required before applying"); self.preview_status_text.setText("Review the proposed changes before applying this remediation. No changes will be made during the preview.")
            else: self.preview_status_title.setText("Select a remediation action"); self.preview_status_text.setText("Choose an action to review its current and recommended configuration.")
            return
        self.action_details.setMaximumHeight(16777215)
        self.action_title.setText(f"{preview.title} — {preview.availability.value}")
        sections = [("Security finding and severity", f"{preview.finding} — {preview.severity}"), ("Current configuration", preview.current_configuration), ("Recommended configuration", preview.recommended_configuration), ("Why this matters", preview.rationale), ("Compatibility considerations", preview.compatibility), ("Required permissions", preview.required_permissions), ("Exact proposed change", preview.exact_change), ("Verification", preview.verification), ("Rollback", preview.rollback), ("Management evidence", preview.management_evidence)]
        self.action_details.setHtml(html_sections(sections)); self.advanced_details.setPlainText(sanitize_display_text(preview.technical_details or "No additional technical details."))
        valid = self.validated_preview is not None and self.validated_preview.action_id == preview.action_id and self.validated_preview.preview_token == preview.preview_token
        ready = valid and preview.availability == ActionAvailability.AVAILABLE and not self.action_busy; self.apply_button.setEnabled(ready); self.apply_button.setToolTip("Apply this previewed remediation after explicit confirmation." if ready else "Preview this remediation before applying it.")
        if ready: self.preview_status_title.setText("Preview complete"); self.preview_status_text.setText("This action is ready for confirmation.")
        elif preview.action_id in self.preview_repeat_reasons: self.preview_status_title.setText("Preview required again"); self.preview_status_text.setText(self.preview_repeat_reasons[preview.action_id])
        elif preview.availability == ActionAvailability.AVAILABLE: self.preview_status_title.setText("Preview required before applying"); self.preview_status_text.setText("Review the proposed changes before applying this remediation. No changes will be made during the preview.")
        elif preview.availability == ActionAvailability.ALREADY_COMPLIANT: self.preview_status_title.setText("No action required"); self.preview_status_text.setText("The current configuration already meets this remediation requirement, so Apply remains unavailable.")
        elif preview.availability == ActionAvailability.MANAGED: self.preview_status_title.setText("Action blocked — managed setting"); self.preview_status_text.setText("WinCur detected organizational management for this setting. Apply remains unavailable. " + sanitize_display_text(preview.management_evidence))
        elif preview.availability == ActionAvailability.REQUIRES_ELEVATION: self.preview_status_title.setText("Administrator preview required"); self.preview_status_text.setText("Administrator authorization is required to complete the read-only preview. Apply remains unavailable.")
        elif preview.availability == ActionAvailability.MANUAL: self.preview_status_title.setText("Manual review required"); self.preview_status_text.setText("WinCur could not safely establish management ownership or supported automation. Apply remains unavailable. " + sanitize_display_text(preview.management_evidence))
        else: self.preview_status_title.setText("Action unavailable"); self.preview_status_text.setText("This configuration cannot be remediated through the supported WinCur workflow. Apply remains unavailable. " + sanitize_display_text(preview.management_evidence))

    def _toggle_advanced(self) -> None:
        visible = not self.advanced_details.isVisible(); self.advanced_details.setVisible(visible); self.advanced_button.setText("Hide Advanced Details" if visible else "Show Advanced Details")

    def _apply_selected_action(self) -> None:
        preview = self.validated_preview
        selected = self._selected_preview()
        if not preview or not selected or preview.action_id != selected.action_id or preview.preview_token != selected.preview_token or preview.availability != ActionAvailability.AVAILABLE or self.action_busy: return
        text = f"Apply only this action?\n\n{preview.title}\n\nExact change:\n{preview.exact_change}\n\nCompatibility:\n{preview.compatibility}\n\nWinCur will capture the original state and verify the result."
        if QMessageBox.question(self, "Confirm hardening action", text, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes: return
        try:
            request_path = pending_output_path("apply-request")
            atomic_write_json(request_path, {"action_id": preview.action_id, "preview_token": preview.preview_token, "created_utc": preview.created_utc})
        except OSError as exc:
            QMessageBox.warning(self, "Remediation could not start", f"WinCur could not securely stage the approved request. No changes were made.\n\n{exc}"); return
        if not self._launch_helper("action", ["--helper-action", preview.action_id, str(request_path)], preview.action_id):
            try: request_path.unlink(missing_ok=True)
            except OSError: pass

    def _rollback_selected(self) -> None:
        row = self.action_history_table.currentRow()
        records = self.action_history_records
        if row < 0 or row >= len(records): return
        record = records[row]
        eligible, reason = rollback_record_eligibility(record, records)
        if not eligible: QMessageBox.information(self, "Rollback unavailable", reason); self._update_rollback_button(); return
        if QMessageBox.question(self, "Confirm rollback", "Restore the captured prior state for this action? This may reduce the hardening level and requires UAC approval.", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes: return
        try:
            request_path = pending_output_path("rollback-request"); atomic_write_json(request_path, record)
        except OSError as exc:
            QMessageBox.warning(self, "Rollback could not start", f"WinCur could not securely stage the approved rollback request. No changes were made.\n\n{exc}"); return
        if not self._launch_helper("rollback", ["--helper-rollback", str(record["action_id"]), str(request_path)], str(record["action_id"])):
            try: request_path.unlink(missing_ok=True)
            except OSError: pass

    def _update_rollback_button(self) -> None:
        if not hasattr(self, "rollback_button"): return
        row = self.action_history_table.currentRow(); records = self.action_history_records
        eligible, reason = (False, "Select a valid rollback-eligible audit record.") if row < 0 or row >= len(records) else rollback_record_eligibility(records[row], records)
        self.rollback_button.setEnabled(eligible and not self.action_busy); self.rollback_button.setToolTip("Restore the validated captured state after confirmation and UAC." if eligible else reason)

    def _open_hardening_audit(self, timestamp_utc: str = "") -> None:
        self._set_page(2); self._set_activity_view(1); self._update_action_history(timestamp_utc)

    def start_scan(self) -> None:
        if self.action_busy or (self.scan_thread and self.scan_thread.isRunning()): return
        privilege = self.application_privilege; profile = self.selected_profile
        self.scan_button.setEnabled(False); self.scan_button.setText("Scanning..."); self.export_button.setEnabled(False); self.profile_combo.setEnabled(False)
        self.scan_message.setText(f"Running a {privilege.lower()} read-only scan using the {profile} profile...")
        if self.current_record: self.assessment_source_label.setText("Assessment state: Previous result remains visible while scanning")
        self.scan_thread = QThread(self); self.worker = self.scan_worker_factory(self.config, profile, privilege); self.worker.moveToThread(self.scan_thread); self.scan_thread.started.connect(self.worker.run)
        self.worker.finished.connect(self._scan_finished); self.worker.failed.connect(self._scan_failed); self.worker.finished.connect(self.scan_thread.quit); self.worker.failed.connect(self.scan_thread.quit)
        self.worker.finished.connect(self.worker.deleteLater); self.worker.failed.connect(self.worker.deleteLater); self.scan_thread.finished.connect(self._thread_finished); self.scan_thread.finished.connect(self.scan_thread.deleteLater); self.scan_thread.start()

    def _scan_finished(self, envelope: AssessmentEnvelope) -> None:
        self._commit_assessment(envelope, persist_history=True)

    def _commit_assessment(self, envelope: AssessmentEnvelope, persist_history: bool) -> None:
        self._invalidate_displayed_baseline_comparison("Displayed assessment changed. Previous comparison results were cleared.")
        self.findings = list(envelope.findings)
        self.current_record = ScanRecord.create(
            APP_VERSION, self.windows_name, self.computer_name, self.findings, envelope.assessment,
            assessment_privilege=envelope.privilege, assessment_source=envelope.source,
            timestamp_utc=envelope.timestamp_utc,
        )
        active_baseline = self.baseline_collection.active
        self.latest_baseline_comparison = compare_to_baseline(active_baseline.assessment_snapshot, self.current_record.to_dict()) if active_baseline else None
        views = (self.category_table, self.tree)
        for view in views: view.setUpdatesEnabled(False)
        self._populate(envelope.assessment)
        for view in views:
            view.setUpdatesEnabled(True); view.viewport().update()
        self.score_panel.value.setText("Not scored" if envelope.assessment.score is None else f"{envelope.assessment.score:.1f}%")
        self.coverage_panel.value.setText(f"{envelope.assessment.coverage:.1f}%")
        self.assessment_profile_label.setText(f"Profile: {envelope.assessment.profile}")
        self.assessment_privilege_label.setText(f"Assessment privilege: {envelope.privilege}")
        self.assessment_timestamp_label.setText(f"Last assessment: {friendly_timestamp(envelope.timestamp_utc)}"); self.assessment_timestamp_label.setToolTip(timestamp_tooltip(envelope.timestamp_utc))
        historical = "historical" in envelope.source.casefold()
        self.assessment_source_label.setText(f"Historical assessment — not a current scan · Policy {envelope.assessment.policy_version}" if historical else f"Scoring policy: {envelope.assessment.policy_version}")
        try:
            timestamp = datetime.fromisoformat(envelope.timestamp_utc.replace("Z", "+00:00")); timestamp = timestamp.replace(tzinfo=timezone.utc) if timestamp.tzinfo is None else timestamp.astimezone(timezone.utc); age_minutes = max(0, int((datetime.now(timezone.utc) - timestamp).total_seconds() / 60))
            freshness = "Historical — not current" if historical else ("Just scanned" if age_minutes < 5 else f"{age_minutes // 60}h {age_minutes % 60}m old" if age_minutes < 1440 else f"{age_minutes // 1440} day(s) old")
        except (ValueError, TypeError): freshness = "Unknown"
        self.assessment_freshness_label.setText(f"Freshness: {freshness}")
        message = "Existing findings re-scored for the selected profile; no new scan was run." if not persist_history else "Scan complete; all assessment views updated."
        if self.score_before_action is not None:
            before = f"{self.score_before_action:.1f}%"; after = "Not scored" if envelope.assessment.score is None else f"{envelope.assessment.score:.1f}%"
            message = f"Verified post-action scan complete. Score before: {before}; after: {after}; coverage: {envelope.assessment.coverage:.1f}%."
            self.score_before_action = None
        self.scan_message.setText(message); self.scan_button.setEnabled(True); self.scan_button.setText("Scan PC"); self.export_button.setEnabled(True); self.profile_combo.setEnabled(True)
        self.assessment_displayed.emit(envelope)
        self._update_dashboard_baseline(); self._refresh_baseline_assessments()
        if persist_history: self._save_history_async(self.current_record)

    def _save_history_async(self, record: ScanRecord) -> None:
        if self.history_thread and self.history_thread.isRunning():
            self.pending_history_records.append(record)
            return
        self.history_thread = QThread(self); self.history_worker = HistoryWorker(record, self.history_path); self.history_worker.moveToThread(self.history_thread)
        self.history_thread.started.connect(self.history_worker.run); self.history_worker.finished.connect(self._history_saved); self.history_worker.finished.connect(self.history_thread.quit); self.history_worker.finished.connect(self.history_worker.deleteLater)
        self.history_thread.finished.connect(self._history_thread_finished); self.history_thread.finished.connect(self.history_thread.deleteLater); self.history_thread.start()

    def _history_saved(self, error: str) -> None:
        if error:
            LOGGER.error("Scan history could not be saved: %s", error)
            self.scan_message.setText("Scan completed, but the assessment could not be saved to local history. The displayed result is still available for review or export.")
            QMessageBox.warning(self, "Assessment history not saved", f"The assessment completed, but WinCur could not save it to local history. Check access to the WinCur application-data folder and try another scan.\n\n{error}")
        self._update_history()

    def _history_thread_finished(self) -> None:
        self.history_thread = None; self.history_worker = None
        if self.pending_history_records: self._save_history_async(self.pending_history_records.pop(0))

    def _scan_failed(self, message: str) -> None:
        self.scan_message.setText("Scan failed; no settings were changed and no new assessment was displayed."); self.scan_button.setEnabled(True); self.scan_button.setText("Scan PC"); self.profile_combo.setEnabled(True)
        self.export_button.setEnabled(self.current_record is not None)
        if self.current_record: self.assessment_source_label.setText("Assessment state: Previous result retained because the scan failed")
        QMessageBox.warning(self, "WinCur scan failed", message)

    def _thread_finished(self) -> None: self.scan_thread = None; self.worker = None

    def _run_elevated_scan(self) -> None:
        if is_administrator(): self.start_scan(); return
        self.profile_combo.setEnabled(False)
        if self.current_record: self.assessment_source_label.setText("Assessment state: Previous result remains visible during the Administrator scan")
        self._launch_helper("scan", ["--helper-scan", self.selected_profile], "")

    def _launch_helper(self, kind: str, arguments: list[str], action_id: str) -> bool:
        if self.action_busy or (self.scan_thread and self.scan_thread.isRunning()): return False
        try:
            output = pending_output_path(kind); started, message = launch_elevated_helper([*arguments, str(output)])
        except OSError as exc:
            started, message = False, f"WinCur could not create a protected helper result path: {exc}"
        if not started:
            self.profile_combo.setEnabled(True); self.scan_message.setText(message + " Standard mode remains available.")
            if kind == "scan" and self.current_record: self.assessment_source_label.setText("Assessment state: Previous result retained; Administrator scan was not started")
            QMessageBox.warning(self, "Elevated operation not started", message)
            return False
        self.pending_path = output; self.pending_kind = kind; self.pending_started = time.monotonic(); self.action_busy = True; self.pending_action_id = action_id
        self.scan_button.setEnabled(False); self.elevated_button.setEnabled(False); self.apply_button.setEnabled(False); self.preview_button.setEnabled(False); self.preview_selected_button.setEnabled(False); self.rollback_button.setEnabled(False); self.scan_message.setText("Waiting for the explicitly approved elevated helper..."); self.helper_timer.start()
        if kind == "preview": self.preview_status_title.setText("Administrator preview in progress"); self.preview_status_text.setText("WinCur is waiting for the explicitly approved read-only preview. No changes are being made.")
        return True

    def _poll_helper(self) -> None:
        if not self.pending_path: return
        if time.monotonic() - self.pending_started > 180:
            kind, action_id = self.pending_kind, self.pending_action_id; self._finish_helper(); self.scan_message.setText("The elevated helper did not return a result. No success was claimed.")
            if kind == "preview": self.preview_repeat_reasons[action_id] = "The administrator preview timed out. Preview this remediation again; Apply remains unavailable."; self._clear_validated_preview(); self._show_action(self.action_tree.currentItem(), None)
            return
        if not self.pending_path.exists(): return
        try:
            payload = json.loads(self.pending_path.read_text(encoding="utf-8")); self.pending_path.unlink(missing_ok=True)
        except (OSError, json.JSONDecodeError) as exc:
            kind, action_id = self.pending_kind, self.pending_action_id; self._finish_helper()
            if kind == "preview": self.preview_repeat_reasons[action_id] = "The administrator preview result could not be read. Preview this remediation again; Apply remains unavailable."; self._clear_validated_preview(); self._show_action(self.action_tree.currentItem(), None)
            QMessageBox.warning(self, "Helper result error", str(exc)); return
        kind, action_id = self.pending_kind, self.pending_action_id; self._finish_helper()
        if not isinstance(payload, dict):
            QMessageBox.warning(self, "Helper result error", "The elevated helper returned an invalid result object. No success was claimed."); return
        if not payload.get("ok"):
            if kind == "preview": self.preview_repeat_reasons[action_id] = "The administrator preview failed. Review the reported error and preview this remediation again; Apply remains unavailable."; self._clear_validated_preview(); self._show_action(self.action_tree.currentItem(), None)
            QMessageBox.warning(self, "Elevated operation failed", str(payload.get("error", "No details were returned."))); return
        try:
            if kind == "scan":
                raw_findings = payload.get("findings")
                if not isinstance(raw_findings, list): raise ValueError("The helper did not return a findings collection.")
                findings = [CheckResult.from_dict(item) for item in raw_findings]; assessment = AssessmentScore.from_dict(payload["assessment"])
                envelope = AssessmentEnvelope(findings, assessment, str(payload["timestamp_utc"]), str(payload["privilege"]), str(payload.get("source", "Live elevated scan")))
                self._scan_finished(envelope); return
            if kind == "preview":
                preview = ActionPreview.from_dict(payload["preview"]); self.previews = [old for old in self.previews if old.action_id != preview.action_id] + [preview]
                self._accept_validated_preview(preview)
                for row in range(self.action_tree.topLevelItemCount()):
                    item = self.action_tree.topLevelItem(row)
                    if item.data(0, Qt.ItemDataRole.UserRole) == preview.action_id:
                        item.setText(2, preview.availability.value); item.setText(3, preview.current_configuration); self.action_tree.setCurrentItem(item); break
                self.scan_message.setText("Elevated preview complete; no settings were changed."); self._show_action(self.action_tree.currentItem(), None); return
            record = ActionRecord.from_dict(payload["record"])
        except (KeyError, TypeError, ValueError) as exc:
            QMessageBox.warning(self, "Helper result error", f"The elevated helper returned incomplete or invalid data. No success was claimed.\n\n{exc}"); return
        if kind == "action" and record.outcome == ActionOutcome.FAILURE and ("stale" in record.message.casefold() or "configuration changed" in record.message.casefold()):
            self.preview_repeat_reasons[record.action_id] = "The configuration or management state changed after preview. Preview this remediation again before applying it."
        self._handle_action_record(record, kind)

    def _handle_action_record(self, record: ActionRecord, kind: str) -> None:
        saved = True
        try: save_action_record(record)
        except OSError as exc:
            saved = False; QMessageBox.warning(self, "Action history", f"The action result could not be saved and verified: {exc}")
        self._update_action_history(record.timestamp_utc if saved else "")
        self.score_before_action = None; self._clear_validated_preview()
        if kind == "action" and record.outcome == ActionOutcome.SUCCESS:
            self.scan_message.setText("Action verified. The previous assessment remains displayed and its score has not been refreshed. Run Scan PC when you want a new assessment.")
        elif kind == "rollback":
            self.scan_message.setText(f"Rollback {record.outcome.value}: {record.verification_evidence}")
        else:
            self.scan_message.setText(f"{record.outcome.value}: {record.verification_evidence}")
        self._show_action_result(record, kind); self._refresh_action_after_operation(record.action_id)

    def _show_action_result(self, record: ActionRecord, kind: str) -> None:
        operation = "Rollback" if kind == "rollback" else "Remediation"
        box = QMessageBox(self); box.setWindowTitle(f"{operation}: {record.outcome.value}"); box.setText(record.message); box.setInformativeText("Verification:\n" + record.verification_evidence)
        icon = QMessageBox.Icon.Information if record.outcome == ActionOutcome.SUCCESS else QMessageBox.Icon.Warning if record.outcome == ActionOutcome.PARTIAL else QMessageBox.Icon.Critical
        box.setIcon(icon); view_button = box.addButton("View in Hardening Audit", QMessageBox.ButtonRole.ActionRole) if kind == "action" and record.outcome == ActionOutcome.SUCCESS else None; box.addButton(QMessageBox.StandardButton.Close); box.exec()
        if view_button is not None and box.clickedButton() is view_button: self._open_hardening_audit(record.timestamp_utc)

    def _refresh_action_after_operation(self, action_id: str) -> None:
        if action_id not in ACTIONS or self.action_busy or (self.preview_thread and self.preview_thread.isRunning()): return
        self.preview_mode = "all"; self._mark_previews_pending([action_id]); self._start_preview_worker(action_id)

    def _finish_helper(self) -> None:
        path = self.pending_path; self.helper_timer.stop(); self.pending_path = None; self.pending_kind = ""; self.pending_action_id = ""; self.action_busy = False
        if path:
            try: path.unlink(missing_ok=True)
            except OSError: LOGGER.warning("Pending helper result could not be removed: %s", path)
        self.scan_button.setEnabled(True); self.elevated_button.setEnabled(self.application_privilege != "Administrator"); self.preview_button.setEnabled(True); self.preview_selected_button.setEnabled(True); self.profile_combo.setEnabled(True); self._update_rollback_button()

    def _populate(self, assessment: AssessmentScore) -> None:
        self.score_panel.value.setText("Not scored" if assessment.score is None else f"{assessment.score:.1f}%"); self.coverage_panel.value.setText(f"{assessment.coverage:.1f}%")
        self.category_table.setRowCount(len(assessment.categories))
        for row, category in enumerate(assessment.categories):
            values = [category.category, "Not scored" if category.score is None else f"{category.score:.1f}%", f"{category.coverage:.1f}%", category.passed, category.failed, category.unknown, category.informational, category.not_applicable]
            for col, value in enumerate(values): self.category_table.setItem(row, col, QTableWidgetItem(str(value)))
        self.methodology_label.setText(f"Profile: {assessment.profile} · Policy: {assessment.policy_version}. Unknown lowers coverage; informational and Not Applicable checks are excluded.")
        self._rebuild_current_findings()
        self.dashboard_findings.clear(); severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        priorities = [(index, finding) for index, finding in enumerate(self.findings) if finding.status == CheckStatus.FAIL and assessment.dispositions.get(finding.check_id) != "Informational"]
        priorities.sort(key=lambda entry: (severity_order.get(entry[1].severity, 9), entry[1].title))
        unknown_count = sum(finding.status == CheckStatus.UNKNOWN and assessment.dispositions.get(finding.check_id) != "Informational" for finding in self.findings)
        self.findings_panel.value.setText(str(len(priorities)))
        needs = "needs" if len(priorities) == 1 else "need"
        self.findings_panel.description.setText(f"{len(priorities)} setting{'s' if len(priorities) != 1 else ''} {needs} attention · {unknown_count} could not be assessed.")
        for index, finding in priorities[:5]:
            item = QTreeWidgetItem([finding.title, evidence_preview(finding.explanation, 125), finding.severity]); item.setData(0, Qt.ItemDataRole.UserRole, index); self._style_severity(item, 2, finding.severity); self.dashboard_findings.addTopLevelItem(item)
        if priorities:
            self.overview_status_label.setText("Some settings need attention"); self.overview_explanation_label.setText(f"{len(priorities)} assessed setting(s) did not meet the selected hardening profile. Review the highest-priority issues below. This is not a guarantee of overall security.")
        elif assessment.coverage < 100 or unknown_count:
            self.overview_status_label.setText("Assessment incomplete"); self.overview_explanation_label.setText(f"No scored failures were detected, but {unknown_count} check(s) could not be assessed. Resolve visibility or compatibility limitations before drawing conclusions.")
        else:
            self.overview_status_label.setText("No assessed issues detected"); self.overview_explanation_label.setText("All assessed, scored checks met the selected profile. This result covers selected configuration settings and is not a guarantee that the computer is secure.")
        if not priorities: self.dashboard_findings.addTopLevelItem(QTreeWidgetItem(["No actionable failed checks to show", "Open Security Issues to review all checks.", "—"]))

    def _rebuild_current_findings(self, *_args) -> None:
        if not hasattr(self, "tree"): return
        self._refresh_current_filter_options()
        assessment = self.current_record.assessment if self.current_record else None; dispositions = assessment.dispositions if assessment else {}; comparisons = {item.check_id: item for item in self.latest_baseline_comparison.results} if self.latest_baseline_comparison else {}
        status_filter = self.current_status_filter.currentText() if hasattr(self, "current_status_filter") else "Needs Attention"; change_filter = self.baseline_change_filter.currentText() if hasattr(self, "baseline_change_filter") else "All changes"; category_filter = self.finding_category_combo.currentText(); severity_filter = self.finding_severity_combo.currentText()
        self.tree.clear()
        for index, finding in enumerate(self.findings):
            informational = dispositions.get(finding.check_id) == "Informational"; comparison = comparisons.get(finding.check_id); change = comparison.classification if comparison else "No baseline comparison"
            status_match = (status_filter == "All Checks" or status_filter == "Needs Attention" and finding.status == CheckStatus.FAIL and not informational or status_filter == "Passed" and finding.status == CheckStatus.PASS and not informational or status_filter == "Could Not Assess" and finding.status == CheckStatus.UNKNOWN and not informational)
            review_classes = (NEWLY_ASSESSABLE, NO_LONGER_ASSESSABLE, EVIDENCE_ONLY, NOT_COMPARABLE)
            change_match = (change_filter == "All changes" or change_filter == "Security setting worsened" and change == REGRESSION or change_filter == "Security setting improved" and change == IMPROVEMENT or change_filter == "No change" and change == UNCHANGED or change_filter == "Requires review" and change in review_classes)
            effective_severity = "Informational" if informational else finding.severity; category_match = category_filter == "All categories" or finding.category == category_filter; severity_match = severity_filter == "All severities" or effective_severity == severity_filter
            if not status_match or not change_match or not category_match or not severity_match: continue
            status_text = f"Informational ({finding.status.value})" if informational else "Could not assess" if finding.status == CheckStatus.UNKNOWN else finding.status.value; item = QTreeWidgetItem([sanitize_display_text(finding.title), effective_severity, status_text, evidence_preview(finding.explanation, 150)]); item.setData(0, Qt.ItemDataRole.UserRole, index); item.setToolTip(0, sanitize_display_text(finding.title)); item.setToolTip(3, sanitize_display_text(finding.explanation))
            self._style_finding_item(item, finding.status, informational); self._style_severity(item, 1, "Informational" if informational else finding.severity); self.tree.addTopLevelItem(item)
        if self.tree.topLevelItemCount(): self.tree.setCurrentItem(self.tree.topLevelItem(0))
        else: self.detail_title.setText("No current findings match these filters."); self.details.clear(); self.technical_finding_details.clear(); self.finding_fix_button.setEnabled(False); self.settings_button.setEnabled(False)

    def _refresh_current_filter_options(self) -> None:
        categories = sorted({finding.category for finding in self.findings})
        selected = self.finding_category_combo.currentText(); self.finding_category_combo.blockSignals(True); self.finding_category_combo.clear(); self.finding_category_combo.addItem("All categories"); self.finding_category_combo.addItems(categories); self.finding_category_combo.setCurrentText(selected if selected in ["All categories", *categories] else "All categories"); self.finding_category_combo.blockSignals(False)

    def _reset_findings_filters(self) -> None:
        for combo, value in ((self.current_status_filter, "Needs Attention"), (self.finding_category_combo, "All categories"), (self.finding_severity_combo, "All severities"), (self.baseline_change_filter, "All changes")):
            combo.blockSignals(True); combo.setCurrentText(value); combo.blockSignals(False)
        self._rebuild_current_findings()

    @staticmethod
    def _unknown_recommendation(finding: CheckResult, privilege: str) -> str:
        context = f"{finding.evidence} {finding.explanation}".casefold()
        if finding.check_id == "local_admins" and "enumerat" in context and ("will not guess" in context or "approved_local_administrators" in context):
            return "Administrator membership was successfully enumerated. Configure an approved-administrator policy to determine whether the detected accounts meet your security requirements."
        if finding.check_id == "smartscreen" and ("not configured / insufficient evidence" in context or "not present" in context):
            return "The inspected SmartScreen configuration values are absent. Review Windows Security > App & browser control to inspect the displayed protection settings."
        if "diagnostic reason: insufficient permissions" in context:
            if privilege.casefold().startswith("admin"):
                return "This assessment already ran with Administrator privileges, but Windows still denied access. Review the technical details and the device's policy or provider availability."
            return "Run an Administrator assessment if appropriate to determine whether the required evidence becomes accessible. No failure is inferred from the unavailable result."
        if "diagnostic reason: not configured / insufficient evidence" in context:
            return "The required configuration evidence was not present. Review the explanation and the relevant Windows settings; absence of evidence is not treated as Pass or Fail."
        if "diagnostic reason: collection failure" in context:
            return "Windows failed to return complete collection data. Review the technical details and retry the assessment after confirming the relevant provider is available."
        if "diagnostic reason: unsupported detection" in context:
            return "This Windows environment does not expose the supported detection mechanism. Review the setting manually using documentation appropriate to this Windows edition."
        if "diagnostic reason: ambiguous configuration" in context:
            return "The collected configuration is ambiguous and does not support a definitive result. Review the technical evidence and applicable organizational policy."
        return "Review the explanation and technical evidence. This inconclusive result is not a confirmed failure."

    def _scoring_presentation(self, finding: CheckResult, disposition: str, disposition_explanation: str) -> tuple[str, str]:
        profile = self.current_record.assessment.profile if self.current_record else "selected"
        if disposition == "Informational":
            return f"Informational in the {profile} profile.", "Excluded from the hardening score and assessment coverage. " + disposition_explanation
        if finding.status == CheckStatus.NOT_APPLICABLE or disposition == "Not Applicable":
            return f"Not Applicable in the {profile} profile.", "Excluded from the hardening score and assessment coverage because this check does not apply."
        eligibility = f"Included in the {profile} profile."
        if finding.status == CheckStatus.UNKNOWN:
            treatment = "Inconclusive. Excluded from the current hardening-score calculation; reduces assessment coverage."
        elif finding.status == CheckStatus.PASS:
            treatment = "Conclusive Pass. Contributes positively to the hardening score using this check's configured weight."
        else:
            treatment = "Conclusive Fail. Contributes zero passing points while remaining in the hardening-score denominator."
        return eligibility, treatment

    def _show_finding(self, current: QTreeWidgetItem | None, previous: QTreeWidgetItem | None) -> None:
        if current is None: return
        index = current.data(0, Qt.ItemDataRole.UserRole)
        if index is None: return
        finding = self.findings[int(index)]; remediation = finding.remediation; current_status = "Could not assess" if finding.status == CheckStatus.UNKNOWN else finding.status.value; self.detail_title.setText(sanitize_display_text(f"{finding.title} · {finding.severity} · {current_status}"))
        disposition = self.current_record.assessment.dispositions.get(finding.check_id, "Scored") if self.current_record else "Scored"
        disposition_explanation = self.current_record.assessment.disposition_explanations.get(finding.check_id, "") if self.current_record else ""
        baseline_result = next((item for item in self.latest_baseline_comparison.results if item.check_id == finding.check_id), None) if self.latest_baseline_comparison else None
        if finding.status == CheckStatus.PASS: recommendation = "No action is required. Continue monitoring this setting through future assessments."
        elif finding.status == CheckStatus.UNKNOWN: recommendation = self._unknown_recommendation(finding, self.current_record.assessment_privilege if self.current_record else "Unknown")
        elif remediation: recommendation = remediation.summary
        else: recommendation = "Review this setting manually. WinCur does not provide an automated action for it."
        why = remediation.impact if remediation else finding.explanation; action_id = self._action_for_check(finding.check_id)
        available = ("WinCur has a safeguarded action. Open Available Fixes and preview the exact change before deciding whether to apply it." if action_id and finding.status == CheckStatus.FAIL else "No WinCur action is offered for this result." if finding.status != CheckStatus.PASS else "No action is needed for a passing check.")
        readable = [("What we found", finding.explanation), ("Why it matters", why), ("Recommended next step", recommendation), ("Available action", available)]
        if baseline_result: readable.append(("Since saved snapshot", f"{self._friendly_baseline_classification(baseline_result.classification)}. {baseline_result.explanation}"))
        self.details.setHtml(html_sections(readable))
        scoring_eligibility, scoring_treatment = self._scoring_presentation(finding, disposition, disposition_explanation)
        technical = [("Raw evidence", finding.evidence), ("Check identifier", finding.check_id), ("Detection status", finding.status.value), ("Severity", finding.severity), ("Scoring eligibility", scoring_eligibility), ("Current scoring treatment", scoring_treatment), ("Assessment privilege", self.current_record.assessment_privilege if self.current_record else "Unknown"), ("Profile and policy", f"{self.current_record.assessment.profile} / {self.current_record.assessment.policy_version}" if self.current_record else "Unknown")]
        if baseline_result: technical.append(("Saved snapshot comparison", f"{baseline_result.classification}. {baseline_result.explanation}"))
        self.technical_finding_details.setHtml(html_sections(technical))
        self.finding_fix_button.setProperty("actionId", action_id); self.finding_fix_button.setEnabled(bool(action_id and finding.status == CheckStatus.FAIL)); uri = remediation.settings_uri if remediation and finding.status != CheckStatus.PASS else None; self.settings_button.setEnabled(bool(uri)); self.settings_button.setProperty("settingsUri", uri)

    @staticmethod
    def _friendly_baseline_classification(classification: str) -> str:
        return {REGRESSION: "Security setting worsened", IMPROVEMENT: "Security setting improved", UNCHANGED: "No change", NEWLY_ASSESSABLE: "Additional check now available", NO_LONGER_ASSESSABLE: "Could not assess now", EVIDENCE_ONLY: "Evidence changed", NOT_COMPARABLE: "Cannot compare", "No baseline comparison": "No saved snapshot"}.get(classification, classification)

    @staticmethod
    def _friendly_status(status: str) -> str:
        return "Could not assess" if status == CheckStatus.UNKNOWN.value else status

    @staticmethod
    def _action_for_check(check_id: str) -> str | None:
        return {"autorun": "disable_autorun", "powershell_logging": "enable_powershell_logging", "firewall_domain": "enable_firewall_profiles", "firewall_private": "enable_firewall_profiles", "firewall_public": "enable_firewall_profiles"}.get(check_id)

    def _toggle_findings_filters(self) -> None:
        visible = self.findings_advanced_filters.isHidden(); self.findings_advanced_filters.setVisible(visible); self.findings_advanced_button.setChecked(visible); self.findings_advanced_button.setText("Hide Advanced Filters" if visible else "Advanced Filters…")

    def _toggle_finding_technical(self) -> None:
        visible = self.technical_finding_details.isHidden(); self.technical_finding_details.setVisible(visible)
        if visible: self.finding_detail_splitter.setSizes(self.layout_store.sizes("finding_details_evidence", [330, 170]))
        self.finding_technical_button.setText("Hide Technical Details" if visible else "Show Technical Details")

    def _open_finding_fix(self) -> None:
        action_id = self.finding_fix_button.property("actionId")
        if not action_id: return
        self._open_security_issues(2)
        for row in range(self.action_tree.topLevelItemCount()):
            item = self.action_tree.topLevelItem(row)
            if item.data(0, Qt.ItemDataRole.UserRole) == action_id: self.action_tree.setCurrentItem(item); break

    def _open_settings(self) -> None:
        uri = self.settings_button.property("settingsUri")
        if uri: QDesktopServices.openUrl(QUrl(str(uri)))

    def export_report(self) -> None:
        if not self.current_record: return
        base_name = assessment_report_filename(self.computer_name, self.current_record.timestamp_utc); documents = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DocumentsLocation); directory = Path(documents) if documents else Path.home(); suggested = unique_report_path(directory, base_name)
        filename, _ = QFileDialog.getSaveFileName(self, "Export WinCur HTML Report", str(suggested), "HTML reports (*.html)", options=QFileDialog.Option.DontUseNativeDialog)
        if not filename: return
        if not filename.lower().endswith(".html"): filename += ".html"
        destination = Path(filename); existed = destination.exists()
        try: export_html(self.current_record, self.config, destination, exclusive=not existed)
        except FileExistsError: QMessageBox.warning(self, "Report export conflict", "A file was created at that location before WinCur could save the report. Choose another filename to avoid overwriting it."); return
        except OSError as exc: QMessageBox.warning(self, "Report export failed", str(exc)); return
        QMessageBox.information(self, "Report exported", f"Report saved to:\n{filename}")

    def _view_last_assessment(self) -> None:
        if not self.history_records: return
        self._view_history_record(self.history_records[-1])

    def _history_selection_changed(self) -> None:
        rows = self.history_table.selectionModel().selectedRows(); self.last_assessment_button.setEnabled(bool(rows))
        if rows:
            item = self.history_table.item(rows[0].row(), 1); record = item.data(Qt.ItemDataRole.UserRole) if item else None
            if isinstance(record, dict):
                assessment = record.get("assessment", {}); score = assessment.get("score"); coverage = assessment.get("coverage")
                score_text = "Not scored" if score is None else f"{float(score):.1f}%"; coverage_text = "Unknown" if coverage is None else f"{float(coverage):.1f}%"
                self.history_record_details.setHtml(html_sections([("Assessment date", friendly_timestamp(record.get("timestamp_utc"))), ("Privilege", record.get("assessment_privilege", "Unknown")), ("Profile", assessment.get("profile", "Legacy")), ("Scoring policy", assessment.get("policy_version", "Unversioned")), ("Score and coverage", f"{score_text} / {coverage_text}"), ("Computer", record.get("computer_name", "Unknown")), ("State", "Historical saved assessment — not current device state")]))
        self._history_checkbox_changed()

    def _history_checkbox_changed(self, *_args) -> None:
        count = len(self._selected_history_indices()); self.history_selection_label.setText(f"{count} selected"); self.delete_history_button.setEnabled(count > 0 and not self._history_write_in_progress())

    def _select_all_visible_history(self) -> None:
        self.history_table.blockSignals(True)
        for row in range(self.history_table.rowCount()):
            item = self.history_table.item(row, 0)
            if item and not self.history_table.isRowHidden(row): item.setCheckState(Qt.CheckState.Checked)
        self.history_table.blockSignals(False); self._history_checkbox_changed()

    def _deselect_all_history(self) -> None:
        self.history_table.blockSignals(True)
        for row in range(self.history_table.rowCount()):
            item = self.history_table.item(row, 0)
            if item: item.setCheckState(Qt.CheckState.Unchecked)
        self.history_table.blockSignals(False); self._history_checkbox_changed()

    def _filter_history_rows(self, profile: str) -> None:
        self.history_table.blockSignals(True)
        for row in range(self.history_table.rowCount()):
            visible = profile == "All profiles" or (self.history_table.item(row, 3) and self.history_table.item(row, 3).text() == profile)
            self.history_table.setRowHidden(row, not visible)
            check = self.history_table.item(row, 0)
            if check: check.setCheckState(Qt.CheckState.Unchecked)
        self.history_table.blockSignals(False); self.history_table.clearSelection(); self._history_checkbox_changed()

    def _history_write_in_progress(self) -> bool:
        return bool(self.pending_history_records or (self.history_thread and self.history_thread.isRunning()))

    def _selected_history_indices(self) -> set[int]:
        indices: set[int] = set()
        for row in range(self.history_table.rowCount()):
            item = self.history_table.item(row, 0)
            stored_index = item.data(int(Qt.ItemDataRole.UserRole) + 1) if item and item.checkState() == Qt.CheckState.Checked else None
            if isinstance(stored_index, int): indices.add(stored_index)
        return indices

    def _delete_selected_history(self) -> None:
        indices = self._selected_history_indices()
        if not indices or self._history_write_in_progress(): return
        count = len(indices)
        prompt = f"Delete {count} selected saved assessment{'s' if count != 1 else ''}?\n\nSaved security snapshots and hardening audit records will not be deleted."
        if QMessageBox.question(self, "Delete selected scans", prompt, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes: return
        try: _, removed = delete_history_indices(indices, self.history_path)
        except OSError as exc: QMessageBox.warning(self, "Scan history", f"The selected assessments could not be deleted: {exc}"); return
        self._after_history_deleted(removed)

    def _clear_scan_history(self) -> None:
        count = len(self.history_records)
        if not count or self._history_write_in_progress(): return
        prompt = f"Delete all {count} saved assessment{'s' if count != 1 else ''}?\n\nThis cannot be undone. Saved security snapshots and hardening audit records will remain intact."
        if QMessageBox.question(self, "Clear all scan history", prompt, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes: return
        try: _, removed = clear_history(self.history_path)
        except OSError as exc: QMessageBox.warning(self, "Scan history", f"Scan history could not be cleared: {exc}"); return
        self._after_history_deleted(removed)

    def _after_history_deleted(self, removed: list[dict]) -> None:
        removed_timestamps = {str(record.get("timestamp_utc")) for record in removed}
        historical_displayed = bool(self.current_record and "historical" in self.current_record.assessment_source.casefold())
        if historical_displayed and str(self.current_record.timestamp_utc) in removed_timestamps: self._reset_displayed_assessment()
        self.selected_trend_point = None
        if hasattr(self, "trend_chart"):
            self.trend_chart.selected_point = None; self.trend_chart.keyboard_index = -1
            self.trend_selection_label.setText("Select a chart point or table row to inspect a saved assessment."); self.trend_view_button.setEnabled(False); self.trend_baseline_button.setEnabled(False); self.trend_compare_button.setEnabled(False); self.trend_table.clearSelection()
        if hasattr(self, "drift_table"): self.drift_table.setRowCount(0)
        self._invalidate_displayed_baseline_comparison("Scan history changed. Choose an assessment and compare again.")
        self._update_history(); self._update_baseline_for_current()

    def _reset_displayed_assessment(self) -> None:
        self.current_record = None; self.findings = []; self.latest_baseline_comparison = None
        self.score_panel.value.setText("--"); self.coverage_panel.value.setText("--"); self.findings_panel.value.setText("--"); self.findings_panel.description.setText("Run a scan to identify confirmed failures and unavailable checks.")
        self.category_table.setRowCount(0); self.tree.clear(); self.dashboard_findings.clear(); self.dashboard_findings.addTopLevelItem(QTreeWidgetItem(["No assessment displayed", "Run Scan PC to assess current settings.", "—"]))
        self.assessment_privilege_label.setText("Assessment privilege: None"); self.assessment_timestamp_label.setText("Last assessment: None"); self.assessment_timestamp_label.setToolTip(""); self.assessment_profile_label.setText(f"Profile: {self.selected_profile}")
        self.assessment_freshness_label.setText("Freshness: No assessment"); self.assessment_source_label.setText("Assessment state: None"); self.overview_status_label.setText("Scan required"); self.overview_explanation_label.setText("Run an assessment to review selected configuration-hardening checks. A score is not a guarantee of protection.")
        self.scan_message.setText("The displayed historical assessment was deleted. Run a scan for current device state."); self.export_button.setEnabled(False); self.details.clear(); self.technical_finding_details.clear(); self.detail_title.setText("Select a finding to view details.")
        self.assessment_displayed.emit(None); self._update_dashboard_baseline()

    def _view_selected_history(self) -> None:
        row = self.history_table.currentRow(); item = self.history_table.item(row, 1) if row >= 0 else None; record = item.data(Qt.ItemDataRole.UserRole) if item else None
        if not isinstance(record, dict):
            if self.history_records: record = self.history_records[-1]
            else: return
        self._view_history_record(record)

    def _view_history_record(self, raw_record: dict) -> None:
        try:
            record = ScanRecord.from_dict(raw_record)
        except (KeyError, TypeError, ValueError):
            QMessageBox.warning(self, "Historical assessment", "The selected history record cannot be displayed."); return
        envelope = AssessmentEnvelope(record.results, record.assessment, record.timestamp_utc, record.assessment_privilege,
                                      "Historical saved assessment — not a current scan")
        self._commit_assessment(envelope, persist_history=False)
        self.scan_message.setText("Historical assessment displayed. Run a new scan for current device state."); self._set_page(0)

    def _update_history(self) -> None:
        try:
            records = load_history(self.history_path, limit=1_000_000); self.history_records = records; count = len(records); displayed = records
            latest = latest_saved_timestamp(records)
            try: action_count = len(load_action_history(limit=1_000_000))
            except (OSError, TypeError, ValueError): action_count = 0
            latest_text = friendly_timestamp(latest) if latest else "None"
            self.history_label.setText(f"{count} saved assessment{'s' if count != 1 else ''} · Latest scan: {latest_text} · {action_count} hardening audit record{'s' if action_count != 1 else ''}")
            self.history_label.setToolTip(timestamp_tooltip(latest) if latest else "No saved assessment timestamp is available.")
            self.last_assessment_button.setEnabled(False); self.clear_history_button.setEnabled(bool(records) and not self._history_write_in_progress()); self.delete_history_button.setEnabled(False)
            self.history_table.blockSignals(True); self.history_table.setRowCount(len(displayed))
            for row, record in enumerate(reversed(displayed)):
                assessment = record.get("assessment", {}); raw_score = assessment.get("score"); raw_coverage = assessment.get("coverage")
                raw_timestamp = record.get("timestamp_utc", "Unknown"); check = QTableWidgetItem(); check.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable); check.setCheckState(Qt.CheckState.Unchecked); check.setData(int(Qt.ItemDataRole.UserRole) + 1, count - 1 - row); check.setToolTip("Select this saved assessment for deletion."); self.history_table.setItem(row, 0, check)
                values = [friendly_timestamp(raw_timestamp), record.get("assessment_privilege", "Unknown"), assessment.get("profile", "Legacy"), "Not scored" if raw_score is None else f"{float(raw_score):.1f}%", "Unknown" if raw_coverage is None else f"{float(raw_coverage):.1f}%"]
                for column, value in enumerate(values):
                    target_column = column + 1; item = QTableWidgetItem(sanitize_display_text(value)); self.history_table.setItem(row, target_column, item); item.setToolTip(sanitize_display_text(value))
                    if column == 0: item.setToolTip(timestamp_tooltip(raw_timestamp)); item.setData(Qt.ItemDataRole.UserRole, record)
            self.history_table.blockSignals(False); self.history_table.clearSelection(); self.history_selection_label.setText("0 selected"); self.history_record_details.setHtml("<p>Select an assessment to view its details.</p>")
            profiles = sorted({history_point(record).profile for record in records})
            history_profile = self.history_profile_filter.currentText(); self.history_profile_filter.blockSignals(True); self.history_profile_filter.clear(); self.history_profile_filter.addItem("All profiles"); self.history_profile_filter.addItems(profiles); self.history_profile_filter.setCurrentText(history_profile if history_profile in ["All profiles", *profiles] else "All profiles"); self.history_profile_filter.blockSignals(False); self._filter_history_rows(self.history_profile_filter.currentText())
            if hasattr(self, "trend_profile_filter"):
                selected = self.trend_profile_filter.currentText(); self.trend_profile_filter.blockSignals(True); self.trend_profile_filter.clear(); self.trend_profile_filter.addItem("All"); self.trend_profile_filter.addItems(profiles); self.trend_profile_filter.setCurrentText(selected if selected in ["All", *profiles] else "All"); self.trend_profile_filter.blockSignals(False)
                self.trend_compare_combo.clear()
                for index, record in enumerate(records):
                    point = history_point(record); raw_timestamp = record.get("timestamp_utc", "Unknown"); score = "—" if point.score is None else f"{point.score:.0f}%"; self.trend_compare_combo.addItem(f"{friendly_timestamp(raw_timestamp)} · {point.privilege} · {score}", index); self.trend_compare_combo.setItemData(self.trend_compare_combo.count() - 1, f"{timestamp_tooltip(raw_timestamp)}\nProfile: {point.profile}\nPolicy: {point.policy_version}", Qt.ItemDataRole.ToolTipRole)
                self.trend_compare_button.setEnabled(bool(getattr(self, "selected_trend_point", None)) and self.trend_compare_combo.count() > 0); self._update_trends(); self._refresh_drift_selectors()
            self._refresh_findings_center(); self._refresh_baseline_assessments()
        except (OSError, TypeError, ValueError):
            self.history_records = []; self.history_label.setText("Scan history is unavailable."); self.last_assessment_button.setEnabled(False); self.delete_history_button.setEnabled(False); self.clear_history_button.setEnabled(False)
        self._update_action_history()

    def _update_action_history(self, select_timestamp_utc: str = "") -> None:
        try:
            records = list(reversed(load_action_history(limit=100))); self.action_history_records = records; self.action_history_table.blockSignals(True); self.action_history_table.setRowCount(len(records)); selected_row = -1
            for row, record in enumerate(records):
                if select_timestamp_utc and str(record.get("timestamp_utc", "")) == select_timestamp_utc: selected_row = row
                raw_timestamp = record.get("timestamp_utc", "Unknown"); rollback = record.get("rollback_status", "Not requested"); operation = "Rollback" if str(rollback).casefold() in ("completed", "partial", "failed") else "Hardening action"; verification = record.get("verification_evidence", ""); combined = f"{verification} · Rollback: {rollback}" if verification else f"Rollback: {rollback}"; values = [friendly_timestamp(raw_timestamp), record.get("action_id", "Unknown"), operation, record.get("outcome", "Unknown"), combined]
                for column, value in enumerate(values):
                    display = evidence_preview(value, 100) if column == 4 else sanitize_display_text(value); item = QTableWidgetItem(display); item.setToolTip(sanitize_display_text(value)); self.action_history_table.setItem(row, column, item)
                    if column == 0: item.setToolTip(timestamp_tooltip(raw_timestamp))
                    elif column == 4: item.setToolTip(sanitize_display_text(f"{combined}\n{record.get('message', '')}"))
            self.action_history_table.blockSignals(False)
            if selected_row >= 0: self.action_history_table.selectRow(selected_row); self.action_history_table.scrollToItem(self.action_history_table.item(selected_row, 0))
            else: self.action_history_table.clearSelection()
            self._update_rollback_button()
        except (OSError, TypeError, ValueError): self.action_history_records = []; self.action_history_table.blockSignals(False); self.action_history_table.setRowCount(0); self._update_rollback_button()

    def closeEvent(self, event) -> None:  # noqa: N802
        if self.action_busy or self.pending_history_records or (self.scan_thread and self.scan_thread.isRunning()) or (self.preview_thread and self.preview_thread.isRunning()) or (self.history_thread and self.history_thread.isRunning()): QMessageBox.information(self, "Operation in progress", "Please wait for the current scan, preview, history save, or explicitly approved action to finish."); event.ignore()
        else: self.layout_store.save(self.layout_splitters); event.accept()

def main() -> int:
    app = QApplication(sys.argv); app.setApplicationName("WinCur"); app.setApplicationVersion(APP_VERSION); app.setStyle("Fusion")
    application_icon = load_application_icon()
    if not application_icon.isNull(): app.setWindowIcon(application_icon)
    try:
        theme_manager = ThemeManager(); theme_manager.apply(app); window = WinCurWindow(theme_manager)
    except (OSError, ValueError) as exc:
        QMessageBox.critical(None, "WinCur configuration error", f"WinCur could not load its scoring configuration:\n{exc}")
        return 2
    window.show(); return app.exec()
