"""Application-wide WinCur appearance management and persistence."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable

from PySide6.QtCore import QObject, QTimer, Signal
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication
from .storage import atomic_write_json


LOGGER = logging.getLogger("wincur.theme")


class AppearanceMode(str, Enum):
    LIGHT = "Light"
    DARK = "Dark"
    SYSTEM = "System"


@dataclass(frozen=True)
class ThemeTokens:
    name: str
    window: str; surface: str; surface_alt: str; panel: str; sidebar_start: str; sidebar_end: str
    text: str; muted_text: str; heading: str; border: str; border_light: str
    nav: str; nav_selected: str; nav_selected_text: str
    tab: str; tab_selected: str; input: str; header_cell: str
    selection: str; selection_text: str; tooltip: str; tooltip_text: str
    button_top: str; button_bottom: str; button_text: str; button_disabled: str; disabled_text: str
    primary_top: str; primary_mid: str; primary_bottom: str; primary_text: str
    notice: str; notice_text: str; notice_border: str
    info_top: str; info_bottom: str; info_text: str
    success: str; success_bg: str; warning: str; warning_bg: str; failure: str; failure_bg: str; neutral: str; neutral_bg: str
    header_top: str; header_high: str; header_mid: str; header_bottom: str; header_border: str; header_subtitle: str
    shield: str; shield_border: str; cross: str
    scrollbar: str; scrollbar_handle: str; scrollbar_handle_hover: str
    critical: str; critical_bg: str; high: str; high_bg: str
    medium: str; medium_bg: str; low: str; low_bg: str
    informational: str; informational_bg: str

    def semantic(self, name: str) -> tuple[str, str]:
        """Return theme-aware foreground/background colors for a semantic state."""
        return {
            "critical": (self.critical, self.critical_bg),
            "high": (self.high, self.high_bg),
            "medium": (self.medium, self.medium_bg),
            "low": (self.low, self.low_bg),
            "pass": (self.success, self.success_bg),
            "fail": (self.failure, self.failure_bg),
            "unknown": (self.warning, self.warning_bg),
            "informational": (self.informational, self.informational_bg),
            "disabled": (self.disabled_text, self.button_disabled),
            "neutral": (self.neutral, self.neutral_bg),
        }.get(name.casefold(), (self.neutral, self.neutral_bg))


LIGHT = ThemeTokens(
    "Light", "#edf3f9", "#ffffff", "#edf4fb", "#f8fbfe", "#78a8e5", "#c4daf4",
    "#17324d", "#3f596f", "#164a8e", "#7893ae", "#b7c8da",
    "#e4f0fd", "#2863b5", "#ffffff", "#cbdcf0", "#ffffff", "#ffffff", "#d9e9fb",
    "#2d67ad", "#ffffff", "#fffbd6", "#17324d",
    "#ffffff", "#cbd9e7", "#123d71", "#d9e0e6", "#6f7f8d",
    "#a9df75", "#52ae31", "#236f14", "#ffffff",
    "#fff3c7", "#5e3f00", "#c9a84b", "#ffffff", "#dfe8f1", "#102f4e",
    "#176b18", "#e7f6df", "#805300", "#fff1bd", "#9a251b", "#f9e4e0", "#526577", "#e8eef4",
    "#6da8ff", "#1764d8", "#0642ae", "#002c87", "#9bc5ff", "#dcecff",
    "#f6fbff", "#b5d3f8", "#39a934", "#d3dfeb", "#7893ae", "#557da8",
    "#8c1d18", "#fde7e5", "#a43b18", "#feeee5", "#7a5200", "#fff2cc", "#225b91", "#e5f1fb", "#405f7d", "#e8f0f7",
)

DARK = ThemeTokens(
    "Dark", "#111820", "#202b36", "#273543", "#19232d", "#123a67", "#0b2440",
    "#eef4fa", "#b9c8d6", "#9bc8ff", "#58738d", "#7894ad",
    "#173b5e", "#245e9e", "#ffffff", "#183957", "#24384a", "#17232e", "#243f58",
    "#2f70b7", "#ffffff", "#26394a", "#f2f7fb",
    "#34485a", "#1e2d3b", "#f2f7fb", "#26333e", "#7f92a3",
    "#72c653", "#398d2a", "#205f19", "#ffffff",
    "#493f20", "#ffe29a", "#8f7834", "#2d3c4a", "#1c2935", "#eef4fa",
    "#63d66a", "#193d24", "#ffc857", "#493b17", "#ff7b70", "#472423", "#aebdca", "#293743",
    "#5a9df5", "#1764d8", "#073e9d", "#001f61", "#7fb4f6", "#d8eaff",
    "#eaf3fb", "#88a8c7", "#49c64a", "#182633", "#45627c", "#5d83a5",
    "#ff8b82", "#4b2224", "#ffad7a", "#472f25", "#ffd166", "#44391f", "#8bc7ff", "#20384c", "#b7c9da", "#293a49",
)


def default_preference_path() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    return base / "WinCur" / "appearance.json"


def windows_prefers_dark() -> bool:
    if os.name != "nt": return False
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as key:
            value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
        return int(value) == 0
    except (OSError, ValueError, TypeError):
        return False


def build_stylesheet(t: ThemeTokens) -> str:
    return f"""
    QApplication,QMainWindow,QDialog,QWidget#content{{background:{t.window};color:{t.text};font-family:"Segoe UI";font-size:13px}}
    QWidget{{color:{t.text};font-family:"Segoe UI"}} QLabel,QCheckBox,QRadioButton{{color:{t.text};background:transparent}}
    QFrame#sidebar{{background:{t.surface};border-right:1px solid {t.border}}}
    QLabel#navTitle{{color:{t.heading};font-size:15px;font-weight:600;padding:6px 10px}}
    QPushButton#navButton{{color:{t.muted_text};background:transparent;border:0;border-radius:8px;padding:10px 12px;text-align:left;font-size:14px}}
    QPushButton#navButton:hover{{color:{t.text};background:{t.nav}}} QPushButton#navButton:pressed{{background:{t.surface_alt}}}
    QPushButton#navButton:checked{{color:{t.nav_selected_text};background:{t.nav_selected};font-weight:600}} QPushButton#navButton:focus{{border:2px solid {t.selection}}}
    QLabel#safetyLabel,QLabel#historyLabel{{color:{t.muted_text};background:{t.panel};border:1px solid {t.border};border-radius:8px;padding:10px;font-size:11px}}
    QLabel#heading{{color:{t.heading};font-size:23px;font-weight:600}} QLabel#pageTitle{{color:{t.heading};font-size:20px;font-weight:600}} QLabel#intro{{color:{t.muted_text};font-size:13px}}
    QLabel#infoValue,QLabel#modeLabel,QLabel#scanMessage{{color:{t.info_text};background:transparent;font-weight:500;padding:2px}}
    QFrame#infoPanel,QFrame#metricPanel,QFrame#card,QFrame#filterPanel{{background:{t.panel};border:1px solid {t.border};border-radius:9px}}
    QLabel#metricTitle{{color:{t.muted_text};font-weight:600}} QLabel#metricValue{{color:{t.heading};font-size:27px;font-weight:650}} QLabel#metricDescription{{color:{t.muted_text};font-size:11px}}
    QLabel#scoreNotice{{color:{t.notice_text};background:{t.notice};border:1px solid {t.notice_border};border-radius:8px;padding:10px}}
    QLabel#methodology{{color:{t.text};background:{t.panel};border:1px solid {t.border};border-radius:8px;padding:10px}} QLabel#detailTitle{{color:{t.heading};font-size:15px;font-weight:600}}
    QPushButton#scanButton{{color:{t.primary_text};font-weight:600;font-size:13px;min-width:105px;padding:8px 15px;border:1px solid {t.primary_bottom};border-radius:7px;background:{t.primary_mid}}}
    QPushButton#scanButton:hover{{background:{t.primary_top}}} QPushButton#scanButton:pressed{{background:{t.primary_bottom}}} QPushButton#scanButton:disabled{{color:{t.disabled_text};background:{t.button_disabled};border-color:{t.border}}}
    QPushButton#xpButton,QPushButton#secondaryButton,QDialogButtonBox QPushButton{{color:{t.button_text};font-weight:500;padding:8px 13px;border:1px solid {t.border};border-radius:7px;background:{t.surface}}}
    QPushButton#xpButton:hover,QPushButton#secondaryButton:hover,QDialogButtonBox QPushButton:hover{{background:{t.surface_alt};border-color:{t.selection}}} QPushButton#xpButton:pressed,QPushButton#secondaryButton:pressed,QDialogButtonBox QPushButton:pressed{{background:{t.button_bottom}}}
    QPushButton#xpButton:disabled,QPushButton#secondaryButton:disabled,QDialogButtonBox QPushButton:disabled{{color:{t.disabled_text};background:{t.button_disabled}}}
    QPushButton#destructiveButton{{color:{t.failure};font-weight:600;padding:8px 13px;border:1px solid {t.failure};border-radius:7px;background:{t.failure_bg}}} QPushButton#destructiveButton:hover{{color:{t.selection_text};background:{t.failure}}} QPushButton#destructiveButton:disabled{{color:{t.disabled_text};background:{t.button_disabled};border-color:{t.border}}}
    QPushButton#xpButton:focus,QPushButton#secondaryButton:focus,QPushButton#scanButton:focus,QPushButton#destructiveButton:focus,QDialogButtonBox QPushButton:focus{{border:2px solid {t.selection}}}
    QPushButton#segmentButton{{color:{t.muted_text};background:{t.tab};border:1px solid {t.border};border-radius:7px;padding:7px 16px}} QPushButton#segmentButton:checked{{color:{t.nav_selected_text};background:{t.nav_selected};font-weight:600;border-color:{t.nav_selected}}} QPushButton#segmentButton:hover:!checked{{color:{t.text};background:{t.surface_alt};border-color:{t.selection}}} QPushButton#segmentButton:focus{{border:2px solid {t.selection};padding:6px 15px}}
    QTabWidget#sectionTabs::pane{{border:0;background:transparent;top:0px}} QTabBar#sectionTabBar{{background:transparent;border:0}} QTabBar#sectionTabBar::base{{background:transparent;border:0;height:0}} QTabBar#sectionTabBar::tab{{color:{t.muted_text};background:transparent;border:0;border-bottom:2px solid transparent;margin-right:4px;padding:9px 15px}} QTabBar#sectionTabBar::tab:hover{{color:{t.text};background:{t.surface_alt}}} QTabBar#sectionTabBar::tab:selected{{color:{t.heading};border-bottom:2px solid {t.selection};font-weight:600}} QTabBar#sectionTabBar::tab:focus{{color:{t.heading};background:{t.surface_alt}}}
    QTableWidget,QTreeWidget,QTextBrowser,QPlainTextEdit,QTextEdit,QListView{{color:{t.text};background:{t.input};alternate-background-color:{t.input};border:1px solid {t.border};border-radius:7px;selection-background-color:{t.selection};selection-color:{t.selection_text};outline:0}}
    QTableWidget::item,QTreeWidget::item{{padding:5px;background:{t.input};border-bottom:1px solid {t.border_light}}}
    QTableWidget::item:hover,QTreeWidget::item:hover{{background:{t.surface_alt};color:{t.text}}}
    QTableWidget::item:selected,QTreeWidget::item:selected,QListView::item:selected{{background:{t.selection};color:{t.selection_text}}}
    QTableWidget::item:selected:hover,QTreeWidget::item:selected:hover,QListView::item:selected:hover{{background:{t.selection};color:{t.selection_text}}}
    QCheckBox{{spacing:7px}}
    QCheckBox::indicator,QTableView::indicator,QTreeView::indicator{{width:16px;height:16px;border:2px solid {t.border};border-radius:4px;background:{t.input}}}
    QCheckBox::indicator:hover,QTableView::indicator:hover,QTreeView::indicator:hover{{border-color:{t.selection};background:{t.surface_alt}}}
    QCheckBox::indicator:checked,QTableView::indicator:checked,QTreeView::indicator:checked{{border-color:{t.selection_text};background:{t.selection}}}
    QCheckBox::indicator:disabled,QTableView::indicator:disabled,QTreeView::indicator:disabled{{border-color:{t.border};background:{t.button_disabled}}}
    QHeaderView::section{{color:{t.muted_text};background:{t.header_cell};border:0;border-bottom:1px solid {t.border};padding:7px;font-weight:600}}
    QLineEdit,QSpinBox{{color:{t.text};background:{t.input};border:1px solid {t.border};border-radius:6px;padding:6px 8px}}
    QComboBox{{color:{t.text};background:{t.input};border:1px solid {t.border};border-radius:6px;padding:6px 30px 6px 8px;min-height:20px}}
    QComboBox::drop-down{{subcontrol-origin:padding;subcontrol-position:top right;width:28px;border:0;background:transparent}}
    QDateEdit{{color:{t.text};background:{t.input};border:1px solid {t.border};border-radius:6px;padding:6px 30px 6px 8px;min-height:20px}}
    QDateEdit::drop-down{{subcontrol-origin:padding;subcontrol-position:top right;width:28px;border:0;background:transparent}}
    QLineEdit:focus,QSpinBox:focus,QComboBox:focus,QDateEdit:focus{{border:2px solid {t.selection}}}
    QComboBox QAbstractItemView{{color:{t.text};background:{t.input};border:1px solid {t.border};selection-background-color:{t.selection};selection-color:{t.selection_text};outline:0}}
    QMenu{{color:{t.text};background:{t.surface};border:1px solid {t.border};border-radius:6px;padding:4px}} QMenu::item{{padding:6px 18px;border-radius:4px}} QMenu::item:selected{{background:{t.selection};color:{t.selection_text}}}
    QToolTip{{color:{t.tooltip_text};background:{t.tooltip};border:1px solid {t.border};border-radius:5px;padding:6px}}
    QMessageBox,QFileDialog{{background:{t.window};color:{t.text}}} QSplitter::handle{{background:{t.border};width:4px;height:4px}} QSplitter::handle:hover{{background:{t.selection}}}
    QScrollBar:vertical{{background:transparent;width:12px;margin:2px}} QScrollBar::handle:vertical{{background:{t.scrollbar_handle};min-height:28px;border-radius:5px}} QScrollBar::handle:vertical:hover{{background:{t.scrollbar_handle_hover}}}
    QScrollBar:horizontal{{background:transparent;height:12px;margin:2px}} QScrollBar::handle:horizontal{{background:{t.scrollbar_handle};min-width:28px;border-radius:5px}} QScrollBar::handle:horizontal:hover{{background:{t.scrollbar_handle_hover}}}
    QScrollBar::add-line,QScrollBar::sub-line{{width:0;height:0}} QScrollBar::add-page,QScrollBar::sub-page{{background:none}}
    """


class ThemeManager(QObject):
    theme_changed = Signal(object)

    def __init__(self, preference_path: Path | None = None, system_detector: Callable[[], bool] | None = None,
                 poll_interval_ms: int = 2000, parent: QObject | None = None) -> None:
        super().__init__(parent); self.preference_path = preference_path or default_preference_path()
        self.system_detector = system_detector or windows_prefers_dark; self.mode = self._load(); self._effective_dark = self._resolve_dark()
        self.timer = QTimer(self); self.timer.setInterval(poll_interval_ms); self.timer.timeout.connect(self.check_system_preference)
        if self.mode == AppearanceMode.SYSTEM: self.timer.start()

    @property
    def tokens(self) -> ThemeTokens: return DARK if self._effective_dark else LIGHT

    @property
    def effective_mode(self) -> AppearanceMode: return AppearanceMode.DARK if self._effective_dark else AppearanceMode.LIGHT

    def _load(self) -> AppearanceMode:
        try:
            data = json.loads(self.preference_path.read_text(encoding="utf-8")); return AppearanceMode(data.get("appearance", "Light"))
        except (OSError, ValueError, TypeError, json.JSONDecodeError): return AppearanceMode.LIGHT

    def _resolve_dark(self) -> bool: return self.mode == AppearanceMode.DARK or (self.mode == AppearanceMode.SYSTEM and self.system_detector())

    def set_mode(self, mode: AppearanceMode | str, persist: bool = True) -> None:
        self.mode = AppearanceMode(mode); self._effective_dark = self._resolve_dark()
        if persist:
            try:
                atomic_write_json(self.preference_path, {"appearance": self.mode.value}, indent=2)
            except OSError:
                LOGGER.exception("Appearance preference could not be saved")
        if self.mode == AppearanceMode.SYSTEM: self.timer.start()
        else: self.timer.stop()
        self.apply()

    def apply(self, application: QApplication | None = None) -> None:
        app = application or QApplication.instance()
        if app is None: return
        t = self.tokens; palette = QPalette()
        for group in (QPalette.ColorGroup.Active, QPalette.ColorGroup.Inactive):
            palette.setColor(group, QPalette.ColorRole.Window, QColor(t.window)); palette.setColor(group, QPalette.ColorRole.WindowText, QColor(t.text)); palette.setColor(group, QPalette.ColorRole.Base, QColor(t.input)); palette.setColor(group, QPalette.ColorRole.AlternateBase, QColor(t.input)); palette.setColor(group, QPalette.ColorRole.Text, QColor(t.text)); palette.setColor(group, QPalette.ColorRole.Button, QColor(t.button_bottom)); palette.setColor(group, QPalette.ColorRole.ButtonText, QColor(t.button_text)); palette.setColor(group, QPalette.ColorRole.Highlight, QColor(t.selection)); palette.setColor(group, QPalette.ColorRole.HighlightedText, QColor(t.selection_text))
        palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(t.tooltip)); palette.setColor(QPalette.ColorRole.ToolTipText, QColor(t.tooltip_text))
        palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor(t.disabled_text)); palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor(t.disabled_text))
        app.setPalette(palette); app.setStyleSheet(build_stylesheet(t)); self.theme_changed.emit(t)

    def check_system_preference(self) -> None:
        if self.mode != AppearanceMode.SYSTEM: return
        new_dark = self._resolve_dark()
        if new_dark != self._effective_dark:
            self._effective_dark = new_dark; self.apply()
