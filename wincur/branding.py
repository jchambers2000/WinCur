"""WinCur branding resources and the focused header-logo interaction."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QRect, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QIcon, QMouseEvent, QPainter, QPixmap
from PySide6.QtWidgets import QDialog, QDialogButtonBox, QLabel, QVBoxLayout, QWidget

from .resources import resource_path


PORTRAIT_RESOURCE = "assets/wincur_portrait.png"
ICON_RESOURCE = "assets/wincur.ico"
EASTER_EGG_TEXT = "created by the managing director"


def portrait_path() -> Path:
    return resource_path(PORTRAIT_RESOURCE)


def icon_path() -> Path:
    return resource_path(ICON_RESOURCE)


def load_portrait(path: Path | None = None) -> QPixmap:
    source = path or portrait_path()
    return QPixmap(str(source)) if source.is_file() else QPixmap()


def load_application_icon(path: Path | None = None) -> QIcon:
    source = path or icon_path()
    return QIcon(str(source)) if source.is_file() else QIcon()


class PortraitView(QWidget):
    """Aspect-preserving, DPI-aware portrait renderer with a neutral backing."""

    def __init__(self, pixmap: QPixmap, size: int, parent: QWidget | None = None) -> None:
        super().__init__(parent); self._portrait = QPixmap(pixmap); self.setFixedSize(size, size)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)

    @property
    def has_artwork(self) -> bool:
        return not self._portrait.isNull()

    @property
    def source_size(self):
        return self._portrait.size()

    def paintEvent(self, event) -> None:  # noqa: N802
        if self._portrait.isNull(): return
        painter = QPainter(self); painter.setRenderHint(QPainter.RenderHint.Antialiasing); painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        frame = self.rect().adjusted(1, 1, -1, -1)
        painter.setPen(QColor("#8b98a6")); painter.setBrush(QColor("#f8f8f4")); painter.drawRoundedRect(frame, 7, 7)
        target = frame.adjusted(4, 4, -4, -4); source_size = self._portrait.size()
        scaled = source_size.scaled(target.size(), Qt.AspectRatioMode.KeepAspectRatio)
        destination = QRect(0, 0, scaled.width(), scaled.height()); destination.moveCenter(target.center())
        painter.drawPixmap(destination, self._portrait, self._portrait.rect())


class HeaderLogo(PortraitView):
    triggered = Signal()

    def __init__(self, pixmap: QPixmap, click_window_ms: int = 2000, parent: QWidget | None = None) -> None:
        super().__init__(pixmap, 48, parent); self._click_count = 0
        self._click_timer = QTimer(self); self._click_timer.setSingleShot(True); self._click_timer.setInterval(click_window_ms); self._click_timer.timeout.connect(self.reset_sequence)
        self.setAccessibleName("WinCur portrait logo")
        if self.has_artwork:
            self.setCursor(Qt.CursorShape.PointingHandCursor); self.setToolTip("WinCur")
        else:
            self.setToolTip(f"Approved portrait artwork is missing: {portrait_path()}")

    @property
    def click_count(self) -> int:
        return self._click_count

    def reset_sequence(self) -> None:
        self._click_timer.stop(); self._click_count = 0

    def register_click(self) -> None:
        if not self.has_artwork: return
        self._click_count += 1
        if self._click_count >= 5:
            self.reset_sequence(); self.triggered.emit(); return
        self._click_timer.start()

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton and self.rect().contains(event.position().toPoint()):
            self.register_click(); event.accept(); return
        super().mouseReleaseEvent(event)


class PortraitEasterEggDialog(QDialog):
    def __init__(self, pixmap: QPixmap, parent: QWidget | None = None) -> None:
        super().__init__(parent); self.setWindowTitle("WinCur"); self.setModal(True); self.setWindowModality(Qt.WindowModality.ApplicationModal)
        layout = QVBoxLayout(self); layout.setContentsMargins(22, 20, 22, 18); layout.setSpacing(14)
        portrait = PortraitView(pixmap, 240, self); portrait.setAccessibleName("WinCur portrait artwork"); layout.addWidget(portrait, 0, Qt.AlignmentFlag.AlignHCenter)
        phrase = QLabel(EASTER_EGG_TEXT); phrase.setAlignment(Qt.AlignmentFlag.AlignCenter); phrase.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByKeyboard | Qt.TextInteractionFlag.TextSelectableByMouse); layout.addWidget(phrase)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close); buttons.rejected.connect(self.reject); buttons.button(QDialogButtonBox.StandardButton.Close).setDefault(True); layout.addWidget(buttons)
        self.resize(300, 340)
