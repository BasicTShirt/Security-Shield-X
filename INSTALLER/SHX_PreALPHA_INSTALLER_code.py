import sys
import os
import urllib.request
import zipfile
import tempfile
import webbrowser
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QPushButton, QLabel, QDialog, QHBoxLayout,
                             QProgressBar, QMessageBox, QFrame)
from PyQt6.QtCore import Qt, QPoint, QSize, QThread, pyqtSignal
from PyQt6.QtGui import QPalette, QColor

TERMS_OF_SERVICE_URL = "https://github.com/BasicTShirt/Security-Shield-X/blob/main/TERMS.txt"

APP_DOWNLOAD_URL = "https://github.com/BasicTShirt/Security-Shield-X/archive/refs/heads/main.zip"

MAIN_WINDOW_WIDTH = 800
MAIN_WINDOW_HEIGHT = 600
MAIN_WINDOW_SIZE = (MAIN_WINDOW_WIDTH, MAIN_WINDOW_HEIGHT)
HEADER_PANEL_HEIGHT = 50


class DownloadThread(QThread):
    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    finished = pyqtSignal(bool, str)

    def __init__(self, url, destination):
        super().__init__()
        self.url = url
        self.destination = destination

    def run(self):
        try:
            self.status.emit("Подготовка к загрузке...")

            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
            temp_path = temp_file.name
            temp_file.close()

            def progress_callback(count, block_size, total_size):
                if total_size > 0:
                    downloaded = count * block_size
                    progress = min(int(downloaded * 100 / total_size), 100)
                    self.progress.emit(progress)

            self.status.emit("Загрузка приложения...")
            urllib.request.urlretrieve(self.url, temp_path, progress_callback)

            self.status.emit("Распаковка файлов...")

            os.makedirs(self.destination, exist_ok=True)

            with zipfile.ZipFile(temp_path, 'r') as zip_ref:
                zip_ref.extractall(self.destination)

            os.unlink(temp_path)

            self.status.emit("Загрузка завершена!")
            self.finished.emit(True, self.destination)

        except Exception as e:
            self.finished.emit(False, f"Ошибка: {str(e)}")


class DownloadDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.download_thread = None
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.WindowCloseButtonHint)
        self.setFixedSize(500, 350)
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        title = QLabel("Загрузка приложения")
        title.setStyleSheet("""
            QLabel {
                color: #e0e0e0;
                font-size: 22px;
                font-weight: bold;
                font-family: "Segoe UI";
                background: transparent;
            }
        """)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Рамка для окна загрузки
        download_frame = QFrame()
        download_frame.setFrameShape(QFrame.Shape.StyledPanel)
        download_frame.setStyleSheet("""
            QFrame {
                background-color: rgba(40, 45, 55, 0.95);
                border: 2px solid rgba(80, 85, 100, 0.8);
                border-radius: 15px;
                padding: 20px;
            }
        """)

        frame_layout = QVBoxLayout(download_frame)
        frame_layout.setSpacing(15)

        self.status_label = QLabel("Готов к загрузке")
        self.status_label.setStyleSheet("""
            QLabel {
                color: #a0a0b0;
                font-size: 14px;
                font-family: "Segoe UI";
                background: transparent;
            }
        """)
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid rgba(80, 90, 110, 0.8);
                border-radius: 8px;
                height: 30px;
                background-color: rgba(30, 35, 45, 0.9);
                color: #e0e0e0;
                font-family: "Segoe UI";
                font-size: 14px;
            }
            QProgressBar::chunk {
                background-color: rgba(155, 89, 182, 0.9);
                border-radius: 6px;
                margin: 2px;
            }
        """)

        frame_layout.addWidget(self.status_label)
        frame_layout.addWidget(self.progress_bar)

        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(20)

        self.download_btn = QPushButton("Начать загрузку")
        self.download_btn.setFixedSize(180, 45)
        self.download_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(155, 89, 182, 0.9);
                color: white;
                border: none;
                border-radius: 10px;
                font-size: 14px;
                font-weight: bold;
                font-family: "Segoe UI";
            }
            QPushButton:hover {
                background-color: rgba(175, 109, 202, 0.95);
            }
            QPushButton:disabled {
                background-color: rgba(80, 85, 95, 0.6);
                color: rgba(150, 150, 150, 0.8);
            }
        """)
        self.download_btn.clicked.connect(self.start_download)

        self.cancel_btn = QPushButton("Отмена")
        self.cancel_btn.setFixedSize(180, 45)
        self.cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(60, 70, 90, 0.9);
                color: #e0e0e0;
                border: none;
                border-radius: 10px;
                font-size: 14px;
                font-weight: bold;
                font-family: "Segoe UI";
            }
            QPushButton:hover {
                background-color: rgba(80, 90, 110, 0.95);
            }
        """)
        self.cancel_btn.clicked.connect(self.reject)

        buttons_layout.addWidget(self.download_btn)
        buttons_layout.addWidget(self.cancel_btn)

        layout.addWidget(title)
        layout.addWidget(download_frame)
        layout.addLayout(buttons_layout)

        self.setLayout(layout)

    def start_download(self):
        self.download_btn.setEnabled(False)
        self.download_btn.setText("Загрузка...")

        download_dir = os.path.join(os.getcwd(), "SecurityShield_App")

        self.download_thread = DownloadThread(APP_DOWNLOAD_URL, download_dir)
        self.download_thread.progress.connect(self.progress_bar.setValue)
        self.download_thread.status.connect(self.status_label.setText)
        self.download_thread.finished.connect(self.download_finished)
        self.download_thread.start()

    def download_finished(self, success, message):
        if success:
            QMessageBox.information(self, "Успех",
                                    f"Приложение успешно скачано!\n\n"
                                    f"Файлы сохранены в:\n{message}\n\n"
                                    f"")
            self.accept()
        else:
            QMessageBox.warning(self, "Ошибка",
                                f"Ошибка загрузки:\n{message}")
            self.download_btn.setEnabled(True)
            self.download_btn.setText("Повторить")

    def closeEvent(self, event):
        if hasattr(self, 'download_thread') and self.download_thread and self.download_thread.isRunning():
            reply = QMessageBox.question(self, "Подтверждение",
                                         "Загрузка еще выполняется. Вы уверены, что хотите отменить?",
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                self.reject()
            else:
                event.ignore()
        else:
            event.accept()


class HeaderPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setFixedHeight(HEADER_PANEL_HEIGHT)
        self._drag_position = QPoint()
        self.initUI()

        self.setStyleSheet("""
            QWidget {
                background-color: rgba(35, 40, 50, 0.98);
                border-top-left-radius: 20px;
                border-top-right-radius: 20px;
            }
        """)

    def initUI(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 0, 10, 0)

        header_title = QLabel("Security Shield - Загрузчик")
        header_title.setStyleSheet("""
            QLabel {
                color: #a0a0b0;
                font-size: 16px;
                font-weight: bold;
                font-family: "Segoe UI";
                background: transparent;
            }
        """)

        layout.addWidget(header_title)
        layout.addStretch(1)

        self.close_btn = QPushButton("X")
        self.close_btn.setFixedSize(30, 30)
        self.close_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #a0a0b0;
                border: none;
                border-radius: 5px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(255, 86, 86, 0.9);
                color: white;
            }
        """)
        self.close_btn.clicked.connect(self.parent.close)

        layout.addWidget(self.close_btn)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_position = event.globalPosition().toPoint() - self.parent.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.MouseButton.LeftButton:
            self.parent.move(event.globalPosition().toPoint() - self._drag_position)
            event.accept()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Security Shield - Загрузчик")
        self.setFixedSize(*MAIN_WINDOW_SIZE)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.initUI()

    def initUI(self):
        central_widget = QWidget()
        central_widget.setStyleSheet("""
            QWidget {
                background-color: rgba(25, 30, 40, 0.98);
                border-radius: 20px;
            }
        """)
        self.setCentralWidget(central_widget)

        main_v_layout = QVBoxLayout(central_widget)
        main_v_layout.setContentsMargins(0, 0, 0, 0)
        main_v_layout.setSpacing(0)

        self.header_panel = HeaderPanel(self)
        main_v_layout.addWidget(self.header_panel)

        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(40, 60, 40, 40)
        content_layout.setSpacing(30)

        title_label = QLabel("Security Shield")
        title_label.setStyleSheet("""
            QLabel {
                color: #e0e0e0;
                font-size: 36px;
                font-weight: bold;
                font-family: "Segoe UI";
                background: transparent;
            }
        """)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        desc_label = QLabel("Загрузчик и установщик приложения")
        desc_label.setStyleSheet("""
            QLabel {
                color: #a0a0b0;
                font-size: 18px;
                font-family: "Segoe UI";
                background: transparent;
            }
        """)
        desc_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        download_btn = QPushButton("Скачать приложение")
        download_btn.setFixedSize(300, 60)
        download_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(155, 89, 182, 0.9);
                color: white;
                border: none;
                border-radius: 12px;
                font-size: 18px;
                font-weight: bold;
                font-family: "Segoe UI";
            }
            QPushButton:hover {
                background-color: rgba(175, 109, 202, 0.95);
            }
        """)
        download_btn.clicked.connect(self.show_download_dialog)

        terms_btn = QPushButton("Пользовательское соглашение")
        terms_btn.setFixedSize(300, 50)
        terms_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(60, 70, 90, 0.9);
                color: #e0e0e0;
                border: none;
                border-radius: 10px;
                font-size: 16px;
                font-family: "Segoe UI";
            }
            QPushButton:hover {
                background-color: rgba(80, 90, 110, 0.95);
                color: white;
            }
        """)
        terms_btn.clicked.connect(lambda: webbrowser.open(TERMS_OF_SERVICE_URL))

        quit_btn = QPushButton("Выход")
        quit_btn.setFixedSize(200, 45)
        quit_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(60, 70, 90, 0.9);
                color: #e0e0e0;
                border: none;
                border-radius: 10px;
                font-size: 16px;
                font-family: "Segoe UI";
            }
            QPushButton:hover {
                background-color: rgba(80, 90, 110, 0.95);
                color: white;
            }
        """)
        quit_btn.clicked.connect(self.close)

        content_layout.addStretch(1)
        content_layout.addWidget(title_label)
        content_layout.addWidget(desc_label)
        content_layout.addSpacing(40)
        content_layout.addWidget(download_btn, 0, Qt.AlignmentFlag.AlignCenter)
        content_layout.addWidget(terms_btn, 0, Qt.AlignmentFlag.AlignCenter)
        content_layout.addSpacing(20)
        content_layout.addWidget(quit_btn, 0, Qt.AlignmentFlag.AlignCenter)
        content_layout.addStretch(1)

        main_v_layout.addWidget(content_widget)

    def show_download_dialog(self):
        dialog = DownloadDialog(self)
        dialog.exec()


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(25, 30, 40))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(220, 220, 220))
    palette.setColor(QPalette.ColorRole.Base, QColor(35, 40, 50))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(45, 50, 60))
    palette.setColor(QPalette.ColorRole.Text, QColor(220, 220, 220))
    palette.setColor(QPalette.ColorRole.Button, QColor(45, 50, 65))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(220, 220, 220))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(155, 89, 182))
    palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.black)
    app.setPalette(palette)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == '__main__':
    main()
