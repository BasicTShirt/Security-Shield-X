import sys
import os
import subprocess
import psutil
import json
import winreg
import hashlib
import math
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QPushButton, QLabel, QDialog, QHBoxLayout,
                             QCheckBox, QStackedWidget, QListWidget,
                             QListWidgetItem, QLineEdit, QMessageBox)
from PyQt6.QtCore import Qt, QTimer, QSettings, QPoint, QSize
from PyQt6.QtGui import QPixmap, QIcon, QColor, QFont

APP_ICON_PATH = "rounded-in-photoretrica.png"
CHECKMARK_PATH = "190411.png"
CROSS_PATH = "1828843.png"
DEFAULT_CHECKMARK_SYMBOL = "✓"
DEFAULT_CROSS_SYMBOL = "✗"
MAIN_WINDOW_WIDTH = 900
MAIN_WINDOW_HEIGHT = 700
MAIN_WINDOW_SIZE = (MAIN_WINDOW_WIDTH, MAIN_WINDOW_HEIGHT)
DIALOG_WIDTH = 500
DIALOG_HEIGHT = 250
DIALOG_SIZE = (DIALOG_WIDTH, DIALOG_HEIGHT)
ACTION_BUTTON_WIDTH = 180
ACTION_BUTTON_HEIGHT = 40
ACTION_BUTTON_SIZE = (ACTION_BUTTON_WIDTH, ACTION_BUTTON_HEIGHT)
STATUS_CONTAINER_SIZE = 300
STATUS_CONTAINER_DIAMETER = (STATUS_CONTAINER_SIZE, STATUS_CONTAINER_SIZE)
ICON_CIRCLE_SIZE = 200
ICON_CIRCLE_DIAMETER = (ICON_CIRCLE_SIZE, ICON_CIRCLE_SIZE)
NAV_PANEL_WIDTH = 250
HEADER_PANEL_HEIGHT = 50

class PasswordManager:
    def __init__(self):
        self.settings = QSettings("SecurityShield", "Password")
        self.password_file = "security_password.dat"
    
    def is_password_set(self):
        return self.settings.contains("password_hash") or os.path.exists(self.password_file)
    
    def set_password(self, password):
        if len(password) != 4 or not password.isdigit():
            return False
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        self.settings.setValue("password_hash", password_hash)
        
        with open(self.password_file, "w", encoding="utf-8") as f:
            f.write(password_hash)
        
        return True
    
    def verify_password(self, password):
        if len(password) != 4 or not password.isdigit():
            return False
        
        stored_hash = self.settings.value("password_hash", "")
        if not stored_hash and os.path.exists(self.password_file):
            with open(self.password_file, "r", encoding="utf-8") as f:
                stored_hash = f.read().strip()
        
        if not stored_hash:
            return False
        
        input_hash = hashlib.sha256(password.encode()).hexdigest()
        return input_hash == stored_hash

class PasswordDialog(QDialog):
    def __init__(self, title, message, parent=None, is_setup=False):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setFixedSize(400, 300 if is_setup else 250)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.is_setup = is_setup
        self.initUI(message)
    
    def initUI(self, message):
        main_widget = QWidget()
        main_widget.setStyleSheet("""
            QWidget {
                background-color: rgba(30, 35, 45, 0.98);
                border-radius: 20px;
                border: 2px solid rgba(155, 89, 182, 0.8);
                box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
            }
        """)
        
        layout = QVBoxLayout(main_widget)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        
        title_label = QLabel("🔐 УСТАНОВКА ПАРОЛЯ" if self.is_setup else "🔐 ВВОД ПАРОЛЯ")
        title_label.setStyleSheet("""
            QLabel {
                color: #9b59b6;
                font-size: 20px;
                font-weight: bold;
                font-family: "Segoe UI";
                background: transparent;
            }
        """)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        message_label = QLabel(message)
        message_label.setStyleSheet("""
            QLabel {
                color: #e0e0e0;
                font-size: 14px;
                font-family: "Segoe UI";
                background: transparent;
            }
        """)
        message_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        message_label.setWordWrap(True)
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setMaxLength(4)
        self.password_input.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.password_input.setFixedHeight(50)
        self.password_input.setStyleSheet("""
            QLineEdit {
                background-color: rgba(40, 45, 55, 0.95);
                border: 2px solid rgba(155, 89, 182, 0.6);
                border-radius: 10px;
                color: #e0e0e0;
                font-size: 24px;
                font-family: "Segoe UI";
                font-weight: bold;
                letter-spacing: 8px;
                padding: 10px;
                selection-background-color: rgba(155, 89, 182, 0.5);
            }
            QLineEdit:focus {
                border: 2px solid rgba(155, 89, 182, 0.9);
                background-color: rgba(45, 50, 60, 0.95);
            }
        """)
        
        if self.is_setup:
            confirm_label = QLabel("Подтверждение пароля:")
            confirm_label.setStyleSheet("""
                QLabel {
                    color: #e0e0e0;
                    font-size: 14px;
                    font-family: "Segoe UI";
                    background: transparent;
                }
            """)
            
            self.confirm_input = QLineEdit()
            self.confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.confirm_input.setMaxLength(4)
            self.confirm_input.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.confirm_input.setFixedHeight(50)
            self.confirm_input.setStyleSheet("""
                QLineEdit {
                    background-color: rgba(40, 45, 55, 0.95);
                    border: 2px solid rgba(155, 89, 182, 0.6);
                    border-radius: 10px;
                    color: #e0e0e0;
                    font-size: 24px;
                    font-family: "Segoe UI";
                    font-weight: bold;
                    letter-spacing: 8px;
                    padding: 10px;
                    selection-background-color: rgba(155, 89, 182, 0.5);
                }
                QLineEdit:focus {
                    border: 2px solid rgba(155, 89, 182, 0.9);
                    background-color: rgba(45, 50, 60, 0.95);
                }
            """)
        
        hint_label = QLabel("Пароль должен состоять из 4 цифр")
        hint_label.setStyleSheet("""
            QLabel {
                color: #a0a0b0;
                font-size: 12px;
                font-family: "Segoe UI";
                background: transparent;
            }
        """)
        hint_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(15)
        
        layout.addWidget(title_label)
        layout.addWidget(message_label)
        layout.addWidget(self.password_input)
        
        if self.is_setup:
            layout.addWidget(confirm_label)
            layout.addWidget(self.confirm_input)
        
        layout.addWidget(hint_label)
        
        if self.is_setup:
            ok_button = QPushButton("Установить пароль")
            ok_button.setFixedHeight(45)
            ok_button.setStyleSheet("""
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
                QPushButton:pressed {
                    background-color: rgba(135, 69, 162, 0.95);
                }
            """)
            ok_button.clicked.connect(self.accept)
            
            buttons_layout.addWidget(ok_button)
        else:
            ok_button = QPushButton("Подтвердить")
            ok_button.setFixedHeight(45)
            ok_button.setStyleSheet("""
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
                QPushButton:pressed {
                    background-color: rgba(135, 69, 162, 0.95);
                }
            """)
            ok_button.clicked.connect(self.accept)
            
            cancel_button = QPushButton("Отмена")
            cancel_button.setFixedHeight(45)
            cancel_button.setStyleSheet("""
                QPushButton {
                    background-color: rgba(60, 70, 85, 0.9);
                    color: #d0d0e0;
                    border: none;
                    border-radius: 10px;
                    font-size: 14px;
                    font-weight: bold;
                    font-family: "Segoe UI";
                }
                QPushButton:hover {
                    background-color: rgba(80, 90, 105, 0.95);
                    color: #ffffff;
                }
                QPushButton:pressed {
                    background-color: rgba(40, 50, 65, 0.95);
                }
            """)
            cancel_button.clicked.connect(self.reject)
            
            buttons_layout.addWidget(ok_button)
            buttons_layout.addWidget(cancel_button)
        
        layout.addLayout(buttons_layout)
        
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(main_widget)
    
    def get_password(self):
        return self.password_input.text()
    
    def get_confirm_password(self):
        if self.is_setup:
            return self.confirm_input.text()
        return ""

class SystemScanner:
    def __init__(self):
        self.suspicious_strings = [
            'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory',
            'reg add', 'powershell', 'cmd.exe /c', 
            'rundll32', 'mshta', 'wscript', 'cscript',
            'certutil', 'bitsadmin', 'wmic', 'schtasks',
            'netsh', 'net user', 'net localgroup', 'taskkill',
            'vssadmin', 'bcdedit', 'diskpart', 'format',
            'attrib', 'takeown', 'icacls', 'cacls',
            'netstat', 'ipconfig', 'arp', 'route'
        ]
        
        self.system_dirs = [
            'C:\\Windows\\', 'C:\\Program Files\\',
            'C:\\Program Files (x86)\\', 'C:\\ProgramData\\'
        ]
    
    def calculate_entropy(self, data):
        if not data:
            return 0.0
        
        entropy = 0.0
        for x in range(256):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        
        return entropy
    
    def calculate_file_hash(self, filepath):
        try:
            hash_func = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except:
            return ''
    
    def scan_running_processes(self):
        suspicious_processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time']):
            try:
                process_info = proc.info
                
                if not process_info['exe'] or any(sys_dir in process_info['exe'] for sys_dir in self.system_dirs):
                    continue
                
                score = 0
                flags = []
                
                exe_path = process_info['exe'] or ''
                if any(x in exe_path.lower() for x in ['temp', 'tmp', 'appdata', 'local\\temp']):
                    score += 20
                    flags.append('Необычное расположение')
                
                proc_name = process_info['name'].lower()
                suspicious_names = ['svchost', 'dllhost', 'rundll32', 'wscript', 'mshta', 'cmd', 'powershell']
                if any(name in proc_name for name in suspicious_names) and 'windows' not in exe_path.lower():
                    score += 15
                    flags.append('Маскировка под системный процесс')
                
                if process_info['cmdline']:
                    cmdline = ' '.join(process_info['cmdline']).lower()
                    for suspicious in self.suspicious_strings:
                        if suspicious.lower() in cmdline:
                            score += 10
                            flags.append(f'Подозрительная команда: {suspicious}')
                
                if process_info['exe'] and os.path.exists(process_info['exe']):
                    try:
                        with open(process_info['exe'], 'rb') as f:
                            data = f.read(4096)
                            entropy = self.calculate_entropy(data)
                            if entropy > 7.0:
                                score += 15
                                flags.append(f'Высокая энтропия: {entropy:.2f}')
                    except:
                        pass
                
                if score > 0:
                    process_data = {
                        'pid': process_info['pid'],
                        'name': process_info['name'],
                        'path': process_info['exe'],
                        'cmdline': process_info['cmdline'],
                        'score': score,
                        'flags': flags,
                        'status': 'MALICIOUS' if score >= 50 else 'SUSPICIOUS',
                        'create_time': datetime.fromtimestamp(process_info['create_time']).isoformat() if process_info['create_time'] else 'N/A'
                    }
                    suspicious_processes.append(process_data)
                    
            except:
                continue
        
        return suspicious_processes
    
    def scan_startup_items(self):
        startup_items = []
        
        if os.name == 'nt':
            startup_paths = [
                os.path.join(os.environ.get('APPDATA', ''), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup'),
                os.path.join(os.environ.get('PROGRAMDATA', ''), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup'),
                r'C:\Users\All Users\Microsoft\Windows\Start Menu\Programs\Startup',
                os.path.join(os.environ.get('USERPROFILE', ''), 'AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup')
            ]
        
        for startup_path in startup_paths:
            if os.path.exists(startup_path):
                for root, dirs, files in os.walk(startup_path):
                    for file in files:
                        filepath = os.path.join(root, file)
                        if filepath.endswith(('.exe', '.bat', '.vbs', '.ps1', '.sh', '.py')):
                            item = self.analyze_file(filepath)
                            if item['score'] > 0:
                                startup_items.append(item)
        
        return startup_items
    
    def analyze_file(self, filepath):
        score = 0
        flags = []
        
        try:
            if os.path.getsize(filepath) > 0:
                with open(filepath, 'rb') as f:
                    data = f.read(4096)
                    entropy = self.calculate_entropy(data)
                    
                    if entropy > 7.0:
                        score += 20
                        flags.append(f'Высокая энтропия: {entropy:.2f}')
                    
                    try:
                        text = data.decode('utf-8', errors='ignore')
                        for suspicious in self.suspicious_strings:
                            if suspicious.lower() in text.lower():
                                score += 15
                                flags.append(f'Содержит: {suspicious}')
                    except:
                        pass
            
            ext = os.path.splitext(filepath)[1].lower()
            if ext in ['.vbs', '.ps1', '.bat']:
                score += 10
                flags.append('Скрипт в автозагрузке')
            
            filename = os.path.basename(filepath).lower()
            suspicious_names = ['crack', 'keygen', 'patch', 'loader', 'injector', 'hack', 'cheat']
            if any(name in filename for name in suspicious_names):
                score += 25
                flags.append('Подозрительное имя файла')
            
        except:
            pass
        
        return {
            'path': filepath,
            'score': score,
            'flags': flags,
            'status': 'MALICIOUS' if score >= 50 else 'SUSPICIOUS' if score > 0 else 'CLEAN'
        }

class SettingsManager:
    def __init__(self):
        self.settings = QSettings("SecurityShield", "AppSettings")

    def get_autostart(self):
        return self.settings.value("autostart", False, type=bool)

    def set_autostart(self, enabled):
        self.settings.setValue("autostart", enabled)
        self.update_windows_autostart(enabled)

    def update_windows_autostart(self, enabled):
        app_path = sys.executable
        app_name = "Security Shield"

        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0, winreg.KEY_SET_VALUE
            )

            if enabled:
                winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, f'"{app_path}"')
            else:
                try:
                    winreg.DeleteValue(key, app_name)
                except:
                    pass

            winreg.CloseKey(key)
        except:
            pass

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
                border-bottom: 2px solid rgba(80, 85, 100, 0.8);
            }
        """)

    def initUI(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 0, 10, 0)
        layout.setSpacing(5)

        header_title = QLabel("🛡️ Security Shield")
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

        self.minimize_btn = QPushButton("—")
        self.minimize_btn.setFixedSize(QSize(30, 30))
        self.minimize_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #e0e0e0;
                border: none;
                border-radius: 5px;
                font-size: 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(80, 85, 100, 0.9);
            }
        """)
        self.minimize_btn.clicked.connect(self.parent.showMinimized)

        self.close_btn = QPushButton("X")
        self.close_btn.setFixedSize(QSize(30, 30))
        self.close_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #ff5555;
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

        layout.addWidget(self.minimize_btn)
        layout.addWidget(self.close_btn)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_position = event.globalPosition().toPoint() - self.parent.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.MouseButton.LeftButton:
            self.parent.move(event.globalPosition().toPoint() - self._drag_position)
            event.accept()

class ThreatDialog(QDialog):
    def __init__(self, threat_info, parent=None):
        super().__init__(parent)
        self.threat_info = threat_info
        self.parent = parent
        self.process_name = ""
        self.process_path = ""
        self.process_pid = ""
        self.parse_threat_info()
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.initUI()

    def parse_threat_info(self):
        try:
            if "PID:" in self.threat_info:
                pid_start = self.threat_info.find("PID:") + 4
                pid_end = self.threat_info.find(")", pid_start)
                if pid_end != -1:
                    self.process_pid = self.threat_info[pid_start:pid_end].strip()

            if "(" in self.threat_info:
                process_part = self.threat_info.split("(")[0].strip()
                self.process_name = process_part

            if self.process_pid and self.process_pid.isdigit():
                try:
                    proc = psutil.Process(int(self.process_pid))
                    self.process_path = proc.exe()
                except:
                    pass
        except:
            pass

    def initUI(self):
        self.setWindowTitle("Обнаружена угроза!")
        self.setFixedSize(*DIALOG_SIZE)

        main_widget = QWidget()
        main_widget.setStyleSheet("""
            QWidget {
                background-color: rgba(30, 35, 45, 0.98);
                border-radius: 20px;
                border: 2px solid rgba(255, 86, 86, 0.8);
                box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
            }
        """)

        layout = QVBoxLayout(main_widget)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        title = QLabel("🚨 ОБНАРУЖЕНА УГРОЗА!")
        title.setStyleSheet("""
            QLabel {
                color: #ff5555;
                font-size: 22px;
                font-weight: bold;
                font-family: "Segoe UI";
                background: transparent;
            }
        """)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        threat_text = QLabel(self.threat_info)
        threat_text.setStyleSheet("""
            QLabel {
                color: #e0e0e0;
                font-size: 15px;
                font-family: "Segoe UI";
                background: transparent;
                padding: 15px;
                border-radius: 10px;
                background-color: rgba(255, 86, 86, 0.1);
                border: 1px solid rgba(255, 86, 86, 0.3);
                min-height: 80px;
            }
        """)
        threat_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        threat_text.setWordWrap(True)

        buttons_layout = QHBoxLayout()
        buttons_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        buttons_layout.setSpacing(20)

        quarantine_btn = QPushButton("Отправить в карантин")
        quarantine_btn.setFixedSize(*ACTION_BUTTON_SIZE)
        quarantine_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(255, 86, 86, 0.9);
                color: white;
                border: none;
                border-radius: 12px;
                font-size: 14px;
                font-weight: bold;
                font-family: "Segoe UI";
                padding: 10px;
            }
            QPushButton:hover {
                background-color: rgba(255, 110, 110, 0.95);
            }
            QPushButton:pressed {
                background-color: rgba(255, 60, 60, 0.95);
            }
        """)
        quarantine_btn.clicked.connect(self.quarantine_threat)

        ignore_btn = QPushButton("Добавить в исключения")
        ignore_btn.setFixedSize(*ACTION_BUTTON_SIZE)
        ignore_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(60, 70, 90, 0.9);
                color: #e0e0e0;
                border: none;
                border-radius: 12px;
                font-size: 14px;
                font-weight: bold;
                font-family: "Segoe UI";
                padding: 10px;
            }
            QPushButton:hover {
                background-color: rgba(80, 90, 110, 0.95);
            }
            QPushButton:pressed {
                background-color: rgba(40, 50, 70, 0.95);
            }
        """)
        ignore_btn.clicked.connect(self.request_password_for_exclusion)

        buttons_layout.addWidget(quarantine_btn)
        buttons_layout.addWidget(ignore_btn)

        layout.addWidget(title)
        layout.addWidget(threat_text)
        layout.addLayout(buttons_layout)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(main_widget)

    def request_password_for_exclusion(self):
        password_dialog = PasswordDialog(
            "Подтверждение пароля",
            "Для добавления в исключения введите пароль:",
            self.parent
        )
        
        if password_dialog.exec() == QDialog.DialogCode.Accepted:
            password = password_dialog.get_password()
            if self.parent.password_manager.verify_password(password):
                self.ignore_threat()
            else:
                QMessageBox.warning(self, "Ошибка", "Неверный пароль!")
        else:
            self.reject()

    def quarantine_threat(self):
        try:
            with open("security_log.txt", "a", encoding="utf-8") as f:
                f.write(f"{datetime.now()} - Отправка в карантин через Windows Defender: {self.threat_info}\n")

            if self.process_pid and self.process_pid.isdigit():
                try:
                    subprocess.run(["taskkill", "/PID", self.process_pid, "/F"], capture_output=True, timeout=5)
                except:
                    pass

            if self.process_path and os.path.exists(self.process_path):
                ps_command = f"""
                try {{
                    if (Test-Path "{self.process_path}") {{
                        Add-MpPreference -ControlledFolderAccessAllowedApplications "{self.process_path}" -ErrorAction SilentlyContinue
                        $scanResult = Start-MpScan -ScanPath "{self.process_path}" -ScanType CustomScan
                        $quarantinePath = "C:\\ProgramData\\Microsoft\\Windows Defender\\Quarantine"
                        if (Test-Path $quarantinePath) {{
                            $destPath = Join-Path $quarantinePath (Split-Path "{self.process_path}" -Leaf)
                            Copy-Item "{self.process_path}" $destPath -Force -ErrorAction SilentlyContinue
                        }}
                    }}
                }}
                catch {{
                    Write-Host "Ошибка при работе с Windows Defender: $_"
                }}
                """

                try:
                    subprocess.run([
                        "powershell",
                        "-Command",
                        ps_command,
                        "-ExecutionPolicy",
                        "Bypass"
                    ], shell=True, timeout=10)
                except:
                    try:
                        key = winreg.OpenKey(
                            winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
                            0, winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
                        )
                        winreg.SetValueEx(key, self.process_path, 0, winreg.REG_DWORD, 0)
                        winreg.CloseKey(key)
                    except:
                        pass

            elif self.process_name:
                for proc in psutil.process_iter(['pid', 'name', 'exe']):
                    try:
                        if proc.info['name'].lower() == self.process_name.lower():
                            proc_path = proc.info.get('exe', '')
                            if proc_path and os.path.exists(proc_path):
                                try:
                                    proc.terminate()
                                except:
                                    try:
                                        proc.kill()
                                    except:
                                        pass

                            with open("security_log.txt", "a", encoding="utf-8") as f:
                                f.write(f"{datetime.now()} - Завершен процесс: {self.process_name}\n")
                            break
                    except:
                        continue

        except:
            with open("security_log.txt", "a", encoding="utf-8") as f:
                f.write(f"{datetime.now()} - Ошибка при отправке в карантин\n")

        self.accept()

    def ignore_threat(self):
        try:
            exclusion_text = ""
            if self.process_name:
                exclusion_text = self.process_name
            elif "(" in self.threat_info:
                process_part = self.threat_info.split("(")[0].strip()
                exclusion_text = process_part
            else:
                exclusion_text = self.threat_info

            if self.parent and hasattr(self.parent, 'add_to_exclusions'):
                self.parent.add_to_exclusions(exclusion_text)

            with open("security_log.txt", "a", encoding="utf-8") as f:
                f.write(f"{datetime.now()} - Добавлено в исключения: {self.threat_info}\n")

        except:
            pass

        self.reject()

class ExclusionsPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.exclusions_set = set()
        self.initUI()
        self.load_exclusions()

    def initUI(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(40, 20, 40, 30)
        layout.setSpacing(20)

        title = QLabel("📋 ИСКЛЮЧЕНИЯ")
        title.setStyleSheet("""
            QLabel {
                color: #e0e0e0;
                font-size: 26px;
                font-weight: bold;
                font-family: "Segoe UI";
                background: transparent;
                padding-bottom: 15px;
            }
        """)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        info_text = QLabel("Здесь отображаются процессы, добавленные в исключения.\nСистема не будет проверять эти процессы на угрозы.")
        info_text.setStyleSheet("""
            QLabel {
                color: #a0a0b0;
                font-size: 15px;
                font-family: "Segoe UI";
                background: transparent;
                padding: 15px;
                border-radius: 10px;
                background-color: rgba(155, 89, 182, 0.15);
                border: 1px solid rgba(155, 89, 182, 0.3);
                margin-bottom: 20px;
            }
        """)
        info_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        info_text.setWordWrap(True)

        self.exclusions_list = QListWidget()
        self.exclusions_list.setStyleSheet("""
            QListWidget {
                background-color: rgba(40, 45, 55, 0.95);
                border: 2px solid rgba(80, 85, 100, 0.8);
                border-radius: 12px;
                color: #e0e0e0;
                font-family: "Segoe UI";
                font-size: 14px;
                padding: 8px;
                outline: none;
            }
            QListWidget::item {
                padding: 15px 20px;
                border-bottom: 1px solid rgba(80, 85, 100, 0.5);
                margin: 3px;
                border-radius: 8px;
                color: #e0e0e0;
                font-size: 14px;
            }
            QListWidget::item:hover {
                background-color: rgba(155, 89, 182, 0.25);
                color: #ffffff;
            }
            QListWidget::item:selected {
                background-color: rgba(155, 89, 182, 0.35);
                color: #ffffff;
            }
            QListWidget::item:alternate {
                background-color: rgba(50, 55, 65, 0.8);
            }
            QScrollBar:vertical {
                background-color: rgba(60, 65, 75, 0.8);
                width: 14px;
                border-radius: 7px;
                margin: 3px;
            }
            QScrollBar::handle:vertical {
                background-color: rgba(155, 89, 182, 0.6);
                border-radius: 7px;
                min-height: 40px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: rgba(155, 89, 182, 0.8);
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)
        self.exclusions_list.setAlternatingRowColors(True)

        delete_btn = QPushButton("🗑️ Удалить выбранное")
        delete_btn.setFixedSize(240, 48)
        delete_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(231, 76, 60, 0.9);
                color: white;
                border: none;
                border-radius: 12px;
                font-size: 15px;
                font-weight: bold;
                font-family: "Segoe UI";
                padding: 12px;
            }
            QPushButton:hover {
                background-color: rgba(231, 100, 84, 0.95);
            }
            QPushButton:pressed {
                background-color: rgba(231, 56, 40, 0.95);
            }
            QPushButton:disabled {
                background-color: rgba(80, 85, 95, 0.6);
                color: rgba(150, 150, 150, 0.8);
            }
        """)
        delete_btn.clicked.connect(self.request_password_for_deletion)

        self.stats_label = QLabel("Исключений: 0")
        self.stats_label.setStyleSheet("""
            QLabel {
                color: #8f9ba8;
                font-size: 14px;
                font-family: "Segoe UI";
                background: transparent;
            }
        """)
        self.stats_label.setAlignment(Qt.AlignmentFlag.AlignRight)

        layout.addWidget(title)
        layout.addWidget(info_text)
        layout.addWidget(self.exclusions_list)

        bottom_layout = QHBoxLayout()
        bottom_layout.addWidget(delete_btn)
        bottom_layout.addStretch(1)
        bottom_layout.addWidget(self.stats_label)

        layout.addLayout(bottom_layout)
        self.setLayout(layout)

    def request_password_for_deletion(self):
        password_dialog = PasswordDialog(
            "Подтверждение пароля",
            "Для удаления исключений введите пароль:",
            self.parent
        )
        
        if password_dialog.exec() == QDialog.DialogCode.Accepted:
            password = password_dialog.get_password()
            if self.parent.password_manager.verify_password(password):
                self.delete_selected()
            else:
                QMessageBox.warning(self, "Ошибка", "Неверный пароль!")

    def load_exclusions(self):
        try:
            if os.path.exists("exclusions.txt"):
                with open("exclusions.txt", "r", encoding="utf-8") as f:
                    for line in f:
                        exclusion = line.strip()
                        if exclusion and exclusion not in self.exclusions_set:
                            self.exclusions_set.add(exclusion)
                            item = QListWidgetItem(f"• {exclusion}")
                            self.exclusions_list.addItem(item)
                self.update_stats()
            else:
                with open("exclusions.txt", "w", encoding="utf-8") as f:
                    pass
        except:
            pass

    def add_exclusion(self, exclusion):
        if exclusion and exclusion not in self.exclusions_set:
            self.exclusions_set.add(exclusion)
            item = QListWidgetItem(f"• {exclusion}")
            self.exclusions_list.addItem(item)
            self.update_stats()
            self.save_to_file()
            self.exclusions_list.scrollToItem(item)
            return True
        return False

    def save_to_file(self):
        try:
            with open("exclusions.txt", "w", encoding="utf-8") as f:
                for exclusion in self.exclusions_set:
                    f.write(f"{exclusion}\n")
        except:
        pass

    def delete_selected(self):
        selected_items = self.exclusions_list.selectedItems()
        if not selected_items:
            return

        for item in selected_items:
            item_text = item.text()
            exclusion = item_text[2:] if item_text.startswith("• ") else item_text

            if exclusion in self.exclusions_set:
                self.exclusions_set.remove(exclusion)

            row = self.exclusions_list.row(item)
            self.exclusions_list.takeItem(row)

        self.save_to_file()
        self.update_stats()

    def update_stats(self):
        count = len(self.exclusions_set)
        self.stats_label.setText(f"Исключений: {count}")

class MainPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.initUI()

    def initUI(self):
        page_layout = QVBoxLayout()
        page_layout.setContentsMargins(0, 0, 0, 0)
        page_layout.setSpacing(0)

        content_widget = QWidget()
        content_widget.setStyleSheet("""
            QWidget {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(30, 35, 45, 0.95), 
                    stop:1 rgba(25, 30, 40, 0.95));
            }
        """)
        content_layout = QVBoxLayout(content_widget)
        content_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        content_layout.setContentsMargins(0, 40, 0, 40)
        content_layout.setSpacing(0)

        self.status_circle = QLabel()
        self.status_circle.setFixedSize(*ICON_CIRCLE_DIAMETER)
        self.status_circle.setAlignment(Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignVCenter)

        circle_container = QWidget()
        circle_container.setFixedSize(*STATUS_CONTAINER_DIAMETER)
        circle_layout = QVBoxLayout(circle_container)
        circle_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        circle_layout.addWidget(self.status_circle)
        circle_layout.setContentsMargins(0, 0, 0, 0)

        self.protect_button = QPushButton("🛡️ АКТИВИРОВАТЬ")
        self.protect_button.setFixedSize(300, 75)
        self.protect_button.setStyleSheet("""
            QPushButton {
                background-color: rgba(155, 89, 182, 0.9);
                color: white;
                border: none;
                border-radius: 14px;
                font-size: 20px;
                font-weight: bold;
                font-family: "Segoe UI";
                padding: 15px;
            }
            QPushButton:hover {
                background-color: rgba(175, 109, 202, 0.95);
            }
            QPushButton:pressed {
                background-color: rgba(135, 69, 162, 0.95);
            }
        """)

        self.status_label = QLabel("Защита неактивна")
        self.status_label.setStyleSheet("""
            QLabel {
                color: #e0e0e0;
                font-size: 20px;
                font-weight: bold;
                font-family: "Segoe UI";
                background: transparent;
            }
        """)
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setFixedHeight(50)

        self.autostart_checkbox = QCheckBox("✅ Автозапуск приложения")
        self.autostart_checkbox.setStyleSheet("""
            QCheckBox {
                color: #b0b0c0;
                font-size: 16px;
                font-family: "Segoe UI";
                background: transparent;
                spacing: 12px;
                padding: 10px;
            }
            QCheckBox::indicator {
                width: 22px;
                height: 22px;
                border-radius: 5px;
                border: 2px solid rgba(155, 89, 182, 0.8);
                background: rgba(40, 45, 55, 0.9);
            }
            QCheckBox::indicator:checked {
                background-color: rgba(155, 89, 182, 0.9);
                border-color: rgba(155, 89, 182, 1);
            }
            QCheckBox::indicator:checked:hover {
                background-color: rgba(175, 109, 202, 0.95);
                border-color: rgba(175, 109, 202, 1);
            }
            QCheckBox::indicator:hover {
                border-color: rgba(175, 109, 202, 1);
            }
        """)

        center_layout = QVBoxLayout()
        center_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        center_layout.setSpacing(15)

        center_layout.addWidget(circle_container)
        center_layout.addSpacing(30)
        center_layout.addWidget(self.protect_button)
        center_layout.addSpacing(20)
        center_layout.addWidget(self.status_label)
        center_layout.addSpacing(15)
        center_layout.addWidget(self.autostart_checkbox)

        content_layout.addStretch(1)
        content_layout.addLayout(center_layout)
        content_layout.addStretch(1)

        page_layout.addWidget(content_widget)

        self.setLayout(page_layout)

class NavigationPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 40)
        layout.setSpacing(15)

        nav_title = QLabel("НАВИГАЦИЯ")
        nav_title.setStyleSheet("""
            QLabel {
                color: rgba(150, 160, 180, 0.9);
                font-size: 14px;
                font-weight: bold;
                font-family: "Segoe UI";
                background: transparent;
                padding-left: 15px;
                padding-bottom: 10px;
                letter-spacing: 1px;
            }
        """)

        self.main_page_btn = QPushButton("🏠 Главная")
        self.main_page_btn.setFixedHeight(55)
        self.main_page_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(155, 89, 182, 0.9);
                color: white;
                border: none;
                border-radius: 12px;
                font-size: 16px;
                font-weight: bold;
                font-family: "Segoe UI";
                text-align: left;
                padding-left: 25px;
                padding-right: 25px;
            }
            QPushButton:hover {
                background-color: rgba(175, 109, 202, 0.95);
            }
            QPushButton:pressed {
                background-color: rgba(135, 69, 162, 0.95);
            }
        """)

        self.exclusions_page_btn = QPushButton("📋 Исключения")
        self.exclusions_page_btn.setFixedHeight(55)
        self.exclusions_page_btn.setStyleSheet("""
            QPushButton {
                background-color: rgba(60, 70, 85, 0.9);
                color: #d0d0e0;
                border: none;
                border-radius: 12px;
                font-size: 16px;
                font-weight: bold;
                font-family: "Segoe UI";
                text-align: left;
                padding-left: 25px;
                padding-right: 25px;
            }
            QPushButton:hover {
                background-color: rgba(80, 90, 105, 0.95);
                color: #ffffff;
            }
            QPushButton:pressed {
                background-color: rgba(40, 50, 65, 0.95);
            }
        """)

        layout.addWidget(nav_title)
        layout.addWidget(self.main_page_btn)
        layout.addWidget(self.exclusions_page_btn)
        layout.addStretch(1)

        info_label = QLabel("Security Shield v2.0N")
        info_label.setStyleSheet("""
            QLabel {
                color: rgba(140, 150, 170, 0.8);
                font-size: 13px;
                font-family: "Segoe UI";
                background: transparent;
                padding-top: 25px;
            }
        """)
        info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(info_label)

        self.setLayout(layout)
        self.setFixedWidth(NAV_PANEL_WIDTH)
        self.setStyleSheet("""
            QWidget {
                background-color: rgba(35, 40, 50, 0.98);
                border-right: 2px solid rgba(80, 85, 100, 0.8);
                border-bottom-left-radius: 20px;
            }
        """)

class ContentArea(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.stacked_widget = QStackedWidget()
        self.stacked_widget.setStyleSheet("""
            QStackedWidget {
                background: transparent;
                border-bottom-right-radius: 20px;
            }
        """)

        layout.addWidget(self.stacked_widget)
        self.setLayout(layout)

class SimpleSecurityApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.password_manager = PasswordManager()
        self.require_password_setup()
        
        # Инициализация остальных компонентов
        self.is_protected = False
        self.threat_check_timer = QTimer()
        self.threat_check_timer.timeout.connect(self.check_for_threats)
        self.settings_manager = SettingsManager()
        self.scanner = SystemScanner()
        self.checkmark_pixmap = None
        self.cross_pixmap = None
        self.load_images()
        self._drag_position = QPoint()
        self.detected_threats_cache = set()
        
        # Создаем интерфейс
        self.initUI()
        self.perform_startup_scan()

    def require_password_setup(self):
        """Проверка и установка пароля при необходимости"""
        if not self.password_manager.is_password_set():
            self.setup_password()
    
    def setup_password(self):
        """Диалог установки пароля (вызывается ДО показа основного окна)"""
        password_dialog = PasswordDialog(
            "Установка пароля",
            "Установите пароль из 4 цифр для добавления в исключения:",
            None,  # parent=None, так как основное окно еще не создано
            is_setup=True
        )
        
        while True:
            result = password_dialog.exec()
            if result == QDialog.DialogCode.Accepted:
                password = password_dialog.get_password()
                confirm_password = password_dialog.get_confirm_password()
                
                # Валидация
                if len(password) != 4 or not password.isdigit():
                    QMessageBox.warning(None, "Ошибка", "Пароль должен состоять из 4 цифр!")
                    continue
                
                if password != confirm_password:
                    QMessageBox.warning(None, "Ошибка", "Пароли не совпадают!")
                    continue
                
                # Установка пароля
                if self.password_manager.set_password(password):
                    QMessageBox.information(None, "Успех", "Пароль успешно установлен!")
                    break
                else:
                    QMessageBox.warning(None, "Ошибка", "Не удалось установить пароль!")
            else:
                # Если пользователь отменил установку пароля
                sys.exit(0)

    def load_images(self):
        image_size = 100
        try:
            if os.path.exists(CHECKMARK_PATH):
                self.checkmark_pixmap = QPixmap(CHECKMARK_PATH)
                self.checkmark_pixmap = self.checkmark_pixmap.scaled(
                    image_size, image_size,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation
                )
            if os.path.exists(CROSS_PATH):
                self.cross_pixmap = QPixmap(CROSS_PATH)
                self.cross_pixmap = self.cross_pixmap.scaled(
                    image_size, image_size,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation
                )
        except:
            pass

    def initUI(self):
        """Инициализация графического интерфейса"""
        self.setWindowTitle('Security Shield')
        self.setFixedSize(*MAIN_WINDOW_SIZE)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        if os.path.exists(APP_ICON_PATH):
            self.setWindowIcon(QIcon(APP_ICON_PATH))

        central_widget = QWidget()
        central_widget.setStyleSheet("""
            QWidget {
                background-color: rgba(25, 30, 40, 0.98);
                border-radius: 20px;
                border: 2px solid rgba(60, 65, 80, 0.9);
                box-shadow: 0 12px 50px rgba(0, 0, 0, 0.4);
            }
        """)
        self.setCentralWidget(central_widget)

        main_v_layout = QVBoxLayout(central_widget)
        main_v_layout.setContentsMargins(0, 0, 0, 0)
        main_v_layout.setSpacing(0)

        self.header_panel = HeaderPanel(self)
        main_v_layout.addWidget(self.header_panel)

        main_h_layout = QHBoxLayout()
        main_h_layout.setContentsMargins(0, 0, 0, 0)
        main_h_layout.setSpacing(0)

        self.nav_panel = NavigationPanel(self)
        self.content_area = ContentArea(self)

        self.main_page = MainPage(self)
        self.exclusions_page = ExclusionsPage(self)

        self.set_cross_icon()

        self.main_page.protect_button.clicked.connect(self.toggle_protection)
        self.main_page.autostart_checkbox.toggled.connect(self.toggle_autostart)

        autostart_enabled = self.settings_manager.get_autostart()
        self.main_page.autostart_checkbox.setChecked(autostart_enabled)

        self.nav_panel.main_page_btn.clicked.connect(lambda: self.switch_page(0))
        self.nav_panel.exclusions_page_btn.clicked.connect(lambda: self.switch_page(1))

        self.content_area.stacked_widget.addWidget(self.main_page)
        self.content_area.stacked_widget.addWidget(self.exclusions_page)

        main_h_layout.addWidget(self.nav_panel)
        main_h_layout.addWidget(self.content_area)

        main_v_layout.addLayout(main_h_layout)
        self.switch_page(0)

    def perform_startup_scan(self):
        """Выполнение начального сканирования"""
        processes = self.scanner.scan_running_processes()
        startup_items = self.scanner.scan_startup_items()
        
        for proc in processes:
            if proc['status'] == 'MALICIOUS':
                threat_info = f"{proc['name']} (PID: {proc['pid']}) - Обнаружен вредоносный процесс"
                self.show_threat_alert_external(threat_info)
                break
        
        for item in startup_items:
            if item['status'] == 'MALICIOUS':
                threat_info = f"Вредоносный файл в автозагрузке: {os.path.basename(item['path'])}"
                self.show_threat_alert_external(threat_info)
                break

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_position = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.MouseButton.LeftButton:
            self.move(event.globalPosition().toPoint() - self._drag_position)
            event.accept()

    def switch_page(self, index):
        self.content_area.stacked_widget.setCurrentIndex(index)

        active_style = """
            QPushButton {
                background-color: rgba(155, 89, 182, 0.9);
                color: white;
                border: none;
                border-radius: 12px;
                font-size: 16px;
                font-weight: bold;
                font-family: "Segoe UI";
                text-align: left;
                padding-left: 25px;
                padding-right: 25px;
            }
            QPushButton:hover {
                background-color: rgba(175, 109, 202, 0.95);
            }
        """

        inactive_style = """
            QPushButton {
                background-color: rgba(60, 70, 85, 0.9);
                color: #d0d0e0;
                border: none;
                border-radius: 12px;
                font-size: 16px;
                font-weight: bold;
                font-family: "Segoe UI";
                text-align: left;
                padding-left: 25px;
                padding-right: 25px;
            }
            QPushButton:hover {
                background-color: rgba(80, 90, 105, 0.95);
                color: #ffffff;
            }
            QPushButton:pressed {
                background-color: rgba(40, 50, 65, 0.95);
            }
        """

        if index == 0:
            self.nav_panel.main_page_btn.setStyleSheet(active_style)
            self.nav_panel.exclusions_page_btn.setStyleSheet(inactive_style)
        else:
            self.nav_panel.main_page_btn.setStyleSheet(inactive_style)
            self.nav_panel.exclusions_page_btn.setStyleSheet(active_style)

    def add_to_exclusions(self, exclusion):
        self.exclusions_page.add_exclusion(exclusion)

    def set_checkmark_icon(self):
        new_radius = int(ICON_CIRCLE_SIZE / 2)
        new_font_size = ICON_CIRCLE_SIZE - 50

        if self.checkmark_pixmap and not self.checkmark_pixmap.isNull():
            self.main_page.status_circle.setPixmap(self.checkmark_pixmap)
            self.main_page.status_circle.setAlignment(Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignVCenter)
            self.main_page.status_circle.setStyleSheet(f"""
                QLabel {{
                    background-color: rgba(46, 204, 113, 0.15);
                    border-radius: {new_radius}px;
                    padding: 25px;
                    border: 2px solid rgba(46, 204, 113, 0.3);
                }}
            """)
        else:
            self.main_page.status_circle.setText(DEFAULT_CHECKMARK_SYMBOL)
            self.main_page.status_circle.setAlignment(Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignVCenter)
            self.main_page.status_circle.setStyleSheet(f"""
                QLabel {{
                    color: #2ecc71;
                    font-size: {new_font_size}px;
                    background-color: rgba(46, 204, 113, 0.15);
                    border-radius: {new_radius}px;
                    padding: 25px;
                    border: 2px solid rgba(46, 204, 113, 0.3);
                }}
            """)

    def set_cross_icon(self):
        new_radius = int(ICON_CIRCLE_SIZE / 2)
        new_font_size = ICON_CIRCLE_SIZE - 50
        if self.cross_pixmap and not self.cross_pixmap.isNull():
            self.main_page.status_circle.setPixmap(self.cross_pixmap)
            self.main_page.status_circle.setAlignment(Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignVCenter)
            self.main_page.status_circle.setStyleSheet(f"""
                QLabel {{
                    background-color: rgba(231, 76, 60, 0.15);
                    border-radius: {new_radius}px;
                    padding: 25px;
                    border: 2px solid rgba(231, 76, 60, 0.3);
                }}
            """)
        else:
            self.main_page.status_circle.setText(DEFAULT_CROSS_SYMBOL)
            self.main_page.status_circle.setAlignment(Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignVCenter)
            self.main_page.status_circle.setStyleSheet(f"""
                QLabel {{
                    color: #e74c3c;
                    font-size: {new_font_size}px;
                    background-color: rgba(231, 76, 60, 0.15);
                    border-radius: {new_radius}px;
                    padding: 25px;
                    border: 2px solid rgba(231, 76, 60, 0.3);
                }}
            """)

    def toggle_autostart(self, checked):
        self.settings_manager.set_autostart(checked)

    def toggle_protection(self):
        self.is_protected = not self.is_protected

        if self.is_protected:
            self.set_checkmark_icon()
            self.main_page.protect_button.hide()
            self.main_page.status_label.setText("ЗАЩИТА АКТИВНА")
            self.start_protection()
        else:
            self.set_cross_icon()
            self.main_page.protect_button.show()
            self.main_page.status_label.setText("Защита неактивна")
            self.stop_protection()

    def start_protection(self):
        self.threat_check_timer.start(30000)
        with open("security_log.txt", "a", encoding="utf-8") as f:
            f.write(f"\n{'=' * 50}\n")
            f.write(f"Защита активирована: {datetime.now()}\n")
            f.write(f"{'=' * 50}\n")

    def stop_protection(self):
        self.threat_check_timer.stop()
        with open("security_log.txt", "a", encoding="utf-8") as f:
            f.write(f"\nЗащита деактивирована: {datetime.now()}\n")

    def check_for_threats(self):
        processes = self.scanner.scan_running_processes()
        
        for proc in processes:
            if proc['status'] == 'MALICIOUS':
                threat_id = f"{proc['pid']}_{proc['name']}"
                if threat_id not in self.detected_threats_cache:
                    self.detected_threats_cache.add(threat_id)
                    threat_info = f"{proc['name']} (PID: {proc['pid']}) - Обнаружен вредоносный процесс"
                    self.show_threat_alert_external(threat_info)
                    with open("security_log.txt", "a", encoding="utf-8") as f:
                        f.write(f"{datetime.now()} - Обнаружен процесс: {threat_info}\n")

    def show_threat_alert_external(self, threat_info):
        try:
            threat_dialog = ThreatDialog(threat_info, self)
            threat_dialog.setWindowFlags(
                Qt.WindowType.FramelessWindowHint |
                Qt.WindowType.WindowStaysOnTopHint |
                Qt.WindowType.Dialog
            )
            threat_dialog.show()
            threat_dialog.raise_()
            threat_dialog.activateWindow()
        except:
            pass

    def show_threat_alert(self, threat_info):
        self.show_threat_alert_external(threat_info)

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    from PyQt6.QtGui import QPalette, QColor
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(25, 30, 40))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(220, 220, 220))
    palette.setColor(QPalette.ColorRole.Base, QColor(35, 40, 50))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(45, 50, 60))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(25, 30, 40))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor(220, 220, 220))
    palette.setColor(QPalette.ColorRole.Text, QColor(220, 220, 220))
    palette.setColor(QPalette.ColorRole.Button, QColor(45, 50, 65))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(220, 220, 220))
    palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
    palette.setColor(QPalette.ColorRole.Link, QColor(155, 89, 182))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(155, 89, 182))
    palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.black)
    app.setPalette(palette)

    window = SimpleSecurityApp()
    window.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
