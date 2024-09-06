import os
import platform
import subprocess
import sys
import logging
import time
from PyQt5 import QtWidgets, QtGui, QtCore
import pyudev

# Set up logging
logging.basicConfig(filename='boot_it.log', level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s:%(message)s')

class BootableUSBThread(QtCore.QThread):
    progress_signal = QtCore.pyqtSignal(str)
    progress_bar_signal = QtCore.pyqtSignal(int)
    task_finished_signal = QtCore.pyqtSignal()
    elapsed_time_signal = QtCore.pyqtSignal(float)

    def __init__(self, iso_path, usb_device, password, system):
        super().__init__()
        self.iso_path = iso_path
        self.usb_device = usb_device
        self.password = password
        self.system = system
        self.start_time = 0

    def run(self):
        self.start_time = time.time()
        try:
            if self.system == "Linux":
                self.progress_signal.emit("Running on Linux: Starting bootable USB creation process.")
                self.create_bootable_usb_linux(self.iso_path, self.usb_device)
            elif self.system == "Windows":
                self.progress_signal.emit("Running on Windows: Starting bootable USB creation process.")
                self.create_bootable_usb_windows(self.iso_path, self.usb_device)
            else:
                raise RuntimeError("Unsupported operating system.")

            self.progress_signal.emit("Bootable USB created successfully!")
        except Exception as e:
            self.progress_signal.emit(f"Error: Failed to create bootable USB: {e}")
            logging.error(f"Failed to create bootable USB: {e}")
        finally:
            elapsed_time = time.time() - self.start_time
            self.progress_signal.emit(f"Process completed in {self.format_time(elapsed_time)}.")
            self.progress_bar_signal.emit(100)
            self.elapsed_time_signal.emit(elapsed_time)  # Send the elapsed time when done
            self.task_finished_signal.emit()

    def create_bootable_usb_linux(self, iso_path, usb_device):
        self.progress_signal.emit("Unmounting the USB device...")
        self.unmount_device_linux(usb_device)
        self.progress_signal.emit("Writing the ISO to the USB device using 'dd' command...")
        self.run_dd_command(iso_path, usb_device)
        self.progress_signal.emit("Syncing the device to ensure data integrity...")
        self.sync_device(usb_device)

    def unmount_device_linux(self, usb_device):
        try:
            partitions = subprocess.check_output(f"lsblk -ln {usb_device} | awk '{{print $1}}'", shell=True).decode().splitlines()
            for partition in partitions:
                mount_check = subprocess.run(['mountpoint', f'/dev/{partition}'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if mount_check.returncode == 0:
                    subprocess.run(['umount', f'/dev/{partition}'], check=True)
                    self.progress_signal.emit(f"Unmounted /dev/{partition}.")
                else:
                    self.progress_signal.emit(f"/dev/{partition} is not mounted.")
        except subprocess.CalledProcessError as e:
            logging.warning(f"Could not unmount {usb_device}: {e}")
            self.progress_signal.emit(f"Warning: Could not unmount {usb_device}.")

    def run_dd_command(self, iso_path, usb_device):
        total_size = os.path.getsize(iso_path)
        dd_command = ['sudo', '-S', 'dd', f'if={iso_path}', f'of={usb_device}', 'bs=4M', 'status=progress', 'oflag=sync']
        with subprocess.Popen(dd_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as proc:
            proc.stdin.write(self.password + '\n')
            proc.stdin.flush()

            transferred = 0
            while True:
                output = proc.stderr.read(1024)
                if not output and proc.poll() is not None:
                    break
                if output:
                    self.progress_signal.emit(f"Writing to USB: {output.strip()}")
                    if "bytes" in output:
                        parts = output.split()
                        try:
                            transferred = int(parts[0])
                            progress = int((transferred / total_size) * 100)
                            self.progress_bar_signal.emit(progress)
                        except (ValueError, IndexError):
                            pass
        proc.wait()
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, dd_command)

    def sync_device(self, usb_device):
        try:
            subprocess.run(['sync'], check=True)
        except subprocess.CalledProcessError as e:
            self.progress_signal.emit(f"Error: Failed to sync {usb_device}: {e}")

    def format_time(self, seconds):
        mins, secs = divmod(seconds, 60)
        return f"{int(mins):02}:{int(secs):02}"

class BootIt(QtWidgets.QWidget):
    update_progress_signal = QtCore.pyqtSignal(str)
    update_progress_bar_signal = QtCore.pyqtSignal(int)
    reset_ui_signal = QtCore.pyqtSignal()
    refresh_usb_signal = QtCore.pyqtSignal()
    update_elapsed_time_signal = QtCore.pyqtSignal(str)

    def __init__(self):
        super().__init__()

        self.system = platform.system()
        self.password = None  # Store the password once per session
        self.timer = None
        self.start_time = 0  # Store the start time of the process
        self.init_ui()
        self.list_removable_drives()

        self.update_progress_signal.connect(self.update_progress)
        self.update_progress_bar_signal.connect(self.update_progress_bar)
        self.reset_ui_signal.connect(self.reset_ui)
        self.refresh_usb_signal.connect(self.list_removable_drives)
        self.update_elapsed_time_signal.connect(self.update_elapsed_time)

        self.apply_dark_theme()

    def init_ui(self):
        self.setWindowTitle("Boot-It: Bootable USB Creator")
        self.setGeometry(300, 200, 600, 400)
        self.setFixedSize(600, 400)

        layout = QtWidgets.QVBoxLayout()

        # Dark Theme Toggle
        self.dark_mode_checkbox = QtWidgets.QCheckBox("Enable Dark Mode")
        self.dark_mode_checkbox.setChecked(True)
        self.dark_mode_checkbox.stateChanged.connect(self.toggle_dark_mode)
        layout.addWidget(self.dark_mode_checkbox)

        # ISO File Selection
        iso_label = QtWidgets.QLabel("1. Select ISO File:")
        iso_label.setFont(QtGui.QFont("Arial", 14, QtGui.QFont.Bold))
        layout.addWidget(iso_label)

        iso_layout = QtWidgets.QHBoxLayout()
        self.iso_entry = QtWidgets.QLineEdit()
        iso_layout.addWidget(self.iso_entry)
        iso_button = QtWidgets.QPushButton("Browse")
        iso_button.clicked.connect(self.browse_iso)
        iso_layout.addWidget(iso_button)
        layout.addLayout(iso_layout)

        # USB Device Selection
        usb_label = QtWidgets.QLabel("2. Select USB Device:")
        usb_label.setFont(QtGui.QFont("Arial", 14, QtGui.QFont.Bold))
        layout.addWidget(usb_label)

        self.usb_combobox = QtWidgets.QComboBox()
        layout.addWidget(self.usb_combobox)

        refresh_button = QtWidgets.QPushButton("Refresh USB List")
        refresh_button.clicked.connect(self.list_removable_drives)
        layout.addWidget(refresh_button)

        # Scrollable Area for Process Information
        self.scroll_area = QtWidgets.QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.progress_text = QtWidgets.QTextEdit()
        self.progress_text.setReadOnly(True)
        self.scroll_area.setWidget(self.progress_text)
        layout.addWidget(self.scroll_area)

        # Progress Bar
        self.progress = QtWidgets.QProgressBar()
        self.progress.setValue(0)
        layout.addWidget(self.progress)

        # Time Elapsed
        self.time_elapsed_label = QtWidgets.QLabel("Time Elapsed: 00:00")
        layout.addWidget(self.time_elapsed_label)

        # Create Button
        create_button = QtWidgets.QPushButton("Create Bootable USB")
        create_button.setFont(QtGui.QFont("Arial", 14, QtGui.QFont.Bold))
        create_button.clicked.connect(self.create_bootable_usb)
        layout.addWidget(create_button)

        self.setLayout(layout)

    def apply_dark_theme(self):
        QtWidgets.QApplication.instance().setStyle("Fusion")
        palette = QtGui.QPalette()
        palette.setColor(QtGui.QPalette.Window, QtGui.QColor(53, 53, 53))
        palette.setColor(QtGui.QPalette.WindowText, QtCore.Qt.white)
        palette.setColor(QtGui.QPalette.Base, QtGui.QColor(25, 25, 25))
        palette.setColor(QtGui.QPalette.AlternateBase, QtGui.QColor(53, 53, 53))
        palette.setColor(QtGui.QPalette.Text, QtCore.Qt.white)
        palette.setColor(QtGui.QPalette.Button, QtGui.QColor(53, 53, 53))
        palette.setColor(QtGui.QPalette.ButtonText, QtCore.Qt.white)
        QtWidgets.QApplication.instance().setPalette(palette)

    def toggle_dark_mode(self, state):
        if state == QtCore.Qt.Checked:
            self.apply_dark_theme()
        else:
            QtWidgets.QApplication.instance().setPalette(QtWidgets.QApplication.style().standardPalette())

    def browse_iso(self):
        iso_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select ISO File", "", "ISO files (*.iso)")
        if iso_path:
            self.iso_entry.setText(iso_path)
            self.update_progress_signal.emit(f"Selected ISO file: {iso_path}")

    def list_removable_drives(self):
        self.update_progress_signal.emit("Scanning for removable USB devices...")
        devices = []
        try:
            if self.system == "Linux":
                context = pyudev.Context()
                for device in context.list_devices(subsystem='block', DEVTYPE='disk'):
                    if device.attributes.asstring('removable') == "1":
                        devices.append(f"{device.device_node} - {device.get('ID_FS_LABEL', 'Unknown')}")
            elif self.system == "Windows":
                result = subprocess.run(['wmic', 'diskdrive', 'where', 'MediaType="Removable Media"', 'get', 'deviceid,size,caption'], stdout=subprocess.PIPE, shell=True)
                lines = result.stdout.decode('utf-8').splitlines()
                for line in lines:
                    if "Disk" in line:
                        parts = line.split()
                        device = f"{parts[0]} - {int(parts[1]) / (1024**3):.2f} GB"
                        devices.append(device)
            if devices:
                self.usb_combobox.clear()
                self.usb_combobox.addItems(devices)
                self.update_progress_signal.emit("Removable USB devices found and listed.")
            else:
                self.usb_combobox.clear()
                self.usb_combobox.addItem("No removable USB devices found")
                self.update_progress_signal.emit("No removable USB devices found.")
        except Exception as e:
            self.update_progress_signal.emit(f"Failed to list USB devices: {e}")

    def create_bootable_usb(self):
        iso_path = self.iso_entry.text()
        usb_device = self.usb_combobox.currentText().split()[0]

        if not iso_path or not os.path.isfile(iso_path):
            QtWidgets.QMessageBox.critical(self, "Error", "Please select a valid ISO file.")
            return

        if not usb_device or "No removable USB devices found" in usb_device:
            QtWidgets.QMessageBox.critical(self, "Error", "Please select a valid USB device.")
            return

        confirm = QtWidgets.QMessageBox.question(self, "Confirmation",
                                                 f"Are you sure you want to create a bootable USB on {usb_device}? This will erase all data on the USB drive!",
                                                 QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
        if confirm != QtWidgets.QMessageBox.Yes:
            self.update_progress_signal.emit("Operation cancelled by user.")
            return

        self.progress.setValue(0)
        self.progress_text.append("Starting the creation process...")

        if not self.password:
            credential_dialog = CredentialDialog()
            if credential_dialog.exec_() == QtWidgets.QDialog.Accepted:
                self.password = credential_dialog.get_credentials()

        # Start the timer
        self.start_time = time.time()
        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.update_elapsed_time)
        self.timer.start(1000)  # Update elapsed time every second

        self.thread = BootableUSBThread(iso_path, usb_device, self.password, self.system)
        self.thread.progress_signal.connect(self.update_progress)
        self.thread.progress_bar_signal.connect(self.update_progress_bar)
        self.thread.elapsed_time_signal.connect(self.update_elapsed_time_final)
        self.thread.task_finished_signal.connect(self.list_removable_drives)
        self.thread.start()

    def update_elapsed_time(self):
        elapsed_time = time.time() - self.start_time
        formatted_time = self.format_time(elapsed_time)
        self.time_elapsed_label.setText(f"Time Elapsed: {formatted_time}")

    def update_elapsed_time_final(self, elapsed_time):
        formatted_time = self.format_time(elapsed_time)
        self.time_elapsed_label.setText(f"Time Elapsed: {formatted_time}")
        if self.timer is not None:
            self.timer.stop()

    def reset_ui(self):
        self.progress.setValue(0)
        self.progress_text.clear()
        self.time_elapsed_label.setText("Time Elapsed: 00:00")

    def update_progress(self, message):
        self.progress_text.append(message)
        self.progress_text.ensureCursorVisible()

    def update_progress_bar(self, value):
        self.progress.setValue(value)

    def format_time(self, seconds):
        mins, secs = divmod(seconds, 60)
        return f"{int(mins):02}:{int(secs):02}"

class CredentialDialog(QtWidgets.QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Enter Credentials")
        self.setGeometry(400, 200, 300, 150)

        layout = QtWidgets.QVBoxLayout()

        # Password Input
        self.password_label = QtWidgets.QLabel("Password:")
        layout.addWidget(self.password_label)
        self.password_input = QtWidgets.QLineEdit()
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        layout.addWidget(self.password_input)

        # Buttons
        self.buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

        self.setLayout(layout)

    def get_credentials(self):
        return self.password_input.text()


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    creator = BootIt()
    creator.show()
    sys.exit(app.exec_())
