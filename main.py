import sys
import os
import base64
import logging
import time
from email import message_from_bytes
from email.policy import default

from PyQt5.QtWidgets import (
    QApplication, QWidget, QPushButton, QFileDialog, QVBoxLayout, 
    QComboBox, QLabel, QMessageBox, QProgressBar, QHBoxLayout, QTextEdit, 
    QGroupBox, QGridLayout, QDialog, QListWidget, QListWidgetItem
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt, QThread, pyqtSignal

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request as GoogleRequest
from googleapiclient.discovery import build, Resource
from googleapiclient.errors import HttpError
from googleapiclient import discovery
from fpdf import FPDF
import pandas as pd

# Configure logging
logging.basicConfig(
    filename='gmail_backup.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.DEBUG
)

# Define OAuth 2.0 scopes
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Retrieve CLIENT_ID and CLIENT_SECRET from environment variables or hardcode them
CLIENT_ID = 'ENTER_CLIENT_ID_HERE'
CLIENT_SECRET = 'ENTER_CLIENT_SECRET_HERE'

if not CLIENT_ID or not CLIENT_SECRET:
    logging.critical("CLIENT_ID and CLIENT_SECRET must be set as environment variables.")
    raise EnvironmentError("CLIENT_ID and CLIENT_SECRET must be set as environment variables.")

# Directory to store tokens
TOKEN_DIR = os.path.join(os.path.expanduser("~"), ".gmail_backup_tokens")
os.makedirs(TOKEN_DIR, exist_ok=True)
TOKEN_PATH = os.path.join(TOKEN_DIR, 'token.json')

# Helper function for retries
def retry(max_retries=3, delay=5, backoff=2):
    def decorator_retry(func):
        def wrapper_retry(*args, **kwargs):
            m_retries, m_delay = max_retries, delay
            while m_retries > 1:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    logging.warning(f"Function {func.__name__} failed with {e}. Retrying in {m_delay} seconds...")
                    time.sleep(m_delay)
                    m_retries -= 1
                    m_delay *= backoff
            # Last attempt
            return func(*args, **kwargs)
        return wrapper_retry
    return decorator_retry

# Class for saving emails in different formats
class EmailSaver:
    def __init__(self, save_format, base_save_path):
        self.save_format = save_format
        self.base_save_path = base_save_path
        self.processed_emails = set()  # To avoid duplicates

    def save_as_txt(self, email_id, content, labels):
        for label in labels:
            folder_path = self.get_label_folder(label)
            file_path = os.path.join(folder_path, f"{email_id}.txt")
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)

    def save_as_eml(self, email_id, raw_email, labels):
        for label in labels:
            folder_path = self.get_label_folder(label)
            file_path = os.path.join(folder_path, f"{email_id}.eml")
            with open(file_path, 'wb') as f:
                f.write(raw_email)

    def save_as_csv(self, email_id, msg_data, labels):
        for label in labels:
            folder_path = self.get_label_folder(label)
            file_path = os.path.join(folder_path, f"{email_id}.csv")
            df = pd.DataFrame([{
                'ID': email_id,
                'Snippet': msg_data.get('snippet', ''),
                'From': self.extract_header(msg_data, 'From'),
                'Subject': self.extract_header(msg_data, 'Subject'),
                'Date': self.extract_header(msg_data, 'Date')
            }])
            df.to_csv(file_path, index=False)

    def save_as_pdf(self, email_id, content, labels):
        for label in labels:
            folder_path = self.get_label_folder(label)
            file_path = os.path.join(folder_path, f"{email_id}.pdf")
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)
            pdf.multi_cell(0, 10, content)
            pdf.output(file_path)

    def save_email(self, email_id, raw_email, msg_data, labels):
        if email_id in self.processed_emails:
            logging.info(f"Email ID {email_id} already processed. Skipping to avoid duplicates.")
            return
        try:
            if self.save_format == 'txt':
                content = msg_data.get('snippet', 'No Content')
                self.save_as_txt(email_id, content, labels)
            elif self.save_format == 'eml':
                self.save_as_eml(email_id, raw_email, labels)
            elif self.save_format == 'csv':
                self.save_as_csv(email_id, msg_data, labels)
            elif self.save_format == 'pdf':
                content = msg_data.get('snippet', 'No Content')
                self.save_as_pdf(email_id, content, labels)
            self.processed_emails.add(email_id)
            logging.debug(f"Email ID {email_id} saved successfully.")
        except Exception as e:
            logging.error(f"Failed to save email ID {email_id} as {self.save_format}: {str(e)}")
            raise e

    def extract_header(self, msg_data, header_name):
        headers = msg_data.get('payload', {}).get('headers', [])
        return next((header['value'] for header in headers if header['name'] == header_name), 'N/A')

    def get_label_folder(self, label):
        # Create a folder for the label if it doesn't exist
        safe_label = "".join([c if c.isalnum() or c in (' ', '_', '-') else "_" for c in label])
        folder_path = os.path.join(self.base_save_path, safe_label)
        os.makedirs(folder_path, exist_ok=True)
        return folder_path

# Thread class for fetching emails
class EmailFetcherThread(QThread):
    progress = pyqtSignal(int)
    preview = pyqtSignal(str, str)
    finished = pyqtSignal()
    error = pyqtSignal(str)
    current_label = pyqtSignal(str)

    def __init__(self, creds, save_format, save_path, selected_labels, batch_size=100):
        super().__init__()
        self.creds = creds
        self.save_format = save_format
        self.save_path = save_path
        self.selected_labels = selected_labels
        self.batch_size = batch_size  # Number of emails to fetch per batch
        self.rate_limit_delay = 0.1  # Delay between API requests in seconds

    @retry(max_retries=3, delay=5, backoff=2)
    def fetch_messages(self, service, label_id):
        messages = []
        request = service.users().messages().list(userId='me', labelIds=[label_id], maxResults=500)
        while request is not None:
            try:
                response = request.execute()
            except HttpError as e:
                logging.error(f"HTTP Error while fetching messages for label {label_id}: {e}")
                raise e
            messages.extend(response.get('messages', []))
            request = service.users().messages().list_next(request, response)
            time.sleep(self.rate_limit_delay)  # Rate limiting
        return messages

    @retry(max_retries=3, delay=5, backoff=2)
    def get_message_raw(self, service, message_id):
        msg = service.users().messages().get(userId='me', id=message_id, format='raw').execute()
        raw_email = base64.urlsafe_b64decode(msg['raw'].encode('ASCII'))
        return raw_email

    @retry(max_retries=3, delay=5, backoff=2)
    def get_message_metadata(self, service, message_id):
        msg_metadata = service.users().messages().get(
            userId='me',
            id=message_id,
            format='metadata',
            metadataHeaders=['From', 'Subject']
        ).execute()
        headers = msg_metadata.get('payload', {}).get('headers', [])
        sender = next((header['value'] for header in headers if header['name'] == 'From'), 'Unknown')
        subject = next((header['value'] for header in headers if header['name'] == 'Subject'), 'No Subject')
        email_labels = msg_metadata.get('labelIds', [])
        return sender, subject, email_labels

    def emit_progress(self, processed, total):
        percentage = int((processed / total) * 100)
        self.progress.emit(percentage)

    def get_label_id(self, service, label_name):
        try:
            labels_result = service.users().labels().list(userId='me').execute()
            labels = labels_result.get('labels', [])
            for label in labels:
                if label['name'] == label_name:
                    return label['id']
            return None
        except Exception as e:
            logging.error(f"Error retrieving label ID for '{label_name}': {str(e)}")
            return None

    def get_label_names(self, service, label_ids):
        try:
            labels_result = service.users().labels().list(userId='me').execute()
            labels = labels_result.get('labels', [])
            id_to_name = {label['id']: label['name'] for label in labels}
            return [id_to_name.get(lid, 'Unknown') for lid in label_ids]
        except Exception as e:
            logging.error(f"Error retrieving label names: {str(e)}")
            return ['Unknown']

    def run(self):
        try:
            service = build('gmail', 'v1', credentials=self.creds)
            logging.info("Gmail service built successfully.")

            email_saver = EmailSaver(self.save_format, self.save_path)

            # Fetch all labels (already selected by user)
            labels_to_process = self.selected_labels
            logging.info(f"Labels to process: {labels_to_process}")

            # Count total emails for progress tracking
            total_emails = 0
            label_email_counts = {}
            for label_name in labels_to_process:
                label_id = self.get_label_id(service, label_name)
                if not label_id:
                    logging.warning(f"Label '{label_name}' not found. Skipping.")
                    continue
                messages = self.fetch_messages(service, label_id)
                label_email_counts[label_name] = len(messages)
                total_emails += len(messages)
            logging.info(f"Total emails to fetch across selected labels: {total_emails}")

            if total_emails == 0:
                self.error.emit("No emails found to backup.")
                self.finished.emit()
                return

            processed_emails = 0

            for label_name in labels_to_process:
                label_id = self.get_label_id(service, label_name)
                if not label_id:
                    logging.warning(f"Label '{label_name}' not found. Skipping.")
                    continue
                self.current_label.emit(label_name)
                messages = self.fetch_messages(service, label_id)
                logging.info(f"Processing label '{label_name}' with {len(messages)} emails.")

                for message in messages:
                    try:
                        message_id = message['id']
                        if message_id in email_saver.processed_emails:
                            logging.debug(f"Email ID {message_id} already processed. Skipping.")
                            processed_emails += 1
                            self.emit_progress(processed_emails, total_emails)
                            continue

                        raw_email = self.get_message_raw(service, message_id)
                        sender, subject, email_labels_ids = self.get_message_metadata(service, message_id)

                        # Convert label IDs to label names
                        email_labels_names = self.get_label_names(service, email_labels_ids)

                        self.preview.emit(sender, subject)
                        email_saver.save_email(message_id, raw_email, {}, email_labels_names)
                        logging.info(f"Saved email ID: {message_id} from {sender} with subject: '{subject}'.")

                    except Exception as e:
                        error_msg = f"Error processing email ID {message_id} in label '{label_name}': {str(e)}"
                        logging.error(error_msg)
                        self.error.emit(error_msg)

                    processed_emails += 1
                    self.emit_progress(processed_emails, total_emails)
                    time.sleep(self.rate_limit_delay)  # Rate limiting

            self.finished.emit()
        except Exception as e:
            critical_msg = f"Failed to fetch emails: {str(e)}"
            logging.critical(critical_msg)
            self.error.emit(critical_msg)

# EML Viewer Dialog (No changes needed)
class EMLViewer(QDialog):
    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path
        self.initUI()

    def initUI(self):
        self.setWindowTitle('EML Viewer')
        self.setGeometry(300, 300, 800, 600)
        layout = QVBoxLayout()

        # Read EML file
        try:
            with open(self.file_path, 'rb') as f:
                raw_email = f.read()
            msg = message_from_bytes(raw_email, policy=default)
        except Exception as e:
            QMessageBox.critical(self, 'Error', f"Failed to read EML file: {str(e)}")
            logging.error(f"Failed to read EML file {self.file_path}: {str(e)}")
            self.close()
            return

        # Display headers
        headers = ['From', 'To', 'Subject', 'Date']
        for header in headers:
            value = msg[header] if msg[header] else 'N/A'
            header_label = QLabel(f"<b>{header}:</b> {value}")
            layout.addWidget(header_label)

        # Display body
        layout.addWidget(QLabel("<b>Body:</b>"))
        body_text = self.get_body(msg)
        self.body_edit = QTextEdit()
        self.body_edit.setReadOnly(True)
        self.body_edit.setHtml(body_text)  # Using HTML for better formatting
        layout.addWidget(self.body_edit)

        # Close button
        close_btn = QPushButton('Close', self)
        close_btn.clicked.connect(self.close)
        layout.addWidget(close_btn, alignment=Qt.AlignRight)

        self.setLayout(layout)

    def get_body(self, msg):
        # Prefer HTML content if available
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get('Content-Disposition'))
                if content_type == 'text/html' and 'attachment' not in content_disposition:
                    return part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='replace')
        else:
            content_type = msg.get_content_type()
            if content_type == 'text/html':
                return msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='replace')
            elif content_type == 'text/plain':
                return "<pre>" + msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='replace') + "</pre>"
        return "No readable content found."

# GUI Class
class GmailBackupApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.thread = None
        self.creds = None  # Initialize creds attribute

    def initUI(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #2E3440;
                color: #D8DEE9;
                font-family: Arial;
            }
            QPushButton {
                background-color: #4C566A;
                border: 2px solid #434C5E;
                border-radius: 5px;
                padding: 10px 20px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #434C5E;
            }
            QComboBox, QSpinBox {
                background-color: #3B4252;
                border: 1px solid #434C5E;
                padding: 5px;
                border-radius: 3px;
                font-size: 14px;
                color: #D8DEE9;
            }
            QLabel {
                font-size: 14px;
            }
            QProgressBar {
                border: 2px solid #434C5E;
                border-radius: 5px;
                text-align: center;
                height: 25px;
            }
            QProgressBar::chunk {
                background-color: #81A1C1;
                width: 20px;
            }
            QGroupBox {
                border: 2px solid #434C5E;
                border-radius: 5px;
                margin-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QTextEdit {
                background-color: #3B4252;
                color: #D8DEE9;
                border: 1px solid #434C5E;
                border-radius: 3px;
                padding: 5px;
                font-size: 14px;
            }
            QListWidget::item {
                padding: 5px;
            }
        """)

        main_layout = QVBoxLayout()

        # Backup Settings Group
        backup_group = QGroupBox("Backup Settings")
        backup_layout = QGridLayout()

        # Format selection
        format_label = QLabel("Select Format:")
        self.format_combo = QComboBox(self)
        self.format_combo.addItems(['txt', 'eml', 'csv', 'pdf'])
        backup_layout.addWidget(format_label, 0, 0)
        backup_layout.addWidget(self.format_combo, 0, 1)

        # Folder selection
        self.folder_btn = QPushButton('Select Save Folder', self)
        self.folder_btn.clicked.connect(self.select_folder)
        self.folder_label = QLabel("No folder selected")
        self.folder_label.setStyleSheet("color: #88C0D0;")
        backup_layout.addWidget(self.folder_btn, 1, 0)
        backup_layout.addWidget(self.folder_label, 1, 1)

        # Select Labels to Backup
        labels_label = QLabel("Select Labels to Backup:")
        self.labels_list = QListWidget(self)
        self.labels_list.setSelectionMode(QListWidget.MultiSelection)
        self.labels_list.setStyleSheet("QListWidget::item:selected { background: #5E81AC; }")
        backup_layout.addWidget(labels_label, 2, 0, 1, 2)
        backup_layout.addWidget(self.labels_list, 3, 0, 1, 2)

        # Authenticate Button
        self.auth_btn = QPushButton('Authenticate', self)
        self.auth_btn.clicked.connect(self.authenticate)
        backup_layout.addWidget(self.auth_btn, 4, 0, 1, 2)

        # Start Backup and EML Viewer buttons
        self.start_btn = QPushButton('Start Backup', self)
        self.start_btn.clicked.connect(self.start_backup)
        self.eml_viewer_btn = QPushButton('Open EML Viewer', self)
        self.eml_viewer_btn.clicked.connect(self.open_eml_viewer)
        self.start_btn.setEnabled(False)  # Disabled until authentication and label selection
        self.eml_viewer_btn.setEnabled(True)
        backup_layout.addWidget(self.start_btn, 5, 0)
        backup_layout.addWidget(self.eml_viewer_btn, 5, 1)

        backup_group.setLayout(backup_layout)
        main_layout.addWidget(backup_group)

        # Progress Bar
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setValue(0)
        main_layout.addWidget(self.progress_bar)

        # Detailed Progress Labels
        progress_details_group = QGroupBox("Progress Details")
        progress_details_layout = QVBoxLayout()
        self.current_label_label = QLabel("Current Label: N/A")
        self.emails_processed_label = QLabel("Emails Processed: 0%")
        progress_details_layout.addWidget(self.current_label_label)
        progress_details_layout.addWidget(self.emails_processed_label)
        progress_details_group.setLayout(progress_details_layout)
        main_layout.addWidget(progress_details_group)

        self.setLayout(main_layout)
        self.setWindowTitle('Gmail Backup Tool')
        self.setGeometry(200, 200, 700, 800)

    def select_folder(self):
        try:
            self.save_path = QFileDialog.getExistingDirectory(self, 'Select Folder')
            if not self.save_path:
                QMessageBox.warning(self, 'Error', 'No folder selected.')
                logging.warning("No folder selected by the user.")
            else:
                self.folder_label.setText(self.save_path)
                logging.info(f"Folder selected: {self.save_path}")
                # Enable start button only if labels are selected
                self.check_start_button_status()
        except Exception as e:
            QMessageBox.critical(self, 'Error', f"Failed to select folder: {str(e)}")
            logging.error(f"Failed to select folder: {str(e)}")

    def authenticate(self):
        try:
            # Initiate OAuth flow
            flow = InstalledAppFlow.from_client_config(
                {
                    "installed": {
                        "client_id": CLIENT_ID,
                        "client_secret": CLIENT_SECRET,
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                        "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob", "http://localhost"]
                    }
                },
                SCOPES
            )
            self.creds = flow.run_local_server(port=0)
            service = build('gmail', 'v1', credentials=self.creds)
            logging.info("Authenticated successfully.")
            QMessageBox.information(self, 'Authenticated', 'Authentication successful!')
            # Fetch labels and populate the labels list
            self.fetch_labels(service)
            # Enable the start button if labels are selected and folder is selected
            self.check_start_button_status()
            self.start_btn.setEnabled(True)
        except Exception as e:
            QMessageBox.critical(self, 'Error', f"Authentication failed: {str(e)}")
            logging.error(f"Authentication failed: {str(e)}")

    def fetch_labels(self, service):
        try:
            request = service.users().labels().list(userId='me')
            labels = []
            while request is not None:
                response = request.execute()
                labels.extend(response.get('labels', []))
                if 'nextPageToken' in response:
                    request = service.users().labels().list(userId='me', pageToken=response['nextPageToken'])
                else:
                    request = None
            logging.info(f"Fetched {len(labels)} labels.")

            # Populate the labels list with checkboxes
            self.labels_list.clear()
            for label in labels:
                item = QListWidgetItem(label['name'])
                item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                item.setCheckState(Qt.Unchecked)
                self.labels_list.addItem(item)
        except AttributeError as e:
            logging.error(f"Failed to fetch labels due to AttributeError: {str(e)}")
            QMessageBox.critical(self, 'Error', f"Failed to fetch labels: {str(e)}")
        except Exception as e:
            logging.error(f"Failed to fetch labels: {str(e)}")
            QMessageBox.critical(self, 'Error', f"Failed to fetch labels: {str(e)}")

    def check_start_button_status(self):
        if hasattr(self, 'save_path') and self.save_path:
            selected_labels = self.get_selected_labels()
            if selected_labels:
                self.start_btn.setEnabled(True)
            else:
                self.start_btn.setEnabled(False)
        else:
            self.start_btn.setEnabled(False)

    def get_selected_labels(self):
        selected_labels = []
        for index in range(self.labels_list.count()):
            item = self.labels_list.item(index)
            if item.checkState() == Qt.Checked:
                selected_labels.append(item.text())
        return selected_labels

    def start_backup(self):
        selected_labels = self.get_selected_labels()
        if not selected_labels:
            QMessageBox.warning(self, 'Error', 'Please select at least one label to backup.')
            logging.warning("Start backup clicked without selecting any labels.")
            return
        save_format = self.format_combo.currentText()
        self.execute_backup(selected_labels, save_format)

    def execute_backup(self, selected_labels, save_format):
        try:
            if not self.creds or not self.creds.valid:
                QMessageBox.warning(self, 'Error', 'Please authenticate first.')
                logging.warning("Start Backup clicked without valid credentials.")
                return
            self.thread = EmailFetcherThread(self.creds, save_format, self.save_path, selected_labels)
            self.thread.progress.connect(self.update_progress)
            self.thread.preview.connect(self.update_preview)
            self.thread.finished.connect(self.on_finished)
            self.thread.error.connect(self.on_error)
            self.thread.current_label.connect(self.update_current_label)
            self.thread.start()
            self.start_btn.setEnabled(False)
            self.eml_viewer_btn.setEnabled(False)
            logging.info("Email fetching thread started.")
        except Exception as e:
            QMessageBox.critical(self, 'Error', f"Failed to start fetching emails: {str(e)}")
            logging.error(f"Failed to start fetching emails: {str(e)}")

    def update_progress(self, value):
        self.progress_bar.setValue(value)
        self.emails_processed_label.setText(f"Emails Processed: {value}%")

    def update_preview(self, sender, subject):
        # Optional: Implement live preview if needed
        pass  # Can be used to show recent emails being processed

    def update_current_label(self, label_name):
        self.current_label_label.setText(f"Current Label: {label_name}")

    def on_finished(self):
        QMessageBox.information(self, 'Done', f"Emails saved successfully in {self.save_path}.")
        self.progress_bar.setValue(100)
        self.current_label_label.setText("Current Label: N/A")
        self.emails_processed_label.setText("Emails Processed: 0%")
        self.start_btn.setEnabled(True)
        self.eml_viewer_btn.setEnabled(True)
        logging.info("Email fetching completed successfully.")

    def on_error(self, message):
        QMessageBox.warning(self, 'Error', message)
        logging.warning(message)

    def get_credentials(self):
        try:
            creds = None
            if os.path.exists(TOKEN_PATH):
                creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)
                logging.info("Loaded credentials from token.json")
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(GoogleRequest())
                    logging.info("Refreshed expired credentials.")
                else:
                    # Define the client configuration directly
                    client_config = {
                        "installed": {
                            "client_id": CLIENT_ID,
                            "client_secret": CLIENT_SECRET,
                            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                            "token_uri": "https://oauth2.googleapis.com/token",
                            "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob", "http://localhost"]
                        }
                    }
                    flow = InstalledAppFlow.from_client_config(client_config, SCOPES)
                    creds = flow.run_local_server(port=0)
                    logging.info("Obtained new credentials via OAuth flow.")
                # Save the credentials for the next run
                with open(TOKEN_PATH, 'w') as token:
                    token.write(creds.to_json())
                    logging.info("Saved new credentials to token.json")
            return creds
        except Exception as e:
            logging.critical(f"Failed to get credentials: {str(e)}")
            raise e

    def open_eml_viewer(self):
        try:
            file_path, _ = QFileDialog.getOpenFileName(self, "Open EML File", "", "EML Files (*.eml)")
            if file_path:
                viewer = EMLViewer(file_path)
                viewer.exec_()
                logging.info(f"Opened EML file: {file_path}")
        except Exception as e:
            QMessageBox.critical(self, 'Error', f"Failed to open EML viewer: {str(e)}")
            logging.error(f"Failed to open EML viewer: {str(e)}")

# Main entry point
def main():
    app = QApplication(sys.argv)
    ex = GmailBackupApp()
    ex.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
