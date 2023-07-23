import sys
from PySide6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QLineEdit, QPushButton, QLabel
from PySide6.QtCore import Qt, QEvent
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import textwrap

class SimpleGUI(QMainWindow):
    def __init__(self):
        super().__init__()

        # Create the main widget and set it as the central widget
        main_widget = QWidget(self)
        self.setCentralWidget(main_widget)

        # Create the layout for the main widget with increased spacing
        layout = QVBoxLayout(main_widget)
        layout.setSpacing(20)

        # Create the text entry widget with increased font size
        self.entry = QLineEdit(self)
        font = self.entry.font()
        font.setPointSize(16)
        self.entry.setFont(font)
        layout.addWidget(self.entry)

        # Create the button with a modern style
        self.button = QPushButton("Encrypt", self)
        font = self.button.font()
        font.setPointSize(16)
        self.button.setFont(font)
        self.button.setStyleSheet(
            "QPushButton { background-color: #4CAF50; color: white; border: 2px solid #4CAF50; border-radius: 8px; padding: 10px; }"
            "QPushButton:hover { background-color: #45a049; }"
            "QPushButton:pressed { background-color: #3e8e41; }"
        )
        self.button.clicked.connect(self.on_button_clicked)
        layout.addWidget(self.button)

        # Create the decrypt button with the same style as the encrypt button
        self.decrypt_button = QPushButton("Decrypt", self)
        self.decrypt_button.setFont(font)
        self.decrypt_button.setStyleSheet(
            "QPushButton { background-color: #f44336; color: white; border: 2px solid #f44336; border-radius: 8px; padding: 10px; }"
            "QPushButton:hover { background-color: #d32f2f; }"
            "QPushButton:pressed { background-color: #c62828; }"
        )
        self.decrypt_button.clicked.connect(self.on_decrypt_button_clicked)
        layout.addWidget(self.decrypt_button)

        # Create the label for displaying the text with increased font size and padding
        self.result_label = QLabel(self)
        font = self.result_label.font()
        font.setPointSize(18)
        self.result_label.setFont(font)
        self.result_label.setStyleSheet("QLabel { padding: 10px; }")
        self.result_label.setWordWrap(True)  # Enable text wrapping
        self.result_label.setFixedWidth(360)  # Set a fixed width for the label
        layout.addWidget(self.result_label, 0, alignment=Qt.AlignmentFlag.AlignTop)

        # Set the layout for the main widget
        main_widget.setLayout(layout)

        # Store the RSA key pair
        self.key = RSA.generate(2048)  # 2048-bit key size, you can choose a different key size if needed
        
    def on_button_clicked(self):
        # Get the text from the entry widget
        entered_text = self.entry.text()

        # Convert the entered_text to bytes (for encryption)
        plaintext = entered_text.encode('utf-8')

        # Encrypt the data using the public key
        cipher = PKCS1_OAEP.new(self.key.publickey())
        ciphertext = cipher.encrypt(plaintext)

        # For demonstration purposes, convert the ciphertext to a string (you may choose different representations)
        encrypted_text = ciphertext.hex()

        # Update the label text with the encrypted result
        wrapped_text = "Encrypted: " + textwrap.fill(encrypted_text, width=self.result_label.width() - 20)
        self.result_label.setText(wrapped_text)

    def on_decrypt_button_clicked(self):
        # Check if there is any encrypted text
        if not self.result_label.text().startswith("Encrypted:"):
            self.result_label.setText("Nothing to decrypt")
            return
        
        # Get the encrypted text from the label
        encrypted_text = self.result_label.text().replace("Encrypted: ", "")

        # Convert the encrypted text to bytes (for decryption)
        ciphertext = bytes.fromhex(encrypted_text)

        # Decrypt the data using the private key
        cipher = PKCS1_OAEP.new(self.key)
        plaintext = cipher.decrypt(ciphertext).decode('utf-8')

        # Update the label text with the decrypted result
        wrapped_text = "Decrypted: " + textwrap.fill(plaintext, width=self.result_label.width() - 20)
        self.result_label.setText(wrapped_text)



if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SimpleGUI()
    window.setWindowTitle("Simple GUI with PySide6")
    window.setGeometry(100, 100, 1280, 720)  # Set a larger initial window size (width=400, height=200)
    window.show()
    sys.exit(app.exec())
