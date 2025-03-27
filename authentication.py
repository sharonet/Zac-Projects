import re
import smtplib
import pyotp
import bcrypt
import os
from cryptography.fernet import Fernet
from email.message import EmailMessage
from email_validator import validate_email, EmailNotValidError

# --- Global Variables ---
ENCRYPTION_KEY = Fernet.generate_key()  # Key for encryption & decryption
cipher = Fernet(ENCRYPTION_KEY)
SECRET_OTP_KEY = pyotp.random_base32()  # Secret key for OTP generation
THRESH_HOLD = 3

# --- Input Validation ---
class InputValidator:
    """Class for validating and sanitizing user inputs."""

    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate if the email format is correct."""
        try:
            validate_email(email, check_deliverability=False)
            return True
        except EmailNotValidError:
            return False

    @staticmethod
    def validate_password(password: str) -> bool:
        """
        Validate password strength:
        - At least 8 characters
        - Contains one uppercase letter, one lowercase letter, one digit, and one special character.
        """
        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        return bool(re.match(pattern, password))

    @staticmethod
    def sanitize_input(user_input: str) -> str:
        """Sanitize input to prevent SQL injection attacks."""
        return re.sub(r"[;\'\"\\]", "", user_input.strip())


# --- Secure Password Handling ---
class PasswordManager:
    """Class for securely hashing and verifying passwords."""

    @staticmethod
    def hash_password(password: str) -> bytes:
        """Hash a password using bcrypt."""
        try:
            salt = bcrypt.gensalt()
            return bcrypt.hashpw(password.encode(), salt)
        except Exception as e:
            print(f"❌ Error hashing password: {e}")
            return None

    @staticmethod
    def verify_password(password: str, hashed_password: bytes) -> bool:
        """Verify if a password matches the stored hash."""
        return bcrypt.checkpw(password.encode(), hashed_password)


# --- OTP Handling ---
class OTPService:
    """Class for handling OTP generation and verification."""

    def __init__(self, user_email: str):
        self.secret = SECRET_OTP_KEY
        self.user_email = user_email

    def generate_otp(self) -> str:
        """Generate a time-based OTP valid for 60 seconds."""
        totp = pyotp.TOTP(self.secret, interval=60)
        return totp.now()

    def verify_otp(self, user_input: str) -> bool:
        """Verify if the provided OTP is correct."""
        totp = pyotp.TOTP(self.secret, interval=60)
        return totp.verify(user_input)

    def send_otp_email(self, otp: str) -> bool:
        """Send OTP to the user's email."""
        sender_email = ""  # Input the sender's email
        sender_password = ""  # Input the sender's email password

        msg = EmailMessage()
        msg.set_content(f"Your OTP for authentication is: {otp}")
        msg["Subject"] = "Your OTP Code"
        msg["From"] = sender_email
        msg["To"] = self.user_email

        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(sender_email, sender_password)
                server.send_message(msg)
            print(f"✅ OTP sent successfully to {self.user_email}")
            return True
        except Exception as e:
            print(f"❌ Error sending email: {e}")
            return False


# --- Encryption & Decryption ---
class SecureFileManager:
    """Class for encrypting and decrypting files."""

    @staticmethod
    def encrypt_file(data: str, filename: str):
        """Encrypt and save data to a file."""
        encrypted_data = cipher.encrypt(data.encode())
        with open(filename, "wb") as file:
            file.write(encrypted_data)

    @staticmethod
    def decrypt_file(filename: str):
        """Decrypt and read data from a file."""
        if not os.path.exists(filename):
            return "❌ Error: Encrypted file not found."

        try:
            with open(filename, "rb") as file:
                encrypted_data = file.read()
            return cipher.decrypt(encrypted_data).decode()
        except Exception as e:
            return f"❌ Error decrypting file: {e}"


# --- Main Authentication Workflow ---
def main():

    """Main function to handle user authentication and secure file access."""

    attempts = 0
    while attempts < THRESH_HOLD:
        # Get user input
        email = input("Enter your email: ")
        password = input("Enter your password: ")

        # Validate email and password
        email = InputValidator.sanitize_input(email)
        password = InputValidator.sanitize_input(password)

        try:
            if not InputValidator.validate_email(email):
                print("❌ Invalid email format.")
                return

            if not InputValidator.validate_password(password):
                print("❌ Password must be at least 8 characters long and include uppercase, lowercase, digit, and special character.")
                return
        except Exception as e:
            print(f"❌ Unexpected validation error: {e}")
            return

        # Hash the password (in real-world, save this in a secure database)
        hashed_password = PasswordManager.hash_password(password)
        if not hashed_password:
            print("❌ Password hashing failed.")
            return

        print("✅ Email and password validated successfully!")

        # Send OTP for authentication
        otp_service = OTPService(email)
        otp = otp_service.generate_otp()

        if not otp_service.send_otp_email(otp):
            print("❌ OTP sending failed. Authentication aborted.")
            return

        # Verify OTP
        user_otp = input("Enter the OTP sent to your email: ")
        if otp_service.verify_otp(user_otp):
            print("✅ Authentication successful!")

            # Encrypt and save a file (example)
            SecureFileManager.encrypt_file("This is a secret file content.", "secret_file.enc")
            print("✅ Secret file has been encrypted!")

            # Read and decrypt the file after successful authentication
            decrypted_data = SecureFileManager.decrypt_file("secret_file.enc")
            print(f"🔓 Decrypted File Content: {decrypted_data}")
            break

        else:
            print("❌ Incorrect OTP. Authentication failed!")
            attempts += 1
    if attempts == THRESH_HOLD:    
        print("❌ Too many failed attempts. Access denied!")

# Run the program
if __name__ == "__main__":
    main()
