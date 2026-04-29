import re
import math
import hashlib
import sqlite3
import random
import string

# -------------------------------
# Common weak passwords list
# -------------------------------
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty",
    "abc123", "password123", "admin", "letmein"
}

# -------------------------------
# DATABASE SETUP
# -------------------------------
def init_db():
    """
    Initializes the SQLite database.
    Creates a table if it does not already exist.
    """
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS password_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        password_hash TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()


# -------------------------------
# HASH FUNCTION
# -------------------------------
def hash_password(password):
    """
    Converts password into a secure SHA-256 hash.
    """
    return hashlib.sha256(password.encode()).hexdigest()


# -------------------------------
# CHECK PASSWORD REUSE
# -------------------------------
def is_password_reused(password):
    """
    Checks if the password already exists in the database.
    """
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()

    hashed = hash_password(password)

    cursor.execute(
        "SELECT * FROM password_history WHERE password_hash = ?",
        (hashed,)
    )

    result = cursor.fetchone()
    conn.close()

    return result is not None


# -------------------------------
# SAVE PASSWORD
# -------------------------------
def save_password(password):
    """
    Stores hashed password in the database.
    """
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()

    hashed = hash_password(password)

    cursor.execute(
        "INSERT INTO password_history (password_hash) VALUES (?)",
        (hashed,)
    )

    conn.commit()
    conn.close()


# -------------------------------
# ENTROPY CALCULATION
# -------------------------------
def calculate_entropy(password):
    """
    Calculates password entropy based on character variety.
    """
    charset = 0

    if re.search(r"[a-z]", password):
        charset += 26
    if re.search(r"[A-Z]", password):
        charset += 26
    if re.search(r"[0-9]", password):
        charset += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        charset += 32

    if charset == 0:
        return 0

    entropy = len(password) * math.log2(charset)
    return round(entropy, 2)


# -------------------------------
# PASSWORD ANALYSIS
# -------------------------------
def analyze_password(password):
    """
    Evaluates password strength based on:
    length, complexity, and entropy.
    """
    score = 0
    feedback = []

    # Length check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Password is too short (minimum 8 characters).")

    # Complexity checks
    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add lowercase letters.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add uppercase letters.")

    if re.search(r"[0-9]", password):
        score += 1
    else:
        feedback.append("Add numbers.")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("Add special characters.")

    # Common password check
    if password.lower() in COMMON_PASSWORDS:
        feedback.append("This is a commonly used password. Avoid it.")
        score = 0

    # Entropy
    entropy = calculate_entropy(password)

    # Strength classification
    if score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Moderate"
    else:
        strength = "Strong"

    return strength, entropy, feedback


# -------------------------------
# PASSWORD SUGGESTION
# -------------------------------
def suggest_password():
    """
    Generates a strong random password.
    """
    characters = (
        string.ascii_letters +
        string.digits +
        "!@#$%^&*()"
    )
    return ''.join(random.choice(characters) for _ in range(14))


# -------------------------------
# MAIN PROGRAM
# -------------------------------
def main():
    print("\n🔐 Password Strength Analyzer (With Database)\n")

    # Initialize database
    init_db()

    password = input("Enter your password: ")

    # Check reuse
    if is_password_reused(password):
        print("\n⚠️ This password has already been used. Please choose a new one.")
        return

    # Analyze password
    strength, entropy, feedback = analyze_password(password)

    print("\n--- Analysis Result ---")
    print(f"Strength: {strength}")
    print(f"Entropy: {entropy} bits")

    # Show suggestions
    if feedback:
        print("\nSuggestions to improve:")
        for item in feedback:
            print(f"- {item}")

    # Suggest stronger password if needed
    if strength != "Strong":
        print("\n💡 Suggested Strong Password:")
        print(suggest_password())

    # Save password securely
    save_password(password)
    print("\n✅ Password stored securely (hashed in database).")


# -------------------------------
# RUN PROGRAM
# -------------------------------
if __name__ == "__main__":
    main()
