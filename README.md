# PII Detection Chat Application

This is a Flask-based chat application that uses Microsoft Presidio to detect Personally Identifiable Information (PII) in messages, including obfuscated forms of emails and phone numbers.

## Features

- Real-time PII detection in chat messages
- Detection of standard and obfuscated email addresses
- Detection of standard and obfuscated phone numbers
- Modern, responsive user interface
- Message history with PII detection results

## Setup Instructions

1. Create a Python virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate
```

2. Install the required packages:
```bash
pip install -r requirements.txt
```

3. Download the required spaCy model:
```bash
python -m spacy download en_core_web_lg
```

4. Run the application:
```bash
python app.py
```

5. Open your web browser and navigate to `http://localhost:5000`

## Testing the Application

You can test the PII detection with various types of messages:

1. Standard email: "My email is user@example.com"
2. Obfuscated email: "Contact me at user at example dot com"
3. Standard phone: "Call me at 123-456-7890"
4. Obfuscated phone: "My number is 3o7-one-7"

## Security Note

The application uses Flask's session for storing messages. In a production environment, you should:
1. Change the `secret_key` in `app.py` to a secure value
2. Implement proper user authentication
3. Use a secure database instead of session storage
4. Enable HTTPS

## License

This project is open source and available under the MIT License. 