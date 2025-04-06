from flask import Flask, render_template, request, session
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
import re

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this to a secure secret key

# Initialize the analyzer engine
analyzer = AnalyzerEngine()

# Dictionary to convert word numbers to digits
number_words = {
    'zero': '0', 'one': '1', 'two': '2', 'three': '3', 'four': '4',
    'five': '5', 'six': '6', 'seven': '7', 'eight': '8', 'nine': '9',
    'oh': '0', 'o': '0', 'null': '0', 'cero': '0', 'sero': '0',
    'i': '1', 'l': '1', '1': '1', 'I': '1', 'L': '1',  # Common replacements for '1'
    # Spanish numbers
    'uno': '1', 'dos': '2', 'tres': '3', 'cuatro': '4', 'cinco': '5',
    'seis': '6', 'siete': '7', 'ocho': '8', 'nueve': '9'
}

# Marketplace-specific context words
marketplace_context = {
    # Contact-related
    'contact', 'reach', 'call', 'text', 'message', 'phone', 'number',
    'email', 'mail', 'inbox', 'dm', 'direct message', 'pm', 'private message',
    # Transaction-related
    'payment', 'pay', 'transfer', 'send', 'receive', 'money', 'cash',
    'price', 'cost', 'fee', 'charge', 'transaction', 'deal', 'offer',
    # Location-related
    'pickup', 'delivery', 'dropoff', 'location', 'address', 'meet',
    'meeting', 'arrange', 'arrangement', 'schedule', 'time', 'date',
    # Verification-related
    'verify', 'confirm', 'check', 'validate', 'authenticate', 'prove',
    # Marketplace-specific
    'listing', 'item', 'product', 'service', 'shipping', 'delivery',
    'buyer', 'seller', 'vendor', 'customer', 'client', 'user',
    # Additional contact patterns
    'reach out', 'get in touch', 'connect', 'communicate', 'message me',
    'text me', 'call me', 'my number', 'my phone', 'my contact',
    'contact info', 'contact details', 'reach me', 'get hold of me'
}

# Add masking configuration
def get_masking_config():
    """Get the current masking configuration"""
    if 'mask_pii' not in session:
        session['mask_pii'] = True
    return session['mask_pii']

def mask_phone_number(number):
    """Mask a phone number while keeping the last 4 digits visible"""
    if len(number) > 4:
        return "***-***-" + number[-4:]
    return "****"

def mask_email(email):
    """Mask an email address while keeping domain visible"""
    if '@' in email:
        username, domain = email.split('@')
        if len(username) > 2:
            masked_username = username[:2] + '*' * (len(username) - 2)
        else:
            masked_username = '*' * len(username)
        return f"{masked_username}@{domain}"
    
    # Handle cases where email is constructed without @
    parts = email.split()
    if len(parts) >= 3:  # Assuming format like "user gmail com"
        username = parts[0]
        domain = parts[1]
        tld = parts[2]
        if len(username) > 2:
            masked_username = username[:2] + '*' * (len(username) - 2)
        else:
            masked_username = '*' * len(username)
        return f"{masked_username}@{domain}.{tld}"
    
    return "****@****.***"

def has_marketplace_context(text):
    """Check if the text contains context suggesting marketplace activity"""
    text_lower = text.lower()
    
    # Check for context words
    words = set(text_lower.split())
    if any(context in words for context in marketplace_context):
        return True
    
    # Check for context phrases
    if any(phrase in text_lower for phrase in marketplace_context):
        return True
    
    # Check for common marketplace patterns
    patterns = [
        r'\b(?:how much|price|cost|fee|charge)\b',
        r'\b(?:where|location|address|meet)\b',
        r'\b(?:when|schedule|time|date)\b',
        r'\b(?:how to|contact|reach|message)\b',
        r'\b(?:payment|transfer|send|receive)\b',
        r'\b(?:my number|my phone|my contact)\b',
        r'\b(?:reach out|get in touch|connect)\b',
        r'\b(?:message me|text me|call me)\b'
    ]
    
    return any(re.search(pattern, text_lower) for pattern in patterns)

def normalize_phone_number(text):
    """Convert a string of numbers and words to a potential phone number"""
    # First convert word numbers to digits
    text = text.replace('(', '').replace(')', '').replace('-', '').replace(' ', '')
    
    # Convert the entire string to lowercase for consistent processing
    text = text.lower()
    
    # Replace common letter/number substitutions
    text = text.replace('o', '0').replace('O', '0')
    text = text.replace('i', '1').replace('I', '1').replace('l', '1').replace('L', '1')
    
    # If the text is already all digits, return it
    if text.isdigit():
        return text
    
    # Process the text character by character
    result = ''
    current_word = ''
    
    for char in text:
        if char.isalpha():
            current_word += char
            # Check if we have a complete number word
            if current_word.lower() in number_words:
                result += number_words[current_word.lower()]
                current_word = ''
        elif char.isdigit():
            # If we have a partial word, check if it's a number word
            if current_word and current_word.lower() in number_words:
                result += number_words[current_word.lower()]
            current_word = ''
            result += char
    
    # Handle any remaining word
    if current_word and current_word.lower() in number_words:
        result += number_words[current_word.lower()]
    
    return result

def is_valid_phone_number(number_str):
    """Check if a string of numbers could be a phone number"""
    # Remove all non-digits
    digits = ''.join(filter(str.isdigit, number_str))
    
    # Check for common phone number patterns
    if len(digits) >= 10 and len(digits) <= 11:
        # Check if it starts with a valid area code
        if digits.startswith(('1', '2', '3', '4', '5', '6', '7', '8', '9')):
            return True
        # Check if it's a valid international format
        if digits.startswith('1') and len(digits) == 11:
            return True
        # Check for common area code patterns
        if len(digits) == 10 and digits[:3] in ['800', '888', '877', '866', '855', '844', '833', '822', '811']:
            return True
        # Check for common US area codes
        if len(digits) == 10:
            return True
    return False

def detect_phone_numbers(text):
    """Detect phone numbers in text including obfuscated ones"""
    # Split text into potential number groups
    words = text.split()
    number_groups = []
    current_group = []
    
    for word in words:
        # If the word contains any digits or number words
        if any(char.isdigit() for char in word) or word.lower() in number_words or word.lower() in ['o', 'i', 'l']:
            current_group.append(word)
        else:
            if current_group:
                number_groups.append(' '.join(current_group))
                current_group = []
    
    # Add the last group if exists
    if current_group:
        number_groups.append(' '.join(current_group))
    
    # Process each group
    valid_numbers = []
    for group in number_groups:
        normalized = normalize_phone_number(group)
        if is_valid_phone_number(normalized):
            valid_numbers.append(normalized)
    
    return valid_numbers

def detect_email(text):
    """Detect email addresses including obfuscated ones"""
    # Common replacements for @ and .
    at_chars = ['@', 'at', 'set', 'fii set', 'fii', '[at]', '(at)', '[@]', '(@)', ' at ', ' set ', ' fii ']
    dot_chars = ['.', 'dot', '[dot]', '(dot)', '[.]', '(.)', ' dot ', ' d0t ', ' d0t']
    
    # Common email domains in marketplace context
    marketplace_domains = {
        'gmail', 'yahoo', 'hotmail', 'outlook', 'icloud', 'protonmail',
        'aol', 'msn', 'live', 'me', 'iCloud', 'Gmail', 'Yahoo', 'Hotmail'
    }
    
    # Convert text to lowercase and split into words
    words = text.lower().split()
    
    # First try: Look for email patterns with @ symbol
    for i in range(len(words) - 2):  # Need at least 3 parts: user @ domain
        # Check if middle word is an @ symbol replacement
        if words[i+1] in at_chars:
            # Check if next part contains a dot replacement
            remaining_text = ' '.join(words[i+2:])
            for dot in dot_chars:
                if dot in remaining_text:
                    # Found potential email pattern
                    return True, f"{words[i]}@{remaining_text.replace(dot, '.')}"
    
    # Second try: Look for domain patterns without @ symbol
    for i in range(len(words) - 1):
        # Check if current word is a common email domain
        if words[i] in marketplace_domains:
            # Look for dot replacement in remaining text
            remaining_text = ' '.join(words[i+1:])
            for dot in dot_chars:
                if dot in remaining_text:
                    # Found potential email pattern
                    username = ' '.join(words[:i])
                    return True, f"{username}@{words[i]}{remaining_text.replace(dot, '.')}"
    
    # Third try: Look for common email patterns without @ or dot
    for i in range(len(words)):
        if words[i] in marketplace_domains:
            # Check if next word is 'com' or similar
            if i + 1 < len(words) and words[i+1] in ['com', 'net', 'org', 'edu', 'gov']:
                username = ' '.join(words[:i])
                return True, f"{username}@{words[i]}.{words[i+1]}"
    
    return False, None

def preprocess_message(message):
    """Preprocess message to detect potential contact information"""
    # Detect phone numbers
    phone_numbers = detect_phone_numbers(message)
    
    # Check for emails
    has_email, email = detect_email(message)
    
    return phone_numbers, has_email, email

@app.route('/toggle_masking', methods=['POST'])
def toggle_masking():
    """Toggle the PII masking setting"""
    session['mask_pii'] = not get_masking_config()
    return {'status': 'success', 'masking_enabled': session['mask_pii']}

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'messages' not in session:
        session['messages'] = []
    
    if request.method == 'POST':
        message = request.form.get('message', '')
        if message:
            # Preprocess message
            phone_numbers, has_email, email = preprocess_message(message)
            
            # Process results
            pii_details = []
            
            # Get masking configuration
            should_mask = get_masking_config()
            
            # Add detected phone numbers
            for phone in phone_numbers:
                display_number = mask_phone_number(phone) if should_mask else phone
                pii_details.append({
                    'type': 'PHONE_NUMBER',
                    'text': phone,
                    'display_text': display_number,
                    'score': 0.85
                })
            
            # Add detected email
            if has_email and email:  # Make sure email is not None
                display_email = mask_email(email) if should_mask else email
                pii_details.append({
                    'type': 'EMAIL_ADDRESS',
                    'text': email,
                    'display_text': display_email,
                    'score': 0.85
                })
            
            # Add message to chat history
            session['messages'].append({
                'text': message,
                'pii_detected': len(pii_details) > 0,
                'pii_details': pii_details,
                'masking_enabled': should_mask
            })
            session.modified = True
    
    return render_template('index.html', messages=session['messages'], masking_enabled=get_masking_config())

if __name__ == '__main__':
    app.run(debug=True) 