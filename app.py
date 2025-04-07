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

# Add detection for international prefixes
country_codes = {
    '+1': 'US/Canada', '+44': 'UK', '+33': 'France', '+49': 'Germany',
    '+61': 'Australia', '+86': 'China', '+91': 'India', '+52': 'Mexico',
    '+55': 'Brazil', '+81': 'Japan', '+82': 'South Korea', '+7': 'Russia',
    '+34': 'Spain', '+39': 'Italy', '+31': 'Netherlands', '+46': 'Sweden',
    '+41': 'Switzerland', '+64': 'New Zealand', '+65': 'Singapore', '+66': 'Thailand',
    '+971': 'UAE', '+972': 'Israel', '+30': 'Greece', '+27': 'South Africa'
}

# Add text obfuscation tricks people might use
obfuscation_patterns = {
    'email': ['mail', 'em ail', 'e mail', 'e-m-a-i-l', 'electronic mail', 'inbox'],
    'phone': ['ph', 'tel', 'cell', 'mobile', 'telephone', 'celphone', 'celfone'],
    'contact': ['c0ntact', 'c0n tact', 'con tact', 'cntct', 'hit me up', 'hmu', 'ping me']
}

# Add common ways to separate numbers or evade detection
separator_chars = [' ', '.', '-', '_', '|', '/', '\\', ':', ';', ',', '*', '+', '(', ')', '[', ']', '{', '}']

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
    # Convert the entire string to lowercase for consistent processing
    text = text.lower()
    
    # First handle simple replacements
    text = text.replace('(', '').replace(')', '').replace('-', '')
    
    # Replace common letter/number substitutions directly
    text = text.replace('o', '0').replace('O', '0')
    text = text.replace('i', '1').replace('I', '1').replace('l', '1').replace('L', '1')
    
    # Split into words
    words = text.split()
    result = ''
    
    # Process each word
    for word in words:
        # Case 1: Word is already a digit
        if word.isdigit():
            result += word
            continue
            
        # Case 2: Word is a number word
        if word in number_words:
            result += number_words[word]
            continue
            
        # Case 3: Word contains digits mixed with letters
        has_digits = any(char.isdigit() for char in word)
        if has_digits:
            # Extract digits
            result += ''.join(char for char in word if char.isdigit())
            continue
            
        # Case 4: Try to match word to number_words even with fuzzy matching
        closest_match = None
        for num_word in number_words:
            if num_word in word or word in num_word:
                closest_match = num_word
                break
                
        if closest_match:
            result += number_words[closest_match]
            continue
    
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
    # First try to detect a complete phone number in the entire text
    full_text_normalized = normalize_phone_number(text)
    if is_valid_phone_number(full_text_normalized):
        return [full_text_normalized]
    
    # Try with different word groupings
    words = text.split()
    all_numbers = []
    
    # Try looking at consecutive groups of words
    for i in range(len(words)):
        for j in range(i+1, min(i+10, len(words)+1)):  # Look at groups of up to 10 words
            group = ' '.join(words[i:j])
            normalized = normalize_phone_number(group)
            if is_valid_phone_number(normalized) and normalized not in all_numbers:
                all_numbers.append(normalized)
    
    return all_numbers

def detect_partial_phone_numbers(text):
    """Detect potential partial phone numbers"""
    # Get numbers and digit sequences
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
    partial_numbers = []
    for group in number_groups:
        normalized = normalize_phone_number(group)
        # Consider sequences of at least 3 digits as potential partial numbers
        if len(normalized) >= 3 and normalized.isdigit() and not is_valid_phone_number(normalized):
            partial_numbers.append(normalized)
    
    return partial_numbers

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

def detect_partial_email(text):
    """Detect potential partial email elements"""
    # Common email domains and TLDs
    email_domains = {
        'gmail', 'yahoo', 'hotmail', 'outlook', 'icloud', 'protonmail',
        'aol', 'msn', 'live', 'me'
    }
    
    email_tlds = {'com', 'net', 'org', 'edu', 'gov', 'io', 'co'}
    
    # Convert text to lowercase and split into words
    words = text.lower().split()
    
    partial_elements = []
    
    # Look for domain names
    for word in words:
        if word in email_domains:
            partial_elements.append({"type": "domain", "text": word})
        elif word in email_tlds:
            partial_elements.append({"type": "tld", "text": word})
        elif '@' in word:
            partial_elements.append({"type": "at_symbol", "text": word})
        elif word in ['at', 'dot']:
            partial_elements.append({"type": "separator", "text": word})
    
    # Check for potential usernames (words that are not common words)
    common_words = set(['the', 'a', 'an', 'and', 'or', 'but', 'if', 'of', 'on', 'in', 'to', 'for', 'with', 'by'])
    for word in words:
        if word not in common_words and len(word) >= 3 and word.isalnum():
            if all(char.isalpha() or char.isdigit() for char in word):
                if word not in email_domains and word not in email_tlds:
                    partial_elements.append({"type": "potential_username", "text": word})
    
    return partial_elements

def detect_vertical_numbers(text):
    """Detect phone numbers that are written vertically (one digit per line)"""
    lines = text.split('\n')
    if len(lines) < 7:  # Need at least 7 lines for a partial phone number
        return []
    
    # Check for vertical digits pattern
    vertical_digits = ''
    for line in lines:
        line = line.strip()
        # Check if the line contains a single number or number word
        if line.isdigit() and len(line) == 1:
            vertical_digits += line
        elif line.lower() in number_words:
            vertical_digits += number_words[line.lower()]
        elif line.lower() in ['o', 'oh']:
            vertical_digits += '0'
        elif line.lower() in ['i', 'l']:
            vertical_digits += '1'
    
    # Check if the vertical text forms a valid phone number
    if len(vertical_digits) >= 7 and is_valid_phone_number(vertical_digits):
        return [vertical_digits]
    
    return []

def detect_international_formats(text):
    """Detect international phone number formats"""
    patterns = [
        # +XX format (international)
        r'\+\d{1,3}[\s\.\-]?\d{1,3}[\s\.\-]?\d{3,4}[\s\.\-]?\d{3,4}',
        # (0XX) format (European)
        r'\(0\d{1,2}\)[\s\.\-]?\d{3,4}[\s\.\-]?\d{3,4}',
        # 00XX format (international dial out)
        r'00\d{1,3}[\s\.\-]?\d{3,4}[\s\.\-]?\d{3,4}'
    ]
    
    found_numbers = []
    for pattern in patterns:
        matches = re.findall(pattern, text)
        for match in matches:
            # Clean up the number
            cleaned = ''.join(filter(lambda x: x.isdigit() or x == '+', match))
            if is_valid_phone_number(cleaned.replace('+', '')):
                found_numbers.append(cleaned)
    
    return found_numbers

def detect_ascii_art_numbers(text):
    """Detect numbers hidden in ASCII art patterns"""
    # Convert common ASCII art digits to numbers
    ascii_art_map = {
        # Example: zero/0
        "ooo\no o\no o\nooo": "0",
        " o \n/ \\\n  |\n  o": "1",
        "___\n  /\n /\n___": "2",
        "___\n__/\n  \\\n___": "3",
        "|_|\n  |\n  |\n  |": "4",
        "___\n|__\n  |\n__/": "5",
        "___\n|__\n| |\n|_|": "6",
        "___\n  /\n /\n/": "7",
        "___\n(_)\n(_)\n(_)": "8",
        "___\n(_)\n  |\n__/": "9"
    }
    
    # Look for potential ASCII art patterns
    lines = text.split('\n')
    potential_digits = []
    
    # Check for 4-line digit patterns
    for i in range(len(lines) - 3):
        for j in range(len(lines[i])):
            # Try to extract a 3x4 block (common ASCII art digit size)
            if j + 3 <= len(lines[i]):
                block = "\n".join([
                    lines[i][j:j+3],
                    lines[i+1][j:j+3],
                    lines[i+2][j:j+3],
                    lines[i+3][j:j+3] if i+3 < len(lines) and j+3 <= len(lines[i+3]) else ""
                ])
                
                # Check if this block matches any known ASCII digit
                for pattern, digit in ascii_art_map.items():
                    # Simple pattern matching (could be improved with fuzzy matching)
                    if block.replace(" ", "") == pattern.replace(" ", ""):
                        potential_digits.append(digit)
    
    # If we found enough digits that could form a phone number
    if len(potential_digits) >= 7:
        number = "".join(potential_digits)
        if is_valid_phone_number(number):
            return [number]
    
    return []

def detect_social_media_handles(text):
    """Detect social media handles that might be used for contact"""
    # Common social media handle patterns
    patterns = [
        r'(?:^|\s)@\w+',  # Twitter/Instagram handle
        r'(?:^|\s)fb\.me/\w+',  # Facebook short URL
        r'(?:^|\s)instagram\.com/[\w\.]+',  # Instagram URL
        r'(?:^|\s)t\.me/\w+',  # Telegram
        r'(?:^|\s)wa\.me/\d+',  # WhatsApp
        r'(?:^|\s)discord(?:\.gg|app\.com/users)/[\w]+',  # Discord
        r'(?:^|\s)signal\.me/#p/\w+',  # Signal
        r'(?:^|\s)linkedin\.com/in/[\w\-]+',  # LinkedIn
        r'(?:^|\s)snapchat\.com/add/\w+',  # Snapchat
        r'(?:^|\s)tiktok\.com/@[\w\.]+',  # TikTok
        r'(?:^|\s)\w+#\d{4}'  # Discord username with discriminator
    ]
    
    handles = []
    for pattern in patterns:
        matches = re.findall(pattern, text.lower())
        handles.extend(matches)
    
    return handles

def detect_leetspeak_numbers(text):
    """Detect phone numbers written in leetspeak (e.g., 5!x 0n3 f0ur)"""
    # Leetspeak mapping
    leetspeak_map = {
        '0': ['0', 'o', 'O', '()', '[]', '{}', '<>', 'oh', 'zero'],
        '1': ['1', 'i', 'I', 'l', 'L', '|', '!', 'one'],
        '2': ['2', 'z', 'Z', 'to', 'too', 'two'],
        '3': ['3', 'e', 'E', 'three'],
        '4': ['4', 'a', 'A', 'four', 'for', '4or'],
        '5': ['5', 's', 'S', 'five'],
        '6': ['6', 'G', 'b', 'six'],
        '7': ['7', 'T', 't', 'seven'],
        '8': ['8', 'B', 'eight', 'ate'],
        '9': ['9', 'g', 'nine']
    }
    
    # First normalize common leetspeak
    words = text.lower().split()
    normalized_words = []
    
    for word in words:
        # Try to convert leetspeak to normal digits
        for digit, variants in leetspeak_map.items():
            for variant in variants:
                word = word.replace(variant, digit)
        normalized_words.append(word)
    
    # Join and check for phone numbers
    normalized_text = ' '.join(normalized_words)
    return detect_phone_numbers(normalized_text)

def detect_caesar_cipher(text):
    """Detect numbers hidden with simple caesar ciphers"""
    # Try common ROT values
    potential_numbers = []
    
    for rot in [1, 2, 3, 4, 5, 13, 25]:
        decoded = ""
        for char in text:
            if char.isalpha():
                ascii_offset = ord('a') if char.islower() else ord('A')
                shifted = (ord(char) - ascii_offset + rot) % 26 + ascii_offset
                decoded += chr(shifted)
            else:
                decoded += char
        
        # Check if the decoded text contains phone numbers
        found_numbers = detect_phone_numbers(decoded)
        potential_numbers.extend(found_numbers)
    
    return potential_numbers

def detect_code_patterns(text):
    """Detect contact info hidden in code-like patterns"""
    # Check for hex/binary/octal patterns that might decode to numbers
    patterns = [
        r'0x[0-9a-fA-F]+',  # Hex
        r'0b[01]+',         # Binary 
        r'0o[0-7]+',        # Octal
        r'\\u[0-9a-fA-F]{4}', # Unicode
        r'\\x[0-9a-fA-F]{2}', # Hex escape
        r'&#\d+;'           # HTML entity
    ]
    
    potential_numbers = []
    
    for pattern in patterns:
        matches = re.findall(pattern, text)
        for match in matches:
            try:
                # Try to convert to integer based on pattern
                if match.startswith('0x'):
                    value = int(match, 16)
                elif match.startswith('0b'):
                    value = int(match, 2)
                elif match.startswith('0o'):
                    value = int(match, 8)
                elif match.startswith('\\u'):
                    value = int(match[2:], 16)
                elif match.startswith('\\x'):
                    value = int(match[2:], 16)
                elif match.startswith('&#'):
                    value = int(match[2:-1])
                
                # Convert to string and check if it could be a phone number
                str_value = str(value)
                if len(str_value) >= 7 and is_valid_phone_number(str_value):
                    potential_numbers.append(str_value)
            except:
                continue
    
    return potential_numbers

def detect_spacing_tricks(text):
    """Detect when spaces or special characters are used to obfuscate numbers"""
    # Remove various separators that might be inserted between digits
    cleaned_text = text
    for sep in separator_chars:
        cleaned_text = cleaned_text.replace(sep, '')
    
    # Check for runs of digits in the cleaned text
    digit_runs = re.findall(r'\d{7,}', cleaned_text)
    
    valid_numbers = []
    for run in digit_runs:
        if is_valid_phone_number(run):
            valid_numbers.append(run)
    
    return valid_numbers

def detect_reverse_numbers(text):
    """Detect numbers written in reverse"""
    # Look for sequences that might be reverse phone numbers
    words = text.split()
    potential_reverses = []
    
    for word in words:
        # Check if word could be a reversed phone number
        cleaned = ''.join(filter(str.isdigit, word))
        if len(cleaned) >= 7:
            reversed_num = cleaned[::-1]  # Reverse the string
            if is_valid_phone_number(reversed_num):
                potential_reverses.append(reversed_num)
    
    return potential_reverses

def detect_first_last_chars(text):
    """Detect when first/last chars of lines form a number"""
    lines = text.split('\n')
    if len(lines) < 7:  # Need at least 7 lines for a partial phone number
        return []
    
    # Get first characters of each line
    first_chars = ''.join([line[0] if line else '' for line in lines])
    last_chars = ''.join([line[-1] if line else '' for line in lines])
    
    potential_numbers = []
    
    # Check first characters
    first_digits = ''.join(filter(str.isdigit, first_chars))
    if len(first_digits) >= 7 and is_valid_phone_number(first_digits):
        potential_numbers.append(first_digits)
    
    # Check last characters
    last_digits = ''.join(filter(str.isdigit, last_chars))
    if len(last_digits) >= 7 and is_valid_phone_number(last_digits):
        potential_numbers.append(last_digits)
    
    return potential_numbers

def preprocess_message(message):
    """Preprocess message to detect potential contact information"""
    # Original detection methods
    phone_numbers, partial_numbers, has_email, email, partial_email_elements = detect_basic_patterns(message)
    
    # Add new detection methods
    # 1. Vertical numbers
    phone_numbers.extend(detect_vertical_numbers(message))
    
    # 2. International formats
    phone_numbers.extend(detect_international_formats(message))
    
    # 3. ASCII art numbers
    phone_numbers.extend(detect_ascii_art_numbers(message))
    
    # 4. Social media handles
    social_handles = detect_social_media_handles(message)
    # Store social handles as partial email elements
    for handle in social_handles:
        partial_email_elements.append({"type": "social_handle", "text": handle.strip()})
    
    # 5. Leetspeak numbers
    phone_numbers.extend(detect_leetspeak_numbers(message))
    
    # 6. Caesar cipher
    phone_numbers.extend(detect_caesar_cipher(message))
    
    # 7. Code patterns
    phone_numbers.extend(detect_code_patterns(message))
    
    # 8. Spacing tricks
    phone_numbers.extend(detect_spacing_tricks(message))
    
    # 9. Reverse numbers
    phone_numbers.extend(detect_reverse_numbers(message))
    
    # 10. First/last chars of lines
    phone_numbers.extend(detect_first_last_chars(message))
    
    # Remove duplicates
    unique_phone_numbers = list(set(phone_numbers))
    
    return unique_phone_numbers, partial_numbers, has_email, email, partial_email_elements

def detect_basic_patterns(message):
    """Original pattern detection functionality"""
    # Detect phone numbers
    phone_numbers = detect_phone_numbers(message)
    
    # Detect partial phone numbers
    partial_numbers = detect_partial_phone_numbers(message)
    
    # Check for emails
    has_email, email = detect_email(message)
    
    # Detect partial email elements
    partial_email_elements = detect_partial_email(message)
    
    return phone_numbers, partial_numbers, has_email, email, partial_email_elements

def check_cross_message_pii(current_message, message_history, max_history=3):
    """Check for PII spread across multiple messages with enhanced detection"""
    if not message_history or len(message_history) == 0:
        return [], False, None
    
    # Get partial elements from current message
    current_numbers, partial_numbers, _, _, partial_email_elements = preprocess_message(current_message)
    
    cross_message_pii = []
    
    # Only check the last N messages for performance
    recent_history = message_history[-max_history:] if len(message_history) > max_history else message_history
    
    # Convert recent history to text messages only
    recent_messages = [msg.get('text', '') for msg in recent_history]
    
    # STEP 1: First try to detect a complete number by joining ALL messages
    # This handles split numbers like "9o3 seven O 3 eight 88" + "5"
    combined_text = ' '.join(recent_messages + [current_message])
    combined_phone_numbers = detect_phone_numbers(combined_text)
    
    # Also check for vertical patterns across messages
    stacked_text = '\n'.join(recent_messages + [current_message])
    vertical_numbers = detect_vertical_numbers(stacked_text)
    combined_phone_numbers.extend(vertical_numbers)
    
    # Check for first/last character patterns across messages
    first_last_numbers = detect_first_last_chars(stacked_text)
    combined_phone_numbers.extend(first_last_numbers)
    
    # Get all previously detected numbers
    individual_numbers = []
    for msg in recent_history:
        pii_details = msg.get('pii_details', [])
        for detail in pii_details:
            if detail.get('type') == 'PHONE_NUMBER':
                individual_numbers.append(detail.get('text'))
    
    # Add current message detected numbers
    individual_numbers.extend(current_numbers)
    
    # Find numbers in combined text that weren't in individual messages
    for number in combined_phone_numbers:
        if number not in individual_numbers:
            cross_message_pii.append({
                'type': 'PHONE_NUMBER',
                'text': number,
                'display_text': mask_phone_number(number) if get_masking_config() else number,
                'score': 0.9,
                'is_cross_message': True
            })
    
    # STEP 2: Try to detect contact info by combining partial patterns
    # This handles cases like "903" + "7038" + "885"
    
    # Get partial numbers from previous messages
    all_partials = []
    for msg in recent_history:
        partial_info = msg.get('partial_info', {})
        parts = partial_info.get('partial_numbers', [])
        all_partials.extend(parts)
    
    # Add partial numbers from current message
    all_partials.extend(partial_numbers)
    
    # Try various combinations of partial numbers
    for i in range(len(all_partials)):
        current_partial = all_partials[i]
        
        # Try combining with other partials
        for j in range(len(all_partials)):
            if i != j:  # Don't combine with self
                combined = current_partial + all_partials[j]
                if is_valid_phone_number(combined) and combined not in individual_numbers:
                    cross_message_pii.append({
                        'type': 'PHONE_NUMBER',
                        'text': combined,
                        'display_text': mask_phone_number(combined) if get_masking_config() else combined,
                        'score': 0.9,
                        'is_cross_message': True
                    })
                
                # Try adding a third partial
                for k in range(len(all_partials)):
                    if k != i and k != j:  # Different from the other two
                        three_combined = current_partial + all_partials[j] + all_partials[k]
                        if is_valid_phone_number(three_combined) and three_combined not in individual_numbers:
                            cross_message_pii.append({
                                'type': 'PHONE_NUMBER',
                                'text': three_combined,
                                'display_text': mask_phone_number(three_combined) if get_masking_config() else three_combined,
                                'score': 0.9,
                                'is_cross_message': True
                            })
    
    # STEP 3: Handle special case of appending a single digit to an otherwise complete number
    # This handles cases like "90370388" + "5"
    
    # Get all detected numbers from previous messages that might be almost complete
    for msg in recent_history:
        pii_details = msg.get('pii_details', [])
        for detail in pii_details:
            if detail.get('type') == 'PHONE_NUMBER':
                prev_number = detail.get('text', '')
                
                # If previous number was 9 digits and current message contains a single digit
                if len(prev_number) == 9 and current_message.strip().isdigit() and len(current_message.strip()) == 1:
                    combined = prev_number + current_message.strip()
                    if is_valid_phone_number(combined) and combined not in individual_numbers:
                        cross_message_pii.append({
                            'type': 'PHONE_NUMBER',
                            'text': combined,
                            'display_text': mask_phone_number(combined) if get_masking_config() else combined,
                            'score': 0.95,
                            'is_cross_message': True
                        })
                
                # Try appending any numbers in the current message
                for word in current_message.split():
                    if word.isdigit() and len(word) <= 2:  # 1 or 2 digits
                        combined = prev_number + word
                        if is_valid_phone_number(combined) and combined not in individual_numbers:
                            cross_message_pii.append({
                                'type': 'PHONE_NUMBER',
                                'text': combined,
                                'display_text': mask_phone_number(combined) if get_masking_config() else combined,
                                'score': 0.95,
                                'is_cross_message': True
                            })
    
    # STEP 4: Check for social media handles across messages
    all_social_handles = []
    for msg in recent_history:
        partial_info = msg.get('partial_info', {})
        elements = partial_info.get('partial_email_elements', [])
        for element in elements:
            if element.get('type') == 'social_handle':
                all_social_handles.append(element.get('text'))
    
    # Add current message social handles
    for element in partial_email_elements:
        if element.get('type') == 'social_handle':
            all_social_handles.append(element.get('text'))
    
    # If we have social handles, add them as PII
    for handle in all_social_handles:
        cross_message_pii.append({
            'type': 'SOCIAL_MEDIA',
            'text': handle,
            'display_text': mask_email(handle) if get_masking_config() else handle,
            'score': 0.9,
            'is_cross_message': True
        })
    
    # STEP 5: Check for email addresses spread across messages
    has_cross_email = False
    cross_email = None
    
    # Look for domain + TLD combinations
    domain_msgs = {}
    tld_msgs = {}
    username_msgs = {}
    
    # Map email components to messages
    for i, msg in enumerate(recent_messages + [current_message]):
        _, _, _, _, partial_elements = preprocess_message(msg)
        
        for element in partial_elements:
            if element.get('type') == 'domain':
                domain_msgs[element.get('text')] = i
            elif element.get('type') == 'tld':
                tld_msgs[element.get('text')] = i
            elif element.get('type') == 'potential_username':
                username_msgs[element.get('text')] = i
    
    # Check if we have username, domain, and TLD in different messages
    for username, u_idx in username_msgs.items():
        for domain, d_idx in domain_msgs.items():
            for tld, t_idx in tld_msgs.items():
                # Check if they're in different messages
                if len({u_idx, d_idx, t_idx}) > 1:
                    reconstructed_email = f"{username}@{domain}.{tld}"
                    has_cross_email = True
                    cross_email = reconstructed_email
                    cross_message_pii.append({
                        'type': 'EMAIL_ADDRESS',
                        'text': reconstructed_email,
                        'display_text': mask_email(reconstructed_email) if get_masking_config() else reconstructed_email,
                        'score': 0.9,
                        'is_cross_message': True
                    })
    
    # Deduplicate results
    unique_pii = []
    seen_texts = set()
    for item in cross_message_pii:
        if item['text'] not in seen_texts:
            seen_texts.add(item['text'])
            unique_pii.append(item)
    
    return unique_pii, has_cross_email, cross_email

@app.route('/toggle_masking', methods=['POST'])
def toggle_masking():
    """Toggle the PII masking setting"""
    session['mask_pii'] = not get_masking_config()
    return {'status': 'success', 'masking_enabled': session['mask_pii']}

@app.route('/clear_chat', methods=['POST'])
def clear_chat():
    """Clear the chat history"""
    if 'messages' in session:
        session['messages'] = []
        session.modified = True
    return {'status': 'success'}

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'messages' not in session:
        session['messages'] = []
    
    if request.method == 'POST':
        message = request.form.get('message', '')
        if message:
            # Preprocess message
            phone_numbers, partial_numbers, has_email, email, partial_email_elements = preprocess_message(message)
            
            # Check for cross-message PII
            cross_message_pii, has_cross_email, cross_email = check_cross_message_pii(message, session['messages'])
            
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
            
            # Add cross-message PII
            pii_details.extend(cross_message_pii)
            
            # Store partial information for future reference (not displayed to user)
            partial_info = {
                'partial_numbers': partial_numbers,
                'partial_email_elements': partial_email_elements
            }
            
            # Add message to chat history
            session['messages'].append({
                'text': message,
                'pii_detected': len(pii_details) > 0,
                'pii_details': pii_details,
                'partial_info': partial_info,
                'masking_enabled': should_mask
            })
            session.modified = True
    
    return render_template('index.html', messages=session['messages'], masking_enabled=get_masking_config())

if __name__ == '__main__':
    app.run(debug=True) 