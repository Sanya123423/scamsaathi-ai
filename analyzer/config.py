"""
ScamSaathi - Configurable Rules, Weights & Indicator Dictionaries
Supports English, Hindi (Devanagari), and Romanized Hindi (Hinglish).
"""

# Risk Severity Thresholds (0 to 100)
SEVERITY_THRESHOLDS = {
    'LOW': (0, 25),
    'MEDIUM': (26, 55),
    'HIGH': (56, 80),
    'CRITICAL': (81, 100)
}

# Individual Indicator Weights (Transparent Base Weights)
INDICATOR_WEIGHTS = {
    # Credential & Banking harvesting (High intrinsic risk)
    'CREDENTIAL_HARVESTING': 35,
    'OTP_OR_PIN_REQUEST': 40,
    
    # Financial coercion & Advance fee
    'ADVANCE_FEE_OR_DEPOSIT': 30,
    'UNREALISTIC_EARNINGS': 25,
    
    # Pressure & Urgency tactics
    'URGENCY_OR_DEADLINE': 20,
    'DISCONNECTION_OR_LEGAL_THREAT': 25,
    
    # Impersonation
    'IMPERSONATION_AUTHORITY': 25,
    'IMPERSONATION_BANK': 25,
    
    # Account verification & KYC coercion
    'KYC_OR_ACCOUNT_SUSPENSION': 30,
    
    # Suspicious link / URL structural forensics
    'SUSPICIOUS_IP_IN_URL': 35,
    'SUSPICIOUS_TLD': 25,
    'URL_SHORTENER_OR_REDIRECT': 15,
    'SPOOFED_BRAND_IN_DOMAIN': 30,
    'SUSPICIOUS_URL_SYNTAX': 20
}

# Compound Signal Multipliers (Detection of suspicious combinations)
COMPOUND_RULES = [
    {
        'name': 'URGENCY_PLUS_CREDENTIAL_THEFT',
        'requires': ['URGENCY_OR_DEADLINE', 'OTP_OR_PIN_REQUEST'],
        'boost': 20,
        'label': 'Compound Threat: Urgent deadline combined with OTP/Credential request'
    },
    {
        'name': 'DISCONNECTION_PLUS_IMPERSONATION',
        'requires': ['DISCONNECTION_OR_LEGAL_THREAT', 'IMPERSONATION_AUTHORITY'],
        'boost': 20,
        'label': 'Compound Threat: Authority impersonation threatening immediate service cutoff'
    },
    {
        'name': 'JOB_TASK_PLUS_ADVANCE_DEPOSIT',
        'requires': ['UNREALISTIC_EARNINGS', 'ADVANCE_FEE_OR_DEPOSIT'],
        'boost': 25,
        'label': 'Compound Threat: Remote task job promising high earnings requiring advance fee'
    },
    {
        'name': 'SUSPICIOUS_LINK_PLUS_KYC_SUSPENSION',
        'requires': ['KYC_OR_ACCOUNT_SUSPENSION', 'SUSPICIOUS_URL_PRESENT'],
        'boost': 25,
        'label': 'Compound Threat: Account suspension warning directing to unverified link'
    }
]

# Indicator Keyword & Pattern Dictionaries
# Contains English, Devanagari Hindi, and Romanized Hindi (Hinglish)
INDICATOR_DICTIONARIES = {
    'OTP_OR_PIN_REQUEST': {
        'id': 'OTP_OR_PIN_REQUEST',
        'category': 'Credential Theft',
        'title': 'Request for OTP, UPI PIN, or Password',
        'weight': INDICATOR_WEIGHTS['OTP_OR_PIN_REQUEST'],
        'explanation': 'Communication asks for a one-time password (OTP), UPI PIN, or account password. Legitimate organizations never request these credentials.',
        'patterns': [
            r'\b(share|send|enter|provide|verify)\b.{0,30}\b(otp|one[-\s]time\s*password|upi\s*pin|atm\s*pin|mpin|cvv|password)\b',
            r'\b(otp|upi\s*pin|atm\s*pin|cvv|password)\b.{0,30}\b(share|send|provide|submit|give)\b',
            r'\b(ओटीपी|पिन|पासवर्ड|सीवीवी)\b.{0,30}\b(भेजें|साझा|बताएं|दर्ज|दे)\b',
            r'\b(otp|pin|password)\b.{0,30}\b(bhejo|bhejein|batao|share|karein|do)\b',
            r'\b6[-\s]?digit\s*otp\b',
            r'\bshare\s*otp\b',
            r'\botp\s*share\b'
        ]
    },

    'CREDENTIAL_HARVESTING': {
        'id': 'CREDENTIAL_HARVESTING',
        'category': 'Credential Theft',
        'title': 'Sensitive Banking Credential Request',
        'weight': INDICATOR_WEIGHTS['CREDENTIAL_HARVESTING'],
        'explanation': 'Requesting sensitive banking credentials, NetBanking login details, card numbers, or CVV.',
        'patterns': [
            r'\b(netbanking|internet\s*banking|credit\s*card|debit\s*card)\b.{0,30}\b(login|credentials|details|number|expire)\b',
            r'\b(16[-\s]?digit\s*card|card\s*number|expiry\s*date|cvv\s*code)\b',
            r'\b(कार्ड\s*नंबर|नेटबैंकिंग|खाता\s*संख्या)\b.{0,30}\b(विवरण|दर्ज|सत्यापित)\b',
            r'\b(card\s*details|bank\s*details)\b.{0,30}\b(bhejo|bhejiye|submit)\b'
        ]
    },

    'ADVANCE_FEE_OR_DEPOSIT': {
        'id': 'ADVANCE_FEE_OR_DEPOSIT',
        'category': 'Job & Financial Fraud',
        'title': 'Advance Payment or Recruitment Deposit Request',
        'weight': INDICATOR_WEIGHTS['ADVANCE_FEE_OR_DEPOSIT'],
        'explanation': 'Requesting advance payment, security deposit, registration fee, or processing charge before receiving a job, prize, or service.',
        'patterns': [
            r'\b(registration\s*fee|security\s*deposit|processing\s*fee|advance\s*deposit|refundable\s*deposit|joining\s*fee)\b',
            r'\b(pay|deposit|transfer|send)\b.{0,30}(?:[₹\$]|\brs\.?|\binr)?\s*[0-9]+',
            r'\b(पंजीकरण\s*शुल्क|जमा\s*राशि|सुरक्षा\s*जमा|अग्रिम\s*भुगतान|फीस\s*जमा)\b',
            r'\b(registration\s*fees|advance\s*payment|deposit\s*karein|paise\s*bhejo)\b',
            r'\bpay\s*(?:[₹\$]|\brs\.?|\binr)?\s*[0-9]+\s*(first|advance|deposit|to\s*claim)?\b'
        ]
    },

    'UNREALISTIC_EARNINGS': {
        'id': 'UNREALISTIC_EARNINGS',
        'category': 'Job & Prize Scam',
        'title': 'Unrealistic Work-From-Home or Prize Claim',
        'weight': INDICATOR_WEIGHTS['UNREALISTIC_EARNINGS'],
        'explanation': 'Promises of high daily/hourly income for trivial tasks (e.g., liking YouTube videos, Telegram reviews) or unverified lottery prizes.',
        'patterns': [
            r'\b(earn|make|income)\b.{0,30}(?:[₹\$]|\brs\.?|\binr)?\s*[0-9]+[0-9,\.]*\b.{0,25}\b(daily|per\s*day|hourly|every\s*day)\b',
            r'\b(part[-\s]?time\s*job|work\s*from\s*home|remote\s*job)\b.{0,40}\b(earn|salary|daily|telegram)\b',
            r'\b(like\s*youtube\s*videos|subscribe\s*channels|hotel\s*review|google\s*review\s*task)\b',
            r'\b(won|selected\s*for)\b.{0,30}\b(lottery|lucky\s*draw|kbc|cash\s*prize|gift\s*card)\b',
            r'\b(घर\s*बैठे|रोजाना|प्रतिदिन)\b.{0,30}\b(कमाएं|रुपये|कमाई|लॉटरी|इनाम)\b',
            r'\b(ghar\s*baithe|roj\s*kamaye|daily\s*income|kbc\s*lottery|inaam)\b'
        ]
    },

    'URGENCY_OR_DEADLINE': {
        'id': 'URGENCY_OR_DEADLINE',
        'category': 'Psychological Coercion',
        'title': 'Urgency and Artificial Deadline Pressure',
        'weight': INDICATOR_WEIGHTS['URGENCY_OR_DEADLINE'],
        'explanation': 'Creating panic by imposing arbitrary short deadlines (e.g., "tonight", "within 2 hours") to force hasty action without thinking.',
        'patterns': [
            r'\b(immediately|urgent|urgently|within\s*[0-9]+\s*(hours?|mins?|minutes?)|tonight|by\s*tonight|at\s*9:?30\s*pm)\b',
            r'\b(act\s*now|last\s*chance|final\s*warning|immediate\s*action\s*required)\b',
            r'\b(तुरंत|तत्काल|आज\s*रात|अंतिम\s*चेतावनी|२\s*घंटे\s*के\s*भीतर)\b',
            r'\b(turant|aaj\s*raat|jaldi|last\s*warning|final\s*notice)\b'
        ]
    },

    'DISCONNECTION_OR_LEGAL_THREAT': {
        'id': 'DISCONNECTION_OR_LEGAL_THREAT',
        'category': 'Impersonation & Extortion',
        'title': 'Threat of Utility Cutoff or Legal Action',
        'weight': INDICATOR_WEIGHTS['DISCONNECTION_OR_LEGAL_THREAT'],
        'explanation': 'Threatening immediate electricity disconnection, SIM blocking, legal warrant, police arrest, or parcel seizure.',
        'patterns': [
            r'\b(power|electricity|bijli|connection)\b.{0,30}\b(disconnected|disconnect|cut[-\s]?off|suspended|stopped)\b',
            r'\b(sim\s*block|sim\s*deactivation|police\s*complaint|legal\s*action|arrest\s*warrant|customs\s*parcel\s*seized)\b',
            r'\b(बिजली\s*काट|कनेक्शन\s*काट|बिजली\s*बंद|सिम\s*ब्लॉक|कानूनी\s*कार्रवाई)\b',
            r'\b(bijli\s*kat\s*di\s*jayegi|power\s*cut|sim\s*band|police\s*case)\b'
        ]
    },

    'IMPERSONATION_AUTHORITY': {
        'id': 'IMPERSONATION_AUTHORITY',
        'category': 'Impersonation',
        'title': 'Authority or Official Personnel Impersonation',
        'weight': INDICATOR_WEIGHTS['IMPERSONATION_AUTHORITY'],
        'explanation': 'Impersonating official entities such as electricity board officers, police, customs officials, or courier executives.',
        'patterns': [
            r'\b(electricity\s*officer|discom\s*officer|customs\s*officer|police\s*officer|telecom\s*officer|cbi\s*officer)\b',
            r'\b(call\s*our\s*officer|contact\s*officer|helpline\s*officer)\b.{0,25}\b[0-9]{10}\b',
            r'\b(बिजली\s*अधिकारी|पुलिस\s*अधिकारी|शाखा\s*प्रबंधक|अधिकारी\s*से\s*संपर्क)\b',
            r'\b(bijli\s*adhikari|officer\s*ko\s*call\s*karein|contact\s*adhikari)\b'
        ]
    },

    'IMPERSONATION_BANK': {
        'id': 'IMPERSONATION_BANK',
        'category': 'Impersonation',
        'title': 'Financial Institution Impersonation',
        'weight': INDICATOR_WEIGHTS['IMPERSONATION_BANK'],
        'explanation': 'Impersonating well-known banks or financial services (e.g., SBI, HDFC, ICICI, PNB, Paytm) to trick the user.',
        'patterns': [
            r'\b(state\s*bank|sbi|hdfc|icici|axis\s*bank|pnb|paytm|phonepe|gpay)\b.{0,40}\b(account|netbanking|kyc|suspended|deactivated|blocked)\b',
            r'\b(एसबीआई|बैंक\s*खाता|नेटबैंकिंग|पेटीएम)\b.{0,30}\b(बंद|निलंबित|केवाईसी)\b',
            r'\b(bank\s*khata|khata\s*band|account\s*block)\b'
        ]
    },

    'KYC_OR_ACCOUNT_SUSPENSION': {
        'id': 'KYC_OR_ACCOUNT_SUSPENSION',
        'category': 'Phishing & Impersonation',
        'title': 'Account Suspension & Mandatory KYC Claim',
        'weight': INDICATOR_WEIGHTS['KYC_OR_ACCOUNT_SUSPENSION'],
        'explanation': 'False claim that an account, service, or card is suspended due to pending KYC, PAN verification, or profile update.',
        'patterns': [
            r'\b(account|netbanking|profile|service)\b.{0,30}\b(suspended|blocked|deactivated|on\s*hold|freeze)\b',
            r'\b(update|verify|complete|link)\b.{0,30}\b(kyc|pan\s*card|aadhaar|profile)\b',
            r'\b(केवाईसी\s*अपडेट|पैन\s*कार्ड\s*लिंक|खाता\s*सत्यापन|खाता\s*निलंबित)\b',
            r'\b(kyc\s*update\s*karein|pan\s*card\s*link|khata\s*unblock)\b'
        ]
    }
}
