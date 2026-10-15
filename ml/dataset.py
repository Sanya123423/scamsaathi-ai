"""
ScamSaathi - Seed Dataset for Machine Learning Classifier
Contains balanced, clearly labeled legitimate (ham) and suspicious (scam/phishing) messages
across English and Hindi domains.
"""

SEED_DATASET = [
    # =========================================================================
    # SUSPICIOUS / SCAM SAMPLES (Class 1)
    # =========================================================================
    # 1. Electricity & Utility Cutoff
    {"text": "Dear customer your electricity power will be disconnected at 9:30 PM tonight due to unpaid bill. Immediately contact our electricity officer at 9876543210.", "label": "suspicious"},
    {"text": "Urgent: Bijli bill not paid. Power will be disconnected tonight by 9 PM. Call discom officer immediately at 9123456789.", "label": "suspicious"},
    {"text": "प्रिय ग्राहक, आपका बिजली बिल बकाया है। आज रात 9:30 बजे बिजली काट दी जाएगी। तुरंत अधिकारी से संपर्क करें 9876543210.", "label": "suspicious"},
    {"text": "Bijli bill update: Your power connection will be cut off tonight at 9:30 PM. Call our executive now to clear dues.", "label": "suspicious"},
    {"text": "Discom alert: Final notice for unpaid power bill. Power will be suspended tonight. Pay now on http://bijli-bill-pay.xyz/update", "label": "suspicious"},
    
    # 2. Part-Time / Work-from-Home Job Fraud
    {"text": "Congratulations! You have been selected for part-time remote job. Earn ₹3000 to ₹8000 daily by simply subscribing YouTube channels. Contact manager on Telegram https://t.me/hr_officer.", "label": "suspicious"},
    {"text": "Work from home opportunity: Earn 5000 rs daily by liking Google maps reviews. Pay 500 registration deposit to activate account.", "label": "suspicious"},
    {"text": "घर बैठे ₹4000 से ₹8000 रोज़ कमाएं। सिर्फ यूट्यूब वीडियो लाइक करें। टेलीग्राम पर संपर्क करें और 500 रुपये सिक्योरिटी डिपॉजिट जमा करें।", "label": "suspicious"},
    {"text": "Hiring remote workers: Earn 3000 daily with simple typing tasks. Joining fee 300 rs refundable. Message on WhatsApp 9876543210.", "label": "suspicious"},
    {"text": "Urgent recruitment: Amazon part time work from home. Earn ₹5000 daily. Pay 999 registration fee to receive task bundle.", "label": "suspicious"},
    
    # 3. Banking KYC & Account Suspension Phishing
    {"text": "Dear SBI Customer, your NetBanking account has been suspended due to pending PAN card verification. Submit 6-digit OTP to verify.", "label": "suspicious"},
    {"text": "Your HDFC bank account is blocked today. Click link http://192.168.1.1/hdfc-kyc to update Aadhaar and avoid permanent closure.", "label": "suspicious"},
    {"text": "प्रिय एसबीआई ग्राहक, आपका बैंक खाता केवाईसी लंबित होने के कारण बंद कर दिया गया है। तुरंत अपना ओटीपी और पासवर्ड साझा करें।", "label": "suspicious"},
    {"text": "State Bank alert: Your ATM debit card has expired. Provide your 16 digit card number, CVV and OTP to renew immediately.", "label": "suspicious"},
    {"text": "ICICI Bank: Important notice! Your account is on hold due to missing KYC. Verify credentials on http://icici-verify-login.xyz now.", "label": "suspicious"},
    
    # 4. Lottery, Prize & Gift Card Scams
    {"text": "Congratulations! You have won ₹25,00,000 in KBC lottery lucky draw. Transfer ₹2500 processing charge to claim your cash.", "label": "suspicious"},
    {"text": "You are selected for ₹50,000 Flipkart festive gift voucher. Pay ₹499 delivery fee to redeem reward immediately.", "label": "suspicious"},
    {"text": "बधाई हो! आपने कौन बनेगा करोड़पति में 25 लाख रुपये की लॉटरी जीती है। अपनी इनाम राशि पाने के लिए 1500 रुपये रजिस्ट्रेशन शुल्क जमा करें।", "label": "suspicious"},
    {"text": "Lucky winner! Your mobile number won 1st prize in lucky draw. Claim your BMW car by calling lottery officer at 9811223344.", "label": "suspicious"},
    
    # 5. Police, Customs & Extortion Scams
    {"text": "Customs Department Notice: A parcel containing contraband in your name has been seized. Call police officer immediately to avoid arrest.", "label": "suspicious"},
    {"text": "Delhi Police Cyber Cell: An arrest warrant has been issued against your Aadhaar for illegal transactions. Contact inspector now.", "label": "suspicious"},
    {"text": "FedEx courier: Your international shipment has been held by Mumbai customs. Transfer ₹12,500 clearance penalty to release parcel.", "label": "suspicious"},
    {"text": "Telecom Department: Your mobile SIM card will be permanently blocked in 2 hours due to police complaint. Call 9876543210.", "label": "suspicious"},
    
    # 6. Credential Harvesting & Unauthorized Links
    {"text": "Urgent security alert: Unauthorized login attempt detected on your email. Click http://login-verify-account.xyz to change password.", "label": "suspicious"},
    {"text": "Dear user, your Netflix subscription expired. Update credit card details and CVV immediately to continue watching.", "label": "suspicious"},
    {"text": "Paytm KYC incomplete: Your wallet is blocked. Share your 6 digit UPI PIN with support executive to reactivate.", "label": "suspicious"},
    {"text": "Income Tax Department: Tax refund of ₹15,480 approved. Submit bank account number, login password and OTP to claim refund.", "label": "suspicious"},
    {"text": "Immediate action required: Power disconnection scheduled tonight. Pay your bill now at http://103.21.244.1/discom.", "label": "suspicious"},
    {"text": "Loan approval: Pre-approved personal loan of ₹5,00,000 without collateral. Pay processing fee of ₹1,200 to disburse funds.", "label": "suspicious"},
    {"text": "WhatsApp Gold update: Download official WhatsApp Gold APK now for exclusive features at http://download-wa-gold.xyz/wa.apk.", "label": "suspicious"},

    # =========================================================================
    # LEGITIMATE / HAM SAMPLES (Class 0)
    # =========================================================================
    # 1. E-Commerce & Parcel Deliveries
    {"text": "Your Amazon order #402-8921 has been shipped via BlueDart with tracking ID A128938. Expected delivery by tomorrow 6 PM.", "label": "legitimate"},
    {"text": "Flipkart Update: Your package has been out for delivery with our delivery executive. Please collect at your address.", "label": "legitimate"},
    {"text": "Your order has been delivered successfully. Thank you for shopping with Myntra. Rate your experience in our app.", "label": "legitimate"},
    {"text": "Zomato: Your food order from Biryani House has been picked up by delivery partner Ramesh and is arriving in 20 mins.", "label": "legitimate"},
    {"text": "Swiggy update: Delivery partner is at your location. Please collect your order.", "label": "legitimate"},
    
    # 2. Genuine Banking Alerts (Informational, standard format)
    {"text": "INR 2500.00 debited from your account **4321 on 14-Oct-26 at ATM HDFC. Available balance is INR 14,230.50.", "label": "legitimate"},
    {"text": "Your salary of INR 65,000 has been credited to your SBI account **9876 by employer TECH CORP on 30-Sep-26.", "label": "legitimate"},
    {"text": "Alert: Your ICICI credit card statement for period ending 15-Oct is generated. Total amount due is INR 4,320.", "label": "legitimate"},
    {"text": "Your UPI payment of ₹350 to Sharma Groceries was successful. Ref No 329182910.", "label": "legitimate"},
    {"text": "State Bank of India: Your recurring deposit account has matured. Amount of INR 52,000 credited to savings account.", "label": "legitimate"},

    # 3. Standard Login / OTP Alerts (Legitimate notifications stating do not share)
    {"text": "482910 is your login OTP for IRCTC portal. Valid for 10 minutes. Do not share this OTP with anyone.", "label": "legitimate"},
    {"text": "Your one time password for verifying email is 912384. Please do not share this code with anyone.", "label": "legitimate"},
    {"text": "Your Uber verification code is 3821. Never share this code with any driver or support agent.", "label": "legitimate"},

    # 4. Work, College & Casual Messages
    {"text": "Hi Rahul, our project status meeting is scheduled for 3:00 PM tomorrow in conference room B. Please bring slides.", "label": "legitimate"},
    {"text": "Team reminder: Please submit your final project reports on the college portal before Friday 5 PM.", "label": "legitimate"},
    {"text": "Hey, let's meet at the library around 4 PM to prepare for tomorrow's cybersecurity lab exam.", "label": "legitimate"},
    {"text": "Please find attached the minutes of the meeting held on Tuesday regarding the hackathon schedule.", "label": "legitimate"},
    {"text": "Can you please send me the notes from today's computer science lecture? I missed the first hour.", "label": "legitimate"},
    {"text": "नमस्ते राहुल, कल सुबह 10 बजे कॉलेज में सेमिनार है। कृपया समय पर सभागार में उपस्थित रहें।", "label": "legitimate"},
    {"text": "कल शाम को क्रिकेट खेलने चलना है क्या? बाकी सब ग्राउंड पर 5 बजे पहुंच रहे हैं।", "label": "legitimate"},

    # 5. Utilities & Subscriptions (Normal invoices without urgent cutoffs)
    {"text": "Your Airtel fiber broadband bill for October of ₹943 has been generated. Due date is 25-Oct-26.", "label": "legitimate"},
    {"text": "Thank you for paying your electricity bill of ₹1,850 on 12-Oct-26. Receipt number is DISCOM-849201.", "label": "legitimate"},
    {"text": "Tata Sky: Your monthly DTH recharge of ₹399 was successful. Your next recharge due date is 14-Nov-26.", "label": "legitimate"},
    {"text": "Your Jio prepaid plan of 2GB/day will expire in 3 days. Recharge via MyJio app or official retailer.", "label": "legitimate"},

    # 6. Travel & Booking Confirmations
    {"text": "IRCTC: Your ticket for train 12951 Mumbai Rajdhani from NDLS to MMCT on 20-Oct is confirmed. Coach B3 Seat 24.", "label": "legitimate"},
    {"text": "IndiGo Flight 6E-204 from Delhi to Bengaluru is on schedule. Web check-in is now open.", "label": "legitimate"},
    {"text": "BookMyShow: Your tickets for movie Inception at PVR Cinema tonight at 7:30 PM are confirmed. Audi 2, Seats E10, E11.", "label": "legitimate"},
    {"text": "Ola Ride OTP is 4920. Ride confirmed with driver Suresh driving Swift Dzire DL 01 AB 1234.", "label": "legitimate"},
    {"text": "Your appointment with Dr. Mehta at Apollo Clinic is scheduled for tomorrow at 11:30 AM.", "label": "legitimate"},
    {"text": "Google Calendar: Reminder - Hackathon Project Presentation starts in 30 minutes.", "label": "legitimate"}
]

def get_labeled_examples():
    """Returns dataset as (texts, labels)."""
    texts = [item["text"] for item in SEED_DATASET]
    labels = [item["label"] for item in SEED_DATASET]
    return texts, labels
