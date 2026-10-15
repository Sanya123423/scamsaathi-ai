"""
ScamSaathi - Context-Aware Safety Recommendations Engine
Generates tailored, actionable safety steps based on detected cyber threat vectors.
"""

def generate_recommendations(
    categories: list[str],
    has_otp_threat: bool = False,
    has_url_threat: bool = False,
    has_advance_fee: bool = False,
    has_utility_threat: bool = False,
    severity: str = 'LOW'
) -> list[str]:
    """
    Produces concise, authoritative security advisories for the user based on detected threats.
    """
    recommendations = []

    # 1. Credential / OTP Specific Advisory
    if has_otp_threat:
        recommendations.append(
            "CRITICAL: Never share OTPs, UPI PINs, ATM PINs, or NetBanking passwords with anyone. Bank and government officials NEVER request passwords or OTPs."
        )

    # 2. Advance Fee & Job Fraud Advisory
    if has_advance_fee:
        recommendations.append(
            "DO NOT send money: Legitimate employers, government departments, and lottery entities never demand advance registration fees or security deposits."
        )

    # 3. Utility / Power Cutoff Advisory
    if has_utility_threat:
        recommendations.append(
            "Do NOT call phone numbers sent via SMS. Contact your local electricity DISCOM directly using the verified customer care number printed on your physical bill."
        )

    # 4. URL & Link Safety Advisory
    if has_url_threat:
        recommendations.append(
            "Do NOT click on unverified links or install APK/executable files sent through messages. Always access services by manually typing the official domain into your browser."
        )

    # 5. Impersonation Advisory
    if 'Impersonation' in categories or 'Phishing & Impersonation' in categories:
        recommendations.append(
            "Verify sender identity: Verify unexpected communications independently by calling the official helpline listed on the organization's certified website."
        )

    # 6. Fallback recommendations if none specifically triggered or low severity
    if not recommendations or severity == 'LOW':
        recommendations.append(
            "Exercise routine cyber vigilance: Verify unexpected attachments, links, and unfamiliar sender IDs before taking action."
        )
        recommendations.append(
            "Ensure multi-factor authentication (MFA/2FA) is enabled across your primary email, banking, and social accounts."
        )

    # 7. Official Indian Cyber Helpline (Universal advisory for all scans)
    recommendations.append(
        "If you suspect fraud or have lost money, report immediately to the National Cyber Crime Reporting Portal at cybercrime.gov.in or call Helpline 1930."
    )

    return recommendations
