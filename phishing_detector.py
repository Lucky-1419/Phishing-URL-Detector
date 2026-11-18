
print("===== PHISHING URL DETECTOR =====")

# Get website URL from user
url = input("Enter a website URL: ")

# Check suspicious keywords
if "login" in url or "verify" in url or "password" in url:
    print("WARNING: This URL contains suspicious keywords!")
else:
    print("No suspicious keywords found.")

print("URL checking completed.")


from urllib.parse import urlparse
import ipaddress

print("===== ADVANCED PHISHING URL DETECTOR =====")

url = input("Enter website URL: ").strip()

# Add HTTPS if the user did not enter a scheme
if "://" not in url:
    url = "http://" + url

parsed = urlparse(url)
domain = parsed.hostname

score = 0
warnings = []

# Check 1: Valid URL and domain
if not domain:
    warnings.append("Invalid or missing domain")
    score += 3
else:
    # Check 2: Check HTTPS
    if parsed.scheme != "https":
        warnings.append("Website does not use HTTPS")
        score += 1

    # Check 3: Suspicious keywords
    suspicious_words = [
        "login", "verify", "password",
        "banking", "account", "secure"
    ]

    for word in suspicious_words:
        if word in url.lower():
            warnings.append("Suspicious keyword found: " + word)
            score += 1

    # Check 4: Check IP address
    try:
        ipaddress.ip_address(domain)
        warnings.append("Website uses an IP address as its domain")
        score += 3
    except ValueError:
        pass

    # Check 5: Check @ symbol
    if "@" in parsed.netloc:
        warnings.append("URL contains an @ symbol")
        score += 2

    # Check 6: Check shortened URLs
    shorteners = [
        "bit.ly", "tinyurl.com", "t.co",
        "is.gd", "cutt.ly"
    ]

    if domain.lower() in shorteners:
        warnings.append("URL uses a shortening service")
        score += 2

# Display results
print("\n===== SCAN RESULTS =====")

if warnings:
    for warning in warnings:
        print("WARNING:", warning)
else:
    print("No suspicious patterns detected.")

print("\nRisk score:", score)

if score >= 5:
    print("RESULT: HIGHER RISK - Investigate this URL.")
elif score >= 2:
    print("RESULT: CAUTION - Some suspicious signs found.")
else:
    print("RESULT: NO MAJOR WARNING SIGNS DETECTED.")

print("\nRemember: This is a basic heuristic checker.")
print("It cannot guarantee that a website is safe.")
