"""
Dataset generator script to populate dataset/phishing_urls.csv with realistic
legitimate and phishing URLs across various categories and attack vectors.
"""

import os
import csv
import random

# Curated base sets
LEGITIMATE_URLS = [
    # Search engines & Portals
    "https://www.google.com",
    "https://www.google.com/search?q=cybersecurity+best+practices",
    "https://www.bing.com",
    "https://www.bing.com/search?q=machine+learning+python",
    "https://duckduckgo.com",
    "https://duckduckgo.com/?q=flask+web+framework",
    "https://search.yahoo.com",
    "https://www.baidu.com",
    # Tech & Developer Platforms
    "https://github.com",
    "https://github.com/torvalds/linux",
    "https://github.com/pallets/flask",
    "https://gitlab.com",
    "https://gitlab.com/explore",
    "https://stackoverflow.com",
    "https://stackoverflow.com/questions/tagged/python",
    "https://pypi.org/project/scikit-learn/",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://scikit-learn.org/stable/modules/ensemble.html",
    "https://pandas.pydata.org/docs/reference/index.html",
    "https://hub.docker.com",
    "https://news.ycombinator.com",
    "https://www.reddit.com/r/netsec",
    "https://www.reddit.com/r/Python",
    "https://medium.com/@infosec/understanding-phishing-attacks",
    "https://dev.to/t/cybersecurity",
    # Big Tech & Cloud
    "https://aws.amazon.com/free/",
    "https://azure.microsoft.com/en-us/solutions/",
    "https://cloud.google.com/security",
    "https://www.apple.com/macbook-pro/",
    "https://support.apple.com/guide/mac-help/welcome/mac",
    "https://www.microsoft.com/en-us/software-download/windows11",
    "https://support.microsoft.com/en-us/windows",
    "https://store.steampowered.com",
    "https://www.cloudflare.com/learning/access-management/what-is-zero-trust/",
    "https://www.digitalocean.com/community/tutorials",
    # E-commerce & Retail
    "https://www.amazon.com/dp/B08N5WRWNW",
    "https://www.amazon.com/gp/bestsellers",
    "https://www.ebay.com/b/Computer-Components-Parts/175673/bn_1643095",
    "https://www.walmart.com/browse/electronics/3944",
    "https://www.target.com/c/electronics/-/N-5xtg6",
    "https://www.bestbuy.com/site/computers-pcs/laptops/abcat0502000.c",
    "https://www.aliexpress.com",
    "https://www.etsy.com/c/jewelry-and-accessories",
    # Academic & Research & Government
    "https://www.wikipedia.org",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://en.wikipedia.org/wiki/Transport_Layer_Security",
    "https://en.wikipedia.org/wiki/Machine_learning",
    "https://mit.edu/research",
    "https://stanford.edu/academics",
    "https://harvard.edu/about",
    "https://ox.ac.uk/admissions",
    "https://cam.ac.uk/research",
    "https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final",
    "https://www.cisa.gov/resources-tools/resources/phishing-infographic",
    "https://www.nsa.gov/cybersecurity/",
    "https://www.fbi.gov/scams-and-safety/common-scams-and-crimes/spoofing-and-phishing",
    "https://www.who.int/news-room",
    "https://www.cdc.gov/healthy-living/index.html",
    # News & Media
    "https://www.bbc.com/news/technology",
    "https://www.cnn.com/tech",
    "https://www.reuters.com/technology/",
    "https://www.theverge.com/tech",
    "https://techcrunch.com/category/security/",
    "https://arstechnica.com/security/",
    "https://www.wired.com/category/security/",
    "https://krebsonsecurity.com",
    "https://www.bleepingcomputer.com/news/security/",
    "https://www.nytimes.com/section/technology",
    "https://www.theguardian.com/technology",
    "https://www.forbes.com/innovation/",
    # Social & Professional
    "https://www.linkedin.com/jobs",
    "https://www.linkedin.com/in/williamhgates",
    "https://twitter.com/NASA",
    "https://x.com/OpenAI",
    "https://www.instagram.com/natgeo/",
    "https://www.facebook.com/meta",
    "https://discord.com/guidelines",
    "https://slack.com/solutions",
    "https://zoom.us/pricing",
    "https://open.spotify.com/genre/discover",
    "https://www.netflix.com/browse",
    # Banking & Finance (Official SSL sites)
    "https://www.chase.com/personal/banking",
    "https://www.bankofamerica.com/smallbusiness/",
    "https://www.wellsfargo.com/help/",
    "https://www.citi.com/credit-cards",
    "https://www.paypal.com/us/home",
    "https://www.stripe.com/docs/api",
    "https://www.mastercard.us/en-us.html",
    "https://www.visa.com/content/dam/VCOM/global/about-visa/documents/visa-facts-figures.pdf",
    "https://www.americanexpress.com/en-us/credit-cards/",
    "https://www.fidelity.com/trading/overview",
]

PHISHING_URLS = [
    # IP Address based URLs
    "http://192.168.1.105/paypal/signin.php?cmd=login_submit",
    "http://142.250.190.46/webscr/login.php?dispatch=5885d80a13c0db1f",
    "http://216.58.214.206/apple-id/account-verify/index.html",
    "http://185.220.101.5/chase-online/auth/login.html",
    "http://45.33.32.156/wellsfargo/secure/verification.php",
    "http://198.51.100.12/bankofamerica/secure-login/update.htm",
    "http://203.0.113.88/secure/update-banking-info.html?id=83721",
    "http://104.244.42.1/netflix-account-suspended/update-billing.php",
    "http://195.123.210.45:8080/microsoft-365/login.aspx?token=92847",
    "http://185.191.171.12/amazon/orders/verify-payment.html",
    # Multiple Subdomains & Brand Spoofing
    "http://paypal.com.verification-center.account-security.tk/login.php",
    "http://appleid.apple.com.verify-billing-info.ssl-security.ml/signin",
    "http://secure.wellsfargo.com.custupdate.client-service.cf/login.jsp",
    "http://chase.online.banking.update-profile.user9218.xyz/auth",
    "http://signin.ebay.com.ws.ebayisapi.dll.sign-in.ga/eBayISAPI.php",
    "http://accounts.google.com.service-login.security-check.gq/login",
    "http://bankofamerica.com.signon.update-credentials.work/session",
    "http://login.microsoftonline.com.oauth2.authorize.portal.top/adfs",
    "http://netflix.account.billing.membership-hold.reactivation.click/view",
    "http://amazon.security-alert.prime-order.confirmation.surf/review",
    # @ Symbol Misdirection
    "http://google.com@phishing-server-912.xyz/secure/login.html",
    "http://paypal.com@verify-account-update.tk/webscr/cmd-login",
    "http://apple.com@icloud-locked-security-support.work/auth",
    "http://chase.com@secure-banking-portal-session.top/signin",
    "http://microsoft.com@office365-tenant-admin-auth.cf/owa",
    "http://amazon.com@payment-declined-reorder.xyz/billing.php",
    "http://wellsfargo.com@online-banking-identity-verify.ml/login",
    "http://bankofamerica.com@fraud-prevention-alert.gq/auth/verify",
    # Hyphen Overuse & Typosquatting
    "http://www-paypal-account-verification-support-center.com/signin",
    "http://secure-apple-id-manage-account-verify-support.com/auth",
    "http://chase-bank-online-security-update-center-login.com/portal",
    "http://netflix-billing-update-reactivate-membership-notice.xyz/home",
    "http://amazon-account-suspension-order-resolution-center.top/case",
    "http://wellsfargo-identity-verification-portal-service.click/auth",
    "http://bank-of-america-safe-pass-security-validation.work/login",
    "http://microsoft-office365-password-reset-notification.top/reset",
    # Suspicious Free/Abused TLDs
    "http://secure-account-verification.tk/login",
    "http://update-your-billing-service.ml/paypal",
    "http://verify-bank-credentials.ga/chase",
    "http://support-ticket-resolution.cf/apple",
    "http://security-alert-notification.gq/google",
    "http://cheap-fast-loans-instant-approval.loan/apply",
    "http://free-crypto-giveaway-airdrop.xyz/claim-tokens",
    "http://download-cracked-software-free.download/patch.exe",
    "http://official-lottery-winner-notification.win/claim",
    "http://hot-dating-chat-near-you.date/register",
    # Known Shorteners masking credential phish
    "http://bit.ly/3xSecLoginPayPalUpdate",
    "http://tinyurl.com/apple-id-verify-locked-992",
    "http://is.gd/chaseBankSecurityAlert",
    "http://cutt.ly/microsoft-teams-meeting-join",
    "http://rb.gy/netflix-membership-expired",
    "http://tiny.cc/wells-fargo-alert-update",
    # High Entropy / Random DGA Strings
    "http://x92kj4n29f8a1mn923zqp9.xyz/login.php?u=victim@domain.com",
    "http://78219038271038192738.click/secure/banking/auth.htm",
    "http://a8f7c9b0e1d2c3b4a5f6.top/verify?session=92847192847",
    "http://pq98zlk1209384756192837.work/account/recovery",
    "http://09128301928301928301928.surf/update-profile.php",
    # Sensitive Action Keywords on Insecure HTTP
    "http://secure-banking-login-auth.com/verify-credentials.php",
    "http://customer-service-billing-invoice-portal.net/login.jsp",
    "http://account-recovery-security-token-validator.org/auth",
    "http://user-password-recovery-support-desk.biz/reset-now",
    "http://payment-gateway-fraud-prevention-alert.info/check",
]

def generate_synthetic_variations():
    """Expands dataset with realistic variations to ensure great ML distribution."""
    random.seed(42)
    urls = []
    
    # 1. Base legitimate URLs
    for u in LEGITIMATE_URLS:
        urls.append((u, 0))
    
    # Legitimate path extensions
    legit_domains = [
        "https://www.google.com", "https://github.com", "https://stackoverflow.com",
        "https://www.microsoft.com", "https://aws.amazon.com", "https://www.wikipedia.org",
        "https://www.python.org", "https://www.digitalocean.com", "https://developer.mozilla.org",
        "https://www.bbc.com", "https://www.reddit.com", "https://www.nytimes.com",
        "https://www.chase.com", "https://www.bankofamerica.com", "https://www.paypal.com"
    ]
    legit_paths = [
        "/about", "/contact-us", "/privacy-policy", "/terms-of-service", "/help/center",
        "/docs/latest/index.html", "/products/overview", "/explore/popular", "/blog/post/1029",
        "/search?q=open+source+software", "/download/release-notes.txt", "/news/2026/03/update",
        "/support/kb/articles/48912", "/account/settings/profile", "/resources/whitepapers/guide.pdf"
    ]
    for d in legit_domains:
        for p in random.sample(legit_paths, 8):
            urls.append((f"{d}{p}", 0))

    # Additional diverse clean domains
    clean_sample_domains = [
        "https://wordpress.org", "https://apache.org", "https://mozilla.org", "https://gnu.org",
        "https://linuxfoundation.org", "https://mit.edu", "https://harvard.edu", "https://stanford.edu",
        "https://nasa.gov", "https://whitehouse.gov", "https://nih.gov", "https://usps.com",
        "https://oracle.com", "https://ibm.com", "https://salesforce.com", "https://intel.com",
        "https://cisco.com", "https://nvidia.com", "https://adobe.com", "https://spotify.com"
    ]
    for c in clean_sample_domains:
        urls.append((c, 0))
        urls.append((f"{c}/features", 0))
        urls.append((f"{c}/about-us", 0))
        urls.append((f"{c}/contact", 0))

    # 2. Base phishing URLs
    for u in PHISHING_URLS:
        urls.append((u, 1))

    # Synthetic realistic phishing generators
    targets = ["paypal", "appleid", "chase-bank", "netflix", "wellsfargo", "amazon-security", "office365", "google-drive", "crypto-wallet", "bofa-online"]
    tlds = ["xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "loan", "surf"]
    suspicious_actions = ["login", "verify-account", "update-billing", "security-alert", "password-reset", "unlock-access", "confirm-identity", "client-portal"]
    
    # Target + action + suspicious tld
    for t in targets:
        for a in suspicious_actions:
            chosen_tld = random.choice(tlds)
            urls.append((f"http://{t}-{a}.{chosen_tld}/index.php?token={random.randint(10000, 99999)}", 1))
            urls.append((f"http://secure.{t}.com.auth-service.{chosen_tld}/{a}.html", 1))
            urls.append((f"http://login.{t}.{chosen_tld}/verify.php?session_id={random.randint(100000, 999999)}", 1))

    # Raw IP Phishing attacks
    for _ in range(40):
        ip = f"{random.randint(11, 215)}.{random.randint(10, 250)}.{random.randint(1, 250)}.{random.randint(1, 250)}"
        kw = random.choice(suspicious_actions)
        urls.append((f"http://{ip}/{kw}/login.php?client_id={random.randint(100, 999)}", 1))

    # Hyphenated spoofing attacks
    for _ in range(35):
        t = random.choice(targets)
        domain = f"www-{t}-online-banking-verification-help-center-{random.randint(10, 99)}.com"
        urls.append((f"http://{domain}/auth/login.html", 1))

    # Random DGA high entropy strings
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    for _ in range(30):
        rand_str = "".join(random.choice(chars) for _ in range(random.randint(18, 26)))
        chosen_tld = random.choice(tlds)
        urls.append((f"http://{rand_str}.{chosen_tld}/update.php?id={random.randint(1000, 9999)}", 1))

    # URL shorteners masking phish
    shorteners = ["bit.ly", "tinyurl.com", "is.gd", "cutt.ly", "rb.gy"]
    for s in shorteners:
        for _ in range(6):
            slug = "".join(random.choice(chars) for _ in range(7))
            urls.append((f"http://{s}/{slug}", 1))

    # Deduplicate while preserving order
    seen = set()
    deduped = []
    for u, label in urls:
        if u not in seen:
            seen.add(u)
            deduped.append((u, label))

    return deduped

def main():
    target_csv = os.path.join(os.path.dirname(__file__), "dataset", "phishing_urls.csv")
    dataset = generate_synthetic_variations()
    
    with open(target_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        for url, label in dataset:
            writer.writerow([url, label])

    legit_count = sum(1 for _, l in dataset if l == 0)
    phish_count = sum(1 for _, l in dataset if l == 1)
    print(f"Generated {len(dataset)} records: {legit_count} Legitimate (0), {phish_count} Phishing (1)")
    print(f"Saved to: {target_csv}")

if __name__ == "__main__":
    main()
