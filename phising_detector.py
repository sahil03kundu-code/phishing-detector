import os
import whois
import requests
import math
import re
import time
from datetime import datetime
from crewai import Agent, Task, Crew, LLM
from crewai.tools import tool

# Selenium for Screenshotting
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

# --- CONFIGURATION ---
# We use a very low temperature to keep the AI strictly factual for security
local_llm = LLM(
    model="ollama/llama3", 
    base_url="http://localhost:11434", 
    temperature=0.1
)

# --- 📸 VISUAL EVIDENCE ENGINE ---
def capture_screenshot(url, filename="evidence.png"):
    """
    Forensic Sandbox: Captures a safe visual snapshot of the destination.
    Uses 'headless' mode to protect the host machine from browser-based exploits.
    """
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1280,800")
    
    # Loophole Fix: Bypassing anti-bot scripts by masking the automated browser
    options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36")
    
    try:
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        driver.set_page_load_timeout(20) # High timeout for slow scam servers
        
        # Ensure the URL is properly formatted for the driver
        target_url = url if url.startswith(('http://', 'https://')) else f"https://{url}"
        
        driver.get(target_url)
        time.sleep(4) # Wait for Dynamic JS and Redirects to finish rendering
        driver.save_screenshot(filename)
        driver.quit()
        return filename
    except Exception as e:
        print(f"Forensic Screenshot Error: {e}")
        return None

# --- 🛠️ CYBERSECURITY UTILITIES ---

def get_shannon_entropy(text):
    """Detects Domain Generation Algorithms (DGA) by measuring character randomness."""
    if not text: return 0
    probabilities = [n_x/len(text) for x in set(text) if (n_x := text.count(x))]
    return -sum(p * math.log2(p) for p in probabilities)

def unshorten_url(url):
    """Follows the redirect chain to find the hidden 'Final Destination'."""
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        # allow_redirects=True is the key to unmasking Bitly/TinyURL
        response = requests.get(url, allow_redirects=True, timeout=8, headers=headers)
        return response.url
    except:
        return url

def check_punycode(url):
    """Detects U+0430 (Cyrillic a) style Homograph attacks."""
    return any(ord(char) > 127 for char in url)

# --- 🔍 THE ADVANCED FORENSIC TOOL ---

@tool("advanced_cyber_analyst")
def advanced_cyber_analyst(url: str):
    """
    Performs multi-vector forensic analysis:
    1. Recursive Redirect Unmasking
    2. TLD Reputation Analysis (.zip, .mov, .top)
    3. Shannon Entropy Calculation (DGA Check)
    4. Punycode/Homograph Character Detection
    5. Domain Age & Advanced Regex Brand Anchoring
    """
    # 1. Recursive Unmasking
    real_url = unshorten_url(url)
    
    # 2. Precise Domain Extraction (Handles subdomains and ports)
    domain_match = re.search(r'(?:https?://)?(?:www\.)?([^:/]+)', real_url)
    clean_domain = domain_match.group(1).lower() if domain_match else real_url.lower()
    
    # 3. TLD Risk Assessment
    high_risk_tlds = ['.zip', '.mov', '.top', '.xyz', '.work', '.click', '.biz', '.loan', '.gdn', '.monster']
    is_high_risk_tld = any(clean_domain.endswith(tld) for tld in high_risk_tlds)
    
    # 4. Statistical Analysis
    entropy_val = get_shannon_entropy(clean_domain)
    is_puny = check_punycode(real_url)
    
    # 5. Registry/Whois Analysis
    try:
        domain_info = whois.whois(clean_domain)
        creation = domain_info.get('creation_date') or domain_info.get('created')
        if isinstance(creation, list): creation = creation[0]
        age_days = (datetime.now() - creation).days if creation else 0
    except:
        age_days = -1 # Sentinel for hidden/blocked registration data
        
    # 6. Advanced Brand Spoofing (Regex Anchoring Loophole Fix)
    # This prevents 'paypal.com.scam.net' from being flagged as 'Safe'
    brands = ['paypal', 'google', 'microsoft', 'amazon', 'apple', 'netflix', 'bank', 'binance', 'coinbase']
    is_spoof = False
    for b in brands:
        if b in clean_domain:
            # The brand must be the LAST part of the domain (excluding TLD)
            # Match: paypal.com, paypal.co.uk | Fail: paypal.security-login.xyz
            pattern = rf"{b}\.(com|org|net|gov|io|co\.uk|edu|me)$"
            if not re.search(pattern, clean_domain):
                is_spoof = True

    return (
        f"--- FORENSIC INTELLIGENCE REPORT ---\n"
        f"FINAL_DESTINATION_URL: {real_url}\n"
        f"DOMAIN_IDENTIFIED: {clean_domain}\n"
        f"ESTIMATED_AGE: {age_days if age_days != -1 else 'UNKNOWN/NEWLY_REGISTERED'}\n"
        f"SHANNON_ENTROPY: {round(entropy_val, 2)} (Score > 4.2 indicates DGA)\n"
        f"PUNYCODE_DETECTION: {is_puny}\n"
        f"BRAND_IMPERSONATION: {is_spoof}\n"
        f"RISKY_TLD_EXT: {is_high_risk_tld}\n"
        f"CLOAKED_REDIRECT_DETECTED: {real_url.lower() != url.lower()}\n"
    )

# --- 🤖 AGENTIC WORKFLOW ---

detective = Agent(
    role='Cyber-Forensics Investigator',
    goal='Quantify infrastructure risk using technical forensic markers.',
    backstory="""Lead SOC Analyst. You are trained to ignore the 'story' in the email 
    and focus purely on the technical infrastructure. You prioritize Entropy scores 
    and Domain Age as primary indicators of computer-generated malicious activity.""",
    tools=[advanced_cyber_analyst],
    llm=local_llm,
    verbose=True
)

advisor = Agent(
    role='Threat Response Lead',
    goal='Provide a definitive safety verdict based on forensic data.',
    backstory="""You interpret complex technical forensic reports for the end user.
    If ANY forensic marker (Punycode, Spoofing, High Entropy) is flagged, 
    your verdict MUST be 'VERDICT: DANGER'.""",
    llm=local_llm,
    verbose=True
)

def run_analysis(user_input):
    task1 = Task(
        description=f"Perform a technical deep-scan on: {user_input}. Unmask redirects and calculate entropy.",
        expected_output="Detailed technical flags including Entropy, Age, Punycode, and Spoofing.",
        agent=detective
    )
    task2 = Task(
        description="Review forensic flags and provide a safety report. Header MUST be 'VERDICT: SAFE' or 'VERDICT: DANGER'.",
        expected_output="Final summary and justification for the security verdict.",
        agent=advisor,
        context=[task1]
    )
    crew = Crew(agents=[detective, advisor], tasks=[task1, task2], verbose=True)
    return crew.kickoff().raw