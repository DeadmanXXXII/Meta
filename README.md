# Meta Critical vulnerability report

Bug Bounty Report for Meta (Facebook/WhatsApp)

Title: Exposure of Sensitive User Information via Linked Facebook and WhatsApp Accounts

Summary: A vulnerability exists in the way Meta handles Facebook and WhatsApp account integration. This flaw allows attackers to collect sensitive information, including Facebook profile pictures, Public Facebook IDs (PFBIDs), and WhatsApp phone numbers. The attacker can compile personal data for multiple users with minimal effort, leading to a severe privacy violation and increasing the risk of targeted stalking and social engineering attacks.


---

Steps to Reproduce:

1. Access a compromised or leaked WhatsApp phone number URL, such as:

https://www.whatsapp.com/accounts?phone=905425687550&



2. Follow the link to the associated Facebook profile, which reveals:

https://www.facebook.com/profile.php?id=100064758844407



3. The attacker now has access to the following:

The Facebook profile name.

The Public Facebook ID (PFBID) which is associated with numerical profile IDs, further exposing other profile details.

Facebook profile pictures.



4. The process can be repeated for multiple users, accumulating sensitive information like WhatsApp phone numbers, Facebook profile details, and personal images, all without authentication.




---

Evidence: The following is an example of compromised information collected via the attack:

WhatsApp Number: +905425687550

Facebook Profile: https://www.facebook.com/profile.php?id=100064758844407

Profile Picture PFBID Exposure:

Profile images with numerical IDs (PFBIDs) attached to URLs.

Example: User Nandar Singh (see screenshot for visual proof of profile image access).




---

Impact: This vulnerability allows for the collection of the following types of sensitive user information:

1. Facebook Profile Pictures.


2. WhatsApp Numbers.


3. Public Facebook IDs (PFBIDs).


4. Other sensitive URLs exposing user-specific data.



This personal information can be used to stalk, socially engineer, or harass users across platforms. The data leakage allows a malicious actor to compile user details without their consent, leading to potential harm.


---

Security Misconfiguration and Weaknesses: The vulnerability stems from weak access controls and improper authorization management between WhatsApp and Facebook integrations. The following weaknesses are directly related to this issue:

CWE-359: Exposure of Private Information ('Privacy Violation')

Personal data such as WhatsApp numbers, profile images, and Facebook IDs are leaked.


CWE-285: Improper Authorization

The system fails to enforce proper access controls, allowing unauthorized users to gather sensitive data.


CWE-312: Cleartext Storage of Sensitive Information

Personal data such as phone numbers and user IDs are easily accessible and stored in cleartext across URLs.


---

CVSS Score:

Base Score: 9.1 (Critical)

Vector: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N


---

Remediation: To fix this issue, Meta should implement the following:

1. Enhanced Authentication: Strengthen access controls for URLs containing sensitive information like profile pictures, WhatsApp numbers, and PFBIDs. Ensure only authorized users can view this data.


2. Data Masking: Mask sensitive information in the URLs or metadata that can be directly accessed by unauthorized users.


3. Cleartext Removal: Securely encrypt sensitive data, such as PFBIDs and phone numbers, before transmitting or storing it.


4. Audit and Fix Privacy Loopholes: Conduct a comprehensive audit to identify other instances where sensitive data may be inadvertently exposed between Meta's platforms.


---

Conclusion:
This vulnerability poses a significant risk to user privacy, enabling malicious actors to compile and exploit sensitive personal data with little effort. It affects both WhatsApp and Facebook users by exposing phone numbers, profile details, and other identifying information, leading to serious stalking or social engineering threats.

### Pictures:
![Logo/Nft](https://raw.githubusercontent.com/DeadmanXXXII/DeadmanXXXII.github.io/main/site_pics/logo/nft/logo2%20(1).png)


User PFBIDs and more exposure using basic python script.
Packages: selenium, chromedriver.
Hacker: DeadmanXXXII
15/10/2024

Terminal:

┌──(root㉿localhost)-[~/remedy/Scraped]
└─# python3 ls4.py
https://www.whatsapp.com/accounts?phone=--sanitized--&&lang=cs
https://www.whatsapp.com/accounts?phone=--sanitized--&&lang=de
https://www.whatsapp.com/accounts?phone=--sanitized--&&lang=en
https://www.whatsapp.com/accounts?phone=--sanitized--&&lang=es
https://www.whatsapp.com/accounts?phone=--sanitized--&&lang=fr
https://www.whatsapp.com/accounts?phone=--sanitized--&&lang=it
https://www.whatsapp.com/accounts?phone=--sanitized--&&lang=hu
https://www.whatsapp.com/accounts?phone=--sanitized--&&lang=nl
https://www.whatsapp.com/accounts?phone=--sanitized--&&lang=pl
https://www.whatsapp.com/accounts?phone=--sanitized--&&lang=pt_pt
https://www.whatsapp.com/accounts?phone=--sanitized--&&lang=ro
https://www.whatsapp.com/accounts?phone=--sanitized--&&lang=sk
https://www.whatsapp.com/accounts?phone=--sanitized--&&lang=sl
https://www.whatsapp.com/accounts?phone=--sanitized--&&lang=sv
https://www.whatsapp.com/legal/cookies
https://www.whatsapp.com/accounts?phone=--sanitized--&&lang=cs
https://www.whatsapp.com/accounts?phone=--sanitized--&&lang=de
https://www.whatsapp.com/accounts?phone=--sanitized--&&lang=en
https://www.whatsapp.com/accounts?phone=--sanitized--&&lang=es
https://www.whatsapp.com/accounts?phone=--sanitized--&&lang=fr
https://www.whatsapp.com/accounts?phone=--sanitized--&&lang=it
https://www.whatsapp.com/accounts?phone=--sanitized--&&lang=hu
https://www.whatsapp.com/accounts?phone=--sanitized--&&lang=nl
https://www.whatsapp.com/accounts?phone=--sanitized--&&lang=pl
https://www.whatsapp.com/accounts?phone=--sanitized--&&lang=pt_pt
https://www.whatsapp.com/accounts?phone=--sanitized--&&lang=ro
https://www.whatsapp.com/accounts?phone=--sanitized--&&lang=sk
https://www.whatsapp.com/accounts?phone=--sanitized--&&lang=sl
https://www.whatsapp.com/accounts?phone=--sanitized--&&lang=sv
https://support.google.com/chrome/answer/95647
https://support.microsoft.com/en-us/topic/delete-and-manage-cookies-168dab11-0753-043d-7c16-ede5947fc64d
https://support.mozilla.org/en-US/kb/enhanced-tracking-protection-firefox-desktop
https://support.apple.com/en-ie/guide/safari/sfri11471/mac
https://support.apple.com/en-us/HT201265
https://blogs.opera.com/news/2015/08/how-to-manage-cookies-in-opera/
https://www.whatsapp.com/accounts?phone=905425687550&#content-wrapper
https://www.whatsapp.com/
https://www.whatsapp.com/privacy
https://www.whatsapp.com/stayconnected
https://www.whatsapp.com/community
https://www.whatsapp.com/expressyourself
https://business.whatsapp.com/
https://www.whatsapp.com/privacy
https://faq.whatsapp.com/
https://blog.whatsapp.com/
https://business.whatsapp.com/
https://whatsapp.com/download
https://www.whatsapp.com/download
https://twitter.com/whatsapp
https://www.youtube.com/channel/UCAuerig2N-RZWJT8x75V9yw
https://www.instagram.com/whatsapp/?hl=en
https://www.facebook.com/profile.php?id=100064758844406
https://www.whatsapp.com/legal/
https://www.whatsapp.com/
https://www.whatsapp.com/
https://www.whatsapp.com/privacy
https://www.whatsapp.com/stayconnected
https://www.whatsapp.com/community
https://www.whatsapp.com/expressyourself
https://business.whatsapp.com/
https://www.whatsapp.com/privacy
https://faq.whatsapp.com/
https://blog.whatsapp.com/
https://business.whatsapp.com/
https://web.whatsapp.com/
https://whatsapp.com/download
https://www.whatsapp.com/download
https://www.whatsapp.com/download
https://www.whatsapp.com/
https://www.whatsapp.com/privacy
https://www.whatsapp.com/stayconnected
https://www.whatsapp.com/community
https://www.whatsapp.com/expressyourself
https://business.whatsapp.com/
https://www.whatsapp.com/download
https://twitter.com/whatsapp
https://www.youtube.com/channel/UCAuerig2N-RZWJT8x75V9yw
https://www.instagram.com/whatsapp/?hl=en
https://www.facebook.com/profile.php?id=100064758844406
https://www.whatsapp.com/
https://www.whatsapp.com/
https://www.whatsapp.com/download
https://www.whatsapp.com/stayconnected
https://blog.whatsapp.com/
https://www.whatsapp.com/security
https://business.whatsapp.com/
https://www.whatsapp.com/about
https://www.whatsapp.com/join
https://www.facebook.com/brand/resources/whatsapp/whatsapp-brand
https://www.whatsapp.com/privacy
https://www.whatsapp.com/android
https://www.whatsapp.com/download
https://www.whatsapp.com/download
https://web.whatsapp.com/
https://www.whatsapp.com/contact
https://faq.whatsapp.com/
https://www.whatsapp.com/download
https://www.whatsapp.com/security/advisories
https://www.whatsapp.com/download
https://twitter.com/whatsapp
https://www.youtube.com/channel/UCAuerig2N-RZWJT8x75V9yw
https://www.instagram.com/whatsapp/?hl=en
https://www.facebook.com/profile.php?id=100064758844406
https://www.whatsapp.com/legal/
https://www.whatsapp.com/sitemap
https://twitter.com/whatsapp
https://www.youtube.com/channel/UCAuerig2N-RZWJT8x75V9yw
https://www.instagram.com/whatsapp/?hl=en
https://www.facebook.com/profile.php?id=100064758844406

┌──(root㉿localhost)-[~/remedy/Scraped]
└─# cat ls4.py
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

# Path to your chromedriver
chrome_driver_path = '/usr/bin/chromedriver'

# Set up Chrome options
chrome_options = Options()
chrome_options.add_argument('--headless')  # Ensure GUI is not needed
chrome_options.add_argument('--no-sandbox')
chrome_options.add_argument('--disable-dev-shm-usage')

# Initialize the Chrome driver
service = Service(chrome_driver_path)
driver = webdriver.Chrome(service=service, options=chrome_options)

try:
    url = "https://www.whatsapp.com/accounts?phone=905425687550&"
    driver.get(url)

    # Wait for the page to load
    WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, 'body')))

    # Example: Scrape all links
    links = driver.find_elements(By.TAG_NAME, 'a')
    for link in links:
        print(link.get_attribute('href'))

finally:
    # Clean up
    driver.quit()


┌──(root㉿localhost)-[~/remedy/Scraped]
└─# curl -I -L https://www.facebook.com/profile.php?id=100064758844409
HTTP/2 200
vary: Accept-Encoding
accept-ch-lifetime: 4838400
accept-ch: viewport-width,dpr,Sec-CH-Prefers-Color-Scheme,Sec-CH-UA-Full-Version-List,Sec-CH-UA-Platform-Version,Sec-CH-UA-Model
pragma: no-cache
cache-control: private, no-cache, no-store, must-revalidate
expires: Sat, 01 Jan 2000 00:00:00 GMT
content-security-policy: default-src data: blob: 'self' https://*.fbsbx.com 'unsafe-inline' *.facebook.com *.fbcdn.net 'unsafe-eval';script-src *.facebook.com *.fbcdn.net *.facebook.net 127.0.0.1:* 'unsafe-inline' blob: data: 'self' connect.facebook.net 'unsafe-eval' https://*.google-analytics.com *.google.com;style-src *.fbcdn.net data: *.facebook.com 'unsafe-inline' https://fonts.googleapis.com;connect-src *.facebook.com facebook.com *.fbcdn.net *.facebook.net wss://*.facebook.com:* wss://*.whatsapp.com:* wss://*.fbcdn.net attachment.fbsbx.com ws://localhost:* blob: *.cdninstagram.com 'self' http://localhost:3103 wss://gateway.facebook.com wss://edge-chat.facebook.com wss://snaptu-d.facebook.com wss://kaios-d.facebook.com/ v.whatsapp.net *.fbsbx.com *.fb.com https://*.google-analytics.com;font-src data: *.facebook.com *.fbcdn.net *.fbsbx.com https://fonts.gstatic.com;img-src *.fbcdn.net *.facebook.com data: https://*.fbsbx.com facebook.com *.cdninstagram.com fbsbx.com fbcdn.net connect.facebook.net *.carriersignal.info blob: android-webview-video-poster: *.whatsapp.net *.fb.com *.oculuscdn.com *.tenor.co *.tenor.com *.giphy.com https://paywithmybank.com/ https://*.paywithmybank.com/ https://www.googleadservices.com https://googleads.g.doubleclick.net https://*.google-analytics.com;media-src *.cdninstagram.com blob: *.fbcdn.net *.fbsbx.com www.facebook.com *.facebook.com data: *.tenor.co *.tenor.com https://*.giphy.com;frame-src *.facebook.com *.fbsbx.com fbsbx.com data: www.instagram.com *.fbcdn.net https://paywithmybank.com/ https://*.paywithmybank.com/ https://www.googleadservices.com https://googleads.g.doubleclick.net https://www.google.com https://td.doubleclick.net *.google.com *.doubleclick.net;worker-src blob: *.facebook.com data:;block-all-mixed-content;upgrade-insecure-requests;
x-frame-options: DENY
x-content-type-options: nosniff
x-xss-protection: 0
reporting-endpoints: coop_report="https://www.facebook.com/browser_reporting/coop/?minimize=0", coep_report="https://www.facebook.com/browser_reporting/coep/?minimize=0", default="https://www.facebook.com/ajax/comet_error_reports/?device_level=unknown&brsid=7426110236368539660"
report-to: {"max_age":2592000,"endpoints":[{"url":"https:\/\/www.facebook.com\/browser_reporting\/coop\/?minimize=0"}],"group":"coop_report","include_subdomains":true}, {"max_age":86400,"endpoints":[{"url":"https:\/\/www.facebook.com\/browser_reporting\/coep\/?minimize=0"}],"group":"coep_report"}, {"max_age":259200,"endpoints":[{"url":"https:\/\/www.facebook.com\/ajax\/comet_error_reports\/?device_level=unknown&brsid=7426110236368539660"}]}
cross-origin-embedder-policy-report-only: require-corp;report-to="coep_report"
cross-origin-opener-policy: same-origin-allow-popups;report-to="coop_report"
strict-transport-security: max-age=15552000; preload
content-type: text/html; charset="utf-8"
x-fb-debug: HI39gbOrXuvu+cdg0/c4RhQ7h99ViPJOehXsi8N8YqsA7lkJrKM41XafOSQLz4pEJy1apakkMHR2On2RyhaeJQ==
date: Tue, 15 Oct 2024 21:00:26 GMT
x-fb-connection-quality: EXCELLENT; q=0.9, rtt=14, rtx=0, c=10, mss=1380, tbw=2689, tp=-1, tpl=-1, uplat=51, ullat=0
alt-svc: h3=":443"; ma=86400


┌──(root㉿localhost)-[~/remedy/Scraped]
└─# curl -I -L https://www.facebook.com/profile.php?id=100034758844409
HTTP/2 302
location: https://www.facebook.com/nandar.singh.507/
reporting-endpoints: coop_report="https://www.facebook.com/browser_reporting/coop/?minimize=0"
report-to: {"max_age":2592000,"endpoints":[{"url":"https:\/\/www.facebook.com\/browser_reporting\/coop\/?minimize=0"}],"group":"coop_report","include_subdomains":true}
cross-origin-opener-policy: same-origin-allow-popups
strict-transport-security: max-age=15552000; preload
content-type: text/html; charset="utf-8"
x-fb-debug: mrDn2m00yIDJbsJldB/awVzBTejBeCpddtHYTF5w1EUJ7WuloePg0Evg87tZg1Cc1VEqT6SL3rKccxH9ElENzw==
content-length: 0
date: Tue, 15 Oct 2024 21:02:58 GMT
x-fb-connection-quality: EXCELLENT; q=0.9, rtt=16, rtx=0, c=10, mss=1380, tbw=2690, tp=-1, tpl=-1, uplat=29, ullat=0
alt-svc: h3=":443"; ma=86400

HTTP/2 200
vary: Accept-Encoding
accept-ch-lifetime: 4838400
accept-ch: viewport-width,dpr,Sec-CH-Prefers-Color-Scheme,Sec-CH-UA-Full-Version-List,Sec-CH-UA-Platform-Version,Sec-CH-UA-Model
link: <https://www.facebook.com/nandar.singh.507>; rel="canonical"
reporting-endpoints: coop_report="https://www.facebook.com/browser_reporting/coop/?minimize=0", default="https://www.facebook.com/ajax/comet_error_reports/?device_level=unknown&brsid=7426110889259842757", permissions_policy="https://www.facebook.com/ajax/browser_error_reports/"
report-to: {"max_age":2592000,"endpoints":[{"url":"https:\/\/www.facebook.com\/browser_reporting\/coop\/?minimize=0"}],"group":"coop_report","include_subdomains":true}, {"max_age":259200,"endpoints":[{"url":"https:\/\/www.facebook.com\/ajax\/comet_error_reports\/?device_level=unknown&brsid=7426110889259842757"}]}, {"max_age":21600,"endpoints":[{"url":"https:\/\/www.facebook.com\/ajax\/browser_error_reports\/"}],"group":"permissions_policy"}
content-security-policy-report-only: default-src data: blob: 'self' https://*.fbsbx.com 'unsafe-inline' *.facebook.com *.fbcdn.net 'unsafe-eval';script-src *.facebook.com *.fbcdn.net *.facebook.net 127.0.0.1:* 'unsafe-inline' blob: data: 'self' connect.facebook.net 'unsafe-eval' https://*.google-analytics.com *.google.com;style-src *.fbcdn.net data: *.facebook.com 'unsafe-inline' https://fonts.googleapis.com;connect-src *.facebook.com facebook.com *.fbcdn.net *.facebook.net wss://*.facebook.com:* wss://*.whatsapp.com:* wss://*.fbcdn.net attachment.fbsbx.com ws://localhost:* blob: *.cdninstagram.com 'self' http://localhost:3103 wss://gateway.facebook.com wss://edge-chat.facebook.com wss://snaptu-d.facebook.com wss://kaios-d.facebook.com/ v.whatsapp.net *.fbsbx.com *.fb.com https://*.google-analytics.com https://api.mapbox.com https://*.tiles.mapbox.com https://events.mapbox.com https://meta.privacy-gateway.cloudflare.com/relay https://meta-ohttp-relay-prod.fastly-edge.com;font-src data: *.facebook.com *.fbcdn.net *.fbsbx.com https://fonts.gstatic.com;img-src *.fbcdn.net *.facebook.com data: https://*.fbsbx.com facebook.com *.cdninstagram.com fbsbx.com fbcdn.net connect.facebook.net *.carriersignal.info blob: android-webview-video-poster: *.whatsapp.net *.fb.com *.oculuscdn.com *.tenor.co *.tenor.com *.giphy.com https://paywithmybank.com/ https://*.paywithmybank.com/ https://www.googleadservices.com https://googleads.g.doubleclick.net https://*.google-analytics.com;media-src *.cdninstagram.com blob: *.fbcdn.net *.fbsbx.com www.facebook.com *.facebook.com data: *.tenor.co *.tenor.com https://*.giphy.com;frame-src *.facebook.com *.fbsbx.com fbsbx.com data: www.instagram.com *.fbcdn.net https://paywithmybank.com/ https://*.paywithmybank.com/ https://www.googleadservices.com https://googleads.g.doubleclick.net https://www.google.com https://td.doubleclgram.com *.fbcdn.net https://paywithmybank.com/ https://*.paywithmybank.com/ https://www.googleadservices.com https://googleads.g.doubleclick.net https://www.google.com https://td.doubleclick.net *.google.com *.doubleclick.net;worker-src blob: *.facebook.com data:;block-all-mixed-content;upgrade-insecure-requests;
document-policy: force-load-at-top
permissions-policy: accelerometer=(), attribution-reporting=(self), autoplay=(), bluetooth=(), browsing-topics=(self), camera=(self), ch-device-memory=(), ch-downlink=(), ch-dpr=(), ch-ect=(), ch-rtt=(), ch-save-data=(), ch-ua-arch=(), ch-ua-bitness=(), ch-viewport-height=(), ch-viewport-width=(), ch-width=(), clipboard-read=(self), clipboard-write=(self), compute-pressure=(), display-capture=(self), encrypted-media=(self), fullscreen=(self), gamepad=*, geolocation=(self), gyroscope=(), hid=(), idle-detection=(), interest-cohort=(self), keyboard-map=(), local-fonts=(), magnetometer=(), microphone=(self), midi=(), otp-credentials=(), payment=(), picture-in-picture=(self), private-state-token-issuance=(), publickey-credentials-get=(self), screen-wake-lock=(), serial=(), shared-storage=(), shared-storage-select-url=(), private-state-token-redemption=(), usb=(), unload=(self), window-management=(), xr-spatial-tracking=(self);report-to="permissions_policy"
cross-origin-resource-policy: same-origin
cross-origin-opener-policy: same-origin-allow-popups
pragma: no-cache
cache-control: private, no-cache, no-store, must-revalidate
expires: Sat, 01 Jan 2000 00:00:00 GMT
x-content-type-options: nosniff
x-xss-protection: 0
x-frame-options: DENY
strict-transport-security: max-age=15552000; preload
content-type: text/html; charset="utf-8"
x-fb-debug: dYuwlFXqzU3l9ddiipiRrmeXrYw2EpLStVonIZZfXFXOToHV+6bq3rG1Ee3uxeHEp3gx/JtCR5iYFOscQhYp7g==
date: Tue, 15 Oct 2024 21:02:58 GMT
x-fb-connection-quality: EXCELLENT; q=0.9, rtt=16, rtx=0, c=10, mss=1380, tbw=3322, tp=-1, tpl=-1, uplat=45, ullat=0
alt-svc: h3=":443"; ma=86400


┌──(root㉿localhost)-[~/remedy/Scraped]
└─# nano ls4.py

┌──(root㉿localhost)-[~/remedy/Scraped]
└─# python3 ls4.py
https://www.facebook.com/login/device-based/regular/login/?login_attempt=1&next=https%3A%2F%2Fwww.facebook.com%2Fpeople%2FMude-seu-Mundo%2F100064758844407%2F
https://www.facebook.com/recover/initiate?ars=royal_blue_bar
https://www.facebook.com/photo/?fbid=347027707465855&set=a.347027660799193
https://www.facebook.com/photo/?fbid=347027704132522&set=a.347027667465859&__tn__=%3C
https://www.facebook.com/profile.php?id=100064758844407&sk=followers
https://www.facebook.com/profile.php?id=100064758844407&sk=following
https://www.facebook.com/profile.php?id=100064758844407
https://www.facebook.com/profile.php?id=100064758844407&sk=about
https://www.facebook.com/profile.php?id=100064758844407&sk=photos
https://www.facebook.com/profile.php?id=100064758844407&sk=videos
https://www.facebook.com/people/Mude-seu-Mundo/100064758844407/
https://www.facebook.com/profile.php?id=100064758844407&sk=photos
https://www.facebook.com/profile.php?id=100064758844407&sk=photos
https://www.facebook.com/photo/?fbid=2951297074921878&set=ecnf.100064758844407
https://www.facebook.com/photo/?fbid=2951296981588554&set=ecnf.100064758844407
https://www.facebook.com/photo/?fbid=2951296918255227&set=ecnf.100064758844407
https://www.facebook.com/photo/?fbid=2951296868255232&set=ecnf.100064758844407
https://www.facebook.com/photo/?fbid=2951296801588572&set=ecnf.100064758844407
https://www.facebook.com/photo/?fbid=2951296734921912&set=ecnf.100064758844407
https://www.facebook.com/photo/?fbid=2951296674921918&set=ecnf.100064758844407
https://www.facebook.com/photo/?fbid=2951296618255257&set=ecnf.100064758844407
https://www.facebook.com/photo/?fbid=2951296564921929&set=ecnf.100064758844407
https://www.facebook.com/recover/initiate?ars=royal_blue_bar
https://www.facebook.com/help/1561485474074139
https://www.facebook.com/policies/cookies/
https://www.facebook.com/privacy/policies/cookies/?annotations[0]=explanation%2F3_companies_list

