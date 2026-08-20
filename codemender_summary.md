# 🔒 CodeMender Security Report

*Generated: 2026-08-20 12:42:10 UTC*

## Summary

**Total findings: 15**

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 1 |
| 🟠 HIGH | 14 |

| Status | Count |
|--------|-------|
| 🔴 OPEN | 15 |

## Findings

| ID | Severity | Confidence | Status | Fix | File | Title |
|----|----------|------------|--------|-----|------|-------|
| `d344b6f5` | 🔴 CRITICAL | 100% | OPEN | — | `DotnetSecurityFailures/Services/VulnerableCommandService.cs` | OS Command Injection / Remote Code Execution via Concatenated Process Arguments |
| `1568a881` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Services/VulnerableNoSQLService.cs` | NoSQL Injection via Unsanitized JSON Query Construction |
| `6f889db2` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Services/VulnerableDatabaseService.cs` | SQL Injection (SQLi) via Concatenated Username in Sqlite Database Query |
| `4ed880a6` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/PathTraversalController.cs` | Path Traversal / Arbitrary File Read via filename Parameter |
| `32e894ae` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/ArbitraryFileWriteController.cs` | Arbitrary File Write / Path Traversal via FileName Parameter |
| `435bdb2f` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/SsrfController.cs` | Server-Side Request Forgery (SSRF) via url Parameter |
| `c02eccc8` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/ZipSlipController.cs` | Arbitrary File Write / Path Traversal via ZIP Archive Extraction (Zip Slip) |
| `31316a1c` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/VulnerableFileUploadController.cs` | Stored Cross-Site Scripting (XSS) via Unvalidated Content-Type on Uploaded Files |
| `d2a62fa6` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/XssSvgController.cs` | Server-Side Request Forgery (SSRF) via SVG Image Processing |
| `d90b7ed4` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/XxeInjectionController.cs` | XML External Entity (XXE) Injection in ProcessUserXml Endpoint |
| `8a430f35` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/XxeInjectionController.cs` | XML External Entity (XXE) Injection in ParseXml Endpoint |
| `f3b33a56` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/VulnerableJwtController.cs` | Bypass of JWT Signature Validation (Algorithm None / Missing Signature) |
| `98c13a8c` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/VulnerableUserProfileController.cs` | Insecure Direct Object Reference (IDOR) on User Profiles Leaking PII |
| `4e33d5a6` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/IdorController.cs` | Insecure Direct Object Reference (IDOR) on idor/profile Endpoint |
| `0aaaee28` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/PrivilegeEscalationController.cs` | Privilege Escalation via User-Controlled Role Parameter during Registration |

## Details

### 1. 🔴 OS Command Injection / Remote Code Execution via Concatenated Process Arguments (`d344b6f5`)

- **Severity**: 🔴 CRITICAL
- **Status**: OPEN
- **Type**: Command Injection
- **File**: `DotnetSecurityFailures/Services/VulnerableCommandService.cs` (L21–79)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

In `VulnerableCommandService.cs`, the method `ExecuteCommandVulnerable` accepts an unvalidated string parameter `userInput`. Depending on the host OS, it starts a command shell (using `cmd.exe` on Windows or `/bin/sh` on Unix-like operating systems) with arguments constructed by concatenating the user input: `$" /c echo Processing: {userInput}"` or `$"-c \"echo Processing: {userInput}\""`. Since the input is directly interpolated into the command string without any sanitization, validation, or escaping, an attacker can append command operators (such as `&`, `&&`, `|`, `;`) followed by arbitrary system commands. These arbitrary commands are then executed by the system shell with the same privileges as the running web application, leading to Remote Code Execution (RCE).

- **Source**: `userInput` string parameter passed to `ExecuteCommandVulnerable` via the `/vulnerabilities/command-injection` page's user input field (line 13 in `CommandInjection.razor`, line 21 in `VulnerableCommandService.cs`).
- **Sanitization**: None.
- **Sink**: `Process.Start(processInfo)` where `processInfo` contains the concatenated command line (line 44 in `VulnerableCommandService.cs`).

**Conceptual Exploit Payload**:
On Windows:
`test & calc`
or:
`test && whoami`

On Unix/Linux:
`test; id`
or:
`test && whoami`

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

### 2. 🔴 NoSQL Injection via Unsanitized JSON Query Construction (`1568a881`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Injection
- **File**: `DotnetSecurityFailures/Services/VulnerableNoSQLService.cs` (L57–89)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

In `VulnerableNoSQLService.cs`, the `AuthenticateUserVulnerable` method constructs a JSON query string for LiteDB by direct string concatenation of user-supplied `username` and `password` variables: `$"{{ \"username\": {username}, \"password\": {password} }}"` (line 63). Because the inputs are not validated or safely serialized, an attacker can supply JSON payloads to inject NoSQL operators (such as `{"$ne": ""}`) to manipulate the query logic. For instance, using `{"$ne": ""}` for the password bypasses the password check entirely, allowing unauthorized authentication as any existing user.

- **Source**: `username` and `password` parameters in `AuthenticateUserVulnerable` (line 57).
- **Sanitization**: None.
- **Sink**: `JsonSerializer.Deserialize<JsonDocument>(queryJson)` (line 66) which constructs a filter used to locate matching users.

**Conceptual Exploit Payload**:
- Input for `username`: `"admin"`
- Input for `password`: `{"$ne": ""}`

This compiles the JSON filter into:
`{ "username": "admin", "password": {"$ne": ""} }`
Which returns the `admin` user because their password is not empty, completely bypassing authentication.

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

### 3. 🔴 SQL Injection (SQLi) via Concatenated Username in Sqlite Database Query (`6f889db2`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Injection
- **File**: `DotnetSecurityFailures/Services/VulnerableDatabaseService.cs` (L67–118)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

In `VulnerableDatabaseService.cs`, the method `SearchUserVulnerable` accepts user input through the `username` parameter. It directly concatenates this input into a SQL query string: `$"SELECT * FROM Users WHERE Username = '{username}' AND IsActive = 1"`. Since there is no escaping, sanitization, or parametrization on `username`, an attacker can inject arbitrary SQL payloads. This allows SQL Injection (SQLi), which can be used to bypass authentication (e.g., retrieving inactive users), perform UNION-based queries to exfiltrate sensitive data from other tables (such as the `Secrets` table containing API keys and passwords), or cause denial of service.

- **Source**: `username` string parameter passed to `SearchUserVulnerable` via the `/vulnerabilities/sql-injection` page's user input field (line 16 in `SqlInjection.razor`, line 67 in `VulnerableDatabaseService.cs`).
- **Sanitization**: None.
- **Sink**: `command.ExecuteReader()` with unparametrized query text (line 79 in `VulnerableDatabaseService.cs`).

**Conceptual Exploit Payload**:
`' UNION SELECT 1, SecretKey, SecretValue, 'Manager', 1 FROM Secrets --`
or simply bypass conditions:
`admin' OR '1'='1`

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

### 4. 🔴 Path Traversal / Arbitrary File Read via filename Parameter (`4ed880a6`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Path Traversal
- **File**: `DotnetSecurityFailures/Controllers/PathTraversalController.cs` (L34–61)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

In `PathTraversalController.cs`, the `DownloadFile` endpoint accepts user input through the `filename` query parameter. This input is directly passed to `Path.Combine(DocumentsPath, filename)` without any validation or sanitization. Since there is no validation to ensure that the file stays within `DocumentsPath` (e.g., checking if the canonical path starts with the base path), an attacker can use path traversal sequences such as `../` or `..\\` to escape the `Documents` directory and read arbitrary files from the filesystem.

- **Source**: `filename` query parameter in `DownloadFile` method (line 35)
- **Sanitization**: None. (It only checks if `filename` is empty or whitespace)
- **Sink**: `System.IO.File.Exists(filePath)` and `System.IO.File.ReadAllText(filePath)` (lines 47, 52)

**Conceptual Exploit Payload**:
`GET /api/vulnerabilities/path-traversal/download?filename=../../../../etc/passwd`
or for Windows:
`GET /api/vulnerabilities/path-traversal/download?filename=..\..\..\..\Windows\win.ini`

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
    [HttpGet(\"download\")]
    public IActionResult DownloadFile([FromQuery] string filename)
    {
        LogDemoActivity(\"DownloadFile\", $"Attempting to download: {filename}");
        
        if (string.IsNullOrWhiteSpace(filename))
        {
            return BadRequest(new { success = false, message = "Filename is required" });
        }

        // VULNERABLE: User input directly concatenated to path
        var filePath = Path.Combine(DocumentsPath, filename);

        if (!System.IO.File.Exists(filePath))
        {
            return NotFound(new { success = false, message = "File not found" });
        }

        var fileContent = System.IO.File.ReadAllText(filePath);
```

</details>

---

### 5. 🔴 Arbitrary File Write / Path Traversal via FileName Parameter (`32e894ae`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Path Traversal
- **File**: `DotnetSecurityFailures/Controllers/ArbitraryFileWriteController.cs` (L28–65)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

In `ArbitraryFileWriteController.cs`, the `SaveBackup` endpoint accepts user input through the `request.FileName` property in the request body. This input is directly concatenated to `_baseDirectory` via `Path.Combine(_baseDirectory, request.FileName)` without prior validation. Although the code later checks if the path resolves to a location outside `_baseDirectory` (setting `isVulnerable = isOutsideBase`), it does so *after* writing the file using `System.IO.File.WriteAllText(filePath, request.Content)`. Therefore, an attacker can write arbitrary files to anywhere on the system that the application has write permissions for (e.g., placing a malicious web shell or overwriting critical configuration/system files).

- **Source**: `request.FileName` and `request.Content` properties in JSON body (lines 29-30)
- **Sanitization**: None before writing the file. (The check occurs after the file has already been written)
- **Sink**: `System.IO.File.WriteAllText(filePath, request.Content)` (line 48)

**Conceptual Exploit Payload**:
```http
POST /api/vulnerabilities/arbitrary-file-write/save HTTP/1.1
Content-Type: application/json

{
  "FileName": "../../../wwwroot/shell.html",
  "Content": "<html><body><h1>Hacked</h1></body></html>"
}
```

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
    [HttpPost("save")]
    public IActionResult SaveBackup([FromBody] BackupRequest request)
    {
        LogDemoActivity("SaveBackup", $"Attempting to write file: {request.FileName}");
        
        if (string.IsNullOrWhiteSpace(request.FileName))
        {
            return BadRequest(new { success = false, message = "Filename is required" });
        }

        if (string.IsNullOrWhiteSpace(request.Content))
        {
            return BadRequest(new { success = false, message = "Content is required" });
        }

        try
        {
            // VULNERABLE: Direct path concatenation without validation
            var filePath = Path.Combine(_baseDirectory, request.FileName);
            
            System.IO.File.WriteAllText(filePath, request.Content);
```

</details>

---

### 6. 🔴 Server-Side Request Forgery (SSRF) via url Parameter (`435bdb2f`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: SSRF
- **File**: `DotnetSecurityFailures/Controllers/SsrfController.cs` (L29–75)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

In `SsrfController.cs`, the `FetchUrl` endpoint accepts user input through the `url` query parameter. This URL is retrieved directly without any validation, sanitation, or restriction of destination addresses (such as verifying against an allowlist or blocking loopback/private IP addresses). The application then issues a GET request using `_httpClient.GetAsync(url)`. This allows an attacker to perform Server-Side Request Forgery (SSRF) to scan internal ports, interact with local or internal microservices, or read cloud metadata endpoints (e.g., `http://169.254.169.254/`).

- **Source**: `url` query parameter in `FetchUrl` (line 30)
- **Sanitization**: None. (It only logs if the URL is internal *after* fetching it, or uses `IsInternalUrl` to return whether it is vulnerable, but it does not block or validate the request beforehand)
- **Sink**: `_httpClient.GetAsync(url)` (line 42)

**Conceptual Exploit Payload**:
`GET /api/vulnerabilities/ssrf/fetch?url=http://127.0.0.1:5000/internal-api`
or:
`GET /api/vulnerabilities/ssrf/fetch?url=http://169.254.169.254/latest/meta-data/`

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
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
            var content = await response.Content.ReadAsStringAsync();
```

</details>

---

### 7. 🔴 Arbitrary File Write / Path Traversal via ZIP Archive Extraction (Zip Slip) (`c02eccc8`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Path Traversal
- **File**: `DotnetSecurityFailures/Controllers/ZipSlipController.cs` (L29–101)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

In `ZipSlipController.cs`, the `ExtractZip` endpoint extracts files from a user-uploaded ZIP archive without validation. The application retrieves the `entry.FullName` from the ZIP entries, uses it in `Path.GetFullPath(Path.Combine(ExtractDirectory, entry.FullName))` (line 61), and extracts the file to that resolved path using `entry.ExtractToFile(fullPath, overwrite: true)` (line 84). Because there is no check preventing files with traversal sequences (e.g. `../../`) from being written outside of `ExtractDirectory`, an attacker can craft a ZIP file containing files with path traversal names to write arbitrary files to any location on the system where the application has write permissions.

- **Source**: `zipFile` form parameter in `ExtractZip` (line 31)
- **Sanitization**: None before extraction. (It tracks `isTraversal` and adds a warning to the response, but it still performs the extraction to `fullPath` first!)
- **Sink**: `entry.ExtractToFile(fullPath, overwrite: true)` (line 84)

**Conceptual Exploit Payload**:
Create a ZIP archive containing a file entry named `../../../../wwwroot/exploit.aspx` (or similar depending on system paths), and upload it to `/api/zip/extract`. The file will be written outside the extraction target directory.

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
    [HttpPost("extract")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> ExtractZip([FromForm] IFormFile zipFile)
    {
        LogDemoActivity("ExtractZip", $"Extracting ZIP file: {zipFile?.FileName}");
        
        if (zipFile == null || zipFile.Length == 0)
        {
            return BadRequest(new { success = false, message = "No file provided" });
        }

        try
        {
            var tempZipPath = Path.GetTempFileName();
            using (var stream = new FileStream(tempZipPath, FileMode.Create))
            {
                await zipFile.CopyToAsync(stream);
            }

            var extractedFiles = new List<ExtractedFileInfo>();
            var warnings = new List<string>();

            using (var archive = ZipFile.OpenRead(tempZipPath))
            {
                var normalizedTargetDir = Path.GetFullPath(ExtractDirectory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;

                foreach (var entry in archive.Entries)
                {
                    if (string.IsNullOrEmpty(entry.Name))
                        continue;

                    // VULNERABLE: No validation before extraction
                    var fullPath = Path.GetFullPath(Path.Combine(ExtractDirectory, entry.FullName));

                    var isTraversal = !fullPath.StartsWith(
                        normalizedTargetDir,
                        StringComparison.OrdinalIgnoreCase);

                    extractedFiles.Add(new ExtractedFileInfo
                    {
                        EntryName = entry.FullName,
                        ResolvedPath = fullPath,
                        IsTraversal = isTraversal,
                        WasExtracted = false
                    });

                    // VULNERABLE: Extract file WITHOUT validation
                    try
                    {
                        var directoryPath = Path.GetDirectoryName(fullPath);
                        if (!string.IsNullOrEmpty(directoryPath) && !Directory.Exists(directoryPath))
                        {
                            Directory.CreateDirectory(directoryPath);
                        }

                        entry.ExtractToFile(fullPath, overwrite: true);
```

</details>

---

### 8. 🔴 Stored Cross-Site Scripting (XSS) via Unvalidated Content-Type on Uploaded Files (`31316a1c`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Web Security
- **File**: `DotnetSecurityFailures/Controllers/VulnerableFileUploadController.cs` (L57–75)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

In `VulnerableFileUploadController.cs`, the `Upload` endpoint accepts any uploaded file and writes its user-supplied content to a unique file path under a temp directory. Crucially, the `ViewFile` endpoint (lines 57-75) serves the uploaded file using the `text/html` Content-Type header explicitly, without checking the file's original format or content-type. Because of this, an attacker can upload a file containing malicious HTML and JavaScript code, and then access it via `/api/files/view/{fileId}`. The victim's browser will execute the JavaScript in the context of the application's origin, leading to stored Cross-Site Scripting (XSS).

- **Source**: `request.Content` and `request.Filename` in the JSON request body to `Upload` (lines 24-25)
- **Sanitization**: None.
- **Sink**: `return File(fileBytes, "text/html")` (line 74)

**Conceptual Exploit Payload**:
1. Upload a file with HTML/JavaScript content:
```http
POST /api/files/upload HTTP/1.1
Content-Type: application/json

{
  "Filename": "exploit.html",
  "Content": "<html><body><script>alert(document.domain)</script></body></html>"
}
```
2. The response returns a `fileId` (e.g., `abc-123`).
3. Point a victim to: `/api/files/view/abc-123`. The browser executes `alert(document.domain)`.

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
    // VULNERABLE: Serves files without proper Content-Type validation
    [HttpGet("view/{fileId}")]
    public IActionResult ViewFile(string fileId)
    {
        if (!UploadedFiles.TryGetValue(fileId, out var uploadedFile))
        {
            return NotFound(new { success = false, message = "File not found" });
        }

        if (!System.IO.File.Exists(uploadedFile.FilePath))
        {
            return NotFound(new { success = false, message = "File not found on disk" });
        }

        var fileBytes = System.IO.File.ReadAllBytes(uploadedFile.FilePath);

        // VULNERABLE: Always serves as text/html without validation!
        // This allows XSS when HTML files with scripts are uploaded
        return File(fileBytes, "text/html");
    }
```

</details>

---

### 9. 🔴 Server-Side Request Forgery (SSRF) via SVG Image Processing (`d2a62fa6`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: SSRF
- **File**: `DotnetSecurityFailures/Controllers/XssSvgController.cs` (L35–116)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

In `XssSvgController.cs`, the `ProcessSvg` endpoint allows users to process an SVG payload. The controller parses the XML content using `XDocument.Parse` and then extracts the `href` values of all `<image>` elements. For each non-data URI reference, it initiates an HTTP GET request using `_httpClient.GetAsync(href)` without validating if the host is an internal address or if it is allowed. An attacker can supply an SVG document containing external images pointing to local loopback addresses (like `http://127.0.0.1/`) or cloud metadata endpoints. The application will fetch the requested internal URL and leak back the response code and content preview, enabling a Server-Side Request Forgery (SSRF) attack.

- **Source**: `request.SvgContent` in the request body (line 37)
- **Sanitization**: None before calling `GetAsync`. (The code checks if `IsInternalUrl` is true *after* or alongside the request, but does not block it).
- **Sink**: `_httpClient.GetAsync(href)` (line 69)

**Conceptual Exploit Payload**:
```http
POST /api/vulnerabilities/xss-svg/process HTTP/1.1
Content-Type: application/json

{
  "SvgContent": "<svg xmlns=\"http://www.w3.org/2000/svg\"><image href=\"http://127.0.0.1:8080/admin\"/></svg>"
}
```

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
    [HttpPost("process")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> ProcessSvg([FromBody] SvgUploadRequest request)
    {
        LogDemoActivity("EmbedExternalImages", "Embedding external images into SVG (SSRF risk)");
        
        if (string.IsNullOrWhiteSpace(request.SvgContent))
        {
            return BadRequest(new { success = false, message = "SVG content is required" });
        }

        var externalRequests = new List<ExternalRequestInfo>();

        try
        {
            var doc = XDocument.Parse(request.SvgContent);
            var ns = XNamespace.Get("http://www.w3.org/2000/svg");

            var images = doc.Descendants(ns + "image")
                .Select(e => e.Attribute("href")?.Value ?? e.Attribute(XNamespace.Get("http://www.w3.org/1999/xlink") + "href")?.Value)
                .Where(href => !string.IsNullOrEmpty(href) && !href.StartsWith("data:"))
                .ToList();

            // DANGEROUS: Fetch each external URL (SSRF risk)
            foreach (var href in images)
            {
                var requestInfo = new ExternalRequestInfo
                {
                    Url = href,
                    IsInternal = IsInternalUrl(href)
                };

                try
                {
                    var response = await _httpClient.GetAsync(href);
```

</details>

---

### 10. 🔴 XML External Entity (XXE) Injection in ProcessUserXml Endpoint (`d90b7ed4`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: XXE Injection
- **File**: `DotnetSecurityFailures/Controllers/XxeInjectionController.cs` (L44–91)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

In `XxeInjectionController.cs`, the `ProcessUserXml` endpoint is vulnerable to XML External Entity (XXE) Injection. The code parses user-supplied XML by explicitly enabling `XmlResolver` (assigning `doc.XmlResolver = new XmlUrlResolver()`). Under normal .NET behavior, this configuration allows the XML parser to process external DTDs and resolve external entities. An attacker can craft an XML input containing an external entity referencing a local system file (e.g., `file:///etc/passwd` or a Windows path) or an internal network resource, causing the application to read the file or perform SSRF, and then return the content in the response.

- **Source**: `request.XmlContent` in the request body (line 45)
- **Sanitization**: None.
- **Sink**: `doc.LoadXml(request.XmlContent)` (line 59)

**Conceptual Exploit Payload**:
```http
POST /api/xxe/process-user HTTP/1.1
Content-Type: application/json

{
  "XmlContent": "<?xml version=\"1.0\" encoding=\"utf-8\"?><!DOCTYPE doc [<!ENTITY xxe SYSTEM \"file:///C:/Windows/win.ini\">]><user><name>&xxe;</name><email>test@test.com</email><bio>bio</bio></user>"
}
```

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
    [HttpPost("process-user")]
    public IActionResult ProcessUserXml([FromBody] XmlRequest request)
    {
        LogDemoActivity("ProcessUserXml", "Processing XML with XmlResolver enabled (VULNERABLE)");

        if (string.IsNullOrWhiteSpace(request.XmlContent))
        {
            return BadRequest(new { Success = false, Error = "XML content is required" });
        }

        try
        {
            // VULNERABLE: Explicitly enabling XmlResolver
            var doc = new XmlDocument();
            doc.XmlResolver = new XmlUrlResolver(); // DANGEROUS!
            doc.LoadXml(request.XmlContent);
```

</details>

---

### 11. 🔴 XML External Entity (XXE) Injection in ParseXml Endpoint (`8a430f35`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: XXE Injection
- **File**: `DotnetSecurityFailures/Controllers/XxeInjectionController.cs` (L147–201)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

In `XxeInjectionController.cs`, the `ParseXml` endpoint parses user-supplied XML content using `XmlReaderSettings` configured with `DtdProcessing = DtdProcessing.Parse` and `XmlResolver = new XmlUrlResolver()`. This configuration permits the parsing of Document Type Definitions (DTDs) and resolves external entities, exposing the endpoint to XML External Entity (XXE) injection attacks. An attacker can use this endpoint to fetch internal files or launch SSRF attacks.

- **Source**: `request.XmlContent` in the request body (line 148)
- **Sanitization**: None.
- **Sink**: `doc.Load(xmlReader)` (line 170)

**Conceptual Exploit Payload**:
```http
POST /api/xxe/parse HTTP/1.1
Content-Type: application/json

{
  "XmlContent": "<?xml version=\"1.0\" encoding=\"utf-8\"?><!DOCTYPE doc [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root><data>&xxe;</data></root>"
}
```

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
    [HttpPost("parse")]
    public IActionResult ParseXml([FromBody] XmlRequest request)
    {
        LogDemoActivity("ParseXml", "Parsing XML with external entities enabled");
        
        if (string.IsNullOrWhiteSpace(request.XmlContent))
        {
            return BadRequest(new { success = false, message = "XML content is required" });
        }

        try
        {
            // VULNERABLE: XmlReaderSettings with DTD processing enabled
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Parse, // DANGEROUS!
                XmlResolver = new XmlUrlResolver() // DANGEROUS!
            };

            using var stringReader = new StringReader(request.XmlContent);
            using var xmlReader = XmlReader.Create(stringReader, settings);

            var doc = new XmlDocument();
            doc.Load(xmlReader);
```

</details>

---

### 12. 🔴 Bypass of JWT Signature Validation (Algorithm None / Missing Signature) (`f3b33a56`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Web Security
- **File**: `DotnetSecurityFailures/Controllers/VulnerableJwtController.cs` (L12–103)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

In `VulnerableJwtController.cs`, the manual JWT validator in the `ValidateToken` method parses JWTs without verifying their signatures. Specifically, the method splits the token by `.` (line 24) and directly decodes and deserializes the payload (line 36-37) without verifying the signature against a secret key. Furthermore, the controller explicitly accepts tokens with the `alg` header set to `none` (lines 44-55) or tokens missing a signature altogether (lines 58-69). This allows attackers to forge JWTs, manipulate claims (such as setting the `role` claim to `admin`), and completely bypass authentication or authorization checks.

- **Source**: `request.Token` in the JSON request body (line 13)
- **Sanitization**: None. (There is no verification step using a secure key).
- **Sink**: The decoded payload is trusted as valid (lines 72-87)

**Conceptual Exploit Payload**:
We can generate a forged JWT payload representing an admin:
- Header: `{"alg":"none","typ":"JWT"}` -> Base64Url encoded: `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0`
- Payload: `{"role":"admin","sub":"attacker"}` -> Base64Url encoded: `eyJyb2xlIjoiYWRtaW4iLCJzdWIiOiJhdHRhY2tlciJ9`
- Token (no signature): `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4iLCJzdWIiOiJhdHRhY2tlciJ9.`

Request:
```http
POST /api/jwt/validate HTTP/1.1
Content-Type: application/json

{
  "Token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4iLCJzdWIiOiJhdHRhY2tlciJ9."
}
```

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
    [HttpPost("validate")]
    public IActionResult ValidateToken([FromBody] JwtValidationRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Token))
        {
            return BadRequest(new { error = "Token is required" });
        }

        try
        {
            // VULNERABLE: Developer decided to parse JWT manually instead of using AddJwtBearer
            // "It's just JSON with Base64 - I can validate it myself!"
            var parts = request.Token.Split('.');

            if (parts.Length < 2)
            {
                return BadRequest(new { error = "Invalid JWT format" });
            }

            // Decode header
            var headerJson = Encoding.UTF8.GetString(Convert.FromBase64String(AddPadding(parts[0])));
            var header = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(headerJson);

            // Decode payload (NO SIGNATURE VALIDATION!)
            var payloadJson = Encoding.UTF8.GetString(Convert.FromBase64String(AddPadding(parts[1])));
            var payload = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(payloadJson);
```

</details>

---

### 13. 🔴 Insecure Direct Object Reference (IDOR) on User Profiles Leaking PII (`98c13a8c`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Web Security
- **File**: `DotnetSecurityFailures/Controllers/VulnerableUserProfileController.cs` (L64–84)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

In `VulnerableUserProfileController.cs`, the `GetProfile` endpoint retrieves a user profile by `id`. Even though the code comments simulate a logged-in user with `currentUserId = 5`, the endpoint does not verify whether the requesting user owns the profile or has authorization to access it. Any client can request any integer ID (e.g., `1` for the Administrator account), allowing an attacker to fetch sensitive personal data such as SSNs, credit card numbers, and salary information of other users.

- **Source**: `id` route parameter in `GetProfile` method (line 65)
- **Sanitization**: None.
- **Sink**: `return Ok(new { ..., data = user })` (lines 78-83)

**Conceptual Exploit Payload**:
`GET /api/user/profile/1` - Retrieves the profile data of the Administrator (ID 1) containing sensitive SSN and salary details.

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
    // VULNERABLE: No authorization check
    [HttpGet("profile/{id}")]
    public IActionResult GetProfile(int id)
    {
        // Simulated current user (should come from authentication)
        const int currentUserId = 5;

        if (!Users.TryGetValue(id, out var user))
        {
            return NotFound(new { success = false, message = "User not found" });
        }

        // VULNERABILITY: No ownership verification!
        // The application returns any user's data without checking
        // if the current user (ID 5) has permission to access it
        return Ok(new
        {
            success = true,
            authorized = id == currentUserId,
            data = user
        });
    }
```

</details>

---

### 14. 🔴 Insecure Direct Object Reference (IDOR) on idor/profile Endpoint (`4e33d5a6`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Web Security
- **File**: `DotnetSecurityFailures/Controllers/IdorController.cs` (L24–40)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

In `IdorController.cs`, the `GetProfile` endpoint allows users to retrieve profile details using an optional `id` parameter. However, the application completely lacks any authorization or authentication check to verify whether the requester is allowed to view the resource. An attacker can supply arbitrary user IDs via the `id` query parameter to retrieve details of other users, exposing sensitive data such as SSNs and credit card numbers.

- **Source**: `id` query parameter in `GetProfile` method (line 25)
- **Sanitization**: None.
- **Sink**: `return Ok(user);` (line 39)

**Conceptual Exploit Payload**:
`GET /api/vulnerabilities/idor/profile?id=42` - Retrieves another user's profile with SSN and credit card details.

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
    // VULNERABLE: No authorization check - anyone can access any profile!
    [HttpGet("profile")]
    public IActionResult GetProfile([FromQuery] int? id)
    {
        LogDemoActivity("GetProfile", $"Accessing profile ID: {id}");
        
        var user = new User
        {
            Id = id ?? 1,
            Email = "victim@company.com",
            Name = "Current User",
            SSN = "123-45-6789",
            CreditCard = "4111-1111-1111-1111",
            Role = "User"
        };
        
        return Ok(user);
    }
```

</details>

---

### 15. 🔴 Privilege Escalation via User-Controlled Role Parameter during Registration (`0aaaee28`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Web Security
- **File**: `DotnetSecurityFailures/Controllers/PrivilegeEscalationController.cs` (L27–69)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

In `PrivilegeEscalationController.cs` and `IdorController.cs` (lines 43-75), registration endpoints accept sensitive fields, specifically the `Role` parameter, from user input during registration. The application assigns this user-provided value directly to the newly registered user object without server-side validation or restricted context (e.g., checking if the requester has permissions to set roles, or only assigning standard "User" roles on signup). This allows any registering user to gain unauthorized administrative privileges simply by setting their role to `Admin` or `SuperAdmin` in their registration request.

- **Source**: `request.Role` field in the request body of `Register` (lines 28, 108 in PrivilegeEscalationController.cs; line 44, 82 in IdorController.cs)
- **Sanitization**: None.
- **Sink**: `Role = role` (line 48 in PrivilegeEscalationController.cs), and `user.Role == "Admin"` checks.

**Conceptual Exploit Payload**:
```http
POST /api/user/register HTTP/1.1
Content-Type: application/json

{
  "Username": "attacker",
  "Email": "attacker@company.com",
  "Password": "password123",
  "Role": "Admin"
}
```
This payload will successfully register an account with `Admin` level privileges.

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
    // VULNERABLE: Accepts role from user input without validation
    [HttpPost("register")]
    public IActionResult Register([FromBody] RegistrationRequest request)
    {
        LogDemoActivity("Register", $"Registration attempt - Username: {request.Username}, Email: {request.Email}, Role: {request.Role ?? "User"}");
        
        if (string.IsNullOrWhiteSpace(request.Username) || 
            string.IsNullOrWhiteSpace(request.Email) ||
            string.IsNullOrWhiteSpace(request.Password))
        {
            return BadRequest(new { success = false, message = "Username, email, and password are required" });
        }

        // VULNERABILITY: Accepting role directly from user input!
        // This is the critical flaw - users can elevate their own privileges
        var role = request.Role ?? "User"; // Default to "User" if not provided
        
        var user = new RegisteredUser\n        {\n            UserId = _nextUserId++,\n            Username = request.Username,\n            Email = request.Email,\n            Role = role, // DANGEROUS: User-controlled value!\n            CreatedAt = DateTime.UtcNow,\n            IsPrivileged = role.Equals("Admin", StringComparison.OrdinalIgnoreCase) || \n                          role.Equals("SuperAdmin", StringComparison.OrdinalIgnoreCase)\n        };
```

</details>

---

