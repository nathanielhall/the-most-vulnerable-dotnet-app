# 🔒 CodeMender Security Report

*Generated: 2026-08-20 11:22:28 UTC*

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
| `eff1be66` | 🔴 CRITICAL | 100% | OPEN | — | `DotnetSecurityFailures/Services/VulnerableCommandService.cs` | OS Command Injection via Shell Execution |
| `0e664ea1` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/XssSvgController.cs` | Server-Side Request Forgery (SSRF) via SVG Image Processing |
| `8b4c1927` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/IdorController.cs` | Privilege Escalation via Mass Assignment / Insecure Role Registration |
| `078eeaf6` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/VulnerableFileUploadController.cs` | Stored Cross-Site Scripting (XSS) via Unvalidated File Content-Type Serving |
| `e10c4aa6` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/XxeInjectionController.cs` | XML External Entity (XXE) Injection |
| `44d878fb` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/ZipSlipController.cs` | Zip Slip Arbitrary File Write via ZIP Extraction |
| `839ee163` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/SsrfController.cs` | Server-Side Request Forgery (SSRF) |
| `c0653b8e` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/ArbitraryFileWriteController.cs` | Arbitrary File Write via Path Traversal |
| `5d5330a3` | 🟠 HIGH | 100% | OPEN | — | `DotnetSecurityFailures/Controllers/PathTraversalController.cs` | Arbitrary File Read via Path Traversal |

## Details

### 1. 🔴 OS Command Injection via Shell Execution (`eff1be66`)

- **Severity**: 🔴 CRITICAL
- **Status**: OPEN
- **Type**: Command Injection
- **File**: `DotnetSecurityFailures/Services/VulnerableCommandService.cs` (L21–79)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `VulnerableCommandService` class contains an `ExecuteCommandVulnerable` method that accepts user input and directly concatenates it into the shell command arguments (`/c echo Processing: {userInput}` or `-c "echo Processing: {userInput}"`). An attacker can exploit this via command chaining/separators (such as `&`, `&&`, `|`, `;`) to execute arbitrary operating system commands with the privileges of the running application process. This vulnerability is reachable via the Blazor interactive UI component at `/vulnerabilities/command-injection`.

Conceptual Exploit Payload:
Input: `test & whoami` (on Windows) or `test; whoami` (on Linux) triggers the execution of `whoami` after echoing `Processing: test`.

</details>

<details>
<summary>Vulnerable Snippet</summary>

```
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
```

</details>

---

### 2. 🔴 Server-Side Request Forgery (SSRF) via SVG Image Processing (`0e664ea1`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: SSRF
- **File**: `DotnetSecurityFailures/Controllers/XssSvgController.cs` (L35–116)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `XssSvgController` contains an endpoint `/api/vulnerabilities/xss-svg/process` that accepts arbitrary SVG content inside `SvgUploadRequest`. The controller parses the XML and extracts any `<image>` element href attribute using `XDocument.Parse` and then goes on to perform an outbound GET request on each of those URLs. This allows an attacker to cause Server-Side Request Forgery (SSRF) by supplying URLs to internal resources, databases, or local services via the SVG image href attributes.

Conceptual Exploit Payload:
POST /api/vulnerabilities/xss-svg/process HTTP/1.1
Host: localhost:7124
Content-Type: application/json

{
  "SvgContent": "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\"><image href=\"http://localhost:5003\" /></svg>"
}

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
```

</details>

---

### 3. 🔴 Privilege Escalation via Mass Assignment / Insecure Role Registration (`8b4c1927`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Mass Assignment
- **File**: `DotnetSecurityFailures/Controllers/IdorController.cs` (L43–75)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `IdorController` registers new users via `/api/vulnerabilities/idor/register`. The endpoint accepts a `RegistrationRequest` JSON body which includes a `Role` property. In the register function, the controller maps the user-provided `Role` directly to the newly created user without checking if the current requester is authorized to assign this role (there is no validation at all, assigning "User" as default but trusting any input). This enables Privilege Escalation / Mass Assignment, where any user can register themselves with "Admin" or "SuperAdmin" privileges.

Conceptual Exploit Payload:
POST /api/vulnerabilities/idor/register HTTP/1.1
Host: localhost:7124
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

        return Ok(new 
        { 
            success = true,
            message = $"User registered successfully with role: {user.Role}",
            userId = user.Id,
            username = user.Name,
            email = user.Email,
            role = user.Role,
            isPrivileged = user.Role == "Admin" || user.Role == "SuperAdmin"
        });
    }
```

</details>

---

### 4. 🔴 Stored Cross-Site Scripting (XSS) via Unvalidated File Content-Type Serving (`078eeaf6`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Web Security
- **File**: `DotnetSecurityFailures/Controllers/VulnerableFileUploadController.cs` (L57–75)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `VulnerableFileUploadController` exposes an upload API `/api/files/upload` where users can upload files by specifying an arbitrary `Filename` and `Content`. In `ViewFile` (`/api/files/view/{fileId}`), the application serves the uploaded file's content using the `text/html` Content-Type (`return File(fileBytes, "text/html")`) regardless of the original file extension or content. This enables a Stored Cross-Site Scripting (XSS) vulnerability, as an attacker can upload a malicious HTML file containing executable JavaScript, which will run in the user's browser context when accessed.

Conceptual Exploit Payload:
POST /api/files/upload HTTP/1.1
Host: localhost:7124
Content-Type: application/json

{
  "Filename": "exploit.html",
  "Content": "<script>alert(document.cookie)</script>"
}

When the file is viewed via GET `/api/files/view/{fileId}`, the script executes.

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

### 5. 🔴 XML External Entity (XXE) Injection (`e10c4aa6`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: XXE
- **File**: `DotnetSecurityFailures/Controllers/XxeInjectionController.cs` (L44–91)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `XxeInjectionController` includes two endpoints (`/api/xxe/process-user` and `/api/xxe/parse`) that accept user-provided XML strings and process them with unsafe configurations. Specifically, in `ProcessUserXml`, it instantiates `XmlDocument` and explicitly sets `doc.XmlResolver = new XmlUrlResolver()`, enabling external entity resolution. In `ParseXml`, it creates an `XmlReader` with `DtdProcessing = DtdProcessing.Parse` and `XmlResolver = new XmlUrlResolver()`. An attacker can send an XML payload with a custom `DOCTYPE` and external entity referencing a local file or internal URL (SSRF), extracting confidential data via the parsed inner text.

Conceptual Exploit Payload:
POST /api/xxe/process-user HTTP/1.1
Host: localhost:7124
Content-Type: application/json

{
  "XmlContent": "<?xml version=\"1.0\"?><!DOCTYPE doc [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><user><name>&xxe;</name><email>test@example.com</email><bio>test</bio></user>"
}

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

### 6. 🔴 Zip Slip Arbitrary File Write via ZIP Extraction (`44d878fb`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Path Traversal
- **File**: `DotnetSecurityFailures/Controllers/ZipSlipController.cs` (L29–125)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `ZipSlipController` extracts uploading zip files via `ZipFile.OpenRead(tempZipPath)`. For each entry, it constructs the target extraction path using `Path.GetFullPath(Path.Combine(ExtractDirectory, entry.FullName))` and proceeds to extract the entry using `entry.ExtractToFile(fullPath, overwrite: true)` without validating that the path resolved from `entry.FullName` does not escape `ExtractDirectory`. An attacker can craft a ZIP file where entry names contain `../` directory traversal sequences, enabling Zip Slip arbitrary file writing.

Conceptual Exploit Payload:
A zip file containing an entry named `../../wwwroot/evil.txt` with malicious payload. When uploaded via POST to `/api/zip/extract`, it gets written outside `ExtractDirectory` into the web root.

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

### 7. 🔴 Server-Side Request Forgery (SSRF) (`839ee163`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: SSRF
- **File**: `DotnetSecurityFailures/Controllers/SsrfController.cs` (L29–75)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `SsrfController` exposes an endpoint `/api/vulnerabilities/ssrf/fetch` that takes a `url` query parameter and directly fetches it using `HttpClient.GetAsync` without any host validation or restriction. This lets an attacker perform Server-Side Request Forgery (SSRF) to read internal pages (such as the simulated internal admin panel on port 5003 or local cloud metadata service `169.254.169.254`).

Conceptual Exploit Payload:
GET /api/vulnerabilities/ssrf/fetch?url=http://localhost:5003 HTTP/1.1
Host: localhost:7124

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

### 8. 🔴 Arbitrary File Write via Path Traversal (`c0653b8e`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Path Traversal
- **File**: `DotnetSecurityFailures/Controllers/ArbitraryFileWriteController.cs` (L28–76)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `ArbitraryFileWriteController` contains a `save` endpoint which allows saving backups using a JSON body. The user can supply `request.FileName`, which is concatenated with `_baseDirectory` via `Path.Combine(_baseDirectory, request.FileName)` without validation, enabling directory traversal (e.g., using `../`). This allows an attacker to write any content to any directory on the filesystem where the application has write permissions (such as overwriting config files or system files).

Conceptual Exploit Payload:
POST /api/vulnerabilities/arbitrary-file-write/save HTTP/1.1
Host: localhost:7124
Content-Type: application/json

{
  "FileName": "../evil.txt",
  "Content": "compromised"
}

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

            var actualPath = Path.GetFullPath(filePath);
            var isOutsideBase = !actualPath.StartsWith(
                Path.GetFullPath(_baseDirectory), 
                StringComparison.OrdinalIgnoreCase
            );

            return Ok(new
            {
                success = true,
                fileName = request.FileName,
                actualPath = actualPath,
                isVulnerable = isOutsideBase,
                message = isOutsideBase 
                    ? "ARBITRARY FILE WRITE SUCCESSFUL!" 
                    : "Backup saved successfully"
            });
        }
        catch (Exception ex)
        {
            return Ok(new
            {
                success = false,
                message = $"Error: {ex.Message}",
                fileName = request.FileName
            });
        }
    }
```

</details>

---

### 9. 🔴 Arbitrary File Read via Path Traversal (`5d5330a3`)

- **Severity**: 🟠 HIGH
- **Status**: OPEN
- **Type**: Path Traversal
- **File**: `DotnetSecurityFailures/Controllers/PathTraversalController.cs` (L34–61)
- **Confidence**: 100%

<details>
<summary>Analysis</summary>

The `PathTraversalController` contains a file download endpoint `/api/vulnerabilities/path-traversal/download` which accepts an untrusted `filename` query parameter. This value is directly passed to `Path.Combine(DocumentsPath, filename)` without validating that the resulting path stays within the intended `DocumentsPath` directory. An attacker can use directory traversal sequences (e.g., `../../`) to escape the directory and read arbitrary files on the system, such as `appsettings.json`.

Conceptual Exploit Payload:
GET /api/vulnerabilities/path-traversal/download?filename=../../appsettings.json HTTP/1.1
Host: localhost:7124

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

