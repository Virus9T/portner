# 🔍 Portner - Port Specific Payload-based Port Scanner

*Portner* is a custom Python-based port scanner that not only checks for open ports but also sends *service-specific payloads* to extract potential banners or protocol responses. This tool is designed for *educational and authorized testing purposes* only.

---

## 📦 Features

- 🔢 Scans a user-defined range of ports
- 🎯 Sends tailored payloads for common services (HTTP, FTP, SMTP, SSH, SMB, etc.)
- 🧠 Falls back to a generic HTTP payload when no specific payload exists
- 🧾 Displays banners/responses received from open ports
- 🧵 Handles timeouts, connection refusals, and other exceptions gracefully
- 🌈 Color-coded output for easy reading (requires a terminal that supports ANSI colors)

---

## 📋 Usage

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/portner.git
   cd portner
   
