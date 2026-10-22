# 🧬 CyberTrace — Advanced File Metadata & Forensics Scanner

CyberTrace is a Python and Streamlit tool for defensive file metadata inspection, integrity hashing, entropy analysis, and image privacy sanitization.

## Features
- Extracts available image EXIF and GPS metadata
- Converts GPS coordinates to decimal degrees and provides map links
- Computes MD5, SHA-1, and SHA-256 checksums
- Calculates Shannon entropy on a 0–8 bits-per-byte scale
- Reads PDF metadata, page count, and encryption status using `pypdf`
- Re-encodes images as PNG without copying source EXIF metadata
- Exports JSON and plain-text audit reports
- Handles absent metadata and many invalid-file cases gracefully

> Entropy is a heuristic only; it does not prove malware, encryption, packing, or steganography. Avoid uploading confidential evidence to a public deployment.

## Run locally
Python 3.9+ is recommended.

```bash
python -m venv .venv
```

Windows PowerShell:
```powershell
.\.venv\Scripts\Activate.ps1
```

macOS/Linux:
```bash
source .venv/bin/activate
```

Install and launch:
```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run SauravKumar_CyberTrace.py
```

Open the local URL printed by Streamlit, usually `http://localhost:8501`.

## Deploy with GitHub and Streamlit Community Cloud
1. Create a GitHub repository and upload these three project files: `app.py`, `README.md`, and `requirements.txt`.
2. In [Streamlit Community Cloud](https://share.streamlit.io/), sign in with GitHub and create an app.
3. Select your repository, branch, and set **Main file path** to `app.py`.
4. Deploy. Streamlit installs the packages listed in `requirements.txt`.

To push from a local folder after creating an empty GitHub repository, run the following commands from that folder (replace `YOUR_USERNAME` with your GitHub username):

```bash
git init
git add SauravKumar_CyberTrace.py README.md requirements.txt
git commit -m "Update CyberTrace"
git branch -M main
git remote add origin https://github.com/sauravinfosec/CyberTrace.git
git push -u origin main
```

If Git is already initialized or `origin` already exists, do not repeat the corresponding setup command.

## Notes and limitations
- Application upload limit is 200 MiB; hosting providers may set a lower request limit.
- The displayed MIME type is inferred from the filename extension, not a security validation.
- Metadata availability depends on the file format and the source file.
- Sanitization creates a newly encoded PNG derivative; it is not byte-identical to the original.
- Do not execute uploaded binaries. This app only reads their bytes for hashes and entropy.
- Encrypted PDFs may not expose all metadata without a password.

## Author
**Saurav Kumar**  
Sandip University, Sijoul (Madhubani)
