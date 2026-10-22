"""
CyberTrace — Advanced File Metadata & Forensics Scanner
Author: Saurav Kumar
License: MIT
"""
from __future__ import annotations

import hashlib
import io
import json
import math
import mimetypes
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import streamlit as st
from PIL import ExifTags, Image, UnidentifiedImageError

try:
    from pypdf import PdfReader
    PYPDF_AVAILABLE = True
except ImportError:
    PdfReader = None
    PYPDF_AVAILABLE = False

APP_VERSION = "1.1.0"
MAX_FILE_SIZE = 200 * 1024 * 1024
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".webp", ".bmp", ".gif"}

st.set_page_config(
    page_title="CyberTrace — File Metadata Scanner",
    page_icon="🧬",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
.block-container {padding-top: 1.5rem; padding-bottom: 2rem;}
.ct-hero {padding: 1.2rem 1.4rem; border-radius: 14px;
background: linear-gradient(120deg, rgba(0,120,120,.18), rgba(40,70,120,.18));
border: 1px solid rgba(120,150,170,.35);}
div[data-testid="stMetric"] {border: 1px solid rgba(120,140,160,.25);
border-radius: 10px; padding: .65rem .8rem;}
</style>
""", unsafe_allow_html=True)


def safe_string(value: Any, max_len: int = 500) -> str:
    """Convert metadata values into bounded readable strings."""
    try:
        if isinstance(value, bytes):
            result = value.decode("utf-8", errors="replace")
        elif isinstance(value, (str, int, float, bool)) or value is None:
            result = str(value)
        elif isinstance(value, (tuple, list)):
            result = ", ".join(safe_string(item, 100) for item in value)
        else:
            result = str(value)
    except Exception:
        result = "<unreadable value>"
    return result[:max_len]


def calculate_hashes(file_bytes: bytes) -> dict[str, str]:
    """Calculate file hashes. MD5/SHA-1 are retained for compatibility."""
    return {
        "MD5": hashlib.md5(file_bytes).hexdigest(),
        "SHA-1": hashlib.sha1(file_bytes).hexdigest(),
        "SHA-256": hashlib.sha256(file_bytes).hexdigest(),
    }


def calculate_entropy(file_bytes: bytes) -> float:
    """Calculate Shannon entropy in bits per byte, from 0 to 8."""
    if not file_bytes:
        return 0.0
    counts = [0] * 256
    for byte in file_bytes:
        counts[byte] += 1
    total = len(file_bytes)
    entropy = -sum((count / total) * math.log2(count / total)
                   for count in counts if count)
    return round(entropy, 4)


def rational_to_float(value: Any) -> float:
    if hasattr(value, "numerator") and hasattr(value, "denominator"):
        denominator = float(value.denominator)
        if denominator == 0:
            raise ValueError("Zero denominator")
        return float(value.numerator) / denominator
    if isinstance(value, (tuple, list)) and len(value) == 2:
        denominator = float(value[1])
        if denominator == 0:
            raise ValueError("Zero denominator")
        return float(value[0]) / denominator
    return float(value)


def convert_dms_to_decimal(dms: Any, ref: Any) -> float | None:
    """Convert EXIF DMS coordinates into signed decimal degrees."""
    try:
        if len(dms) != 3:
            return None
        deg, minute, second = (rational_to_float(v) for v in dms)
        result = deg + minute / 60 + second / 3600
        if safe_string(ref).upper() in {"S", "W"}:
            result = -result
        if not math.isfinite(result):
            return None
        return round(result, 7)
    except (TypeError, ValueError, ZeroDivisionError, OverflowError):
        return None


def extract_image_metadata(data: bytes):
    """Return EXIF fields, raw GPS fields, decoded GPS, image copy and error."""
    try:
        with Image.open(io.BytesIO(data)) as source:
            source.load()
            image = source.copy()
            image_format = source.format or "Unknown"
            exif = source.getexif()
            metadata = {}
            gps_raw = {}

            for tag_id, value in exif.items():
                name = ExifTags.TAGS.get(tag_id, str(tag_id))
                if name == "GPSInfo":
                    try:
                        gps_ifd = exif.get_ifd(ExifTags.IFD.GPSInfo)
                    except (AttributeError, KeyError, TypeError):
                        gps_ifd = value if isinstance(value, dict) else {}
                    for gps_id, gps_value in gps_ifd.items():
                        gps_raw[ExifTags.GPSTAGS.get(gps_id, str(gps_id))] = gps_value
                else:
                    metadata[name] = safe_string(value)

            if not gps_raw:
                try:
                    gps_ifd = exif.get_ifd(ExifTags.IFD.GPSInfo)
                    gps_raw = {
                        ExifTags.GPSTAGS.get(k, str(k)): v
                        for k, v in gps_ifd.items()
                    }
                except (AttributeError, KeyError, TypeError):
                    pass

            gps = None
            required = ("GPSLatitude", "GPSLatitudeRef",
                        "GPSLongitude", "GPSLongitudeRef")
            if all(key in gps_raw for key in required):
                lat = convert_dms_to_decimal(
                    gps_raw["GPSLatitude"], gps_raw["GPSLatitudeRef"])
                lon = convert_dms_to_decimal(
                    gps_raw["GPSLongitude"], gps_raw["GPSLongitudeRef"])
                if lat is not None and lon is not None and -90 <= lat <= 90 and -180 <= lon <= 180:
                    gps = {
                        "latitude": lat,
                        "longitude": lon,
                        "google_maps_url": f"https://www.google.com/maps?q={lat},{lon}",
                        "osm_url": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}",
                    }
            return metadata, gps_raw, gps, image, image_format
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        return {}, {}, None, None, f"Image could not be decoded: {safe_string(exc, 250)}"
    except Exception as exc:
        return {}, {}, None, None, f"Metadata extraction failed: {safe_string(exc, 250)}"


def strip_image_metadata(image: Image.Image) -> bytes:
    """Re-encode image pixels to PNG without carrying source EXIF metadata."""
    output = io.BytesIO()
    if image.mode in ("RGBA", "RGB", "L", "LA"):
        clean_image = image.copy()
    elif "transparency" in image.info:
        clean_image = image.convert("RGBA")
    else:
        clean_image = image.convert("RGB")
    clean_image.save(output, format="PNG", optimize=True)
    return output.getvalue()


def extract_pdf_metadata(file_bytes: bytes) -> dict[str, Any]:
    if not PYPDF_AVAILABLE:
        return {"Status": "pypdf is not installed; PDF metadata is unavailable."}
    try:
        reader = PdfReader(io.BytesIO(file_bytes), strict=False)
        result = {"IsEncrypted": bool(reader.is_encrypted), "PageCount": None}
        if reader.is_encrypted:
            result["Status"] = "Encrypted PDF; some properties may not be available."
            try:
                if reader.decrypt(""):
                    result["PageCount"] = len(reader.pages)
            except Exception:
                pass
            return result
        if reader.metadata:
            for key, value in reader.metadata.items():
                result[str(key).lstrip("/")] = safe_string(value)
        result["PageCount"] = len(reader.pages)
        return result
    except Exception as exc:
        return {"PDF Parsing Error": safe_string(exc, 300)}


def json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {safe_string(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    return safe_string(value)


def make_text_report(report: dict[str, Any]) -> str:
    return (
        "CYBERTRACE FORENSIC METADATA REPORT\n"
        + "=" * 42 + "\n"
        + json.dumps(json_safe(report), indent=2, ensure_ascii=False)
        + "\n\nNote: Entropy is a heuristic, not proof of malware or encryption.\n"
    )


def main() -> None:
    st.markdown(
        '<div class="ct-hero"><h1>🧬 CyberTrace</h1>'
        '<p>File metadata inspection · Cryptographic integrity · Privacy auditing</p>'
        f'<p>Version {APP_VERSION} · In-memory analysis where possible</p></div>',
        unsafe_allow_html=True,
    )
    with st.sidebar:
        st.title("🧬 CyberTrace")
        st.caption("Digital Forensics & Metadata Engine")
        st.markdown("---")
        st.markdown(
            "**Modules**\n\n"
            "- EXIF and camera metadata\n"
            "- GPS coordinate extraction\n"
            "- MD5 / SHA-1 / SHA-256\n"
            "- Shannon entropy\n"
            "- Image metadata sanitizer\n"
            "- JSON / TXT audit reports"
        )
        st.info("Geotagged photos may reveal where they were captured.")
        st.caption("Avoid uploading confidential evidence to a public deployment.")

    uploaded_file = st.file_uploader(
        "Choose a file to analyze",
        type=None,
        help="Images and PDFs receive format-specific analysis; other files receive hashes and entropy.",
    )
    if uploaded_file is None:
        st.info("Upload a file to begin. The original file is not modified.")
        st.warning("High entropy is only a triage signal and does not prove a file is malicious.")
        return

    file_name = Path(uploaded_file.name).name
    file_bytes = uploaded_file.getvalue()
    if len(file_bytes) > MAX_FILE_SIZE:
        st.error("File exceeds the 200 MiB application upload limit.")
        return
    if not file_bytes:
        st.error("The uploaded file is empty.")
        return

    extension = Path(file_name).suffix.lower()
    hashes = calculate_hashes(file_bytes)
    entropy = calculate_entropy(file_bytes)
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    mime_type = mimetypes.guess_type(file_name)[0] or "application/octet-stream"

    st.subheader("File overview")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("File size", f"{len(file_bytes) / 1024:,.2f} KiB")
    c2.metric("Entropy", f"{entropy:.4f} / 8")
    c3.metric("MIME guess", mime_type)
    c4.metric("Extension", extension or "(none)")

    if entropy >= 7.2:
        st.warning("High byte entropy: may reflect compression, encryption, or packing; not a malware verdict.")
    else:
        st.caption("Entropy is below the high-randomness heuristic threshold; this does not prove the file is safe.")

    with st.expander("Cryptographic integrity hashes", expanded=True):
        h1, h2, h3 = st.columns(3)
        for col, label in zip((h1, h2, h3), ("MD5", "SHA-1", "SHA-256")):
            col.markdown(f"**{label}**")
            col.code(hashes[label])
        st.caption("Use SHA-256 for modern integrity checks. MD5/SHA-1 are included for compatibility.")

    report = {
        "application": "CyberTrace",
        "application_version": APP_VERSION,
        "scan_timestamp_utc": timestamp,
        "file": {
            "name": file_name,
            "size_bytes": len(file_bytes),
            "extension": extension,
            "mime_type_guess": mime_type,
        },
        "hashes": hashes,
        "entropy_bits_per_byte": entropy,
        "entropy_interpretation": "heuristic only; not proof of maliciousness",
        "metadata": {},
        "warnings": [],
    }

    if extension in IMAGE_EXTENSIONS:
        st.subheader("Image and EXIF analysis")
        metadata, gps_raw, gps, image, image_format_or_error = extract_image_metadata(file_bytes)
        if image is None:
            st.warning(image_format_or_error or "Image decoding failed.")
            report["warnings"].append(image_format_or_error or "Image decoding failed")
        else:
            st.caption(f"Format: {image_format_or_error} · Dimensions: {image.width} × {image.height} · Mode: {image.mode}")
            image_col, metadata_col = st.columns([1, 1.4])
            with image_col:
                st.image(image, caption="Analyzed image", use_container_width=True)
            with metadata_col:
                if gps:
                    st.error("GPS coordinates found — review before sharing.")
                    st.write(f"**Latitude:** `{gps['latitude']}`")
                    st.write(f"**Longitude:** `{gps['longitude']}`")
                    st.markdown(f"[Open in Google Maps]({gps['google_maps_url']}) · [OpenStreetMap]({gps['osm_url']})")
                    st.map([{"lat": gps["latitude"], "lon": gps["longitude"]}], latitude="lat", longitude="lon", zoom=12)
                    report["geolocation"] = gps
                else:
                    st.success("No usable GPS coordinate pair was found in parsed EXIF metadata.")

            report["metadata"]["exif"] = metadata
            if metadata:
                st.dataframe(
                    [{"Field": key, "Value": value} for key, value in metadata.items()],
                    use_container_width=True,
                    hide_index=True,
                )
            else:
                st.info("No standard EXIF fields found, or this format does not expose them.")
            if gps_raw:
                report["metadata"]["gps_raw"] = {k: safe_string(v) for k, v in gps_raw.items()}

            st.markdown("#### Privacy metadata stripper")
            st.write("Re-encodes decoded pixels as PNG. Source EXIF is not copied, but encoding and some image features may change.")
            try:
                sanitized_bytes = strip_image_metadata(image)
                st.download_button(
                    "Download sanitized PNG",
                    data=sanitized_bytes,
                    file_name=f"{Path(file_name).stem}_sanitized.png",
                    mime="image/png",
                    use_container_width=True,
                )
                report["sanitization"] = {
                    "available": True,
                    "output_format": "PNG",
                    "note": "Re-encoded from decoded pixels; verify derivative before relying on it.",
                }
            except Exception as exc:
                st.error(f"Sanitization failed: {safe_string(exc, 250)}")
                report["warnings"].append("Image sanitization failed")

    elif extension == ".pdf" or file_bytes.startswith(b"%PDF-"):
        st.subheader("PDF document forensics")
        pdf_metadata = extract_pdf_metadata(file_bytes)
        report["metadata"]["pdf"] = pdf_metadata
        st.dataframe(
            [{"Property": key, "Value": safe_string(value)} for key, value in pdf_metadata.items()],
            use_container_width=True,
            hide_index=True,
        )
        if pdf_metadata.get("IsEncrypted"):
            st.warning("PDF is encrypted; some properties may not be readable without a password.")
    else:
        st.subheader("Generic file analysis")
        st.info("No specialized parser is enabled for this file type. Hashes and entropy were calculated.")

    st.divider()
    st.subheader("Export forensic audit report")
    report_json = json.dumps(json_safe(report), indent=2, ensure_ascii=False).encode("utf-8")
    report_txt = make_text_report(report).encode("utf-8")
    left, right = st.columns(2)
    with left:
        st.download_button(
            "Download JSON report", report_json,
            file_name=f"cybertrace_{hashes['SHA-256'][:12]}.json",
            mime="application/json", use_container_width=True,
        )
    with right:
        st.download_button(
            "Download TXT report", report_txt,
            file_name=f"cybertrace_{hashes['SHA-256'][:12]}.txt",
            mime="text/plain; charset=utf-8", use_container_width=True,
        )


if __name__ == "__main__":
    main()
