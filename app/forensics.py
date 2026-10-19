import hashlib
import mimetypes
import os
from PIL import Image, UnidentifiedImageError

def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def inspect_file(path, original_name):
    guessed, _ = mimetypes.guess_type(original_name)
    result = {
        "file_name": original_name,
        "sha256": sha256_file(path),
        "size_bytes": os.path.getsize(path),
        "mime_type": guessed or "application/octet-stream",
        "image": None,
        "ocr": {"status": "disabled", "text": None},
        "object_detection": {"status": "not_implemented", "detections": []},
        "warnings": ["Automated findings are leads for review, not proof of authenticity or criminal activity."]
    }
    try:
        with Image.open(path) as image:
            exif = {}
            try:
                from PIL.ExifTags import TAGS
                for key, value in image.getexif().items():
                    if isinstance(value, bytes):
                        value = f"<{len(value)} bytes>"
                    exif[TAGS.get(key, str(key))] = str(value)[:500]
            except Exception:
                pass
            result["image"] = {
                "format": image.format, "width": image.width,
                "height": image.height, "mode": image.mode, "exif": exif
            }
            if os.getenv("OMNIFORENSICS_ENABLE_OCR", "false").lower() == "true":
                try:
                    import pytesseract
                    result["ocr"] = {"status": "completed", "text": pytesseract.image_to_string(image)[:12000]}
                except Exception as exc:
                    result["ocr"] = {"status": "unavailable", "text": None, "detail": str(exc)[:250]}
            else:
                result["ocr"] = {
                    "status": "disabled", "text": None,
                    "detail": "Optional: install Tesseract and pytesseract, then enable OCR."
                }
    except (UnidentifiedImageError, OSError):
        pass
    return result
