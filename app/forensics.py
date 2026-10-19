import hashlib
import mimetypes
import os
from pathlib import Path
from PIL import Image, UnidentifiedImageError

def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def file_signature(path):
    """Return a conservative format hint based on bytes, not the user-supplied extension."""
    with open(path, "rb") as stream:
        head = stream.read(32)
    if head.startswith(b"\xff\xd8\xff"): return "image/jpeg"
    if head.startswith(b"\x89PNG\r\n\x1a\n"): return "image/png"
    if head.startswith((b"GIF87a", b"GIF89a")): return "image/gif"
    if head.startswith((b"II*\x00", b"MM\x00*")): return "image/tiff"
    if head.startswith(b"BM"): return "image/bmp"
    if head.startswith(b"%PDF-"): return "application/pdf"
    if head.startswith(b"PK\x03\x04"): return "application/zip"
    if head.startswith(b"\x1aE\xdf\xa3"): return "video/webm"
    if len(head) >= 12 and head[4:8] == b"ftyp": return "video/mp4"
    if head.startswith(b"RIFF") and head[8:12] == b"WAVE": return "audio/wav"
    if head.startswith(b"RIFF") and head[8:12] == b"AVI ": return "video/x-msvideo"
    if head.startswith(b"\xd4\xc3\xb2\xa1") or head.startswith(b"\xa1\xb2\xc3\xd4") or head.startswith(b"\x0a\x0d\x0d\x0a"):
        return "application/vnd.tcpdump.pcap"
    if head.startswith(b"\x7fELF"): return "application/x-elf"
    if head.startswith(b"MZ"): return "application/vnd.microsoft.portable-executable"
    if head.startswith(b"\x00\x00\x01\x00"): return "image/x-icon"
    return None

def inspect_file(path, original_name):
    guessed, _ = mimetypes.guess_type(original_name)
    signature = file_signature(path)
    result = {
        "file_name": original_name,
        "sha256": sha256_file(path),
        "size_bytes": os.path.getsize(path),
        "mime_type": signature or guessed or "application/octet-stream",
        "extension_mime_type": guessed,
        "signature_mime_type": signature,
        "image": None,
        "ocr": {"status": "disabled", "text": None},
        "object_detection": {"status": "not_configured", "detections": []},
        "warnings": ["Automated findings are leads for review, not proof of authenticity or criminal activity."]
    }
    if signature and guessed and signature != guessed:
        compatible = {("application/zip", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
                      ("application/zip", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
                      ("application/zip", "application/vnd.openxmlformats-officedocument.presentationml.presentation")}
        if (signature, guessed) not in compatible:
            result["warnings"].append("File extension MIME type differs from its detected byte signature; inspect manually.")
    try:
        with Image.open(path) as image:
            image.verify()
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
            result["image"] = {"format": image.format, "width": image.width, "height": image.height,
                               "mode": image.mode, "exif": exif}
            if os.getenv("OMNIFORENSICS_ENABLE_OCR", "false").lower() == "true":
                try:
                    import pytesseract
                    result["ocr"] = {"status": "completed", "text": pytesseract.image_to_string(image)[:12000]}
                except Exception as exc:
                    result["ocr"] = {"status": "unavailable", "text": None, "detail": str(exc)[:250]}
            else:
                result["ocr"] = {"status": "disabled", "text": None,
                                 "detail": "Optional: install Tesseract and pytesseract, then enable OCR."}
            model_path = os.getenv("OMNIFORENSICS_YOLO_MODEL", "").strip()
            if model_path:
                try:
                    from ultralytics import YOLO
                    model = YOLO(model_path)
                    prediction = model.predict(source=path, verbose=False, conf=0.25)
                    detections = []
                    for result_item in prediction[:1]:
                        names = result_item.names
                        if result_item.boxes is not None:
                            for box in result_item.boxes:
                                cls_id = int(box.cls[0].item())
                                detections.append({
                                    "label": str(names.get(cls_id, cls_id)),
                                    "confidence": round(float(box.conf[0].item()), 4),
                                    "bbox_xyxy": [round(float(v), 2) for v in box.xyxy[0].tolist()]
                                })
                    result["object_detection"] = {"status": "completed", "model": Path(model_path).name,
                                                  "detections": detections,
                                                  "note": "Model-dependent suggestions; manually review every detection."}
                except Exception as exc:
                    result["object_detection"] = {"status": "unavailable", "detections": [], "detail": str(exc)[:250]}
    except (UnidentifiedImageError, OSError, ValueError):
        pass

    # Optional, bounded video inspection. OpenCV is deliberately an optional dependency.
    if signature and signature.startswith("video/"):
        try:
            import cv2
            capture = cv2.VideoCapture(str(path))
            if not capture.isOpened():
                result["video"] = {"status": "unreadable"}
            else:
                fps = float(capture.get(cv2.CAP_PROP_FPS) or 0)
                frame_count = int(capture.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
                width = int(capture.get(cv2.CAP_PROP_FRAME_WIDTH) or 0)
                height = int(capture.get(cv2.CAP_PROP_FRAME_HEIGHT) or 0)
                duration = round(frame_count / fps, 3) if fps > 0 else None
                video_info = {"status": "metadata_only", "width": width, "height": height,
                              "fps": round(fps, 3) if fps else None, "frame_count": frame_count,
                              "duration_seconds": duration, "sampled_frames": 0, "detections": []}
                model = None
                model_path = os.getenv("OMNIFORENSICS_YOLO_MODEL", "").strip()
                if model_path:
                    try:
                        from ultralytics import YOLO
                        model = YOLO(model_path)
                    except Exception as exc:
                        video_info["detection_status"] = "unavailable"
                        video_info["detection_detail"] = str(exc)[:250]
                if frame_count > 0 and fps > 0:
                    # At most 12 evenly spaced samples; never process every frame automatically.
                    sample_count = min(12, frame_count)
                    sample_indices = sorted(set(round(i * (frame_count - 1) / max(sample_count - 1, 1))
                                                for i in range(sample_count)))
                    for frame_index in sample_indices:
                        capture.set(cv2.CAP_PROP_POS_FRAMES, frame_index)
                        ok, frame = capture.read()
                        if not ok:
                            continue
                        video_info["sampled_frames"] += 1
                        if model is not None:
                            try:
                                predictions = model.predict(source=frame, verbose=False, conf=0.25)
                                for prediction in predictions[:1]:
                                    names = prediction.names
                                    if prediction.boxes is not None:
                                        for box in prediction.boxes:
                                            cls_id = int(box.cls[0].item())
                                            video_info["detections"].append({
                                                "timestamp_seconds": round(frame_index / fps, 3),
                                                "frame_index": frame_index,
                                                "label": str(names.get(cls_id, cls_id)),
                                                "confidence": round(float(box.conf[0].item()), 4),
                                                "bbox_xyxy": [round(float(v), 2) for v in box.xyxy[0].tolist()]
                                            })
                            except Exception as exc:
                                video_info["detection_status"] = "unavailable"
                                video_info["detection_detail"] = str(exc)[:250]
                                model = None
                capture.release()
                if model is not None:
                    video_info["detection_status"] = "completed"
                    video_info["note"] = "Only sampled frames were analyzed; missed events are possible."
                elif not model_path:
                    video_info["detection_status"] = "not_configured"
                result["video"] = video_info
        except Exception as exc:
            result["video"] = {"status": "unavailable", "detail": str(exc)[:250],
                               "note": "Optional dependency: pip install opencv-python-headless."}
    return result
