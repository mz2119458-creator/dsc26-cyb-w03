import unicodedata
import uuid
import re
from dataclasses import dataclass

MAX_BYTES = 25 * 1024 * 1024

class ValidationError(Exception):
    def __init__(self, errors: dict[str, str]):
        self.errors = errors
        super().__init__(str(errors))

@dataclass(frozen=True)
class CleanUpload:
    stored_name: str
    display_name: str
    extension: str
    content_type: str
    size_bytes: int
    matter_id: str

def validate_upload(meta: dict) -> CleanUpload:
    errors = {}
    
    filename = meta.get("filename")
    filename_valid = False
    display_name = ""
    ext = ""
    
    if not isinstance(filename, str):
        errors["filename"] = "Filename must be a string."
    else:
        display_name = unicodedata.normalize("NFC", filename)
        if not (1 <= len(display_name) <= 120):
            errors["filename"] = "Filename length must be between 1 and 120 characters."
        else:
            has_cc = any(unicodedata.category(c) == 'Cc' for c in display_name)
            bidi_chars = {
                '\u061C', '\u200E', '\u200F',
                '\u202A', '\u202B', '\u202C', '\u202D', '\u202E',
                '\u2066', '\u2067', '\u2068', '\u2069'
            }
            has_bidi = any(c in bidi_chars for c in display_name)
            
            if has_cc or has_bidi:
                errors["filename"] = "Filename contains prohibited control or bidi characters."
            elif '/' in display_name or '\\' in display_name or '..' in display_name:
                errors["filename"] = "Filename contains path traversal sequences."
            elif display_name.startswith('.'):
                errors["filename"] = "Filename must not start with a dot."
            else:
                if '.' not in display_name:
                    errors["filename"] = "Filename must have an extension."
                else:
                    parts = display_name.rsplit('.', 1)
                    name_part, ext_part = parts[0], parts[1].lower()
                    if not name_part.strip():
                        errors["filename"] = "Filename must have a non-blank name before the dot."
                    elif ext_part not in ("pdf", "docx"):
                        errors["filename"] = "Extension must be pdf or docx."
                    else:
                        filename_valid = True
                        ext = ext_part

    content_type = meta.get("content_type")
    if filename_valid:
        expected_ct = (
            "application/pdf" if ext == "pdf" 
            else "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        if not isinstance(content_type, str) or content_type != expected_ct:
            errors["content_type"] = f"Invalid content_type for {ext}."
    else:
        if not isinstance(content_type, str):
            errors["content_type"] = "content_type must be a string."

    first_bytes = meta.get("first_bytes")
    if filename_valid:
        if not isinstance(first_bytes, bytes):
            errors["first_bytes"] = "first_bytes must be bytes."
        else:
            if ext == "pdf" and not first_bytes.startswith(b"%PDF-"):
                errors["first_bytes"] = "PDF must start with %PDF-."
            elif ext == "docx" and not first_bytes.startswith(b"PK\x03\x04"):
                errors["first_bytes"] = "DOCX must start with PK\\x03\\x04."
    else:
        if not isinstance(first_bytes, bytes):
            errors["first_bytes"] = "first_bytes must be bytes."

    size_bytes = meta.get("size_bytes")
    if type(size_bytes) is not int or isinstance(size_bytes, bool):
        errors["size_bytes"] = "size_bytes must be an integer."
    elif not (1 <= size_bytes <= MAX_BYTES):
        errors["size_bytes"] = f"size_bytes must be between 1 and {MAX_BYTES}."

    matter_id = meta.get("matter_id")
    if not isinstance(matter_id, str):
        errors["matter_id"] = "matter_id must be a string."
    else:
        if not all(ord(c) < 128 for c in matter_id):
            errors["matter_id"] = "matter_id must be ASCII only."
        else:
            pattern = re.compile(r"^MAT-\d{4}-\d{5}$")
            if not pattern.fullmatch(matter_id):
                errors["matter_id"] = "matter_id must match format MAT-YYYY-NNNNN."

    if errors:
        raise ValidationError(errors)

    canonical_ct = (
        "application/pdf" if ext == "pdf" 
        else "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )
    stored_name = f"{uuid.uuid4().hex}.{ext}"

    return CleanUpload(
        stored_name=stored_name,
        display_name=display_name,
        extension=ext,
        content_type=canonical_ct,
        size_bytes=size_bytes,
        matter_id=matter_id
    )
