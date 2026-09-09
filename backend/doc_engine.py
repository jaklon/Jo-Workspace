import io
import os
import openpyxl
from docx import Document
from pypdf import PdfReader


def extract_text_from_pdf(file_bytes: bytes) -> str:
    """Membaca teks dari file PDF digital."""
    reader = PdfReader(io.BytesIO(file_bytes))
    text_pages = []
    for i, page in enumerate(reader.pages):
        page_text = page.extract_text() or ""
        if page_text.strip():
            text_pages.append(f"--- Halaman {i + 1} ---\n{page_text}")
    return "\n\n".join(text_pages) if text_pages else "(PDF tidak memiliki teks terbaca atau merupakan hasil scan)"


def extract_text_from_docx(file_bytes: bytes) -> str:
    """Membaca teks dari file Word (DOCX)."""
    doc = Document(io.BytesIO(file_bytes))
    paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]
    return "\n".join(paragraphs)


def extract_text_from_xlsx(file_bytes: bytes) -> str:
    """Membaca data tabular dari file Excel (XLSX)."""
    wb = openpyxl.load_workbook(io.BytesIO(file_bytes), data_only=True)
    sheets_text = []
    for sheet_name in wb.sheetnames:
        sheet = wb[sheet_name]
        sheet_lines = [f"=== Sheet: {sheet_name} ==="]
        for row in sheet.iter_rows(values_only=True):
            if any(cell is not None for cell in row):
                row_str = " | ".join(str(cell) if cell is not None else "" for cell in row)
                sheet_lines.append(row_str)
        sheets_text.append("\n".join(sheet_lines))
    return "\n\n".join(sheets_text)


def parse_document_file(filename: str, file_bytes: bytes) -> str:
    """Entry point untuk mengekstraksi dokumen berdasarkan ekstensinya."""
    ext = os.path.splitext(filename)[1].lower()
    
    if ext == ".pdf":
        return extract_text_from_pdf(file_bytes)
    elif ext in [".docx", ".doc"]:
        return extract_text_from_docx(file_bytes)
    elif ext in [".xlsx", ".xls"]:
        return extract_text_from_xlsx(file_bytes)
    elif ext in [".txt", ".csv", ".json", ".md", ".py", ".ts", ".js"]:
        return file_bytes.decode("utf-8", errors="ignore")
    else:
        raise ValueError(f"Format ekstensi '{ext}' belum didukung.")