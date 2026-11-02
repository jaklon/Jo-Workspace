import io
import zipfile
from pathlib import Path
import openpyxl
from docx import Document
from pypdf import PdfReader
from config import DOCUMENT_EXTENSIONS, MAX_EXTRACTED

UNREADABLE_PAGE = "[Halaman {page} tidak terbaca: tidak ada lapisan teks, perlu OCR]"


def validate_archive(data):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        if len(archive.infolist()) > 5000 or sum(i.file_size for i in archive.infolist()) > 40 * 1024 * 1024:
            raise ValueError("Dokumen terkompresi terlalu besar untuk diproses.")


def extract_text_from_pdf(data):
    reader = PdfReader(io.BytesIO(data))
    if reader.is_encrypted:
        raise ValueError("PDF terenkripsi. Unggah salinan yang dapat dibaca.")
    if len(reader.pages) > 300:
        raise ValueError("Maksimal 300 halaman per PDF. Pisahkan dokumen.")
    sections, empty = [], []
    for i, page in enumerate(reader.pages, 1):
        text = page.extract_text() or ""
        if text.strip():
            sections.append(f"[Halaman {i}]\n{text}")
        else:
            # Keep a marker so answers and coverage can say which pages were never read.
            sections.append(UNREADABLE_PAGE.format(page=i))
            empty.append(str(i))
        if sum(map(len, sections)) > MAX_EXTRACTED:
            raise ValueError("Teks dokumen terlalu panjang. Pisahkan dokumen.")
    if len(empty) == len(reader.pages):
        raise ValueError("PDF memerlukan OCR pada halaman " + ", ".join(empty[:20]) + ". Unggah PDF dengan lapisan teks atau halaman tersebut sebagai gambar.")
    return "\n\n".join(sections)


def extract_text_from_docx(data):
    validate_archive(data)
    doc = Document(io.BytesIO(data))
    sections = []
    for i, block in enumerate(doc.iter_inner_content(), 1):
        if hasattr(block, "rows"):
            for row_index, row in enumerate(block.rows, 1):
                sections.append(f"[Tabel {i}, baris {row_index}] " + " | ".join(cell.text for cell in row.cells))
        elif block.text.strip():
            sections.append(f"[Paragraf {i}] {block.text}")
    for i, section in enumerate(doc.sections, 1):
        for label, container in (("Header", section.header), ("Footer", section.footer)):
            sections.extend(f"[{label} {i}] {p.text}" for p in container.paragraphs if p.text.strip())
    return "\n".join(sections)


def extract_text_from_xlsx(data):
    validate_archive(data)
    wb = openpyxl.load_workbook(io.BytesIO(data), data_only=False, read_only=True)
    sections, count = [], 0
    try:
        for sheet in wb:
            if (sheet.max_row and sheet.max_row > 10_000) or (sheet.max_column and sheet.max_column > 200):
                raise ValueError("Sheet terlalu besar. Ekspor bagian relevan sebagai CSV.")
            for number, row in enumerate(sheet.iter_rows(values_only=True), 1):
                if any(c is not None for c in row):
                    line = f"[Sheet {sheet.title}, baris {number}] " + " | ".join(str(c) if c is not None else "" for c in row)
                    count += len(line)
                    if count > MAX_EXTRACTED:
                        raise ValueError("Teks spreadsheet terlalu panjang. Pisahkan file.")
                    sections.append(line)
    finally:
        wb.close()
    return "\n".join(sections)


def parse_document_file(filename, data):
    try:
        return _parse_document_file(filename, data)
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("Dokumen rusak atau tidak cocok dengan formatnya. Ekspor ulang file lalu coba lagi.") from exc


def _parse_document_file(filename, data):
    extension = Path(filename).suffix.lower()
    if extension not in DOCUMENT_EXTENSIONS:
        raise ValueError("Format tidak didukung. DOC/XLS lama perlu dikonversi ke DOCX/XLSX.")
    if extension == ".pdf":
        if not data.startswith(b"%PDF-"):
            raise ValueError("Isi file bukan PDF yang valid.")
        text = extract_text_from_pdf(data)
    elif extension == ".docx":
        text = extract_text_from_docx(data)
    elif extension == ".xlsx":
        text = extract_text_from_xlsx(data)
    else:
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ValueError("File teks harus memakai UTF-8; konversikan encoding terlebih dahulu.") from exc
        if "\x00" in text:
            raise ValueError("File biner tidak dapat diproses sebagai teks.")
    if not text.strip():
        raise ValueError("Dokumen tidak memiliki teks yang dapat dibaca.")
    if len(text) > MAX_EXTRACTED:
        raise ValueError(f"Dokumen melebihi {MAX_EXTRACTED:,} karakter. Pisahkan dokumen.")
    return text
