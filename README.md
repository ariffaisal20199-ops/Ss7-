# putraazari

Program OSINT forensik ringan untuk Linux/Termux yang membantu menganalisis kata kunci, risiko social engineering, dork Google, metadata berkas, dan SQLite database secara sederhana.

## Fitur
- Profil kata kunci dan flag risiko
- Rekomendasi Google dork
- Analisis metadata berkas dan direktori
- Deteksi SQLite database dan hitung jumlah baris
- Ringkasan panduan social engineering

## Jalankan
```bash
python3 osint_forensic_tool.py "Alice Smith weather geometry physics"
python3 osint_forensic_tool.py "Alice Smith" --input /sdcard --json
```

## Uji
```bash
python3 -m unittest discover -s tests -v
```

## Catatan
Gunakan dengan etika, legalitas, dan batasan yang sesuai. Program ini ditujukan untuk pembelajaran, audit internal, atau investigasi defensif.
