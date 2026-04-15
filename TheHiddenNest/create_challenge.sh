#!/bin/bash
set -e

echo "[+] Generating Morse audio..."
python3 generate_audio.py

echo "[+] Creating ZIP archive..."
cd build
zip -P NestP457! hidden.zip note.txt fake_flag.txt audio.wav
cd ..

echo "[+] Embedding EXIF metadata..."
exiftool -overwrite_original -Comment="cGFzc3dvcmQ6IE5lc3RQNDU3IQpIaW50OiBBIHNlY3JldCBpcyBuZXN0ZWQgYmVuZWF0aCB0aGUgc3VyZmFjZS4=" source/welcome.jpg

echo "[+] Appending ZIP to image..."
mkdir -p dist
cat source/welcome.jpg build/hidden.zip > dist/welcome.jpg

echo "[+] Challenge created successfully!"
echo "File located at: dist/welcome.jpg"
