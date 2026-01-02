# `findText` (OCR, optional)

Finds text on screen using OCR and returns bounding boxes.

Requires building with `-tags ocr` and having Tesseract available.

Input:
```json
{ "text": "OK", "rect": { "x": 0, "y": 0, "w": 800, "h": 600 }, "lang": "eng", "maxResults": 5 }
```

