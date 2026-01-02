# `clickTextThenType` (OCR, optional)

Finds `text` on screen via OCR, clicks it, then types `typeText`.

Requires building with `-tags ocr` and having Tesseract available.

Input:
```json
{
  "text": "Username",
  "typeText": "alice@example.com",
  "rect": { "x": 0, "y": 0, "w": 1200, "h": 900 },
  "lang": "eng",
  "button": "left",
  "double": false,
  "afterClickDelayMs": 150
}
```

