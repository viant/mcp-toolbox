# `findImage`

Finds occurrences of a template image within a screenshot region (naive grayscale match).

Input:
```json
{
  "templateURL": "file:///tmp/button.png",
  "rect": { "x": 0, "y": 0, "w": 800, "h": 600 },
  "maxResults": 1,
  "threshold": 0.95,
  "step": 1,
  "displayId": -1,
  "maxTimeMs": 2000
}
```

Output:
```json
{
  "result": {
    "matches": [
      { "x": 123, "y": 456, "w": 50, "h": 20, "score": 0.98 }
    ]
  }
}
```
