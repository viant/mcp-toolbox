# `run`

Runs a sequence of Desktop DSL commands.

Input:
```json
{
  "commands": [
    "move(100,200)",
    "click('left')",
    "type('hello')",
    "keyTap('enter')",
    "path = screenshot()"
  ],
  "actionDelaysMs": 50,
  "displayId": -1,
  "mouseSleepMs": 0,
  "keySleepMs": 10
}
```

Supported commands (initial set):
- `move(x,y)` / `moveSmooth(x,y[,low,high,delayMs])`
- `click([button][,double])` or `click(button='left', double=false)`
- `scroll(x,y[,delayMs])` / `scrollDir(amount,'up'|'down'|'left'|'right')`
- `keyTap(key[,mod1,mod2...])`
- `keyDown(key)` / `keyUp(key)` / `keyToggle(key,'down'|'up')`
- `mouseToggle(button,'down'|'up')`
- `dragSmooth(x,y[,button])`
- `moveRelative(dx,dy)`
- `scrollSmooth(toY[,num,sleepMs,toX])`
- `readClipboard()` / `writeClipboard(text)`
- `saveClipboard(destURL[,format='auto'])`
- `getPixelColor(x,y[,displayId])`
- `findImage(templateURL[,threshold=0.95,step=1,maxResults=1])`
- `clickImage(templateURL[,button='left',double=false,threshold=0.95,step=1])`
- `setDisplay(displayId)`
- `displayInfo()`
- `convertCoords(mode,x,y[,w,h])`
- `typeIntoWindow(titleContains,text[,delayMs])`
- `findText(text[,lang='eng',maxResults=5])` (OCR, optional)
- `clickText(text[,lang='eng',button='left',double=false,delayMs=0])` (OCR, optional)
- `clickTextThenType(text,typeText[,lang='eng',button='left',double=false,afterClickDelayMs=150])` (OCR, optional)
- `type(text)`
- `sleep(ms)`
- `screenshot([destURL='file:///...'][,x=..,y=..,w=..,h=..])` (returns `{destURL,bytes}`; assignment supported)

Outputs:
- `data`: assigned values
- `actions`: an execution trace
