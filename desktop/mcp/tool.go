package mcp

import (
	"context"
	_ "embed"
	"encoding/json"

	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/schema"
	protoserver "github.com/viant/mcp-protocol/server"
	desktopsvc "github.com/viant/mcp-toolbox/desktop/service"
)

//go:embed tools/info.md
var descInfo string

//go:embed tools/mouseMove.md
var descMouseMove string

//go:embed tools/mouseClick.md
var descMouseClick string

//go:embed tools/scroll.md
var descScroll string

//go:embed tools/keyTap.md
var descKeyTap string

//go:embed tools/type.md
var descType string

//go:embed tools/screenshot.md
var descScreenshot string

//go:embed tools/screenshotData.md
var descScreenshotData string

//go:embed tools/run.md
var descRun string

//go:embed tools/listWindows.md
var descListWindows string

//go:embed tools/activateWindow.md
var descActivateWindow string

//go:embed tools/windowBounds.md
var descWindowBounds string

//go:embed tools/minWindow.md
var descMinWindow string

//go:embed tools/maxWindow.md
var descMaxWindow string

//go:embed tools/closeWindow.md
var descCloseWindow string

//go:embed tools/setForegroundWindow.md
var descSetForegroundWindow string

//go:embed tools/sendWindowMsg.md
var descSendWindowMsg string

//go:embed tools/readClipboard.md
var descReadClipboard string

//go:embed tools/writeClipboard.md
var descWriteClipboard string

//go:embed tools/saveClipboard.md
var descSaveClipboard string

//go:embed tools/keyDown.md
var descKeyDown string

//go:embed tools/keyUp.md
var descKeyUp string

//go:embed tools/keyToggle.md
var descKeyToggle string

//go:embed tools/mouseToggle.md
var descMouseToggle string

//go:embed tools/dragSmooth.md
var descDragSmooth string

//go:embed tools/moveRelative.md
var descMoveRelative string

//go:embed tools/scrollDir.md
var descScrollDir string

//go:embed tools/scrollSmooth.md
var descScrollSmooth string

//go:embed tools/startProcess.md
var descStartProcess string

//go:embed tools/getPixelColor.md
var descGetPixelColor string

//go:embed tools/samplePixels.md
var descSamplePixels string

//go:embed tools/findImage.md
var descFindImage string

//go:embed tools/clickImage.md
var descClickImage string

//go:embed tools/displayInfo.md
var descDisplayInfo string

//go:embed tools/setDisplay.md
var descSetDisplay string

//go:embed tools/convertCoords.md
var descConvertCoords string

//go:embed tools/typeIntoWindow.md
var descTypeIntoWindow string

//go:embed tools/findText.md
var descFindText string

//go:embed tools/clickText.md
var descClickText string

//go:embed tools/clickTextThenType.md
var descClickTextThenType string

func registerTools(base *protoserver.DefaultHandler, h *Handler) error {
	svc := h.service

	if err := protoserver.RegisterTool[*desktopsvc.InfoInput, *desktopsvc.InfoOutput](base.Registry, "info", descInfo, func(ctx context.Context, in *desktopsvc.InfoInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.Info(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.MouseMoveInput, *desktopsvc.MouseMoveOutput](base.Registry, "mouseMove", descMouseMove, func(ctx context.Context, in *desktopsvc.MouseMoveInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.MouseMove(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.MouseClickInput, *desktopsvc.MouseClickOutput](base.Registry, "mouseClick", descMouseClick, func(ctx context.Context, in *desktopsvc.MouseClickInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.MouseClick(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.ScrollInput, *desktopsvc.ScrollOutput](base.Registry, "scroll", descScroll, func(ctx context.Context, in *desktopsvc.ScrollInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.Scroll(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.KeyTapInput, *desktopsvc.KeyTapOutput](base.Registry, "keyTap", descKeyTap, func(ctx context.Context, in *desktopsvc.KeyTapInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.KeyTap(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.TypeInput, *desktopsvc.TypeOutput](base.Registry, "type", descType, func(ctx context.Context, in *desktopsvc.TypeInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.Type(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	// screenshot always writes to destURL (defaults to a temp file:// URL).
	if err := protoserver.RegisterTool[*desktopsvc.ScreenshotInput, *desktopsvc.ScreenshotOutput](base.Registry, "screenshot", descScreenshot, func(ctx context.Context, in *desktopsvc.ScreenshotInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if in == nil {
			in = &desktopsvc.ScreenshotInput{}
		}
		if in.DestURL == "" {
			url, err := desktopsvc.DefaultScreenshotDestURL()
			if err != nil {
				return buildErrorResult(err.Error())
			}
			in.DestURL = url
		}
		out, err := svc.Screenshot(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		// Match browserScreenshot behavior: return only destURL+bytes, no inline data.
		out.Encoding = ""
		out.Data = ""
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	// screenshotData returns base64 inline (avoid for large images).
	if err := protoserver.RegisterTool[*desktopsvc.ScreenshotInput, *desktopsvc.ScreenshotOutput](base.Registry, "screenshotData", descScreenshotData, func(ctx context.Context, in *desktopsvc.ScreenshotInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if in == nil {
			in = &desktopsvc.ScreenshotInput{}
		}
		in.DestURL = ""
		out, err := svc.Screenshot(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.RunInput, *desktopsvc.RunOutput](base.Registry, "run", descRun, func(ctx context.Context, in *desktopsvc.RunInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.Run(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.ListWindowsInput, *desktopsvc.ListWindowsOutput](base.Registry, "listWindows", descListWindows, func(ctx context.Context, in *desktopsvc.ListWindowsInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.ListWindows(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.ActivateWindowInput, *desktopsvc.ActivateWindowOutput](base.Registry, "activateWindow", descActivateWindow, func(ctx context.Context, in *desktopsvc.ActivateWindowInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.ActivateWindow(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.WindowBoundsInput, *desktopsvc.WindowBoundsOutput](base.Registry, "windowBounds", descWindowBounds, func(ctx context.Context, in *desktopsvc.WindowBoundsInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.WindowBounds(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.WindowStateInput, *desktopsvc.WindowStateOutput](base.Registry, "minWindow", descMinWindow, func(ctx context.Context, in *desktopsvc.WindowStateInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.MinWindow(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.WindowStateInput, *desktopsvc.WindowStateOutput](base.Registry, "maxWindow", descMaxWindow, func(ctx context.Context, in *desktopsvc.WindowStateInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.MaxWindow(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.CloseWindowInput, *desktopsvc.CloseWindowOutput](base.Registry, "closeWindow", descCloseWindow, func(ctx context.Context, in *desktopsvc.CloseWindowInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.CloseWindow(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.SetForegroundWindowInput, *desktopsvc.SetForegroundWindowOutput](base.Registry, "setForegroundWindow", descSetForegroundWindow, func(ctx context.Context, in *desktopsvc.SetForegroundWindowInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.SetForegroundWindow(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.SendWindowMsgInput, *desktopsvc.SendWindowMsgOutput](base.Registry, "sendWindowMsg", descSendWindowMsg, func(ctx context.Context, in *desktopsvc.SendWindowMsgInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.SendWindowMsg(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.ReadClipboardInput, *desktopsvc.ReadClipboardOutput](base.Registry, "readClipboard", descReadClipboard, func(ctx context.Context, in *desktopsvc.ReadClipboardInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.ReadClipboard(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.WriteClipboardInput, *desktopsvc.WriteClipboardOutput](base.Registry, "writeClipboard", descWriteClipboard, func(ctx context.Context, in *desktopsvc.WriteClipboardInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.WriteClipboard(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.SaveClipboardInput, *desktopsvc.SaveClipboardOutput](base.Registry, "saveClipboard", descSaveClipboard, func(ctx context.Context, in *desktopsvc.SaveClipboardInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.SaveClipboard(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.KeyToggleInput, *desktopsvc.KeyToggleOutput](base.Registry, "keyDown", descKeyDown, func(ctx context.Context, in *desktopsvc.KeyToggleInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if in == nil {
			in = &desktopsvc.KeyToggleInput{}
		}
		in.Down = "down"
		out, err := svc.KeyToggle(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.KeyToggleInput, *desktopsvc.KeyToggleOutput](base.Registry, "keyUp", descKeyUp, func(ctx context.Context, in *desktopsvc.KeyToggleInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if in == nil {
			in = &desktopsvc.KeyToggleInput{}
		}
		in.Down = "up"
		out, err := svc.KeyToggle(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.KeyToggleInput, *desktopsvc.KeyToggleOutput](base.Registry, "keyToggle", descKeyToggle, func(ctx context.Context, in *desktopsvc.KeyToggleInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.KeyToggle(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.MouseToggleInput, *desktopsvc.MouseToggleOutput](base.Registry, "mouseToggle", descMouseToggle, func(ctx context.Context, in *desktopsvc.MouseToggleInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.MouseToggle(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.DragSmoothInput, *desktopsvc.DragSmoothOutput](base.Registry, "dragSmooth", descDragSmooth, func(ctx context.Context, in *desktopsvc.DragSmoothInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.DragSmooth(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.MoveRelativeInput, *desktopsvc.MoveRelativeOutput](base.Registry, "moveRelative", descMoveRelative, func(ctx context.Context, in *desktopsvc.MoveRelativeInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.MoveRelative(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.ScrollDirInput, *desktopsvc.ScrollDirOutput](base.Registry, "scrollDir", descScrollDir, func(ctx context.Context, in *desktopsvc.ScrollDirInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.ScrollDir(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.ScrollSmoothInput, *desktopsvc.ScrollSmoothOutput](base.Registry, "scrollSmooth", descScrollSmooth, func(ctx context.Context, in *desktopsvc.ScrollSmoothInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.ScrollSmooth(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.StartProcessInput, *desktopsvc.StartProcessOutput](base.Registry, "startProcess", descStartProcess, func(ctx context.Context, in *desktopsvc.StartProcessInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.StartProcess(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.GetPixelColorInput, *desktopsvc.GetPixelColorOutput](base.Registry, "getPixelColor", descGetPixelColor, func(ctx context.Context, in *desktopsvc.GetPixelColorInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.GetPixelColor(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.SamplePixelsInput, *desktopsvc.SamplePixelsOutput](base.Registry, "samplePixels", descSamplePixels, func(ctx context.Context, in *desktopsvc.SamplePixelsInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.SamplePixels(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.FindImageInput, *desktopsvc.FindImageOutput](base.Registry, "findImage", descFindImage, func(ctx context.Context, in *desktopsvc.FindImageInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.FindImage(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.ClickImageInput, *desktopsvc.ClickImageOutput](base.Registry, "clickImage", descClickImage, func(ctx context.Context, in *desktopsvc.ClickImageInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.ClickImage(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.DisplayInfoInput, *desktopsvc.DisplayInfoOutput](base.Registry, "displayInfo", descDisplayInfo, func(ctx context.Context, in *desktopsvc.DisplayInfoInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.DisplayInfo(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.SetDisplayInput, *desktopsvc.SetDisplayOutput](base.Registry, "setDisplay", descSetDisplay, func(ctx context.Context, in *desktopsvc.SetDisplayInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.SetDisplay(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.ConvertCoordsInput, *desktopsvc.ConvertCoordsOutput](base.Registry, "convertCoords", descConvertCoords, func(ctx context.Context, in *desktopsvc.ConvertCoordsInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.ConvertCoords(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.TypeIntoWindowInput, *desktopsvc.TypeIntoWindowOutput](base.Registry, "typeIntoWindow", descTypeIntoWindow, func(ctx context.Context, in *desktopsvc.TypeIntoWindowInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.TypeIntoWindow(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.FindTextInput, *desktopsvc.FindTextOutput](base.Registry, "findText", descFindText, func(ctx context.Context, in *desktopsvc.FindTextInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.FindText(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.ClickTextInput, *desktopsvc.ClickTextOutput](base.Registry, "clickText", descClickText, func(ctx context.Context, in *desktopsvc.ClickTextInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.ClickText(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*desktopsvc.ClickTextThenTypeInput, *desktopsvc.ClickTextThenTypeOutput](base.Registry, "clickTextThenType", descClickTextThenType, func(ctx context.Context, in *desktopsvc.ClickTextThenTypeInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.ClickTextThenType(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	return nil
}

func buildErrorResult(message string) (*schema.CallToolResult, *jsonrpc.Error) {
	return nil, jsonrpc.NewError(jsonrpc.InvalidParams, message, nil)
}

func buildSuccessResultOut(service *desktopsvc.Service, payload any) (*schema.CallToolResult, *jsonrpc.Error) {
	if service.UseTextField() {
		b, _ := json.Marshal(payload)
		return &schema.CallToolResult{Content: []schema.CallToolResultContentElem{{Type: "text", Text: string(b)}}}, nil
	}
	return &schema.CallToolResult{StructuredContent: map[string]any{"result": payload}}, nil
}
