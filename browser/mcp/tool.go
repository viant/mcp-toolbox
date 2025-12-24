package mcp

import (
	"context"
	_ "embed"
	"encoding/json"

	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/schema"
	protoserver "github.com/viant/mcp-protocol/server"
	browsersvc "github.com/viant/mcp-toolbox/browser/service"
)

//go:embed tools/webdriverStart.md
var descStart string

//go:embed tools/webdriverStop.md
var descStop string

//go:embed tools/webdriverOpen.md
var descOpen string

//go:embed tools/webdriverClose.md
var descClose string

//go:embed tools/webdriverRun.md
var descRun string

//go:embed tools/webdriverCallDriver.md
var descCallDriver string

//go:embed tools/webdriverCallElement.md
var descCallElement string

//go:embed tools/webdriverCaptureStart.md
var descCaptureStart string

//go:embed tools/webdriverCaptureStop.md
var descCaptureStop string

//go:embed tools/webdriverCaptureStatus.md
var descCaptureStatus string

//go:embed tools/webdriverCaptureClear.md
var descCaptureClear string

//go:embed tools/webdriverCaptureExport.md
var descCaptureExport string

//go:embed tools/webdriverScreenshot.md
var descScreenshot string

//go:embed tools/browserDriverInstall.md
var descDriverInstall string

//go:embed tools/browserDriverUpdate.md
var descDriverUpdate string

//go:embed tools/browserGetSource.md
var descGetSource string

//go:embed tools/browserGetDOM.md
var descGetDOM string

//go:embed tools/browserSessions.md
var descSessions string

//go:embed tools/browserScreenshotData.md
var descScreenshotData string

//go:embed tools/browserEvalJS.md
var descEvalJS string

func registerTools(base *protoserver.DefaultHandler, h *Handler) error {
	svc := h.service

	if err := protoserver.RegisterTool[*browsersvc.StartInput, *browsersvc.StartOutput](base.Registry, "webdriverStart", descStart, func(ctx context.Context, in *browsersvc.StartInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.Start(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.StartInput, *browsersvc.StartOutput](base.Registry, "browserStart", descStart, func(ctx context.Context, in *browsersvc.StartInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.Start(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.StopInput, *browsersvc.StopOutput](base.Registry, "webdriverStop", descStop, func(ctx context.Context, in *browsersvc.StopInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.Stop(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.StopInput, *browsersvc.StopOutput](base.Registry, "browserStop", descStop, func(ctx context.Context, in *browsersvc.StopInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.Stop(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.OpenSessionInput, *browsersvc.OpenSessionOutput](base.Registry, "webdriverOpen", descOpen, func(ctx context.Context, in *browsersvc.OpenSessionInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.OpenSession(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.OpenSessionInput, *browsersvc.OpenSessionOutput](base.Registry, "browserOpen", descOpen, func(ctx context.Context, in *browsersvc.OpenSessionInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.OpenSession(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.CloseSessionInput, *browsersvc.CloseSessionOutput](base.Registry, "webdriverClose", descClose, func(ctx context.Context, in *browsersvc.CloseSessionInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.CloseSession(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.CloseSessionInput, *browsersvc.CloseSessionOutput](base.Registry, "browserClose", descClose, func(ctx context.Context, in *browsersvc.CloseSessionInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.CloseSession(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.RunInput, *browsersvc.RunOutput](base.Registry, "webdriverRun", descRun, func(ctx context.Context, in *browsersvc.RunInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.Run(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.RunInput, *browsersvc.RunOutput](base.Registry, "browserRun", descRun, func(ctx context.Context, in *browsersvc.RunInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.Run(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.WebDriverCallInput, *browsersvc.CallOutput](base.Registry, "webdriverCallDriver", descCallDriver, func(ctx context.Context, in *browsersvc.WebDriverCallInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.CallDriver(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.WebDriverCallInput, *browsersvc.CallOutput](base.Registry, "browserCallDriver", descCallDriver, func(ctx context.Context, in *browsersvc.WebDriverCallInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.CallDriver(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.WebElementCallInput, *browsersvc.WebElementCallOutput](base.Registry, "webdriverCallElement", descCallElement, func(ctx context.Context, in *browsersvc.WebElementCallInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.CallElement(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.WebElementCallInput, *browsersvc.WebElementCallOutput](base.Registry, "browserCallElement", descCallElement, func(ctx context.Context, in *browsersvc.WebElementCallInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.CallElement(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.CaptureStartInput, *browsersvc.CaptureStartOutput](base.Registry, "webdriverCaptureStart", descCaptureStart, func(ctx context.Context, in *browsersvc.CaptureStartInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.CaptureStart(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.CaptureStartInput, *browsersvc.CaptureStartOutput](base.Registry, "browserCaptureStart", descCaptureStart, func(ctx context.Context, in *browsersvc.CaptureStartInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.CaptureStart(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.CaptureStopInput, *browsersvc.CaptureStopOutput](base.Registry, "webdriverCaptureStop", descCaptureStop, func(ctx context.Context, in *browsersvc.CaptureStopInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.CaptureStop(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.CaptureStopInput, *browsersvc.CaptureStopOutput](base.Registry, "browserCaptureStop", descCaptureStop, func(ctx context.Context, in *browsersvc.CaptureStopInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.CaptureStop(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.CaptureStatusInput, *browsersvc.CaptureStatusOutput](base.Registry, "webdriverCaptureStatus", descCaptureStatus, func(ctx context.Context, in *browsersvc.CaptureStatusInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.CaptureStatus(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.CaptureStatusInput, *browsersvc.CaptureStatusOutput](base.Registry, "browserCaptureStatus", descCaptureStatus, func(ctx context.Context, in *browsersvc.CaptureStatusInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.CaptureStatus(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.CaptureClearInput, *browsersvc.CaptureClearOutput](base.Registry, "webdriverCaptureClear", descCaptureClear, func(ctx context.Context, in *browsersvc.CaptureClearInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.CaptureClear(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.CaptureClearInput, *browsersvc.CaptureClearOutput](base.Registry, "browserCaptureClear", descCaptureClear, func(ctx context.Context, in *browsersvc.CaptureClearInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.CaptureClear(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.CaptureExportInput, *browsersvc.CaptureExportOutput](base.Registry, "webdriverCaptureExport", descCaptureExport, func(ctx context.Context, in *browsersvc.CaptureExportInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.CaptureExport(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.CaptureExportInput, *browsersvc.CaptureExportOutput](base.Registry, "browserCaptureExport", descCaptureExport, func(ctx context.Context, in *browsersvc.CaptureExportInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.CaptureExport(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.ScreenshotInput, *browsersvc.ScreenshotOutput](base.Registry, "webdriverScreenshot", descScreenshot, func(ctx context.Context, in *browsersvc.ScreenshotInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if in == nil {
			in = &browsersvc.ScreenshotInput{}
		}
		if in.DestURL == "" {
			destURL, derr := browsersvc.DefaultScreenshotDestURL(in.SessionID)
			if derr != nil {
				return buildErrorResult(derr.Error())
			}
			in.DestURL = destURL
		}
		out, err := svc.Screenshot(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.ScreenshotInput, *browsersvc.ScreenshotOutput](base.Registry, "browserScreenshot", descScreenshot, func(ctx context.Context, in *browsersvc.ScreenshotInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if in == nil {
			in = &browsersvc.ScreenshotInput{}
		}
		if in.DestURL == "" {
			destURL, derr := browsersvc.DefaultScreenshotDestURL(in.SessionID)
			if derr != nil {
				return buildErrorResult(derr.Error())
			}
			in.DestURL = destURL
		}
		out, err := svc.Screenshot(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.ScreenshotInput, *browsersvc.ScreenshotOutput](base.Registry, "browserScreenshotData", descScreenshotData, func(ctx context.Context, in *browsersvc.ScreenshotInput) (*schema.CallToolResult, *jsonrpc.Error) {
		// For inline/base64 results, do not force destURL.
		out, err := svc.Screenshot(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.ScreenshotInput, *browsersvc.ScreenshotOutput](base.Registry, "webdriverScreenshotData", descScreenshotData, func(ctx context.Context, in *browsersvc.ScreenshotInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.Screenshot(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.DriverInstallInput, *browsersvc.DriverInstallOutput](base.Registry, "browserDriverInstall", descDriverInstall, func(ctx context.Context, in *browsersvc.DriverInstallInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.DriverInstall(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.DriverInstallInput, *browsersvc.DriverInstallOutput](base.Registry, "browserDriverUpdate", descDriverUpdate, func(ctx context.Context, in *browsersvc.DriverInstallInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if in == nil {
			in = &browsersvc.DriverInstallInput{}
		}
		in.Force = true
		out, err := svc.DriverInstall(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.GetSourceInput, *browsersvc.GetSourceOutput](base.Registry, "browserGetSource", descGetSource, func(ctx context.Context, in *browsersvc.GetSourceInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.GetSource(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.GetSourceInput, *browsersvc.GetSourceOutput](base.Registry, "webdriverGetSource", descGetSource, func(ctx context.Context, in *browsersvc.GetSourceInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.GetSource(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.GetDOMInput, *browsersvc.GetDOMOutput](base.Registry, "browserGetDOM", descGetDOM, func(ctx context.Context, in *browsersvc.GetDOMInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.GetDOM(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.GetDOMInput, *browsersvc.GetDOMOutput](base.Registry, "webdriverGetDOM", descGetDOM, func(ctx context.Context, in *browsersvc.GetDOMInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.GetDOM(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.SessionsInput, *browsersvc.SessionsOutput](base.Registry, "browserSessions", descSessions, func(ctx context.Context, in *browsersvc.SessionsInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.Sessions(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.SessionsInput, *browsersvc.SessionsOutput](base.Registry, "webdriverSessions", descSessions, func(ctx context.Context, in *browsersvc.SessionsInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.Sessions(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.EvalJSInput, *browsersvc.EvalJSOutput](base.Registry, "browserEvalJS", descEvalJS, func(ctx context.Context, in *browsersvc.EvalJSInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.EvalJS(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	if err := protoserver.RegisterTool[*browsersvc.EvalJSInput, *browsersvc.EvalJSOutput](base.Registry, "webdriverEvalJS", descEvalJS, func(ctx context.Context, in *browsersvc.EvalJSInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.EvalJS(ctx, in)
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

func buildSuccessResultOut(service *browsersvc.Service, payload any) (*schema.CallToolResult, *jsonrpc.Error) {
	if service.UseTextField() {
		b, _ := json.Marshal(payload)
		return &schema.CallToolResult{Content: []schema.CallToolResultContentElem{{Type: "text", Text: string(b)}}}, nil
	}
	return &schema.CallToolResult{StructuredContent: map[string]any{"result": payload}}, nil
}
