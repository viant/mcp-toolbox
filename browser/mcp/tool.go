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

//go:embed tools/browserHealth.md
var descHealth string

//go:embed tools/browserScreenshotData.md
var descScreenshotData string

//go:embed tools/browserEvalJS.md
var descEvalJS string

//go:embed tools/browserFind.md
var descFind string

//go:embed tools/browserClick.md
var descClick string

//go:embed tools/browserFill.md
var descFill string

//go:embed tools/browserPress.md
var descPress string

//go:embed tools/browserWait.md
var descWait string

//go:embed tools/browserHover.md
var descHover string

//go:embed tools/browserWaitURL.md
var descWaitURL string

//go:embed tools/browserStorageSave.md
var descStorageSave string

//go:embed tools/browserStorageLoad.md
var descStorageLoad string

//go:embed tools/browserClickText.md
var descClickText string

//go:embed tools/browserFillByLabel.md
var descFillByLabel string

//go:embed tools/browserDebugDump.md
var descDebugDump string

func registerTools(base *protoserver.DefaultHandler, h *Handler) error {
	svc := h.service

	if err := registerToolNames(base.Registry, toolNames("start"), descStart, svc, svc.Start); err != nil {
		return err
	}
	if err := registerToolNames(base.Registry, toolNames("stop"), descStop, svc, svc.Stop); err != nil {
		return err
	}
	if err := registerToolNames(base.Registry, toolNames("open"), descOpen, svc, svc.OpenSession); err != nil {
		return err
	}
	if err := registerToolNames(base.Registry, toolNames("close"), descClose, svc, svc.CloseSession); err != nil {
		return err
	}
	if err := registerToolNames(base.Registry, toolNames("run"), descRun, svc, svc.Run); err != nil {
		return err
	}
	if err := registerToolNames(base.Registry, toolNames("callDriver"), descCallDriver, svc, svc.CallDriver); err != nil {
		return err
	}
	if err := registerToolNames(base.Registry, toolNames("callElement"), descCallElement, svc, svc.CallElement); err != nil {
		return err
	}

	if err := registerToolNames(base.Registry, toolNames("captureStart"), descCaptureStart, svc, svc.CaptureStart); err != nil {
		return err
	}
	if err := registerToolNames(base.Registry, toolNames("captureStop"), descCaptureStop, svc, svc.CaptureStop); err != nil {
		return err
	}
	if err := registerToolNames(base.Registry, toolNames("captureStatus"), descCaptureStatus, svc, svc.CaptureStatus); err != nil {
		return err
	}
	if err := registerToolNames(base.Registry, toolNames("captureClear"), descCaptureClear, svc, svc.CaptureClear); err != nil {
		return err
	}
	if err := registerToolNames(base.Registry, toolNames("captureExport"), descCaptureExport, svc, svc.CaptureExport); err != nil {
		return err
	}

	if err := registerToolNames(base.Registry, toolNames("screenshot"), descScreenshot, svc, svc.Screenshot); err != nil {
		return err
	}
	if err := registerToolNames(base.Registry, toolNames("screenshotData"), descScreenshotData, svc, func(ctx context.Context, in *browsersvc.ScreenshotInput) (*browsersvc.ScreenshotOutput, error) {
		if in == nil {
			in = &browsersvc.ScreenshotInput{}
		}
		req := *in
		req.DestURL = ""
		return svc.Screenshot(ctx, &req)
	}); err != nil {
		return err
	}

	if err := registerToolNames(base.Registry, toolNames("driverInstall"), descDriverInstall, svc, svc.DriverInstall); err != nil {
		return err
	}
	if err := registerToolNames(base.Registry, toolNames("driverUpdate"), descDriverUpdate, svc, func(ctx context.Context, in *browsersvc.DriverInstallInput) (*browsersvc.DriverInstallOutput, error) {
		if in == nil {
			in = &browsersvc.DriverInstallInput{}
		}
		req := *in
		req.Force = true
		return svc.DriverInstall(ctx, &req)
	}); err != nil {
		return err
	}

	if err := registerToolNames(base.Registry, toolNames("getSource"), descGetSource, svc, svc.GetSource); err != nil {
		return err
	}
	if err := registerToolNames(base.Registry, toolNames("getDOM"), descGetDOM, svc, svc.GetDOM); err != nil {
		return err
	}

	if err := registerToolNames(base.Registry, toolNames("sessions"), descSessions, svc, svc.Sessions); err != nil {
		return err
	}
	if err := registerToolNames(base.Registry, toolNames("health"), descHealth, svc, svc.Health); err != nil {
		return err
	}

	if err := registerToolNames(base.Registry, toolNames("evalJS"), descEvalJS, svc, svc.EvalJS); err != nil {
		return err
	}

	if err := registerToolNames(base.Registry, toolNames("find"), descFind, svc, svc.Find); err != nil {
		return err
	}
	if err := registerToolNames(base.Registry, toolNames("click"), descClick, svc, svc.Click); err != nil {
		return err
	}
	if err := registerToolNames(base.Registry, toolNames("hover"), descHover, svc, svc.Hover); err != nil {
		return err
	}
	if err := registerToolNames(base.Registry, toolNames("fill"), descFill, svc, svc.Fill); err != nil {
		return err
	}
	if err := registerToolNames(base.Registry, toolNames("press"), descPress, svc, svc.Press); err != nil {
		return err
	}
	if err := registerToolNames(base.Registry, toolNames("wait"), descWait, svc, svc.Wait); err != nil {
		return err
	}
	if err := registerToolNames(base.Registry, toolNames("waitURL"), descWaitURL, svc, svc.WaitURL); err != nil {
		return err
	}
	if err := registerToolNames(base.Registry, toolNames("storageSave"), descStorageSave, svc, svc.StorageSave); err != nil {
		return err
	}
	if err := registerToolNames(base.Registry, toolNames("storageLoad"), descStorageLoad, svc, svc.StorageLoad); err != nil {
		return err
	}
	if err := registerToolNames(base.Registry, toolNames("clickText"), descClickText, svc, svc.ClickText); err != nil {
		return err
	}
	if err := registerToolNames(base.Registry, toolNames("fillByLabel"), descFillByLabel, svc, svc.FillByLabel); err != nil {
		return err
	}
	if err := registerToolNames(base.Registry, toolNames("debugDump"), descDebugDump, svc, svc.DebugDump); err != nil {
		return err
	}

	return nil
}

func toolNames(primary string) []string {
	return []string{primary}
}

func registerToolNames[I any, O any](
	registry *protoserver.Registry,
	names []string,
	description string,
	service *browsersvc.Service,
	fn func(context.Context, *I) (*O, error),
) error {
	for _, name := range names {
		if err := registerTool(registry, name, description, service, fn); err != nil {
			return err
		}
	}
	return nil
}

func registerTool[I any, O any](
	registry *protoserver.Registry,
	name string,
	description string,
	service *browsersvc.Service,
	fn func(context.Context, *I) (*O, error),
) error {
	return protoserver.RegisterTool[*I, *O](registry, name, description, func(ctx context.Context, in *I) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := fn(ctx, in)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(service, out)
	})
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
