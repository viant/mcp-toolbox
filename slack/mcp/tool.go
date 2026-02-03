package mcp

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"time"

	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/schema"
	protoserver "github.com/viant/mcp-protocol/server"
	slservice "github.com/viant/mcp-toolbox/slack/service"
)

//go:embed tools/slackPostMessage.md
var descPostMessage string

//go:embed tools/slackListChannels.md
var descListChannels string

//go:embed tools/slackListMessages.md
var descListMessages string

//go:embed tools/slackListThreadMessages.md
var descListThreadMessages string

//go:embed tools/slackThreadFromURL.md
var descThreadFromURL string

func logToolStart(name string) time.Time                             { return time.Now() }
func logToolEnd(name string, start time.Time, err error)             {}
func startToolPending(name string, args any, start time.Time) func() { return func() {} }

func registerTools(base *protoserver.DefaultHandler, h *Handler) error {
	svc := h.service
	// Post message
	if err := protoserver.RegisterTool[*slservice.PostMessageInput, *slservice.PostMessageOutput](base.Registry, "slackPostMessage", descPostMessage, func(ctx context.Context, in *slservice.PostMessageInput) (*schema.CallToolResult, *jsonrpc.Error) {
		start := logToolStart("slackPostMessage")
		stop := startToolPending("slackPostMessage", in, start)
		defer stop()
		if in == nil || in.Channel == "" || (in.Text == "" && len(in.Blocks) == 0) {
			return buildErrorResult("channel and one of text/blocks are required")
		}
		out, err := svc.PostMessage(ctx, in)
		if err != nil {
			logToolEnd("slackPostMessage", start, err)
			return buildErrorResult(err.Error())
		}
		logToolEnd("slackPostMessage", start, nil)
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	// List channels
	if err := protoserver.RegisterTool[*slservice.ListChannelsInput, *slservice.ListChannelsOutput](base.Registry, "slackListChannels", descListChannels, func(ctx context.Context, in *slservice.ListChannelsInput) (*schema.CallToolResult, *jsonrpc.Error) {
		start := logToolStart("slackListChannels")
		stop := startToolPending("slackListChannels", in, start)
		defer stop()
		out, err := svc.ListChannels(ctx, in)
		if err != nil {
			logToolEnd("slackListChannels", start, err)
			return buildErrorResult(err.Error())
		}
		logToolEnd("slackListChannels", start, nil)
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	// List messages
	if err := protoserver.RegisterTool[*slservice.ListMessagesInput, *slservice.ListMessagesOutput](base.Registry, "slackListMessages", descListMessages, func(ctx context.Context, in *slservice.ListMessagesInput) (*schema.CallToolResult, *jsonrpc.Error) {
		start := logToolStart("slackListMessages")
		stop := startToolPending("slackListMessages", in, start)
		defer stop()
		if in == nil || in.Channel == "" {
			return buildErrorResult("channel is required")
		}
		out, err := svc.ListMessages(ctx, in)
		if err != nil {
			logToolEnd("slackListMessages", start, err)
			return buildErrorResult(err.Error())
		}
		logToolEnd("slackListMessages", start, nil)
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	// List thread messages (replies)
	if err := protoserver.RegisterTool[*slservice.ListThreadMessagesInput, *slservice.ListThreadMessagesOutput](base.Registry, "slackListThreadMessages", descListThreadMessages, func(ctx context.Context, in *slservice.ListThreadMessagesInput) (*schema.CallToolResult, *jsonrpc.Error) {
		start := logToolStart("slackListThreadMessages")
		stop := startToolPending("slackListThreadMessages", in, start)
		defer stop()
		if in == nil || in.Channel == "" || in.ThreadTs == "" {
			return buildErrorResult("channel and threadTs are required")
		}
		out, err := svc.ListThreadMessages(ctx, in)
		if err != nil {
			logToolEnd("slackListThreadMessages", start, err)
			return buildErrorResult(err.Error())
		}
		logToolEnd("slackListThreadMessages", start, nil)
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	// Get thread messages from a Slack message URL
	if err := protoserver.RegisterTool[*slservice.ListThreadMessagesInput, *slservice.ListThreadMessagesOutput](base.Registry, "slackThreadFromURL", descThreadFromURL, func(ctx context.Context, in *slservice.ListThreadMessagesInput) (*schema.CallToolResult, *jsonrpc.Error) {
		start := logToolStart("slackThreadFromURL")
		stop := startToolPending("slackThreadFromURL", in, start)
		defer stop()
		if in == nil || in.URL == "" {
			return buildErrorResult("url is required")
		}
		// Service derives channel/threadTs from URL if fields are empty
		out, err := svc.ListThreadMessages(ctx, in)
		if err != nil {
			logToolEnd("slackThreadFromURL", start, err)
			return buildErrorResult(err.Error())
		}
		logToolEnd("slackThreadFromURL", start, nil)
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	return nil
}

func buildErrorResult(message string) (*schema.CallToolResult, *jsonrpc.Error) {
	return nil, jsonrpc.NewError(jsonrpc.InvalidParams, message, nil)
}

func buildSuccessResultOut(service *slservice.Service, payload any) (*schema.CallToolResult, *jsonrpc.Error) {
	if service.UseTextField() {
		b, _ := json.Marshal(payload)
		return &schema.CallToolResult{Content: []schema.CallToolResultContentElem{schema.TextContent{Type: "text", Text: string(b)}}}, nil
	}
	return &schema.CallToolResult{StructuredContent: map[string]any{"result": payload}}, nil
}

func _unused(s string) { fmt.Print(s) }
