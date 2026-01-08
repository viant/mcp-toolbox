package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	selog "github.com/tebeka/selenium/log"
	"github.com/viant/afs"
)

type CaptureState struct {
	mux sync.Mutex

	enabled bool
	started time.Time

	includeBodies bool
	enableConsole bool
	enableNetwork bool

	maxBodyBytes  int
	redact        bool
	redactHeaders map[string]bool

	inflight  map[string]*NetworkTransaction
	completed []*NetworkTransaction
	console   []*ConsoleEntry
	wsURL     map[string]string
	wsFrames  []*WebSocketFrame
	streams   []*StreamMessage
	errors    []string

	sink *captureSink
}

func newCaptureState(req *CaptureStartInput) *CaptureState {
	state := &CaptureState{
		enabled:       true,
		started:       time.Now(),
		includeBodies: true,
		enableConsole: true,
		enableNetwork: true,
		maxBodyBytes:  1_000_000,
		redact:        true,
		redactHeaders: map[string]bool{},
		inflight:      map[string]*NetworkTransaction{},
		completed:     []*NetworkTransaction{},
		console:       []*ConsoleEntry{},
		wsURL:         map[string]string{},
		wsFrames:      []*WebSocketFrame{},
		streams:       []*StreamMessage{},
		errors:        []string{},
	}
	for _, h := range []string{"authorization", "cookie", "set-cookie", "x-api-key"} {
		state.redactHeaders[h] = true
	}
	if req == nil {
		return state
	}
	if req.MaxBodyBytes > 0 {
		state.maxBodyBytes = req.MaxBodyBytes
	}
	if req.Redact != nil {
		state.redact = *req.Redact
	}
	if len(req.RedactHeaders) > 0 {
		state.redactHeaders = map[string]bool{}
		for _, h := range req.RedactHeaders {
			state.redactHeaders[strings.ToLower(strings.TrimSpace(h))] = true
		}
	}
	if req.EnableConsole != nil {
		state.enableConsole = *req.EnableConsole
	}
	if req.EnableNetwork != nil {
		state.enableNetwork = *req.EnableNetwork
	}
	if req.IncludeBodies != nil {
		state.includeBodies = *req.IncludeBodies
	}
	return state
}

func (s *CaptureState) Summary() *CaptureSummary {
	s.mux.Lock()
	defer s.mux.Unlock()
	return &CaptureSummary{
		StartedAt:         s.started,
		RequestsInFlight:  len(s.inflight),
		RequestsCompleted: len(s.completed),
		ConsoleEntries:    len(s.console),
		WebSocketFrames:   len(s.wsFrames),
		StreamMessages:    len(s.streams),
		Errors:            append([]string(nil), s.errors...),
	}
}

func (s *CaptureState) Clear() {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.inflight = map[string]*NetworkTransaction{}
	s.completed = []*NetworkTransaction{}
	s.console = []*ConsoleEntry{}
	s.wsURL = map[string]string{}
	s.wsFrames = []*WebSocketFrame{}
	s.streams = []*StreamMessage{}
	s.errors = []string{}
	s.started = time.Now()
	if s.sink != nil {
		s.sink.nextConsole = 0
		s.sink.nextNetwork = 0
		s.sink.nextWS = 0
		s.sink.nextStreams = 0
	}
}

func (s *CaptureState) Snapshot(maxEntries int, includeConsole, includeNetwork, includeWebSocket, includeStreams bool) (console []*ConsoleEntry, network []*NetworkTransaction, ws []*WebSocketFrame, streams []*StreamMessage) {
	s.mux.Lock()
	defer s.mux.Unlock()
	if maxEntries <= 0 {
		maxEntries = 10_000
	}
	if includeConsole {
		limit := min(maxEntries, len(s.console))
		console = append([]*ConsoleEntry(nil), s.console[len(s.console)-limit:]...)
	}
	if includeNetwork {
		limit := min(maxEntries, len(s.completed))
		network = append([]*NetworkTransaction(nil), s.completed[len(s.completed)-limit:]...)
	}
	if includeWebSocket {
		limit := min(maxEntries, len(s.wsFrames))
		ws = append([]*WebSocketFrame(nil), s.wsFrames[len(s.wsFrames)-limit:]...)
	}
	if includeStreams {
		limit := min(maxEntries, len(s.streams))
		streams = append([]*StreamMessage(nil), s.streams[len(s.streams)-limit:]...)
	}
	return
}

func (s *CaptureState) Drain(sess *Session) {
	if sess == nil || sess.driver == nil {
		return
	}
	s.drainConsole(sess.driver)
	s.drainPerformance(sess)
}

func (s *CaptureState) drainConsole(driver any) {
	if !s.enableConsole {
		return
	}
	wd, ok := driver.(interface {
		Log(typ selog.Type) ([]selog.Message, error)
	})
	if !ok {
		return
	}
	messages, err := wd.Log(selog.Browser)
	if err != nil || len(messages) == 0 {
		return
	}
	s.mux.Lock()
	defer s.mux.Unlock()
	for _, msg := range messages {
		s.console = append(s.console, &ConsoleEntry{Timestamp: msg.Timestamp, Level: string(msg.Level), Message: msg.Message})
	}
}

func (s *CaptureState) drainPerformance(sess *Session) {
	if !s.enableNetwork && !s.enableConsole {
		return
	}
	wd, ok := sess.driver.(interface {
		Log(typ selog.Type) ([]selog.Message, error)
		SessionID() string
	})
	if !ok {
		return
	}
	messages, err := wd.Log(selog.Performance)
	if err != nil {
		return
	}
	for _, msg := range messages {
		method, params, perr := parsePerformanceLogMessage(msg.Message)
		if perr != nil {
			continue
		}
		switch method {
		case "Network.requestWillBeSent":
			if s.enableNetwork {
				s.onRequestWillBeSent(params)
			}
		case "Network.requestWillBeSentExtraInfo":
			if s.enableNetwork {
				s.onRequestExtraInfo(params)
			}
		case "Network.responseReceived":
			if s.enableNetwork {
				s.onResponseReceived(params)
			}
		case "Network.responseReceivedExtraInfo":
			if s.enableNetwork {
				s.onResponseExtraInfo(params)
			}
		case "Network.loadingFinished":
			if s.enableNetwork {
				s.onLoadingFinished(sess, params)
			}
		case "Network.loadingFailed":
			if s.enableNetwork {
				s.onLoadingFailed(params)
			}
		case "Network.requestServedFromCache":
			if s.enableNetwork {
				s.onRequestServedFromCache(params)
			}
		case "Network.dataReceived":
			if s.enableNetwork {
				s.onDataReceived(params)
			}
		case "Network.eventSourceMessageReceived":
			if s.enableNetwork {
				s.onEventSourceMessage(params)
			}
		case "Network.webSocketCreated":
			if s.enableNetwork {
				s.onWebSocketCreated(params)
			}
		case "Network.webSocketFrameSent":
			if s.enableNetwork {
				s.onWebSocketFrame(params, "sent")
			}
		case "Network.webSocketFrameReceived":
			if s.enableNetwork {
				s.onWebSocketFrame(params, "received")
			}
		case "Network.webSocketClosed":
			if s.enableNetwork {
				s.onWebSocketClosed(params)
			}
		case "Runtime.consoleAPICalled":
			s.onRuntimeConsole(params)
		case "Runtime.exceptionThrown":
			s.onRuntimeException(params)
		}
	}
}

func (s *CaptureState) onRequestWillBeSent(params json.RawMessage) {
	type request struct {
		URL      string         `json:"url"`
		Method   string         `json:"method"`
		Headers  map[string]any `json:"headers"`
		PostData string         `json:"postData,omitempty"`
	}
	type input struct {
		RequestID string         `json:"requestId"`
		Timestamp float64        `json:"timestamp"`
		Type      string         `json:"type,omitempty"`
		Initiator map[string]any `json:"initiator,omitempty"`
		Request   request        `json:"request"`
	}
	in := &input{}
	if err := json.Unmarshal(params, in); err != nil {
		return
	}
	tx := &NetworkTransaction{
		RequestID:      in.RequestID,
		URL:            in.Request.URL,
		Method:         in.Request.Method,
		RequestHeaders: redactIfNeeded(in.Request.Headers, s.redact, s.redactHeaders),
		ResourceType:   in.Type,
		Initiator:      in.Initiator,
		StartTimestamp: in.Timestamp,
	}
	if s.includeBodies && in.Request.PostData != "" {
		tx.RequestBody = capBody(in.Request.PostData, false, s.maxBodyBytes)
	}
	s.mux.Lock()
	defer s.mux.Unlock()
	s.inflight[in.RequestID] = tx
}

func (s *CaptureState) onRequestExtraInfo(params json.RawMessage) {
	type input struct {
		RequestID string         `json:"requestId"`
		Headers   map[string]any `json:"headers"`
	}
	in := &input{}
	if err := json.Unmarshal(params, in); err != nil {
		return
	}
	s.mux.Lock()
	defer s.mux.Unlock()
	tx := s.inflight[in.RequestID]
	if tx == nil {
		return
	}
	if tx.RequestHeaders == nil {
		tx.RequestHeaders = map[string]any{}
	}
	for k, v := range redactIfNeeded(in.Headers, s.redact, s.redactHeaders) {
		tx.RequestHeaders[k] = v
	}
}

func (s *CaptureState) onResponseReceived(params json.RawMessage) {
	type response struct {
		Status            int            `json:"status"`
		StatusText        string         `json:"statusText"`
		MimeType          string         `json:"mimeType"`
		Headers           map[string]any `json:"headers"`
		FromDiskCache     bool           `json:"fromDiskCache,omitempty"`
		FromPrefetchCache bool           `json:"fromPrefetchCache,omitempty"`
		FromServiceWorker bool           `json:"fromServiceWorker,omitempty"`
	}
	type input struct {
		RequestID string   `json:"requestId"`
		Timestamp float64  `json:"timestamp"`
		Type      string   `json:"type,omitempty"`
		Response  response `json:"response"`
	}
	in := &input{}
	if err := json.Unmarshal(params, in); err != nil {
		return
	}
	s.mux.Lock()
	defer s.mux.Unlock()
	tx := s.inflight[in.RequestID]
	if tx == nil {
		tx = &NetworkTransaction{RequestID: in.RequestID}
		s.inflight[in.RequestID] = tx
	}
	tx.Status = in.Response.Status
	tx.StatusText = in.Response.StatusText
	tx.MimeType = in.Response.MimeType
	tx.FromDiskCache = in.Response.FromDiskCache
	tx.FromPrefetchCache = in.Response.FromPrefetchCache
	tx.FromServiceWorker = in.Response.FromServiceWorker
	tx.ResponseHeaders = redactIfNeeded(in.Response.Headers, s.redact, s.redactHeaders)
	if tx.ResourceType == "" {
		tx.ResourceType = in.Type
	}
}

func (s *CaptureState) onResponseExtraInfo(params json.RawMessage) {
	type input struct {
		RequestID string         `json:"requestId"`
		Headers   map[string]any `json:"headers"`
	}
	in := &input{}
	if err := json.Unmarshal(params, in); err != nil {
		return
	}
	s.mux.Lock()
	defer s.mux.Unlock()
	tx := s.inflight[in.RequestID]
	if tx == nil {
		return
	}
	if tx.ResponseHeaders == nil {
		tx.ResponseHeaders = map[string]any{}
	}
	for k, v := range redactIfNeeded(in.Headers, s.redact, s.redactHeaders) {
		tx.ResponseHeaders[k] = v
	}
}

func (s *CaptureState) onLoadingFailed(params json.RawMessage) {
	type input struct {
		RequestID string  `json:"requestId"`
		Timestamp float64 `json:"timestamp"`
		ErrorText string  `json:"errorText"`
		Canceled  bool    `json:"canceled"`
	}
	in := &input{}
	if err := json.Unmarshal(params, in); err != nil {
		return
	}
	s.mux.Lock()
	defer s.mux.Unlock()
	tx := s.inflight[in.RequestID]
	if tx == nil {
		tx = &NetworkTransaction{RequestID: in.RequestID}
		s.inflight[in.RequestID] = tx
	}
	tx.ErrorText = in.ErrorText
	tx.WasCanceled = in.Canceled
	tx.EndTimestamp = in.Timestamp
	s.finishLocked(in.RequestID, tx)
}

func (s *CaptureState) onLoadingFinished(sess *Session, params json.RawMessage) {
	type input struct {
		RequestID         string  `json:"requestId"`
		Timestamp         float64 `json:"timestamp"`
		EncodedDataLength float64 `json:"encodedDataLength"`
	}
	in := &input{}
	if err := json.Unmarshal(params, in); err != nil {
		return
	}

	s.mux.Lock()
	tx := s.inflight[in.RequestID]
	if tx == nil {
		tx = &NetworkTransaction{RequestID: in.RequestID}
		s.inflight[in.RequestID] = tx
	}
	tx.EndTimestamp = in.Timestamp
	tx.EncodedDataSize = int64(in.EncodedDataLength)
	start := tx.StartTimestamp
	end := tx.EndTimestamp
	s.mux.Unlock()

	if s.includeBodies {
		body, enc, truncated, berr := getResponseBody(sess, in.RequestID, s.maxBodyBytes)
		if berr == nil && (body != "" || enc != "") {
			s.mux.Lock()
			tx.ResponseBody = &CapturedBody{Encoding: enc, Data: body, Truncated: truncated}
			s.mux.Unlock()
		} else if berr != nil {
			s.mux.Lock()
			tx.ResponseBodyError = berr.Error()
			s.mux.Unlock()
		}
	}

	s.mux.Lock()
	if start > 0 && end >= start {
		tx.DurationMs = int64((end - start) * 1000)
	}
	s.finishLocked(in.RequestID, tx)
	s.mux.Unlock()
}

func (s *CaptureState) finishLocked(requestID string, tx *NetworkTransaction) {
	s.completed = append(s.completed, tx)
	delete(s.inflight, requestID)
}

func (s *CaptureState) onRequestServedFromCache(params json.RawMessage) {
	type input struct {
		RequestID string `json:"requestId"`
	}
	in := &input{}
	if err := json.Unmarshal(params, in); err != nil {
		return
	}
	s.mux.Lock()
	defer s.mux.Unlock()
	tx := s.inflight[in.RequestID]
	if tx == nil {
		tx = &NetworkTransaction{RequestID: in.RequestID}
		s.inflight[in.RequestID] = tx
	}
	tx.ServedFromCache = true
}

func (s *CaptureState) onDataReceived(params json.RawMessage) {
	type input struct {
		RequestID  string  `json:"requestId"`
		DataLength float64 `json:"dataLength"`
	}
	in := &input{}
	if err := json.Unmarshal(params, in); err != nil {
		return
	}
	s.mux.Lock()
	defer s.mux.Unlock()
	tx := s.inflight[in.RequestID]
	if tx == nil {
		tx = &NetworkTransaction{RequestID: in.RequestID}
		s.inflight[in.RequestID] = tx
	}
	tx.DataReceivedBytes += int64(in.DataLength)
}

func (s *CaptureState) onEventSourceMessage(params json.RawMessage) {
	type input struct {
		RequestID string  `json:"requestId"`
		Timestamp float64 `json:"timestamp"`
		EventName string  `json:"eventName"`
		EventID   string  `json:"eventId"`
		Data      string  `json:"data"`
	}
	in := &input{}
	if err := json.Unmarshal(params, in); err != nil {
		return
	}
	msg := &StreamMessage{
		RequestID: in.RequestID,
		Timestamp: in.Timestamp,
		EventName: in.EventName,
		EventID:   in.EventID,
		Data:      capBody(in.Data, false, s.maxBodyBytes),
	}
	s.mux.Lock()
	if tx := s.inflight[in.RequestID]; tx != nil {
		msg.URL = tx.URL
	} else if u, ok := s.wsURL[in.RequestID]; ok {
		msg.URL = u
	}
	s.streams = append(s.streams, msg)
	s.mux.Unlock()
}

func (s *CaptureState) onWebSocketCreated(params json.RawMessage) {
	type input struct {
		RequestID string `json:"requestId"`
		URL       string `json:"url"`
	}
	in := &input{}
	if err := json.Unmarshal(params, in); err != nil {
		return
	}
	s.mux.Lock()
	s.wsURL[in.RequestID] = in.URL
	s.mux.Unlock()
}

func (s *CaptureState) onWebSocketFrame(params json.RawMessage, direction string) {
	type frame struct {
		Opcode      int    `json:"opcode"`
		Mask        bool   `json:"mask"`
		PayloadData string `json:"payloadData"`
	}
	type input struct {
		RequestID string  `json:"requestId"`
		Timestamp float64 `json:"timestamp"`
		Response  frame   `json:"response"`
	}
	in := &input{}
	if err := json.Unmarshal(params, in); err != nil {
		type input2 struct {
			RequestID string  `json:"requestId"`
			Timestamp float64 `json:"timestamp"`
			Request   frame   `json:"request"`
		}
		in2 := &input2{}
		if err2 := json.Unmarshal(params, in2); err2 != nil {
			return
		}
		in.RequestID = in2.RequestID
		in.Timestamp = in2.Timestamp
		in.Response = in2.Request
	}
	f := &WebSocketFrame{
		RequestID: in.RequestID,
		Timestamp: in.Timestamp,
		Direction: direction,
		Opcode:    in.Response.Opcode,
		Mask:      in.Response.Mask,
		Payload:   capBody(in.Response.PayloadData, false, s.maxBodyBytes),
	}
	s.mux.Lock()
	if u, ok := s.wsURL[in.RequestID]; ok {
		f.URL = u
	} else if tx := s.inflight[in.RequestID]; tx != nil {
		f.URL = tx.URL
	}
	s.wsFrames = append(s.wsFrames, f)
	s.mux.Unlock()
}

func (s *CaptureState) onWebSocketClosed(params json.RawMessage) {
	// Currently unused; placeholder for future diagnostics.
	_ = params
}

func (s *CaptureState) onRuntimeConsole(params json.RawMessage) {
	if !s.enableConsole {
		return
	}
	type arg struct {
		Type        string `json:"type"`
		Value       any    `json:"value,omitempty"`
		Description string `json:"description,omitempty"`
	}
	type input struct {
		Type string `json:"type"`
		Args []arg  `json:"args"`
	}
	in := &input{}
	if err := json.Unmarshal(params, in); err != nil {
		return
	}
	parts := make([]string, 0, len(in.Args))
	for _, a := range in.Args {
		if a.Description != "" {
			parts = append(parts, a.Description)
		} else if a.Value != nil {
			parts = append(parts, fmt.Sprintf("%v", a.Value))
		} else {
			parts = append(parts, a.Type)
		}
	}
	s.mux.Lock()
	s.console = append(s.console, &ConsoleEntry{Timestamp: time.Now(), Level: in.Type, Message: strings.Join(parts, " ")})
	s.mux.Unlock()
}

func (s *CaptureState) onRuntimeException(params json.RawMessage) {
	if !s.enableConsole {
		return
	}
	type input struct {
		Details struct {
			Text      string `json:"text"`
			Exception struct {
				Description string `json:"description"`
			} `json:"exception"`
		} `json:"exceptionDetails"`
	}
	in := &input{}
	if err := json.Unmarshal(params, in); err != nil {
		return
	}
	msg := in.Details.Text
	if in.Details.Exception.Description != "" {
		msg = in.Details.Exception.Description
	}
	s.mux.Lock()
	s.console = append(s.console, &ConsoleEntry{Timestamp: time.Now(), Level: "exception", Message: msg})
	s.mux.Unlock()
}

func parsePerformanceLogMessage(raw string) (string, json.RawMessage, error) {
	var outer struct {
		Message json.RawMessage `json:"message"`
	}
	if err := json.Unmarshal([]byte(raw), &outer); err != nil {
		return "", nil, err
	}
	if len(outer.Message) == 0 {
		return "", nil, errors.New("missing message field")
	}
	var inner struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if outer.Message[0] == '"' {
		var msgStr string
		if err := json.Unmarshal(outer.Message, &msgStr); err != nil {
			return "", nil, err
		}
		if err := json.Unmarshal([]byte(msgStr), &inner); err != nil {
			return "", nil, err
		}
		return inner.Method, inner.Params, nil
	}
	if err := json.Unmarshal(outer.Message, &inner); err != nil {
		return "", nil, err
	}
	return inner.Method, inner.Params, nil
}

func redactIfNeeded(headers map[string]any, redact bool, redactHeaders map[string]bool) map[string]any {
	if headers == nil {
		return nil
	}
	out := map[string]any{}
	for k, v := range headers {
		if redact && redactHeaders[strings.ToLower(k)] {
			out[k] = "<redacted>"
			continue
		}
		out[k] = v
	}
	return out
}

func capBody(body string, base64Encoded bool, maxBytes int) *CapturedBody {
	if maxBytes <= 0 {
		maxBytes = 1_000_000
	}
	encoding := ""
	if base64Encoded {
		encoding = "base64"
	}
	truncated := false
	if len(body) > maxBytes {
		body = body[:maxBytes]
		truncated = true
	}
	return &CapturedBody{Encoding: encoding, Data: body, Truncated: truncated}
}

func getResponseBody(sess *Session, requestID string, maxBytes int) (data string, encoding string, truncated bool, err error) {
	if sess == nil || sess.driver == nil || sess.Remote == "" {
		return "", "", false, errors.New("missing session remote")
	}
	wdSession := sess.driver.SessionID()
	if wdSession == "" {
		return "", "", false, errors.New("missing webdriver session id")
	}
	type result struct {
		Body          string `json:"body"`
		Base64Encoded bool   `json:"base64Encoded"`
	}
	raw, err := cdpExecute(sess.Remote, wdSession, "Network.getResponseBody", map[string]any{"requestId": requestID})
	if err != nil {
		return "", "", false, err
	}
	out := &result{}
	if err := json.Unmarshal(raw, out); err != nil {
		return "", "", false, err
	}
	capped := capBody(out.Body, out.Base64Encoded, maxBytes)
	return capped.Data, capped.Encoding, capped.Truncated, nil
}

func cdpExecute(remote, wdSession, cmd string, params map[string]any) (json.RawMessage, error) {
	payload := map[string]any{"cmd": cmd, "params": params}
	if raw, err := postW3C(remote, wdSession, "goog/cdp/execute", payload); err == nil {
		return raw, nil
	}
	return postW3C(remote, wdSession, "chromium/send_command_and_get_result", payload)
}

func postW3C(remote, wdSession, endpoint string, payload map[string]any) (json.RawMessage, error) {
	u, err := neturl.Parse(remote)
	if err != nil {
		return nil, err
	}
	u.Path = path.Join(u.Path, "session", wdSession, endpoint)
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("cdp %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var decoded struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(b, &decoded); err != nil {
		return nil, err
	}
	if len(decoded.Value) == 0 {
		decoded.Value = json.RawMessage(`{}`)
	}
	return decoded.Value, nil
}

type captureSink struct {
	fs             afs.Service
	baseURL        string
	indexURL       string
	indexWriter    io.WriteCloser
	splitArtifacts bool

	flushInterval time.Duration
	lastSync      time.Time
	nextConsole   int
	nextNetwork   int
	nextWS        int
	nextStreams   int
}

func (s *CaptureState) StartSink(fs afs.Service, sinkURL string, flushIntervalMs int, splitArtifacts bool) error {
	if sinkURL == "" {
		return nil
	}
	if fs == nil {
		fs = afs.New()
	}
	if flushIntervalMs <= 0 {
		flushIntervalMs = 500
	}
	baseURL := sinkURL
	indexURL := sinkURL
	if splitArtifacts {
		baseURL = deriveArtifactsBaseURL(sinkURL)
		indexURL = joinURLPath(baseURL, "index.jsonl")
		// Best-effort create directory structure.
		_ = fs.Create(context.Background(), baseURL, 0o755, true)
		_ = fs.Create(context.Background(), joinURLPath(baseURL, "roundtrip"), 0o755, true)
		_ = fs.Create(context.Background(), joinURLPath(baseURL, "ws"), 0o755, true)
		_ = fs.Create(context.Background(), joinURLPath(baseURL, "streams"), 0o755, true)
	}
	w, err := fs.NewWriter(context.Background(), indexURL, os.FileMode(0644))
	if err != nil {
		return err
	}
	s.mux.Lock()
	defer s.mux.Unlock()
	if s.sink != nil && s.sink.indexWriter != nil {
		_ = s.sink.indexWriter.Close()
	}
	s.sink = &captureSink{
		fs:             fs,
		baseURL:        baseURL,
		indexURL:       indexURL,
		indexWriter:    w,
		splitArtifacts: splitArtifacts,
		flushInterval:  time.Duration(flushIntervalMs) * time.Millisecond,
		lastSync:       time.Now(),
		nextConsole:    0,
		nextNetwork:    0,
		nextWS:         0,
		nextStreams:    0,
	}
	return nil
}

func (s *CaptureState) CloseSink() error {
	s.mux.Lock()
	defer s.mux.Unlock()
	if s.sink == nil || s.sink.indexWriter == nil {
		return nil
	}
	err := s.sink.indexWriter.Close()
	s.sink.indexWriter = nil
	return err
}

func (s *CaptureState) FlushSink() error {
	s.mux.Lock()
	sink := s.sink
	if sink == nil || sink.indexWriter == nil {
		s.mux.Unlock()
		return nil
	}
	pendingConsole := append([]*ConsoleEntry(nil), s.console[sink.nextConsole:]...)
	pendingNetwork := append([]*NetworkTransaction(nil), s.completed[sink.nextNetwork:]...)
	pendingWS := append([]*WebSocketFrame(nil), s.wsFrames[sink.nextWS:]...)
	pendingStreams := append([]*StreamMessage(nil), s.streams[sink.nextStreams:]...)
	s.mux.Unlock()

	if len(pendingConsole) == 0 && len(pendingNetwork) == 0 && len(pendingWS) == 0 && len(pendingStreams) == 0 {
		return nil
	}
	writeLine := func(v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		_, err = sink.indexWriter.Write(append(b, '\n'))
		return err
	}
	for _, entry := range pendingConsole {
		if err := writeLine(map[string]any{"type": "console", "entry": entry}); err != nil {
			return err
		}
	}
	startID := sink.nextNetwork + 1
	for i, tx := range pendingNetwork {
		if !sink.splitArtifacts {
			if err := writeLine(map[string]any{"type": "network", "tx": tx}); err != nil {
				return err
			}
			continue
		}
		id := startID + i

		reqRel := fmt.Sprintf("roundtrip/request_%05d.json", id)
		resRel := fmt.Sprintf("roundtrip/response_%05d.json", id)
		reqURL := joinURLPath(sink.baseURL, reqRel)
		resURL := joinURLPath(sink.baseURL, resRel)

		reqObj := map[string]any{
			"id":             id,
			"requestId":      tx.RequestID,
			"url":            tx.URL,
			"method":         tx.Method,
			"resourceType":   tx.ResourceType,
			"initiator":      tx.Initiator,
			"startTimestamp": tx.StartTimestamp,
			"headers":        tx.RequestHeaders,
			"body":           tx.RequestBody,
		}
		resObj := map[string]any{
			"id":                id,
			"requestId":         tx.RequestID,
			"url":               tx.URL,
			"status":            tx.Status,
			"statusText":        tx.StatusText,
			"mimeType":          tx.MimeType,
			"endTimestamp":      tx.EndTimestamp,
			"durationMs":        tx.DurationMs,
			"encodedDataSize":   tx.EncodedDataSize,
			"errorText":         tx.ErrorText,
			"wasCanceled":       tx.WasCanceled,
			"headers":           tx.ResponseHeaders,
			"body":              tx.ResponseBody,
			"servedFromCache":   tx.ServedFromCache,
			"fromDiskCache":     tx.FromDiskCache,
			"fromPrefetchCache": tx.FromPrefetchCache,
			"fromServiceWorker": tx.FromServiceWorker,
			"responseBodyError": tx.ResponseBodyError,
			"dataReceivedBytes": tx.DataReceivedBytes,
		}
		if err := sink.fs.Upload(context.Background(), reqURL, 0o644, bytes.NewReader(mustJSON(reqObj))); err != nil {
			return err
		}
		if err := sink.fs.Upload(context.Background(), resURL, 0o644, bytes.NewReader(mustJSON(resObj))); err != nil {
			return err
		}
		if err := writeLine(map[string]any{
			"type":              "network",
			"id":                id,
			"url":               tx.URL,
			"method":            tx.Method,
			"status":            tx.Status,
			"mimeType":          tx.MimeType,
			"servedFromCache":   tx.ServedFromCache,
			"fromDiskCache":     tx.FromDiskCache,
			"fromPrefetchCache": tx.FromPrefetchCache,
			"fromServiceWorker": tx.FromServiceWorker,
			"responseBodyError": tx.ResponseBodyError,
			"dataReceivedBytes": tx.DataReceivedBytes,
			"requestFile":       reqRel,
			"responseFile":      resRel,
		}); err != nil {
			return err
		}
	}

	startWS := sink.nextWS + 1
	for i, f := range pendingWS {
		if !sink.splitArtifacts {
			if err := writeLine(map[string]any{"type": "ws", "frame": f}); err != nil {
				return err
			}
			continue
		}
		id := startWS + i
		wsRel := fmt.Sprintf("ws/ws_%05d.json", id)
		wsURL := joinURLPath(sink.baseURL, wsRel)
		if err := sink.fs.Upload(context.Background(), wsURL, 0o644, bytes.NewReader(mustJSON(f))); err != nil {
			return err
		}
		if err := writeLine(map[string]any{"type": "ws", "id": id, "file": wsRel, "requestId": f.RequestID, "url": f.URL, "direction": f.Direction, "opcode": f.Opcode}); err != nil {
			return err
		}
	}

	startStream := sink.nextStreams + 1
	for i, m := range pendingStreams {
		if !sink.splitArtifacts {
			if err := writeLine(map[string]any{"type": "stream", "message": m}); err != nil {
				return err
			}
			continue
		}
		id := startStream + i
		rel := fmt.Sprintf("streams/stream_%05d.json", id)
		u := joinURLPath(sink.baseURL, rel)
		if err := sink.fs.Upload(context.Background(), u, 0o644, bytes.NewReader(mustJSON(m))); err != nil {
			return err
		}
		if err := writeLine(map[string]any{"type": "stream", "id": id, "file": rel, "requestId": m.RequestID, "url": m.URL, "eventName": m.EventName}); err != nil {
			return err
		}
	}
	s.mux.Lock()
	if s.sink != nil {
		s.sink.nextConsole += len(pendingConsole)
		s.sink.nextNetwork += len(pendingNetwork)
		s.sink.nextWS += len(pendingWS)
		s.sink.nextStreams += len(pendingStreams)
	}
	shouldSync := s.sink != nil && s.sink.flushInterval > 0 && time.Since(s.sink.lastSync) >= s.sink.flushInterval
	var writer io.WriteCloser
	if shouldSync && s.sink != nil {
		s.sink.lastSync = time.Now()
		writer = s.sink.indexWriter
	}
	s.mux.Unlock()
	if shouldSync {
		if syncer, ok := writer.(interface{ Sync() error }); ok {
			_ = syncer.Sync()
		}
	}
	return nil
}

func deriveArtifactsBaseURL(sinkURL string) string {
	u, err := neturl.Parse(sinkURL)
	if err != nil || u == nil {
		// Fallback: treat as raw path-ish string.
		sinkURL = strings.TrimSuffix(sinkURL, "/")
		if strings.HasSuffix(sinkURL, ".jsonl") {
			sinkURL = strings.TrimSuffix(sinkURL, ".jsonl")
		}
		return sinkURL
	}
	p := strings.TrimSuffix(u.Path, "/")
	ext := path.Ext(p)
	if ext != "" {
		p = strings.TrimSuffix(p, ext)
	}
	u.Path = p
	return u.String()
}

func joinURLPath(baseURL, elem string) string {
	u, err := neturl.Parse(baseURL)
	if err != nil || u == nil {
		return strings.TrimSuffix(baseURL, "/") + "/" + strings.TrimPrefix(elem, "/")
	}
	u.Path = path.Join(u.Path, elem)
	return u.String()
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
