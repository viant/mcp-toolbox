package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tebeka/selenium"
	"github.com/tebeka/selenium/chrome"
	"github.com/tebeka/selenium/firefox"
	selog "github.com/tebeka/selenium/log"
	"github.com/viant/afs"
	"github.com/viant/toolbox"
	"github.com/viant/toolbox/data"
)

const (
	ChromeDriver   = "chromedriver"
	GeckoDriver    = "geckodriver"
	ChromeBrowser  = "chrome"
	FirefoxBrowser = "firefox"

	defaultFindElementTimeout = 10 * time.Second
)

// Service provides WebDriver automation utilities for the Browser MCP server.
type Service struct {
	useText               bool
	install               string
	fs                    afs.Service
	headful               bool
	autoMatchChromeDriver bool

	mux      sync.Mutex
	sessions map[string]*Session
}

type Session struct {
	ID            string
	Browser       string
	Pid           int
	DriverPath    string
	DriverVersion string
	Capabilities  []string
	Remote        string

	driver  selenium.WebDriver
	service *selenium.Service
	lock    sync.Mutex

	handlesMux sync.Mutex
	handleSeq  uint64
	handles    map[string]*elementHandle

	// state provides $var expansion for command parameters and exit checks.
	state data.Map

	capture *CaptureState
	net     *netTracker
}

type elementHandle struct {
	element  selenium.WebElement
	created  time.Time
	lastUsed time.Time
}

func NewService(cfg *Config) *Service {
	if cfg == nil {
		cfg = &Config{}
	}
	install := defaultInstallDir(cfg.InstallDir)
	return &Service{
		useText:               !cfg.UseData,
		install:               install,
		fs:                    afs.New(),
		headful:               cfg.ForceHeadful,
		autoMatchChromeDriver: cfg.AutoMatchChromeDriver,
		sessions:              map[string]*Session{},
	}
}

func (s *Service) UseTextField() bool { return s.useText }

func (s *Service) Start(ctx context.Context, in *StartInput) (*StartOutput, error) {
	if in == nil {
		in = &StartInput{}
	}
	port := in.Port
	if port == 0 {
		port = 4444
	}
	driver := strings.ToLower(strings.TrimSpace(in.Driver))
	if driver == "" {
		driver = ChromeDriver
	}
	sessionID := fmt.Sprintf("localhost:%d", port)

	s.mux.Lock()
	old := s.sessions[sessionID]
	s.mux.Unlock()
	if old != nil {
		// If an existing driver on this port appears healthy, reuse it instead of
		// stopping. This prevents disrupting active sessions and avoids timeouts.
		host, portStr := splitHostPort(sessionID)
		port, _ := strconv.Atoi(portStr)
		if !in.Restart && driverStatusOK(host, port) {
			return &StartOutput{
				Pid:           old.Pid,
				DriverPath:    old.DriverPath,
				DriverVersion: old.DriverVersion,
				SessionID:     old.ID,
			}, nil
		}
		_ = s.stopSession(old)
	}

	sess := &Session{ID: sessionID, Capabilities: in.Capabilities, state: data.Map{}}
	ensureSessionState(sess)
	switch driver {
	case ChromeDriver:
		sess.Browser = ChromeBrowser
	case GeckoDriver:
		sess.Browser = FirefoxBrowser
	default:
		return nil, fmt.Errorf("unsupported driver: %s", in.Driver)
	}

	var (
		path string
		err  error
	)
	if s.autoMatchChromeDriver && driver == ChromeDriver {
		path, err = ensureChromeDriverMatchesInstalledChrome(ctx, s.install)
	} else {
		path, err = ensureDriverAvailable(ctx, s.install, driver)
	}
	if err != nil && s.autoMatchChromeDriver && driver == ChromeDriver {
		// Fallback to the pinned/default driver if auto-match fails.
		path, err = ensureDriverAvailable(ctx, s.install, driver)
	}
	if err != nil {
		return nil, err
	}
	sess.DriverPath = path
	if sess.Browser == ChromeBrowser {
		if v, ok := chromedriverFullVersion(ctx, path); ok {
			sess.DriverVersion = v
		}
	}

	// Start driver service.
	// Start driver service and wait until it responds healthy.
	switch driver {
	case ChromeDriver:
		svc, err := selenium.NewChromeDriverService(sess.DriverPath, port)
		if err != nil {
			return nil, fmt.Errorf("failed to start chromedriver service %w", err)
		}
		sess.service = svc
		// Best-effort set PID if available (tebeka/selenium doesn't expose directly).
	case GeckoDriver:
		svc, err := selenium.NewGeckoDriverService(sess.DriverPath, port)
		if err != nil {
			return nil, fmt.Errorf("failed to start geckodriver service %w", err)
		}
		sess.service = svc
	}

	// Probe readiness with backoff up to ~10s.
	start := time.Now()
	for {
		if driverStatusOK("localhost", port) {
			break
		}
		if time.Since(start) > 10*time.Second {
			return nil, fmt.Errorf("webdriver did not become ready on port %d", port)
		}
		time.Sleep(200 * time.Millisecond)
	}

	s.mux.Lock()
	s.sessions[sessionID] = sess
	s.mux.Unlock()

	return &StartOutput{
		Pid:           sess.Pid,
		DriverPath:    sess.DriverPath,
		DriverVersion: sess.DriverVersion,
		SessionID:     sess.ID,
	}, nil
}

func (s *Service) Stop(_ context.Context, in *StopInput) (*StopOutput, error) {
	if in == nil {
		in = &StopInput{}
	}
	port := in.Port
	if port == 0 {
		port = 4444
	}
	id := fmt.Sprintf("localhost:%d", port)

	s.mux.Lock()
	sess := s.sessions[id]
	if sess != nil {
		delete(s.sessions, id)
	}
	s.mux.Unlock()

	if sess != nil {
		_ = s.stopSession(sess)
	}
	return &StopOutput{}, nil
}

func (s *Service) stopSession(sess *Session) error {
	if sess == nil {
		return nil
	}
	if sess.capture != nil {
		_ = sess.capture.CloseSink()
	}
	if sess.driver != nil {
		_ = sess.driver.Quit()
		sess.driver = nil
	}
	if sess.service != nil {
		_ = sess.service.Stop()
		sess.service = nil
	}
	return nil
}

func (s *Service) OpenSession(ctx context.Context, in *OpenSessionInput) (*OpenSessionOutput, error) {
	if in == nil {
		in = &OpenSessionInput{}
	}
	if in.SessionID == "" {
		in.SessionID = "localhost:4444"
	}
	if in.Remote == "" {
		host, port := splitHostPort(in.SessionID)
		in.Remote = fmt.Sprintf("http://%s:%s/wd/hub", host, port)
	}

	s.mux.Lock()
	sess := s.sessions[in.SessionID]
	if sess == nil {
		sess = &Session{ID: in.SessionID, state: data.Map{}}
		ensureSessionState(sess)
		s.sessions[in.SessionID] = sess
	}
	s.mux.Unlock()
	ensureSessionState(sess)

	if sess.driver != nil {
		_ = sess.driver.Quit()
		sess.driver = nil
	}

	// Merge capabilities: request overrides session capabilities if provided.
	capArgs := in.Capabilities
	if len(capArgs) == 0 {
		capArgs = sess.Capabilities
	} else {
		sess.Capabilities = capArgs
	}

	sess.Browser = resolveBrowser(sess.Browser, in.Browser)

	if s.headful {
		capArgs = enforceHeadfulCaps(capArgs)
	}

	if err := s.ensureLocalDriverService(ctx, sess, in); err != nil {
		return nil, err
	}

	caps := selenium.Capabilities{}
	switch sess.Browser {
	case ChromeBrowser:
		caps.AddChrome(chrome.Capabilities{Args: capArgs})
		caps.SetLogLevel(selog.Performance, selog.All)
		caps.SetLogLevel(selog.Browser, selog.All)
	case FirefoxBrowser:
		caps.AddFirefox(firefox.Capabilities{Args: capArgs})
		caps.SetLogLevel(selog.Browser, selog.All)
	default:
		caps["browserName"] = sess.Browser
	}

	driver, err := selenium.NewRemote(caps, in.Remote)
	if err != nil {
		return nil, err
	}
	sess.driver = driver
	sess.Remote = in.Remote
	if sess.handles == nil {
		sess.handles = map[string]*elementHandle{}
	}

	// Reset trackers per open.
	if sess.capture != nil {
		sess.capture.Clear()
	}
	if sess.net != nil {
		sess.net = &netTracker{}
	}

	// Ensure session cleanup.
	_ = ctx
	out := &OpenSessionOutput{SessionID: sess.ID}
	if sess.driver != nil {
		out.WebDriverSessionID = sess.driver.SessionID()
	}
	if strings.TrimSpace(in.URL) != "" {
		nav := navigationWithDefaults(in.Navigation)
		if err := s.getWithGuard(sess, in.URL, nav); err != nil {
			return nil, err
		}
		if err := s.afterNavigate(ctx, sess, nav); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Service) ensureLocalDriverService(ctx context.Context, sess *Session, in *OpenSessionInput) error {
	if sess == nil || in == nil {
		return nil
	}
	// If the session already has a service, assume it is running.
	if sess.service != nil {
		return nil
	}
	// Only auto-start for default local sessions (when no remote was explicitly provided).
	if strings.TrimSpace(in.Remote) == "" {
		return nil
	}
	host, portStr := splitHostPort(in.SessionID)
	if !isLocalHost(host) {
		return nil
	}
	defaultRemote := fmt.Sprintf("http://%s:%s/wd/hub", host, portStr)
	if in.Remote != defaultRemote {
		return nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 {
		return fmt.Errorf("invalid session port: %s", portStr)
	}

	driverName := ChromeDriver
	if sess.Browser == FirefoxBrowser {
		driverName = GeckoDriver
	}
	if sess.DriverPath == "" {
		var (
			path string
			err  error
		)
		if s.autoMatchChromeDriver && driverName == ChromeDriver {
			path, err = ensureChromeDriverMatchesInstalledChrome(ctx, s.install)
		} else {
			path, err = ensureDriverAvailable(ctx, s.install, driverName)
		}
		if err != nil && s.autoMatchChromeDriver && driverName == ChromeDriver {
			// Fallback to the pinned/default driver if auto-match fails.
			path, err = ensureDriverAvailable(ctx, s.install, driverName)
		}
		if err != nil {
			return err
		}
		sess.DriverPath = path
		if sess.Browser == ChromeBrowser {
			if v, ok := chromedriverFullVersion(ctx, path); ok {
				sess.DriverVersion = v
			}
		}
	}

	switch driverName {
	case ChromeDriver:
		svc, err := selenium.NewChromeDriverService(sess.DriverPath, port)
		if err != nil {
			return fmt.Errorf("failed to start chromedriver service %w", err)
		}
		sess.service = svc
	case GeckoDriver:
		svc, err := selenium.NewGeckoDriverService(sess.DriverPath, port)
		if err != nil {
			return fmt.Errorf("failed to start geckodriver service %w", err)
		}
		sess.service = svc
	default:
		return fmt.Errorf("unsupported driver: %s", driverName)
	}
	return nil
}

func isLocalHost(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

func (s *Service) CloseSession(_ context.Context, in *CloseSessionInput) (*CloseSessionOutput, error) {
	if in == nil || in.SessionID == "" {
		return nil, errors.New("sessionID is required")
	}
	sess, err := s.session(in.SessionID)
	if err != nil {
		return nil, err
	}
	_ = s.stopSession(sess)
	return &CloseSessionOutput{SessionID: in.SessionID}, nil
}

func (s *Service) session(id string) (*Session, error) {
	s.mux.Lock()
	defer s.mux.Unlock()
	sess := s.sessions[id]
	if sess == nil {
		return nil, fmt.Errorf("unknown session: %s", id)
	}
	return sess, nil
}

func (s *Service) Run(ctx context.Context, in *RunInput) (*RunOutput, error) {
	if in == nil {
		in = &RunInput{}
	}
	if in.SessionID == "" {
		in.SessionID = "localhost:4444"
	}
	sess, err := s.session(in.SessionID)
	if err != nil {
		return nil, err
	}
	if sess.driver == nil {
		_, err := s.OpenSession(ctx, &OpenSessionInput{SessionID: in.SessionID, Browser: in.Browser, Remote: in.Remote, Capabilities: in.NavigationCaps()})
		if err != nil {
			return nil, err
		}
		sess, _ = s.session(in.SessionID)
	}

	nav := navigationWithDefaults(in.Navigation)
	out := &RunOutput{SessionID: in.SessionID, Data: map[string]any{}, LookupErrors: []string{}, Warnings: []string{}}

	if len(in.Actions) == 0 && len(in.Commands) > 0 {
		if err := in.initFromCommands(); err != nil {
			return nil, err
		}
	}
	if len(in.Actions) == 0 {
		return out, nil
	}

	delay := time.Duration(in.ActionDelay) * time.Millisecond
	for _, action := range in.Actions {
		for _, call := range action.Calls {
			if len(call.Parameters) > 0 {
				for i, item := range call.Parameters {
					call.Parameters[i] = sess.state.Expand(item)
				}
			}
			if action.Selector == nil {
				if isGetMethod(call.Method) && len(call.Parameters) == 1 && toolbox.IsString(call.Parameters[0]) {
					URL := toolbox.AsString(call.Parameters[0])
					if err := s.getWithGuard(sess, URL, nav); err != nil {
						return nil, err
					}
					if err := s.afterNavigate(ctx, sess, nav); err != nil {
						return nil, err
					}
					sess.drainTrackers()
					continue
				}
				resp, err := s.CallDriver(ctx, &WebDriverCallInput{SessionID: in.SessionID, Key: action.Key, Call: call, PathKind: action.PathKind})
				if err != nil {
					return nil, err
				}
				merge(out.Data, resp.Data)
				sess.drainTrackers()
				continue
			}
			resp, err := s.CallElement(ctx, &WebElementCallInput{SessionID: in.SessionID, Selector: action.Selector, Call: call, PathKind: action.PathKind})
			if err != nil {
				return nil, err
			}
			if resp.LookupError != "" {
				out.LookupErrors = append(out.LookupErrors, resp.LookupError)
			}
			merge(out.Data, resp.Data)
			sess.drainTrackers()
			if delay > 0 {
				time.Sleep(delay)
			}
		}
	}
	if v, ok := sess.state["_webdriver_last_nav_timeout"]; ok && v != nil {
		out.Warnings = append(out.Warnings, toolbox.AsString(v))
		delete(sess.state, "_webdriver_last_nav_timeout")
	}
	return out, nil
}

func (s *Service) CallDriver(_ context.Context, in *WebDriverCallInput) (*CallOutput, error) {
	if in == nil || in.Call == nil {
		return nil, errors.New("call is required")
	}
	sess, err := s.session(in.SessionID)
	if err != nil {
		return nil, err
	}
	if sess.driver == nil {
		return nil, fmt.Errorf("session not open: %s", in.SessionID)
	}
	resp := &CallOutput{Data: map[string]any{}}
	key := in.Key
	if key == "" {
		key = in.Call.Method
	}
	sess.lock.Lock()
	defer sess.lock.Unlock()
	return resp, s.call(sess, sess.driver, sess.driver, in.Call, resp, key, in.PathKind)
}

func (s *Service) CallElement(ctx context.Context, in *WebElementCallInput) (*WebElementCallOutput, error) {
	if in == nil || in.Call == nil || in.Selector == nil {
		return nil, errors.New("selector and call are required")
	}
	sess, err := s.session(in.SessionID)
	if err != nil {
		return nil, err
	}
	if sess.driver == nil {
		return nil, fmt.Errorf("session not open: %s", in.SessionID)
	}
	out := &WebElementCallOutput{Data: map[string]any{}}

	if err := in.Selector.Validate(); err != nil {
		return nil, fmt.Errorf("invalid selector: %v", err)
	}

	// Locator selectors are resolved via DOM-side query (multi-match) + best-effort WebElement conversion.
	if in.Selector.By == "locator" {
		loc, ok := parseLocatorExpr(in.Selector.Value)
		if !ok {
			out.LookupError = fmt.Sprintf("invalid locator: %s", in.Selector.Value)
			return out, nil
		}
		visibleOnly := false
		switch in.Call.Method {
		case "Click", "SendKeys", "Clear", "Submit":
			visibleOnly = true
		}
		waitMs := in.Call.WaitTimeMs
		elements, matches, err := s.ResolveLocator(ctx, sess, loc, &ResolveLocatorOptions{
			MaxWaitMs:       waitMs,
			MinMatches:      1,
			MaxMatches:      1,
			Strict:          false,
			VisibleOnly:     visibleOnly,
			ResolveElements: true,
		})
		if err != nil {
			out.LookupError = fmt.Sprintf("failed to resolve locator: %v", err)
			return out, nil
		}
		if len(elements) == 0 {
			out.LookupError = fmt.Sprintf("no element matched locator")
			return out, nil
		}
		_ = matches
		// proceed with the resolved element as if found by selector
		element := elements[0]
		callOut := &CallOutput{Data: map[string]any{}}
		key := in.Selector.Key
		if key == "" {
			key = in.Selector.Value
		}
		if in.Call.Method == "Click" || in.Call.Method == "SendKeys" || in.Call.Method == "Clear" || in.Call.Method == "Submit" {
			if err := s.ensureVisible(element); err != nil {
				out.LookupError = fmt.Sprintf("element %s is not visible: %v", in.Selector.Value, err)
				return nil, err
			}
		}
		err = s.call(sess, sess.driver, element, in.Call, callOut, key, in.PathKind)
		if isStaleElementError(err) {
			// best-effort: re-resolve
			elements, _, _ = s.ResolveLocator(ctx, sess, loc, &ResolveLocatorOptions{
				MaxWaitMs:       waitMs,
				MinMatches:      1,
				MaxMatches:      1,
				Strict:          false,
				VisibleOnly:     visibleOnly,
				ResolveElements: true,
			})
			if len(elements) > 0 {
				err = s.call(sess, sess.driver, elements[0], in.Call, callOut, key, in.PathKind)
			}
		}
		if err != nil {
			return nil, err
		}
		merge(out.Data, callOut.Data)
		out.Result = callOut.Result
		return out, nil
	}

	var element selenium.WebElement
	sess.lock.Lock()
	defer sess.lock.Unlock()
	err = sess.driver.WaitWithTimeout(func(wd selenium.WebDriver) (bool, error) {
		element, err = sess.driver.FindElement(in.Selector.By, in.Selector.Value)
		if element != nil {
			return true, nil
		}
		return false, nil
	}, defaultFindElementTimeout)
	if err != nil || element == nil {
		out.LookupError = fmt.Sprintf("failed to lookup element: %s %s, %v", in.Selector.By, in.Selector.Value, err)
		return out, nil
	}
	callOut := &CallOutput{Data: map[string]any{}}
	key := in.Selector.Key
	if key == "" {
		key = in.Selector.Value
	}
	switch in.Call.Method {
	case "Click", "SendKeys", "Clear", "Submit":
		if err := s.ensureVisible(element); err != nil {
			out.LookupError = fmt.Sprintf("element %s is not visible: %v", in.Selector.Value, err)
			return nil, err
		}
	}

	err = s.call(sess, sess.driver, element, in.Call, callOut, key, in.PathKind)
	if isStaleElementError(err) {
		element, _ = sess.driver.FindElement(in.Selector.By, in.Selector.Value)
		if element != nil {
			err = s.call(sess, sess.driver, element, in.Call, callOut, key, in.PathKind)
		}
	}
	if err != nil {
		return nil, err
	}
	merge(out.Data, callOut.Data)
	out.Result = callOut.Result
	return out, nil
}

func (s *Service) ensureVisible(element selenium.WebElement) error {
	var err error
	var ok bool
	for i := 0; i < 10; i++ {
		if ok, err = element.IsDisplayed(); ok {
			break
		}
		if isStaleElementError(err) {
			return err
		}
		time.Sleep(200 * time.Millisecond)
	}
	return err
}

func (s *Service) call(sess *Session, driver selenium.WebDriver, caller any, call *MethodCall, response *CallOutput, key string, kind PathKind) error {
	if call.WaitTimeMs == 0 {
		if err := s.callMethod(caller, call.Method, response, call.Parameters); err != nil {
			return err
		}
		addResultIfPresent(response.Result, response.Data, key, call, kind)
		if call.ThinkTimeMs > 0 {
			time.Sleep(time.Millisecond * time.Duration(call.ThinkTimeMs))
		}
		return nil
	}

	var err error
	err = driver.WaitWithTimeout(func(wd selenium.WebDriver) (bool, error) {
		err = s.callMethod(caller, call.Method, response, call.Parameters)
		if err != nil {
			return false, err
		}
		addResultIfPresent(response.Result, response.Data, key, call, kind)
		if call.Exit == "" {
			return true, nil
		}
		ok, e := evaluateExit(sess.state, response.Data, call.Exit)
		return ok, e
	}, time.Duration(call.WaitTimeMs)*time.Millisecond)
	if call.IgnoreTimeout && isPageLoadTimeout(err) {
		return nil
	}
	if call.IgnoreTimeout {
		return nil
	}
	return err
}

func (s *Service) callMethod(owner any, methodName string, response *CallOutput, parameters []any) error {
	if methodName == "TableData" {
		parameters = append([]any{owner}, parameters...)
		owner = s
	}
	method, err := toolbox.GetFunction(owner, methodName)
	if err != nil {
		return err
	}
	converted, err := toolbox.AsCompatibleFunctionParameters(method, parameters)
	if err != nil {
		return err
	}
	response.Result = toolbox.CallFunction(method, converted...)
	last := response.Result[len(response.Result)-1]
	if last != nil {
		if e, ok := last.(error); ok {
			return e
		}
	}
	return nil
}

func (sess *Session) drainTrackers() {
	if sess.capture != nil {
		sess.capture.Drain(sess)
		_ = sess.capture.FlushSink()
	} else if sess.net != nil && sess.driver != nil {
		sess.net.Drain(sess.driver)
	}
}

func splitHostPort(sessionID string) (string, string) {
	parts := strings.SplitN(sessionID, ":", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return sessionID, "4444"
}

func merge(dst map[string]any, src map[string]any) {
	if dst == nil || src == nil {
		return
	}
	for k, v := range src {
		dst[k] = v
	}
}
