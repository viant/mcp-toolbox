package graph

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    neturl "net/url"
    "time"

    "github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
    models "github.com/microsoftgraph/msgraph-sdk-go/models"
    "strings"
)

type CalendarService struct{ m *Manager }

func NewCalendarService(m *Manager) *CalendarService { return &CalendarService{m: m} }

func (s *CalendarService) List(ctx context.Context, in *ListEventsInput, scopes []string, prompt func(string)) (*ListEventsOutput, error) {
    if in.DaysAhead <= 0 { in.DaysAhead = 7 }
    // Build REST query with optional $filter/$orderby
    q := neturl.Values{}
    if len(in.OrderBy) > 0 { q.Set("$orderby", strings.Join(in.OrderBy, ",")) } else { q.Set("$orderby", "start/dateTime DESC") }
    if in.Filter != "" { q.Set("$filter", in.Filter) }
    cred, err := s.m.Credential(ctx, in.Account.Alias, in.Account.TenantID, scopes, prompt)
    if err != nil { return nil, err }
    tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: scopes}); if err != nil { return nil, err }
    url := "https://graph.microsoft.com/v1.0/me/events"; if enc := q.Encode(); enc != "" { url += "?"+enc }
    req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil); req.Header.Set("Authorization", "Bearer "+tok.Token)
    resp, err := http.DefaultClient.Do(req); if err != nil { return nil, err }
    defer resp.Body.Close(); if resp.StatusCode >= 300 { return nil, fmt.Errorf("list events failed: %s", resp.Status) }
    var payload struct{ Value []struct{ ID, Subject string; Start, End struct{ DateTime string `json:"dateTime"` }; Location struct{ DisplayName string `json:"displayName"` }; Organizer struct{ EmailAddress struct{ Address string `json:"address"` } `json:"emailAddress"` } } `json:"value"` }
    if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil { return nil, err }
    out := &ListEventsOutput{}
    for _, ev := range payload.Value { out.Events = append(out.Events, CalendarEvent{ID: ev.ID, Subject: ev.Subject, StartISO: ev.Start.DateTime, EndISO: ev.End.DateTime, Location: ev.Location.DisplayName, Organizer: ev.Organizer.EmailAddress.Address}) }
    return out, nil
}

func (s *CalendarService) Create(ctx context.Context, in *CreateEventInput, scopes []string, prompt func(string)) (*CalendarEvent, error) {
	client, err := s.m.Client(ctx, in.Account.Alias, in.Account.TenantID, scopes, prompt)
	if err != nil {
		return nil, err
	}
	ev := models.NewEvent()
	ev.SetSubject(ptr(in.Subject))
	tz := in.TimeZone
	if tz == "" {
		tz = "UTC"
	}
	start := models.NewDateTimeTimeZone()
	start.SetDateTime(ptr(in.StartISO))
	start.SetTimeZone(ptr(tz))
	end := models.NewDateTimeTimeZone()
	end.SetDateTime(ptr(in.EndISO))
	end.SetTimeZone(ptr(tz))
	ev.SetStart(start)
	ev.SetEnd(end)
	if in.Location != "" {
		loc := models.NewLocation()
		loc.SetDisplayName(ptr(in.Location))
		ev.SetLocation(loc)
	}
	if len(in.Attendees) > 0 {
		var attendees []models.Attendeeable
		for _, a := range in.Attendees {
			email := models.NewEmailAddress()
			email.SetAddress(ptr(a))
			att := models.NewAttendee()
			att.SetEmailAddress(email)
			attendees = append(attendees, att)
		}
		ev.SetAttendees(attendees)
	}
	if in.BodyText != "" {
		body := models.NewItemBody()
		body.SetContentType(ptr(models.TEXT_BODYTYPE))
		body.SetContent(ptr(in.BodyText))
		ev.SetBody(body)
	}
	created, err := client.Me().Events().Post(ctx, ev, nil)
	if err != nil {
		return nil, fmt.Errorf("create event: %w", err)
	}
	out := &CalendarEvent{
		ID:        ptrVal(created.GetId()),
		Subject:   ptrVal(created.GetSubject()),
		StartISO:  dateTimeToISO(created.GetStart()),
		EndISO:    dateTimeToISO(created.GetEnd()),
		Location:  locationName(created.GetLocation()),
		Organizer: organizerAddress(created.GetOrganizer()),
	}
	return out, nil
}

func dateTimeToISO(dt models.DateTimeTimeZoneable) string {
	if dt == nil {
		return ""
	}
	if dt.GetDateTime() != nil {
		return *dt.GetDateTime()
	}
	return ""
}

func locationName(loc models.Locationable) string {
	if loc == nil || loc.GetDisplayName() == nil {
		return ""
	}
	return *loc.GetDisplayName()
}

func organizerAddress(org models.Recipientable) string {
	if org == nil || org.GetEmailAddress() == nil || org.GetEmailAddress().GetAddress() == nil {
		return ""
	}
	return *org.GetEmailAddress().GetAddress()
}

var _ = time.Now
