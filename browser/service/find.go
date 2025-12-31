package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	defaultFindWaitMs = 10000
	defaultFindPollMs = 200
	defaultFindMax    = 20
)

// Find resolves a locator into 0..N matches with metadata.
// It uses ExecuteScript (DOM-side) so it can do multi-match and extract rect/text/attrs.
func (s *Service) Find(ctx context.Context, in *FindInput) (*FindOutput, error) {
	if in == nil {
		in = &FindInput{}
	}
	if in.SessionID == "" {
		in.SessionID = "localhost:4444"
	}
	sess, err := s.session(in.SessionID)
	if err != nil {
		return nil, err
	}
	if sess.driver == nil {
		return nil, fmt.Errorf("session not open: %s", in.SessionID)
	}
	if in.Locator == nil {
		return nil, fmt.Errorf("locator is required")
	}

	maxWait := in.MaxWaitMs
	if maxWait <= 0 {
		maxWait = defaultFindWaitMs
	}
	poll := in.PollMs
	if poll <= 0 {
		poll = defaultFindPollMs
	}
	min := in.MinMatches
	if min <= 0 {
		min = 1
	}
	max := in.MaxMatches
	if max <= 0 {
		max = defaultFindMax
	}
	if max < 1 {
		max = 1
	}
	if max > 200 {
		max = 200
	}

	start := time.Now()
	var last []*FindMatch
	var lastErr error
	for time.Since(start) < time.Duration(maxWait)*time.Millisecond {
		matches, err := s.findOnce(sess, in.Locator, max, in.VisibleOnly)
		if err != nil {
			lastErr = err
		} else {
			lastErr = nil
			last = matches
			if in.Strict {
				if len(matches) == 1 {
					return s.findOutput(in, matches), nil
				}
			} else if len(matches) >= min {
				return s.findOutput(in, matches), nil
			}
		}
		select {
		case <-ctx.Done():
			break
		case <-time.After(time.Duration(poll) * time.Millisecond):
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	out := s.findOutput(in, last)
	if in.Strict {
		out.Warning = fmt.Sprintf("strict locator expected 1 match, got %d", len(last))
	}
	return out, nil
}

func (s *Service) findOutput(in *FindInput, matches []*FindMatch) *FindOutput {
	out := &FindOutput{SessionID: in.SessionID, Matches: matches, Data: map[string]any{}}
	key := strings.TrimSpace(in.Key)
	if key != "" {
		out.Data[key] = matches
	}
	return out
}

func (s *Service) findOnce(sess *Session, loc *Locator, limit int, visibleOnly bool) ([]*FindMatch, error) {
	raw, err := json.Marshal(loc)
	if err != nil {
		return nil, err
	}
	res, err := sess.driver.ExecuteScript(findScript, []any{string(raw), limit, visibleOnly})
	if err != nil {
		return nil, err
	}
	// ExecuteScript returns decoded JSON-like structures (map/slice).
	b, err := json.Marshal(res)
	if err != nil {
		return nil, err
	}
	var out []*FindMatch
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

const findScript = `
return (function(locatorJSON, limit, visibleOnly) {
  function safeStr(v) { return (v == null) ? "" : String(v); }
  function norm(s) { return safeStr(s).trim(); }
  function lc(s) { return norm(s).toLowerCase(); }
  function hasAny(v) { return Array.isArray(v) && v.length > 0; }
  function attr(el, name) { try { return norm(el && el.getAttribute && el.getAttribute(name)); } catch (e) { return ""; } }

  function isVisible(el) {
    try {
      if (!el) return false;
      const r = el.getBoundingClientRect();
      if (!r || r.width <= 0 || r.height <= 0) return false;
      const st = window.getComputedStyle(el);
      if (!st) return true;
      if (st.visibility === 'hidden' || st.display === 'none' || Number(st.opacity || '1') === 0) return false;
      return true;
    } catch (e) {
      return false;
    }
  }

  function cssEscapeIdent(s) {
    // Minimal escape for ids/testids in generated selectors.
    return safeStr(s).replace(/([ #;?%&,.+*~':\"!^$\\[\\]()=>|\\/])/g,'\\\\$1');
  }

  function cssPath(el) {
    if (!el || el.nodeType !== 1) return '';
    const id = el.getAttribute && el.getAttribute('id');
    if (id) return '#' + cssEscapeIdent(id);
    const tid = el.getAttribute && (el.getAttribute('data-testid') || el.getAttribute('data-test-id'));
    if (tid) return '[data-testid=\"' + cssEscapeIdent(tid) + '\"]';
    // Build a short nth-of-type path.
    let path = '';
    let cur = el;
    let depth = 0;
    while (cur && cur.nodeType === 1 && depth < 6) {
      const tag = lc(cur.tagName);
      let nth = 1;
      let sib = cur;
      while ((sib = sib.previousElementSibling)) {
        if (lc(sib.tagName) === tag) nth++;
      }
      const seg = tag + (nth > 1 ? ':nth-of-type(' + nth + ')' : '');
      path = seg + (path ? ' > ' + path : '');
      cur = cur.parentElement;
      depth++;
      if (cur && cur.getAttribute) {
        const pid = cur.getAttribute('id');
        if (pid) {
          path = '#' + cssEscapeIdent(pid) + ' > ' + path;
          break;
        }
      }
    }
    return path;
  }

  function textOf(el) {
    try {
      const t = el.innerText != null ? el.innerText : el.textContent;
      return norm(t).replace(/\\s+/g,' ');
    } catch (e) {
      return '';
    }
  }

  function implicitRole(el) {
    try {
      if (!el || el.nodeType !== 1) return '';
      const tag = lc(el.tagName);
      const type = lc(attr(el, 'type'));
      if (tag === 'a' || tag === 'area') {
        return attr(el, 'href') ? 'link' : '';
      }
      if (tag === 'button') return 'button';
      if (tag === 'summary') return 'button';
      if (tag === 'dialog') return 'dialog';
      if (tag === 'img') return 'img';
      if (tag === 'table') return 'table';
      if (tag === 'tr') return 'row';
      if (tag === 'th') {
        const scope = lc(attr(el, 'scope'));
        if (scope === 'row') return 'rowheader';
        return 'columnheader';
      }
      if (tag === 'td') return 'cell';
      if (tag === 'ul' || tag === 'ol') return 'list';
      if (tag === 'li') return 'listitem';
      if (tag === 'nav') return 'navigation';
      if (tag === 'main') return 'main';
      if (tag === 'header') return 'banner';
      if (tag === 'footer') return 'contentinfo';
      if (tag === 'form') return 'form';
      if (tag === 'section') {
        // region only if labelled (matches common browser behavior)
        if (attr(el, 'aria-label') || attr(el, 'aria-labelledby')) return 'region';
        return '';
      }
      if (tag === 'textarea') return 'textbox';
      if (tag === 'select') return 'combobox';
      if (tag === 'input') {
        if (type === 'checkbox') return 'checkbox';
        if (type === 'radio') return 'radio';
        if (type === 'range') return 'slider';
        if (type === 'number') return 'spinbutton';
        if (type === 'submit' || type === 'reset' || type === 'button' || type === 'image') return 'button';
        if (type === 'search') return 'searchbox';
        if (type === 'email' || type === 'tel' || type === 'url' || type === 'password' || type === 'text' || type === '') return 'textbox';
      }
      if (tag === 'h1' || tag === 'h2' || tag === 'h3' || tag === 'h4' || tag === 'h5' || tag === 'h6') return 'heading';
    } catch (e) {}
    return '';
  }

  function roleOf(el) {
    const explicit = attr(el, 'role');
    if (explicit) return lc(explicit);
    return implicitRole(el);
  }

  function nameOf(el) {
    try {
      // Minimal accessible-ish name: aria-label, aria-labelledby, then text.
      const al = attr(el, 'aria-label');
      if (al) return al;
      const lb = attr(el, 'aria-labelledby');
      if (lb) {
        const ids = lb.split(/\\s+/g).filter(Boolean);
        const parts = [];
        for (const id of ids) {
          const n = document.getElementById(id);
          if (n) parts.push(textOf(n));
        }
        const joined = norm(parts.join(' '));
        if (joined) return joined;
      }

      // <label for="id"> association and wrapping label.
      const id = attr(el, 'id');
      if (id) {
        try {
          const labels = Array.from(document.querySelectorAll('label[for="' + id.replace(/"/g, '\\"') + '"]'));
          const labelText = norm(labels.map(textOf).join(' '));
          if (labelText) return labelText;
        } catch (e) {}
      }
      try {
        let p = el;
        while (p && p.nodeType === 1) {
          if (lc(p.tagName) === 'label') {
            const t = textOf(p);
            if (t) return t;
            break;
          }
          p = p.parentElement;
        }
      } catch (e) {}

      // alt/title/value/placeholder fallbacks.
      const tag = lc(el.tagName);
      const type = lc(attr(el, 'type'));
      if (tag === 'img' || tag === 'area' || (tag === 'input' && type === 'image')) {
        const alt = attr(el, 'alt');
        if (alt) return alt;
      }
      // Use value for buttons.
      if (tag === 'input' && (type === 'submit' || type === 'reset' || type === 'button')) {
        const v = attr(el, 'value');
        if (v) return v;
      }
      const title = attr(el, 'title');
      if (title) return title;

      const placeholder = attr(el, 'placeholder');
      if (placeholder) return placeholder;

      return textOf(el);
    } catch (e) {
      return '';
    }
  }

  function queryXPath(xpath, root) {
    const out = [];
    try {
      const ctx = root || document;
      const it = document.evaluate(xpath, ctx, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null);
      for (let i = 0; i < it.snapshotLength; i++) {
        const n = it.snapshotItem(i);
        if (n && n.nodeType === 1) out.push(n);
      }
    } catch (e) {}
    return out;
  }

  function resolveBase(loc, root) {
    const css = norm(loc.css);
    const xp = norm(loc.xpath);
    if (css) {
      try { return Array.from((root || document).querySelectorAll(css)); } catch (e) { return []; }
    }
    if (xp) return queryXPath(xp, root);
    // Default base: all elements (we'll filter).
    return Array.from((root || document).querySelectorAll('*'));
  }

  // Node identity helpers for de-dupe/intersection.
  const _idMap = (typeof WeakMap !== 'undefined') ? new WeakMap() : null;
  let _idSeq = 1;
  function nodeId(el) {
    if (!_idMap) return null;
    let v = _idMap.get(el);
    if (!v) { v = _idSeq++; _idMap.set(el, v); }
    return v;
  }
  function uniqEls(list) {
    const out = [];
    const seen = new Set();
    for (const el of list || []) {
      if (!el || el.nodeType !== 1) continue;
      const id = nodeId(el);
      const key = id != null ? String(id) : (el.__lfid || (el.__lfid = String(Math.random())));
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(el);
    }
    return out;
  }
  function unionEls(a, b) { return uniqEls([].concat(a || [], b || [])); }
  function diffEls(a, b) {
    const bSet = new Set();
    for (const el of b || []) {
      if (!el || el.nodeType !== 1) continue;
      const id = nodeId(el);
      if (id != null) bSet.add(String(id));
    }
    const out = [];
    for (const el of a || []) {
      if (!el || el.nodeType !== 1) continue;
      const id = nodeId(el);
      if (id != null && bSet.has(String(id))) continue;
      out.push(el);
    }
    return uniqEls(out);
  }
  function intersectEls(a, b) {
    const bSet = new Set();
    for (const el of b || []) {
      if (!el || el.nodeType !== 1) continue;
      const id = nodeId(el);
      if (id != null) bSet.add(String(id));
    }
    const out = [];
    for (const el of a || []) {
      if (!el || el.nodeType !== 1) continue;
      const id = nodeId(el);
      if (id != null && bSet.has(String(id))) out.push(el);
    }
    return uniqEls(out);
  }

  function matchText(candidate, wanted, exact) {
    if (!wanted) return true;
    const c = lc(candidate);
    const w = lc(wanted);
    return exact ? (c === w) : (c.indexOf(w) !== -1);
  }

  function applyLeafFilters(list, loc, exact, visibleOnly) {
    const roleWanted = norm(loc.role);
    const nameWanted = norm(loc.name);
    const textWanted = norm(loc.text);
    const testIDWanted = norm(loc.testID || loc.testId);
    const out = [];
    for (const el of list || []) {
      if (!el || el.nodeType !== 1) continue;
      if (visibleOnly && !isVisible(el)) continue;
      if (testIDWanted) {
        const tid = norm(el.getAttribute && (el.getAttribute('data-testid') || el.getAttribute('data-test-id')));
        if (!matchText(tid, testIDWanted, true)) continue;
      }
      if (roleWanted) {
        const r = roleOf(el);
        if (!matchText(r, roleWanted, true)) continue;
      }
      if (nameWanted) {
        if (!matchText(nameOf(el), nameWanted, exact)) continue;
      }
      if (textWanted) {
        if (!matchText(textOf(el), textWanted, exact)) continue;
      }
      out.push(el);
    }
    return uniqEls(out);
  }

  function leafUsed(loc) {
    return !!(norm(loc.css) || norm(loc.xpath) || norm(loc.role) || norm(loc.name) || norm(loc.text) || norm(loc.testID) || norm(loc.testId));
  }

  // Resolves a locator into WebElements, supporting within/any/all/not composition.
  function resolveElements(loc, root) {
    if (!loc) return [];
    const exact = !!loc.exact;
    // within applies as root scoping for the whole locator.
    const roots = (function() {
      if (loc.within) {
        const ws = resolveElements(loc.within, root);
        return ws.length ? ws : [];
      }
      return [root || document];
    })();
    const locNoWithin = Object.assign({}, loc);
    delete locNoWithin.within;

    let acc = [];
    for (const r of roots) {
      let base = [];

      // Composite branches.
      if (hasAny(locNoWithin.any)) {
        for (const sub of locNoWithin.any) base = unionEls(base, resolveElements(sub, r));
      }
      if (hasAny(locNoWithin.all)) {
        // Intersection across all.
        let inter = null;
        for (const sub of locNoWithin.all) {
          const subEls = resolveElements(sub, r);
          inter = inter == null ? subEls : intersectEls(inter, subEls);
        }
        if (leafUsed(locNoWithin)) {
          const leaf = applyLeafFilters(resolveBase(locNoWithin, r), locNoWithin, exact, visibleOnly);
          base = base.length ? intersectEls(base, leaf) : leaf;
        }
        base = base.length ? intersectEls(base, inter || []) : (inter || []);
      }

      // Leaf branch (no composite).
      if (!hasAny(locNoWithin.any) && !hasAny(locNoWithin.all)) {
        base = applyLeafFilters(resolveBase(locNoWithin, r), locNoWithin, exact, visibleOnly);
      }

      // Apply not subtraction.
      if (locNoWithin.not) {
        const neg = resolveElements(locNoWithin.not, r);
        // If locator is just not(...), treat base as all under root.
        if (!leafUsed(locNoWithin) && !hasAny(locNoWithin.any) && !hasAny(locNoWithin.all)) {
          base = diffEls(Array.from((r || document).querySelectorAll('*')), neg);
          base = applyLeafFilters(base, locNoWithin, exact, visibleOnly);
        } else {
          base = diffEls(base, neg);
        }
      }

      acc = unionEls(acc, base);
    }
    return acc;
  }

  const loc = JSON.parse(locatorJSON || '{}') || {};
  const candidates = resolveElements(loc, document);

  const matches = [];
  for (const el of candidates || []) {
    if (!el || el.nodeType !== 1) continue;
    const rect = (function() {
      try {
        const r = el.getBoundingClientRect();
        return { x: r.x, y: r.y, width: r.width, height: r.height };
      } catch (e) { return null; }
    })();
    const attrs = {};
    try {
      const keep = ['id','class','name','type','value','placeholder','role','aria-label','data-testid','data-test-id','href'];
      for (const k of keep) {
        const v = el.getAttribute && el.getAttribute(k);
        if (v != null && String(v).trim()) attrs[k] = String(v);
      }
    } catch (e) {}
    matches.push({
      selector: cssPath(el),
      tag: lc(el.tagName),
      text: textOf(el),
      role: roleOf(el),
      name: nameOf(el),
      attrs: attrs,
      rect: rect,
      visible: isVisible(el),
    });
    if (matches.length >= limit) break;
  }
  return matches;
})(arguments[0], arguments[1], arguments[2]);
`
