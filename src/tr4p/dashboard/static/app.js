"use strict";

// Dashboard front end. Everything that comes from the network (paths, user
// agents, details) is attacker-controlled, so it is only ever written with
// textContent or setAttribute, never as HTML.
(function () {
  const NS = "http://www.w3.org/2000/svg";
  const MAX_FEED_ROWS = 300;
  const TIER_RANK = { none: 0, low: 1, medium: 2, high: 3, released: -1 };
  const SEVERITY = {
    none: { label: "None", icon: "dash" }, low: { label: "Low", icon: "info" },
    medium: { label: "Medium", icon: "warn" }, high: { label: "High", icon: "stop" },
    released: { label: "Released", icon: "dash" },
  };
  const ICONS = {
    info: "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm-1 5h2v2h-2zm0 4h2v6h-2z",
    warn: "M12 2 1 21h22zm-1 7h2v6h-2zm0 8h2v2h-2z",
    stop: "M8.3 2h7.4L22 8.3v7.4L15.7 22H8.3L2 15.7V8.3zM11 6h2v8h-2zm0 10h2v2h-2z",
    dash: "M4 11h16v2H4z",
    ok: "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm-1.2 14.4-4-4 1.4-1.4 2.6 2.6 5-5 1.4 1.4z",
    bad: "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm4.2 12.8-1.4 1.4-2.8-2.8-2.8 2.8-1.4-1.4 2.8-2.8-2.8-2.8 1.4-1.4 2.8 2.8 2.8-2.8 1.4 1.4-2.8 2.8z",
    up: "M12 6 4 16h16z", down: "M12 18 4 8h16z", both: "M12 4 6 10h12zm0 16 6-6H6z",
  };

  const $ = function (id) { return document.getElementById(id); };
  const state = {
    csrf: "", sessions: null, sort: { key: "tier", dir: "desc" }, tier: "", text: "",
    detailKey: null, feedFilter: "", alertsOnly: false, events: [], presets: {},
  };

  // ----------------------------------------------------------------- helpers

  function node(tag, className, text) {
    const item = document.createElement(tag);
    if (className) { item.className = className; }
    if (text !== undefined && text !== null) { item.textContent = String(text); }
    return item;
  }

  function icon(name) {
    const svg = document.createElementNS(NS, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("class", "icon");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("focusable", "false");
    const path = document.createElementNS(NS, "path");
    path.setAttribute("d", ICONS[name]);
    svg.appendChild(path);
    return svg;
  }

  function badge(tier) {
    const kind = SEVERITY[tier] ? tier : "none";
    const item = node("span", "badge sev-" + kind);
    item.appendChild(icon(SEVERITY[kind].icon));
    item.appendChild(document.createTextNode(SEVERITY[kind].label));
    return item;
  }

  const pad = function (n) { return String(n).padStart(2, "0"); };
  function clock(ts) {
    const d = new Date(ts * 1000);
    return pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  }
  function absolute(ts) {
    const d = new Date(ts * 1000);
    return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) + " " + clock(ts);
  }
  function relative(ts) {
    const delta = Math.max(0, Date.now() / 1000 - ts);
    if (delta < 60) { return Math.floor(delta) + " s ago"; }
    if (delta < 3600) { return Math.floor(delta / 60) + " min ago"; }
    if (delta < 86400) { return Math.floor(delta / 3600) + " h ago"; }
    return Math.floor(delta / 86400) + " d ago";
  }
  function duration(seconds) {
    const total = Math.max(0, Math.floor(seconds));
    const days = Math.floor(total / 86400);
    const rest = total % 86400;
    return (days ? days + "d " : "") + pad(Math.floor(rest / 3600)) + ":" +
      pad(Math.floor((rest % 3600) / 60)) + ":" + pad(rest % 60);
  }
  function number(value) { return Number(value || 0).toLocaleString(); }

  // A time shown both ways: the clock time, and how long ago. The tooltip and
  // the datetime attribute carry the full date in UTC.
  function timeCell(ts, withRelative) {
    const item = node("time", "mono");
    item.dateTime = new Date(ts * 1000).toISOString();
    item.title = absolute(ts) + " (local), " + item.dateTime;
    item.dataset.ts = String(ts);
    item.dataset.relative = withRelative ? "1" : "";
    item.textContent = withRelative ? clock(ts) + " (" + relative(ts) + ")" : clock(ts);
    return item;
  }
  function refreshTimes() {
    document.querySelectorAll("time[data-relative='1']").forEach(function (item) {
      const ts = Number(item.dataset.ts);
      item.textContent = clock(ts) + " (" + relative(ts) + ")";
    });
  }

  async function api(path, body) {
    const options = { credentials: "same-origin", headers: {} };
    if (body !== undefined) {
      options.method = "POST";
      options.headers["Content-Type"] = "application/json";
      options.headers["X-Requested-With"] = "dashboard";
      options.headers["X-CSRF-Token"] = state.csrf;
      options.body = JSON.stringify(body);
    }
    const response = await fetch(path, options);
    if (response.status === 401) {
      window.location.replace("/login");
      throw new Error("signed out");
    }
    if (!response.ok) {
      let message = "Request failed (" + response.status + ").";
      try {
        const data = await response.json();
        if (data && typeof data.error === "string") { message = data.error; }
      } catch (ignored) { /* keep the generic message */ }
      throw new Error(message);
    }
    return response.json();
  }

  function setState(element, text, isError, retry) {
    element.className = "state" + (isError ? " error" : "");
    element.textContent = text;
    if (retry) {
      const button = node("button", "btn", "Retry");
      button.type = "button";
      button.addEventListener("click", retry);
      element.appendChild(document.createTextNode(" "));
      element.appendChild(button);
    }
  }

  // ------------------------------------------------------------------ status

  function showConnection(kind, text) {
    const pill = $("status");
    pill.dataset.state = kind;
    $("status-text").textContent = text;
    $("status-icon").replaceChildren(icon(kind === "running" ? "ok" : (kind === "stopped" ? "bad" : "dash")));
  }

  function setStat(id, value, note) {
    $("s-" + id).textContent = value;
    if (note !== undefined && $("n-" + id)) { $("n-" + id).textContent = note; }
  }

  function showStatus(status) {
    const stats = status.stats || {};
    const tiers = stats.tiers || {};
    const pit = status.tarpit || {};
    const decoy = status.decoy || {};
    const notices = status.alerts || {};
    showConnection(status.running ? "running" : "stopped", status.running ? "Running" : "Stopped");
    $("uptime").textContent = duration(status.uptime || 0);
    $("instance").textContent = status.instance ? status.instance.name + " v" + status.instance.version : "";
    setStat("requests", number(stats.requests));
    setStat("canary", number(stats.canary_hits));
    setStat("alerts", number(stats.alerts), notices.configured
      ? notices.sent + " sent, " + notices.suppressed + " held back, " + notices.failed + " failed"
      : "No webhook or e-mail set");
    setStat("flagged", number((tiers.low || 0) + (tiers.medium || 0) + (tiers.high || 0)),
      "High " + (tiers.high || 0) + ", medium " + (tiers.medium || 0) + ", low " + (tiers.low || 0));
    setStat("held", number(pit.held), (pit.sessions || 0) + " sessions, " + (pit.dropped || 0) +
      " dropped, " + (pit.abandoned || 0) + " gave up");
    setStat("burned", duration(pit.burned_seconds || 0), number(stats.delayed) + " delayed requests, " +
      (stats.teleported || 0) + " redirected, " + (stats.blocklist || 0) + " on blocklist");
    setStat("bytes", Math.round((stats.trap_bytes || 0) / 1024).toLocaleString() + " KB",
      "About " + Math.round((stats.trap_bytes || 0) / 4).toLocaleString() + " tokens (estimate: bytes / 4)");
    setStat("decoy", !decoy.enabled ? "Off" : (decoy.running ? "Running" : "Down, failing closed"),
      decoy.enabled ? decoy.profile + ", " + (decoy.served || 0) + " served, " + (decoy.touches || 0) +
        " sensitive, " + (decoy.restarts || 0) + " restarts" : "High tier stays on the tarpit");
    setStat("tracked", number(stats.tracked_sessions));
    setStat("mode", status.mode === "proxy" ? "Reverse proxy" : "Standalone",
      status.canary ? "Canaries rotate in " + duration(status.canary.next_rotation_in) : "");
    if (typeof status.level === "number" && !state.formDirty) { showLevel(status.level); }
  }

  // ---------------------------------------------------------------- sessions

  function sessionTier(session) { return session.released ? "released" : session.tier; }

  function compare(a, b) {
    const key = state.sort.key;
    let result;
    if (key === "tier") { result = TIER_RANK[sessionTier(a)] - TIER_RANK[sessionTier(b)]; }
    else if (key === "ip") { result = String(a.ip).localeCompare(String(b.ip), undefined, { numeric: true }); }
    else { result = (a[key] || 0) - (b[key] || 0); }
    if (result === 0) { result = (a.last_seen || 0) - (b.last_seen || 0); }
    return state.sort.dir === "asc" ? result : -result;
  }

  function matches(session) {
    if (state.tier && sessionTier(session) !== state.tier) { return false; }
    if (!state.text) { return true; }
    const hay = [session.ip, session.user_agent, session.campaign, session.key]
      .concat(Object.keys(session.signals || {})).join(" ").toLowerCase();
    return hay.indexOf(state.text.toLowerCase()) !== -1;
  }

  function sessionRow(session) {
    const row = node("tr");
    if (session.key === state.detailKey) { row.className = "selected"; }
    row.dataset.key = session.key;
    row.appendChild(node("td")).appendChild(badge(sessionTier(session)));
    row.appendChild(node("td", "num", Math.round(session.score)));
    row.appendChild(node("td", "num", session.phase || 0));
    row.appendChild(node("td", "mono ipcell", session.ip || "-"));

    const chips = node("div", "chips");
    Object.keys(session.signals || {}).sort().forEach(function (name) {
      const count = session.signals[name];
      chips.appendChild(node("span", "chip", count > 1 ? name + " x" + count : name));
    });
    Object.keys(session.inherited || {}).sort().forEach(function (name) {
      const chip = node("span", "chip", name + " (inherited)");
      chip.title = "Carried over from a session with the same address and header fingerprint";
      chips.appendChild(chip);
    });
    row.appendChild(node("td")).appendChild(chips);
    const campaign = node("td", "num", session.campaign ? session.campaign.slice(0, 8) : "-");
    if (session.campaign) { campaign.title = "Linked to other sessions by a reused secret"; }
    row.appendChild(campaign);
    const client = node("td", "client", session.user_agent || "(no user agent)");
    client.title = session.user_agent || "";
    row.appendChild(client);
    row.appendChild(node("td")).appendChild(timeCell(session.last_seen, true));

    const actions = node("div", "row-actions");
    const detail = node("button", "btn", "Timeline");
    detail.type = "button";
    detail.setAttribute("aria-label", "Open timeline for session from " + (session.ip || "unknown address"));
    detail.addEventListener("click", function () { openDetail(session.key); });
    const release = node("button", "btn", session.released ? "Re-arm" : "Release");
    release.type = "button";
    release.setAttribute("aria-label", (session.released ? "Re-arm session from " : "Release session from ") +
      (session.ip || "unknown address"));
    release.addEventListener("click", async function () {
      release.disabled = true;
      try {
        await api("/api/v1/sessions/release", { key: session.key, released: !session.released });
        await loadSessions();
      } catch (error) {
        release.disabled = false;
        setState($("sessions-state"), error.message, true);
      }
    });
    actions.appendChild(detail);
    actions.appendChild(release);
    row.appendChild(node("td")).appendChild(actions);
    return row;
  }

  function renderSessions() {
    const body = $("sessions");
    const all = state.sessions || [];
    const shown = all.filter(matches).sort(compare);
    body.replaceChildren.apply(body, shown.map(sessionRow));
    $("session-count").textContent = shown.length + " of " + all.length + " sessions";
    const stateLine = $("sessions-state");
    if (state.sessions === null) { return; }
    if (all.length === 0) {
      setState(stateLine, "No flagged sessions. A session appears here when a visitor trips a tripwire.");
    } else if (shown.length === 0) {
      setState(stateLine, "No sessions match the filter.");
    } else {
      setState(stateLine, "");
    }
    document.querySelectorAll("#sessions-table th[data-sort]").forEach(function (th) {
      const active = th.dataset.sort === state.sort.key;
      th.setAttribute("aria-sort", active ? (state.sort.dir === "asc" ? "ascending" : "descending") : "none");
      const button = th.querySelector("button");
      const old = button.querySelector("svg");
      if (old) { old.remove(); }
      button.appendChild(icon(active ? (state.sort.dir === "asc" ? "up" : "down") : "both"));
    });
  }

  async function loadSessions() {
    try {
      const data = await api("/api/v1/sessions");
      state.sessions = data.sessions;
      renderSessions();
    } catch (error) {
      if (error.message !== "signed out") {
        state.sessions = state.sessions || null;
        setState($("sessions-state"), "Could not load sessions: " + error.message, true, loadSessions);
      }
    }
  }

  let sessionsTimer = null;
  function scheduleSessions() {
    if (sessionsTimer !== null) { return; }
    sessionsTimer = window.setTimeout(function () {
      sessionsTimer = null;
      loadSessions();
      if (state.detailKey) { loadDetail(state.detailKey, true); }
    }, 800);
  }

  // ------------------------------------------------------------------ detail

  function fact(label, value) {
    const wrap = node("div");
    wrap.appendChild(node("dt", "", label));
    wrap.appendChild(node("dd", "", value));
    return wrap;
  }

  async function loadDetail(key, quiet) {
    const body = $("timeline");
    if (!quiet) { setState($("timeline-state"), "Loading timeline"); }
    let timeline, report;
    try {
      const results = await Promise.all([
        api("/api/v1/sessions/timeline?key=" + encodeURIComponent(key)),
        api("/api/v1/sessions/report?key=" + encodeURIComponent(key)),
      ]);
      timeline = results[0];
      report = results[1];
    } catch (error) {
      setState($("timeline-state"), "Could not load this session: " + error.message, true,
        function () { loadDetail(key, false); });
      return;
    }
    if (state.detailKey !== key) { return; }
    const session = timeline.session;
    const facts = $("facts");
    facts.replaceChildren(
      fact("Address", session.ip || "-"),
      fact("Client", session.user_agent || "(no user agent)"),
      fact("Severity", SEVERITY[sessionTier(session)].label + ", score " + Math.round(session.score) +
        ", tarpit phase " + (session.phase || 0)),
      fact("Campaign", session.campaign || "none"),
      fact("Decoy presented", session.theme || "not moved to the decoy"),
      fact("Session id", session.key),
      fact("First seen", absolute(session.created)),
      fact("Last seen", absolute(session.last_seen)),
      fact("Requests", number(session.requests)),
    );
    facts.querySelectorAll("div:last-child dd, div:nth-child(6) dd").forEach(function (dd) { dd.classList.add("mono"); });

    const playbook = $("playbook");
    playbook.replaceChildren();
    report.stages.forEach(function (stage) {
      const item = node("li");
      item.appendChild(node("strong", "", stage.stage + ": "));
      item.appendChild(document.createTextNode(Object.keys(stage.signals).sort().map(function (name) {
        return name + " x" + stage.signals[name];
      }).join(", ")));
      if (stage.example) { item.appendChild(node("span", "example", "For example: " + stage.example)); }
      playbook.appendChild(item);
    });
    if (!report.stages.length) { playbook.appendChild(node("li", "", "No stages recorded yet.")); }
    const m = report.metrics;
    $("playbook-note").textContent = "Held " + m.held_seconds + " s and sent " + m.bytes_sent +
      " bytes (measured). About " + m.estimated_tokens + " tokens (estimate: bytes / 4, input only, no price).";

    const linked = $("linked");
    linked.replaceChildren();
    const others = (state.sessions || []).filter(function (s) {
      return session.campaign && s.campaign === session.campaign && s.key !== key;
    });
    if (!others.length) { linked.appendChild(node("li", "muted", "No linked sessions.")); }
    others.forEach(function (other) {
      const item = node("li");
      const open = node("button", "btn", other.ip + " (" + other.key.slice(0, 8) + ")");
      open.type = "button";
      open.addEventListener("click", function () { openDetail(other.key); });
      item.appendChild(open);
      linked.appendChild(item);
    });

    body.replaceChildren.apply(body, timeline.events.map(eventRow));
    setState($("timeline-state"), timeline.events.length ? "" : "No events recorded for this session.");
    if (timeline.truncated) {
      setState($("timeline-state"), "Showing the latest " + timeline.events.length + " events.");
    }
  }

  function openDetail(key) {
    state.detailKey = key;
    const panel = $("detail");
    panel.hidden = false;
    const query = "?key=" + encodeURIComponent(key);
    $("report-md").href = "/api/v1/sessions/report" + query + "&format=md";
    $("report-json").href = "/api/v1/sessions/report" + query + "&download=1";
    $("facts").replaceChildren();
    $("playbook").replaceChildren();
    $("timeline").replaceChildren();
    $("detail-title").focus();
    renderSessions();
    loadDetail(key, false);
  }

  function closeDetail() {
    const key = state.detailKey;
    state.detailKey = null;
    $("detail").hidden = true;
    renderSessions();
    // Rows are rebuilt on every refresh, so find the opener again by its key.
    const row = key ? document.querySelector('#sessions tr[data-key="' + CSS.escape(key) + '"] button') : null;
    if (row) { row.focus(); } else { $("h-sessions").focus(); }
  }

  // ------------------------------------------------------------------ events

  function eventRow(event) {
    const row = node("tr");
    row.dataset.alert = event.alert ? "1" : "0";
    row.appendChild(node("td")).appendChild(timeCell(event.ts, false));
    row.appendChild(node("td")).appendChild(badge(event.tier || "none"));
    const what = node("td", "what");
    what.appendChild(node("strong", "", event.kind === "signal" ? event.signal : event.kind));
    if (event.alert) { what.appendChild(node("span", "chip", "alert")); }
    what.appendChild(document.createTextNode(" " + (event.detail || "")));
    row.appendChild(what);
    const request = node("td", "request mono");
    if (event.kind !== "system") {
      request.textContent = (event.method ? event.method + " " : "") + (event.path || "") +
        (event.ip ? "  from " + event.ip : "") + "  score " + Math.round(event.score || 0);
    }
    row.appendChild(request);
    return row;
  }

  function feedVisible(event) {
    if (state.alertsOnly && !event.alert) { return false; }
    if (!state.feedFilter) { return true; }
    const hay = [event.kind, event.signal, event.detail, event.path, event.ip, event.user_agent]
      .join(" ").toLowerCase();
    return hay.indexOf(state.feedFilter.toLowerCase()) !== -1;
  }

  function renderFeed() {
    const body = $("feed");
    const shown = state.events.filter(feedVisible);
    body.replaceChildren.apply(body, shown.map(eventRow));
    setState($("feed-state"), shown.length ? "" : (state.events.length
      ? "No events match the filter." : "No events yet. They appear here as they happen."));
  }

  function addEvent(event) {
    state.events.unshift(event);
    if (state.events.length > MAX_FEED_ROWS) { state.events.length = MAX_FEED_ROWS; }
    renderFeed();
  }

  // ---------------------------------------------------------------- settings

  function showLevel(level) {
    document.querySelectorAll("#level-form input").forEach(function (input) {
      input.checked = Number(input.value) === level;
    });
    const preset = state.presets[String(level)];
    $("level-note").textContent = preset
      ? "Delays start at " + preset.tarpit.base_delay + " s and double up to " + preset.tarpit.max_delay +
        " s (medium tier: up to " + preset.tarpit.light_max_delay + " s). Rabbit hole " +
        preset.maze.rabbit_depth + " levels deep, long pages up to " +
        Math.round(preset.maze.burn_bytes / 1024) + " KB, redirect chance " +
        Math.round(preset.maze.redirect_chance * 100) + "%."
      : (level === 0 ? "Custom values are in use (see advanced settings)." : "");
  }

  function fillSettings(data) {
    state.presets = data.presets || {};
    showLevel(data.level);
    document.querySelectorAll("#settings-form [name]").forEach(function (input) {
      const parts = input.name.split(".");
      const value = (data.values[parts[0]] || {})[parts[1]];
      if (input.type === "checkbox") { input.checked = Boolean(value); } else { input.value = value; }
    });
    state.formDirty = false;
  }

  function settingsMessage(kind, text, id) {
    const message = $(id || "settings-message");
    message.dataset.kind = kind;
    message.textContent = text;
  }

  function clearFieldErrors() {
    document.querySelectorAll(".field-error").forEach(function (item) { item.remove(); });
    document.querySelectorAll("#settings-form [aria-invalid]").forEach(function (input) {
      input.removeAttribute("aria-invalid");
      input.removeAttribute("aria-describedby");
    });
  }

  // Values the browser's own constraints reject never leave the page.
  function validateFields() {
    clearFieldErrors();
    let first = null;
    document.querySelectorAll("#settings-form input[type='number']").forEach(function (input) {
      if (input.checkValidity()) { return; }
      const error = node("span", "field-error",
        input.validity.valueMissing ? "Enter a number." :
        "Enter a value from " + input.min + " to " + input.max + ".");
      error.id = input.id + "-error";
      input.setAttribute("aria-invalid", "true");
      input.setAttribute("aria-describedby", error.id);
      input.parentNode.appendChild(error);
      first = first || input;
    });
    if (first) { first.focus(); }
    return first === null;
  }

  // ------------------------------------------------------------------- start

  function connect() {
    const stream = new EventSource("/api/v1/stream");
    stream.addEventListener("status", function (message) {
      showStatus(JSON.parse(message.data));
    });
    stream.addEventListener("activity", function (message) {
      const event = JSON.parse(message.data);
      addEvent(event);
      scheduleSessions();
    });
    stream.onerror = function () {
      showConnection("unknown", "Reconnecting");
      fetch("/api/v1/state", { credentials: "same-origin" })
        .then(function (response) { return response.json(); })
        .then(function (data) { if (!data.authenticated) { window.location.replace("/login"); } })
        .catch(function () { /* the service is down; the stream keeps retrying */ });
    };
  }

  function bind() {
    $("logout").addEventListener("click", async function () {
      try { await api("/api/v1/logout", {}); } catch (error) { /* signing out anyway */ }
      window.location.replace("/login");
    });
    $("detail-close").addEventListener("click", closeDetail);
    $("session-filter").addEventListener("input", function (e) { state.text = e.target.value; renderSessions(); });
    $("tier-filter").addEventListener("change", function (e) { state.tier = e.target.value; renderSessions(); });
    $("feed-filter").addEventListener("input", function (e) { state.feedFilter = e.target.value; renderFeed(); });
    $("alerts-only").addEventListener("change", function (e) { state.alertsOnly = e.target.checked; renderFeed(); });
    document.querySelectorAll("#sessions-table th[data-sort] button").forEach(function (button) {
      button.addEventListener("click", function () {
        const key = button.closest("th").dataset.sort;
        state.sort = state.sort.key === key
          ? { key: key, dir: state.sort.dir === "asc" ? "desc" : "asc" }
          : { key: key, dir: key === "ip" ? "asc" : "desc" };
        renderSessions();
      });
    });
    $("level-form").addEventListener("change", async function (e) {
      if (e.target.name !== "level") { return; }
      try {
        fillSettings(await api("/api/v1/settings", { level: Number(e.target.value) }));
        settingsMessage("ok", "Level " + e.target.value + " is active.", "level-message");
      } catch (error) {
        settingsMessage("error", error.message, "level-message");
      }
    });
    $("settings-form").addEventListener("input", function () { state.formDirty = true; });
    $("settings-form").addEventListener("submit", async function (event) {
      event.preventDefault();
      settingsMessage("", "");
      if (!validateFields()) { settingsMessage("error", "Some values need attention."); return; }
      const values = {};
      document.querySelectorAll("#settings-form [name]").forEach(function (input) {
        const parts = input.name.split(".");
        values[parts[0]] = values[parts[0]] || {};
        if (input.type === "checkbox") { values[parts[0]][parts[1]] = input.checked; }
        else if (input.step === "1") { values[parts[0]][parts[1]] = parseInt(input.value, 10); }
        else { values[parts[0]][parts[1]] = parseFloat(input.value); }
      });
      try {
        fillSettings(await api("/api/v1/settings", { values: values }));
        settingsMessage("ok", "Settings saved.");
      } catch (error) {
        settingsMessage("error", error.message);
      }
    });
    window.setInterval(refreshTimes, 10000);
    window.setInterval(loadSessions, 15000);
  }

  async function start() {
    bind();
    setState($("sessions-state"), "Loading sessions");
    try {
      const session = await api("/api/v1/session");
      state.csrf = session.csrf;
    } catch (error) {
      showConnection("stopped", "Not reachable");
      setState($("sessions-state"), "Could not reach the service.", true, function () { window.location.reload(); });
      setState($("feed-state"), "Could not reach the service.", true);
      return;
    }
    renderSessions();
    api("/api/v1/events?limit=100").then(function (history) {
      state.events = history.events;
      renderFeed();
    }).catch(function (error) {
      setState($("feed-state"), "Could not load events: " + error.message, true, start);
    });
    api("/api/v1/settings").then(fillSettings).catch(function (error) {
      settingsMessage("error", "Could not load settings: " + error.message);
    });
    loadSessions();
    connect();
  }

  start();
})();
