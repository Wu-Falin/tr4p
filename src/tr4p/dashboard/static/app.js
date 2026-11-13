"use strict";

// Dashboard front end. Everything that comes from the network (paths, user
// agents, details) is attacker-controlled, so it is only ever written with
// textContent, never as HTML.
(function () {
  const MAX_FEED_ROWS = 300;
  const el = function (id) { return document.getElementById(id); };
  const feed = el("feed");
  const sessionsBody = el("sessions");
  let csrf = "";
  let sessionsTimer = null;
  let timelineKey = null;

  function node(tag, className, text) {
    const item = document.createElement(tag);
    if (className) { item.className = className; }
    if (text !== undefined && text !== null) { item.textContent = String(text); }
    return item;
  }

  function clock(seconds) {
    return new Date(seconds * 1000).toLocaleTimeString([], { hour12: false });
  }

  function duration(seconds) {
    const total = Math.max(0, Math.floor(seconds));
    const days = Math.floor(total / 86400);
    const hours = Math.floor((total % 86400) / 3600);
    const minutes = Math.floor((total % 3600) / 60);
    const rest = total % 60;
    const pad = function (n) { return String(n).padStart(2, "0"); };
    return (days ? days + "d " : "") + pad(hours) + ":" + pad(minutes) + ":" + pad(rest);
  }

  function ago(seconds) {
    const delta = Math.max(0, Date.now() / 1000 - seconds);
    if (delta < 60) { return Math.floor(delta) + "s ago"; }
    if (delta < 3600) { return Math.floor(delta / 60) + "m ago"; }
    if (delta < 86400) { return Math.floor(delta / 3600) + "h ago"; }
    return Math.floor(delta / 86400) + "d ago";
  }

  async function api(path, body) {
    const options = { credentials: "same-origin", headers: {} };
    if (body !== undefined) {
      options.method = "POST";
      options.headers["Content-Type"] = "application/json";
      options.headers["X-Requested-With"] = "dashboard";
      options.headers["X-CSRF-Token"] = csrf;
      options.body = JSON.stringify(body);
    }
    const response = await fetch(path, options);
    if (response.status === 401) {
      window.location.replace("/login");
      throw new Error("signed out");
    }
    if (!response.ok) {
      let message = "request failed: " + response.status;
      try {
        const data = await response.json();
        if (data && typeof data.error === "string") { message = data.error; }
      } catch (ignored) { /* keep the generic message */ }
      throw new Error(message);
    }
    return response.json();
  }

  // ------------------------------------------------------------------ status

  function setState(state, text) {
    el("status").dataset.state = state;
    el("status-text").textContent = text;
  }

  function showStatus(status) {
    const stats = status.stats || {};
    const tiers = stats.tiers || {};
    setState(status.running ? "running" : "stopped", status.running ? "Running" : "Stopped");
    el("uptime").textContent = duration(status.uptime || 0);
    el("instance").textContent = status.instance ? status.instance.name + " · v" + status.instance.version : "";
    el("c-requests").textContent = (stats.requests || 0).toLocaleString();
    el("c-canary").textContent = (stats.canary_hits || 0).toLocaleString();
    el("c-alerts").textContent = (stats.alerts || 0).toLocaleString();
    el("c-low").textContent = tiers.low || 0;
    el("c-medium").textContent = tiers.medium || 0;
    el("c-high").textContent = tiers.high || 0;
    el("c-flagged").textContent = (tiers.low || 0) + (tiers.medium || 0) + (tiers.high || 0);
    el("c-tracked").textContent = (stats.tracked_sessions || 0).toLocaleString();
    const pit = status.tarpit || {};
    el("c-held").textContent = (pit.held || 0).toLocaleString();
    el("c-held-note").textContent =
      (pit.sessions || 0) + " sessions · " + (pit.dropped || 0) + " dropped · " +
      (pit.abandoned || 0) + " gave up";
    el("c-burned").textContent = duration(pit.burned_seconds || 0);
    el("c-burned-note").textContent = (stats.delayed || 0).toLocaleString() + " delayed requests";
    if (typeof status.level === "number" && !formDirty) { showLevel(status.level); }
    el("c-mode").textContent = status.mode === "proxy" ? "Reverse proxy" : "Standalone";
    if (status.canary) {
      el("c-rotation").textContent = "Canaries rotate in " + duration(status.canary.next_rotation_in);
    }
  }

  // -------------------------------------------------------------------- feed

  function feedRow(event) {
    const row = node("li", event.alert ? "alert" : "");
    row.dataset.alert = event.alert ? "1" : "0";
    const time = node("time", "", clock(event.ts));
    time.dateTime = new Date(event.ts * 1000).toISOString();
    row.appendChild(time);
    row.appendChild(node("span", "tier tier-" + (event.tier || "none"), event.tier || "none"));

    const what = node("div", "what");
    const label = event.kind === "signal" ? event.signal : event.kind;
    what.appendChild(node("strong", "", label));
    what.appendChild(document.createTextNode(" " + (event.detail || "")));
    row.appendChild(what);

    if (event.kind === "system") { return row; }   // operator actions have no request behind them
    const meta = node("div", "meta");
    if (event.path) {
      meta.appendChild(node("span", "path", (event.method ? event.method + " " : "") + event.path));
      meta.appendChild(document.createTextNode(" · "));
    }
    meta.appendChild(document.createTextNode(
      (event.ip || "-") + " · score " + Math.round(event.score || 0)
    ));
    row.appendChild(meta);
    return row;
  }

  function applyFilter() {
    const alertsOnly = el("alerts-only").checked;
    let visible = 0;
    for (const row of feed.children) {
      const show = !alertsOnly || row.dataset.alert === "1";
      row.hidden = !show;
      if (show) { visible += 1; }
    }
    el("feed-empty").hidden = visible > 0;
  }

  function addEvent(event, atTop) {
    const row = feedRow(event);
    if (atTop) { feed.prepend(row); } else { feed.appendChild(row); }
    while (feed.children.length > MAX_FEED_ROWS) { feed.lastElementChild.remove(); }
  }

  // ---------------------------------------------------------------- sessions

  function sessionRow(session) {
    const row = node("tr");
    const tier = session.released ? "released" : session.tier;
    row.appendChild(node("td")).appendChild(node("span", "tier tier-" + tier, tier));
    if (session.key === timelineKey) { row.className = "selected"; }
    row.appendChild(node("td", "num", Math.round(session.score)));
    row.appendChild(node("td", "num", session.phase || 0));
    row.appendChild(node("td", "", session.ip || "-"));

    const chips = node("div", "chips");
    Object.keys(session.signals || {}).sort().forEach(function (name) {
      const count = session.signals[name];
      chips.appendChild(node("span", "chip", count > 1 ? name + " ×" + count : name));
    });
    Object.keys(session.inherited || {}).sort().forEach(function (name) {
      const chip = node("span", "chip", name + " (inherited)");
      chip.title = "Carried over from a session with the same address and header fingerprint";
      chips.appendChild(chip);
    });
    row.appendChild(node("td")).appendChild(chips);

    row.appendChild(node("td", "client", session.user_agent || "(no user agent)"));
    row.appendChild(node("td", "num", ago(session.last_seen)));

    const button = node("button", "ghost", session.released ? "Re-arm" : "Release");
    button.type = "button";
    button.title = session.released
      ? "Let detection act on this session again"
      : "Stop treating this session as an attacker";
    button.addEventListener("click", async function () {
      button.disabled = true;
      try {
        await api("/api/v1/sessions/release", { key: session.key, released: !session.released });
        await loadSessions();
      } catch (error) {
        button.disabled = false;
      }
    });
    const history = node("button", "ghost", "Timeline");
    history.type = "button";
    history.addEventListener("click", function () { showTimeline(session.key); });
    const actions = node("div", "row-actions");
    actions.appendChild(history);
    actions.appendChild(button);
    row.appendChild(node("td")).appendChild(actions);
    return row;
  }

  // ---------------------------------------------------------------- timeline

  async function showTimeline(key) {
    timelineKey = key;
    const list = el("timeline");
    let data;
    try {
      data = await api("/api/v1/sessions/timeline?key=" + encodeURIComponent(key));
    } catch (error) {
      hideTimeline();
      return;
    }
    const session = data.session;
    el("timeline-summary").textContent =
      (session.ip || "-") + " · tier " + (session.released ? "released" : session.tier) +
      " · score " + Math.round(session.score) + " · phase " + (session.phase || 0) +
      " · " + session.requests + " requests · first seen " + ago(session.created) +
      (data.truncated ? " · showing the latest " + data.events.length + " events" : "");
    list.replaceChildren.apply(list, data.events.map(feedRow));
    el("timeline-empty").hidden = data.events.length > 0;
    el("timeline-panel").hidden = false;
    el("timeline-panel").scrollIntoView({ behavior: "smooth", block: "nearest" });
    loadSessions().catch(function () { /* ignored */ });
  }

  function hideTimeline() {
    timelineKey = null;
    el("timeline-panel").hidden = true;
    loadSessions().catch(function () { /* ignored */ });
  }

  // ---------------------------------------------------------------- settings

  let presets = {};
  let formDirty = false;

  function showLevel(level) {
    document.querySelectorAll("#levels .level").forEach(function (button) {
      button.setAttribute("aria-pressed", String(Number(button.dataset.level) === level));
    });
    const preset = presets[String(level)];
    el("level-note").textContent = preset
      ? "Delays start at " + preset.base_delay + " s and double up to " + preset.max_delay +
        " s (medium tier: up to " + preset.light_max_delay + " s)."
      : (level === 0 ? "Custom values are in use (see advanced settings)." : "");
  }

  function fillSettings(data) {
    presets = data.presets || {};
    showLevel(data.level);
    document.querySelectorAll("#settings-form [name]").forEach(function (input) {
      const parts = input.name.split(".");
      const value = (data.values[parts[0]] || {})[parts[1]];
      if (input.type === "checkbox") { input.checked = Boolean(value); } else { input.value = value; }
    });
    formDirty = false;
  }

  function settingsMessage(kind, text) {
    const message = el("settings-message");
    message.dataset.kind = kind;
    message.textContent = text;
  }

  async function loadSettings() {
    fillSettings(await api("/api/v1/settings"));
  }

  document.querySelectorAll("#levels .level").forEach(function (button) {
    button.addEventListener("click", async function () {
      try {
        fillSettings(await api("/api/v1/settings", { level: Number(button.dataset.level) }));
        settingsMessage("ok", "Level " + button.dataset.level + " is active.");
      } catch (error) {
        settingsMessage("error", error.message);
      }
    });
  });

  el("settings-form").addEventListener("input", function () { formDirty = true; });
  el("settings-form").addEventListener("submit", async function (event) {
    event.preventDefault();
    const values = {};
    document.querySelectorAll("#settings-form [name]").forEach(function (input) {
      const parts = input.name.split(".");
      values[parts[0]] = values[parts[0]] || {};
      if (input.type === "checkbox") {
        values[parts[0]][parts[1]] = input.checked;
      } else if (input.step === "1") {
        values[parts[0]][parts[1]] = parseInt(input.value, 10);
      } else {
        values[parts[0]][parts[1]] = parseFloat(input.value);
      }
    });
    try {
      fillSettings(await api("/api/v1/settings", { values: values }));
      settingsMessage("ok", "Saved.");
    } catch (error) {
      settingsMessage("error", error.message);
    }
  });

  async function loadSessions() {
    const data = await api("/api/v1/sessions");
    sessionsBody.replaceChildren.apply(sessionsBody, data.sessions.map(sessionRow));
    el("sessions-empty").hidden = data.sessions.length > 0;
  }

  function scheduleSessions() {
    if (sessionsTimer !== null) { return; }
    sessionsTimer = window.setTimeout(function () {
      sessionsTimer = null;
      loadSessions().catch(function () { /* next event retries */ });
    }, 800);
  }

  // ------------------------------------------------------------------- start

  function connect() {
    const stream = new EventSource("/api/v1/stream");
    stream.addEventListener("status", function (message) {
      showStatus(JSON.parse(message.data));
    });
    stream.addEventListener("activity", function (message) {
      addEvent(JSON.parse(message.data), true);
      applyFilter();
      scheduleSessions();
    });
    stream.onerror = function () {
      setState("stopped", "Not reachable");
      // EventSource retries by itself. If the session is gone, go sign in.
      fetch("/api/v1/state", { credentials: "same-origin" })
        .then(function (response) { return response.json(); })
        .then(function (state) {
          if (!state.authenticated) { window.location.replace("/login"); }
        })
        .catch(function () { /* service is down; keep retrying */ });
    };
  }

  async function start() {
    const session = await api("/api/v1/session");
    csrf = session.csrf;
    const history = await api("/api/v1/events?limit=100");
    history.events.forEach(function (event) { addEvent(event, false); });
    applyFilter();
    await loadSessions();
    await loadSettings();
    connect();
    window.setInterval(function () {
      loadSessions().catch(function () { /* ignored */ });
    }, 15000);
  }

  el("alerts-only").addEventListener("change", applyFilter);
  el("timeline-close").addEventListener("click", hideTimeline);
  el("logout").addEventListener("click", async function () {
    try { await api("/api/v1/logout", {}); } catch (error) { /* signing out anyway */ }
    window.location.replace("/login");
  });

  start().catch(function () { setState("stopped", "Not reachable"); });
})();
