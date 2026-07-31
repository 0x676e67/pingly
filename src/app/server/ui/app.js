"use strict";

const VIEW_META = {
    overview: ["Current request", "Connection analysis"],
    tls: ["Client hello", "TLS analysis"],
    http: ["Header order", "HTTP request"],
    h2: ["Frame sequence", "HTTP/2 analysis"],
    h3: ["Transport parameters", "HTTP/3 analysis"],
    ws: ["Live connection", "WebSocket debugger"],
    tcp: ["Packet capture", "TCP analysis"],
    proxy: ["Cross-layer latency", "Latency analysis"],
    json: ["Serialized response", "Raw JSON"],
};
const VIEW_ORDER = Object.keys(VIEW_META);
const SERVER_ROUTES = /* PINGLY_ROUTES */ [];
const DEFAULT_JSON_ROUTE = "/api/all";
const LATENCY_PATH = "/api/latency";
const WEBSOCKET_PATH = "/api/websocket";
const WEBSOCKET_PREPARE_PATHS = {
    http1: "/api/websocket/http1",
    http2: "/api/websocket/http2",
};
const WEBSOCKET_TRANSPORT_LABELS = {
    http1: "HTTP/1.1",
    http2: "HTTP/2",
};
const WEBSOCKET_PREPARE_RETRY_STATUS = 409;
const UNAVAILABLE_LABEL = "Unavailable";
const JSON_ROUTE_FEEDBACK_MS = 300;
const PRIORITY_PROBE_TIMEOUT_MS = 10_000;
const PRIORITY_PROBE_SETTLE_MS = 250;
const WEBSOCKET_DEFAULT_MAX_MESSAGE_SIZE = 256 * 1024;
const WEBSOCKET_HISTORY_LIMIT = 100;
const WEBSOCKET_TEXT_PREVIEW_LIMIT = 4096;
const WEBSOCKET_BINARY_PREVIEW_LIMIT = 512;
const UTF8_ENCODER = new TextEncoder();
const PRIORITY_PROBES = [
    {
        id: "navigation",
        label: "Navigation",
        context: "document",
        icon: "external-link",
        kind: "navigation",
    },
    {
        id: "fetch-high",
        label: "Fetch high",
        context: "fetch(high)",
        icon: "arrow-up",
        kind: "fetch",
        priority: "high",
    },
    {
        id: "fetch-auto",
        label: "Fetch auto",
        context: "fetch(auto)",
        icon: "minus",
        kind: "fetch",
        priority: "auto",
    },
    {
        id: "fetch-low",
        label: "Fetch low",
        context: "fetch(low)",
        icon: "arrow-down",
        kind: "fetch",
        priority: "low",
    },
];

// Blink assigns a baseline from the resource type before applying loading hints. Source:
// <https://chromium.googlesource.com/chromium/src/+/HEAD/third_party/blink/renderer/platform/loader/fetch/resource_fetcher.cc>
const CHROMIUM_RESOURCE_DEFAULTS = [
    { resource: "CSS / font", blink: "VeryHigh", net: "HIGHEST", weight: 256 },
    { resource: "fetch() / XSL / script", blink: "High", net: "MEDIUM", weight: 220 },
    { resource: "Manifest", blink: "Medium", net: "LOW", weight: 183 },
    { resource: "Image / media / SVG", blink: "Low", net: "LOWEST", weight: 147 },
    {
        resource: "Prefetch / speculation / dictionary",
        blink: "VeryLow",
        net: "IDLE",
        weight: 110,
    },
];

// Chromium maps Blink priorities to net priorities, then through the legacy SPDY scale. Sources:
// <https://chromium.googlesource.com/chromium/src/+/HEAD/third_party/blink/renderer/platform/exported/web_url_request.cc>
// <https://chromium.googlesource.com/chromium/src/+/HEAD/net/spdy/spdy_http_utils.cc>
const CHROMIUM_PRIORITY_BY_WEIGHT = new Map([
    [256, "VeryHigh / HIGHEST"],
    [220, "High / MEDIUM"],
    [183, "Medium / LOW"],
    [147, "Low / LOWEST"],
    [110, "VeryLow / IDLE"],
    [74, "THROTTLED"],
]);

const state = {
    data: null,
    jsonData: null,
    jsonRoute: DEFAULT_JSON_ROUTE,
    jsonLoadingRoute: null,

    priorityProbes: {
        http2: new Map(),
        http3: new Map(),
    },
    priorityProbeRunning: new Set(),
    proxyAnalysis: null,
    proxyError: "",
    proxyProgress: 0,
    proxyRunning: false,
    proxySamplesCompleted: 0,
    proxySamplesTotal: 0,
    proxySocket: null,
    proxyTimer: null,
    websocket: {
        address: "",
        closeRequested: false,
        error: "",
        headers: [],
        httpVersion: "",
        maxMessageSize: WEBSOCKET_DEFAULT_MAX_MESSAGE_SIZE,
        messages: [],
        mode: "text",
        prepareController: null,
        receivedConnectionInfo: false,
        socket: null,
        status: "idle",
        tls: null,
        transport: "http1",
    },
    activeView: "overview",
    controller: null,
    jsonController: null,
};

const refs = {};
const systemTheme = window.matchMedia("(prefers-color-scheme: dark)");
const desktopLayout = window.matchMedia("(min-width: 768px)");
let toastTimer;
let followsSystemTheme = true;

document.addEventListener("DOMContentLoaded", init);

function init() {
    refs.loading = document.getElementById("loading-state");
    refs.error = document.getElementById("error-state");
    refs.errorMessage = document.getElementById("error-message");
    refs.workspace = document.getElementById("analysis-workspace");
    refs.status = document.getElementById("capture-status");
    refs.statusLabel = document.getElementById("capture-status-label");
    refs.statusDot = document.getElementById("capture-status-dot");
    refs.themeButton = document.getElementById("theme-button");

    refs.downloadButton = document.getElementById("download-button");
    refs.retryButton = document.getElementById("retry-button");

    refs.copyJsonButton = document.getElementById("copy-json-button");
    refs.json = document.getElementById("json-content");
    refs.jsonRoutes = document.getElementById("json-route-options");
    refs.jsonRouteLabel = document.getElementById("json-route-label");
    refs.toast = document.getElementById("toast");
    refs.main = document.getElementById("main-content");
    refs.sidebar = document.getElementById("analysis-sidebar");
    refs.sidebarToggle = document.getElementById("sidebar-toggle");
    refs.sidebarBackdrop = document.getElementById("analysis-sidebar-backdrop");
    refs.navItems = Array.from(document.querySelectorAll("[data-view]"));
    refs.panels = Array.from(document.querySelectorAll("[data-panel]"));
    refs.websocketStatus = document.getElementById("websocket-status");
    refs.websocketStatusDot = document.getElementById("websocket-status-dot");
    refs.websocketStatusLabel = document.getElementById("websocket-status-label");
    refs.websocketUrl = document.getElementById("websocket-url");
    refs.websocketConnectButton = document.getElementById("websocket-connect-button");
    refs.websocketAnalysis = document.getElementById("websocket-analysis-content");
    refs.websocketModeButtons = Array.from(
        document.querySelectorAll("[data-websocket-mode]")
    );
    refs.websocketTransportButtons = Array.from(
        document.querySelectorAll("[data-websocket-transport]")
    );
    refs.websocketInput = document.getElementById("websocket-message-input");
    refs.websocketInputSize = document.getElementById("websocket-message-size");
    refs.websocketSendButton = document.getElementById("websocket-send-button");
    refs.websocketClearButton = document.getElementById("websocket-clear-button");
    refs.websocketMessageLog = document.getElementById("websocket-message-log");
    refs.websocketMessageCount = document.getElementById("websocket-message-count");

    renderJsonRouteOptions();
    bindEvents();
    restoreTheme();
    refs.websocketUrl.textContent = websocketUrl();
    renderWebSocket();

    const initialView = window.location.hash.slice(1);
    if (VIEW_ORDER.includes(initialView)) {
        state.activeView = initialView;
    }
    activateView(state.activeView, false);
    paintIcons();
    syncSidebarLayout();
    fetchAnalysis();
}

function bindEvents() {
    refs.navItems.forEach(function (item) {
        item.addEventListener("click", function () {
            const mobile = !desktopLayout.matches;

            activateView(item.dataset.view, true);
            setMobileSidebar(false);

            if (mobile) {
                refs.main.focus();
            }
        });

        item.addEventListener("keydown", function (event) {
            if (!["ArrowDown", "ArrowRight", "ArrowUp", "ArrowLeft"].includes(event.key)) {
                return;
            }

            event.preventDefault();
            const direction = event.key === "ArrowDown" || event.key === "ArrowRight" ? 1 : -1;
            const current = VIEW_ORDER.indexOf(item.dataset.view);
            const next = (current + direction + VIEW_ORDER.length) % VIEW_ORDER.length;
            activateView(VIEW_ORDER[next], true);
            refs.navItems[next].focus();
        });
    });

    refs.retryButton.addEventListener("click", fetchAnalysis);

    refs.downloadButton.addEventListener("click", downloadJson);
    refs.copyJsonButton.addEventListener("click", function () {
        if (state.jsonData !== null) {
            copyText(JSON.stringify(state.jsonData, null, 2), refs.copyJsonButton);
        }
    });
    refs.jsonRoutes.addEventListener("click", function (event) {
        const button = event.target.closest("[data-json-route]");
        if (button) {
            void selectJsonRoute(button.dataset.jsonRoute);
        }
    });
    refs.themeButton.addEventListener("click", toggleTheme);
    refs.sidebarToggle.addEventListener("click", function () {
        const opening = !refs.sidebar.classList.contains("is-open");
        setMobileSidebar(opening);

        if (opening) {
            const activeItem = refs.navItems.find(function (item) {
                return item.dataset.view === state.activeView;
            });
            activeItem?.focus();
        }
    });
    refs.sidebarBackdrop.addEventListener("click", function () {
        setMobileSidebar(false);
        refs.sidebarToggle.focus();
    });
    document.addEventListener("keydown", function (event) {
        if (event.key === "Escape" && refs.sidebar.classList.contains("is-open")) {
            setMobileSidebar(false);
            refs.sidebarToggle.focus();
        }
    });
    systemTheme.addEventListener("change", syncSystemTheme);
    desktopLayout.addEventListener("change", syncSidebarLayout);
    window.addEventListener("resize", syncSidebarLayout, { passive: true });
    window.addEventListener("load", syncSidebarLayout, { once: true });
    window.addEventListener("beforeunload", closeWebSocketForUnload);

    refs.websocketConnectButton.addEventListener("click", toggleWebSocket);
    refs.websocketSendButton.addEventListener("click", sendWebSocketMessage);
    refs.websocketClearButton.addEventListener("click", clearWebSocketMessages);
    refs.websocketInput.addEventListener("input", renderWebSocketComposer);
    refs.websocketInput.addEventListener("keydown", function (event) {
        if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
            event.preventDefault();
            sendWebSocketMessage();
        }
    });
    refs.websocketModeButtons.forEach(function (button) {
        button.addEventListener("click", function () {
            setWebSocketMode(button.dataset.websocketMode);
        });
    });
    refs.websocketTransportButtons.forEach(function (button) {
        button.addEventListener("click", function () {
            setWebSocketTransport(button.dataset.websocketTransport);
        });
    });
}

function syncSidebarLayout() {
    setMobileSidebar(refs.sidebar.classList.contains("is-open"));
}

function setMobileSidebar(open) {
    const mobile = !desktopLayout.matches;
    const visible = mobile && open;

    refs.sidebar.classList.toggle("is-open", visible);
    refs.sidebarToggle.setAttribute("aria-expanded", String(visible));
    refs.sidebarToggle.setAttribute(
        "aria-label",
        visible ? "Close analysis navigation" : "Open analysis navigation"
    );
    refs.sidebarToggle.title = visible
        ? "Close analysis navigation"
        : "Open analysis navigation";
    refs.sidebar.toggleAttribute("inert", mobile && !visible);

    if (mobile) {
        refs.sidebar.setAttribute("aria-hidden", String(!visible));
    } else {
        refs.sidebar.removeAttribute("aria-hidden");
    }

    refs.sidebarBackdrop.hidden = !visible;
    document.body.classList.toggle("mobile-sidebar-open", visible);
}

function restoreTheme() {
    let theme;

    try {
        const stored = window.localStorage.getItem("pingly-theme");
        if (stored === "light" || stored === "dark") {
            theme = stored;
        }
    } catch (_) {
        // The system preference remains available when storage is blocked.
    }

    followsSystemTheme = theme === undefined;
    applyTheme(theme ?? preferredSystemTheme());
}

function preferredSystemTheme() {
    return systemTheme.matches ? "dark" : "light";
}

function syncSystemTheme() {
    if (followsSystemTheme) {
        applyTheme(preferredSystemTheme());
    }
}

function toggleTheme() {
    const current = document.documentElement.dataset.theme;
    const next = current === "dark" ? "light" : "dark";
    followsSystemTheme = false;
    applyTheme(next);

    try {
        window.localStorage.setItem("pingly-theme", next);
    } catch (_) {
        // The theme still applies when storage is unavailable.
    }
}

function applyTheme(theme) {
    if (typeof window.applyPinglyTheme === "function") {
        window.applyPinglyTheme(theme);
    } else {
        document.documentElement.dataset.theme = theme;
        document.documentElement.style.colorScheme = theme;
    }

    refs.themeButton.setAttribute(
        "aria-label",
        theme === "dark" ? "Use light theme" : "Use dark theme"
    );
    refs.themeButton.title = refs.themeButton.getAttribute("aria-label");

    const currentIcon = refs.themeButton.querySelector("[data-lucide]");
    if (currentIcon) {
        currentIcon.remove();
    }

    const icon = document.createElement("i");
    icon.className = "icon";
    icon.dataset.lucide = theme === "dark" ? "sun" : "moon";
    icon.setAttribute("aria-hidden", "true");
    refs.themeButton.append(icon);
    paintIcons();
}

function paintIcons() {
    if (!window.lucide || typeof window.lucide.createIcons !== "function") {
        return;
    }

    try {
        window.lucide.createIcons();
    } catch (_) {
        // Text labels and accessible names remain available without the icons.
    }
}

function setStatus(label, mode) {
    refs.statusLabel.textContent = label;
    refs.status.dataset.state = mode || "loading";
    refs.statusDot.classList.toggle("status-dot-animated", mode !== "error");
}

function showLoading() {
    refs.loading.hidden = false;
    refs.error.hidden = true;
    refs.workspace.hidden = true;
    setStatus("Analyzing", "");
}

function showError(error) {
    refs.loading.hidden = true;
    refs.workspace.hidden = true;
    refs.error.hidden = false;
    refs.errorMessage.textContent = error instanceof Error
        ? error.message
        : "The analysis response could not be loaded.";
    setStatus(UNAVAILABLE_LABEL, "error");
    paintIcons();
}

async function fetchAnalysis() {
    cancelJsonRequest();

    if (state.controller) {
        state.controller.abort();
    }

    const controller = new AbortController();
    state.controller = controller;
    showLoading();

    try {
        const response = await fetch("/api/all", {
            cache: "no-store",
            signal: controller.signal,
        });

        if (!response.ok) {
            throw new Error("The server returned HTTP " + response.status + ".");
        }

        const data = await response.json();
        loadAnalysis(data);
    } catch (error) {
        if (error && error.name === "AbortError") {
            return;
        }
        showError(error);
    } finally {
        if (state.controller === controller) {
            state.controller = null;
        }
    }
}

function loadAnalysis(data) {
    if (!isObject(data)) {
        showError(new Error("The response is not a Pingly analysis object."));
        return;
    }

    resetProxyProbe();
    recordCurrentPriorityProbes(data);
    state.data = data;
    refs.loading.hidden = true;
    refs.error.hidden = true;
    refs.workspace.hidden = false;
    refs.downloadButton.disabled = false;

    renderSummary(data);
    renderNavigationCounts(data);
    renderOverview(data);
    renderTls(data.tls);
    renderHttp(data);
    renderHttp2(data.http2);
    renderHttp3(data.http3, data.tls);
    renderTcp(data.tcp);
    renderProxy();
    showJsonResponse(DEFAULT_JSON_ROUTE, data);

    const now = new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "medium",
    }).format(new Date());
    document.getElementById("captured-at").textContent = "Captured " + now;

    setStatus("Live", "live");
    activateView(state.activeView, false);
    paintIcons();
}

function jsonRouteLabel(path) {
    const name = path.slice("/api/".length);
    const httpVersion = /^http(\d+)$/.exec(name);

    if (httpVersion) {
        return "HTTP/" + httpVersion[1];
    }

    if (name === "all") {
        return "All";
    }

    return name.length <= 3 ? name.toUpperCase() : name;
}

function renderJsonRouteOptions() {
    const fragment = document.createDocumentFragment();

    SERVER_ROUTES.filter(function (route) {
        return route.path.startsWith("/api/") && route.method === "ANY";
    }).forEach(function (route) {
        const button = create("button", "nav-link flex-shrink-0 px-2");
        const spinner = create(
            "span",
            "spinner-border spinner-border-sm json-route-spinner"
        );
        spinner.setAttribute("aria-hidden", "true");
        button.append(
            create("span", "json-route-option-label", jsonRouteLabel(route.path)),
            spinner
        );
        button.type = "button";
        button.dataset.jsonRoute = route.path;
        button.title = route.path + " - " + route.purpose + " - " + route.availability;
        button.setAttribute("aria-pressed", "false");
        fragment.append(button);
    });

    refs.jsonRoutes.replaceChildren(fragment);
    syncJsonRouteOptions();
}

function syncJsonRouteOptions() {
    refs.jsonRouteLabel.textContent = state.jsonRoute;
    if (state.jsonLoadingRoute) {
        refs.jsonRoutes.setAttribute("aria-busy", "true");
    } else {
        refs.jsonRoutes.removeAttribute("aria-busy");
    }

    refs.jsonRoutes.querySelectorAll("[data-json-route]").forEach(function (button) {
        const active = button.dataset.jsonRoute === state.jsonRoute;
        const loading = button.dataset.jsonRoute === state.jsonLoadingRoute;
        button.classList.toggle("active", active);
        button.classList.toggle("is-loading", loading);
        button.disabled = loading;
        button.setAttribute("aria-pressed", String(active));
        if (loading) {
            button.setAttribute("aria-busy", "true");
        } else {
            button.removeAttribute("aria-busy");
        }
    });
}

function cancelJsonRequest() {
    const controller = state.jsonController;
    state.jsonController = null;
    state.jsonLoadingRoute = null;

    if (controller) {
        controller.abort();
    }

    refs.json.removeAttribute("aria-busy");
    syncJsonRouteOptions();
}

function showJsonResponse(path, data) {
    state.jsonRoute = path;
    state.jsonData = data;
    refs.json.textContent = JSON.stringify(data, null, 2);
    refs.json.removeAttribute("aria-busy");
    refs.copyJsonButton.disabled = false;
    syncJsonRouteOptions();
}

async function selectJsonRoute(path) {
    const knownRoute = SERVER_ROUTES.some(function (route) {
        return route.path === path &&
            route.path.startsWith("/api/") &&
            route.method === "ANY";
    });
    if (!knownRoute) {
        return;
    }

    cancelJsonRequest();

    const controller = new AbortController();
    state.jsonController = controller;
    state.jsonRoute = path;
    state.jsonLoadingRoute = path;
    state.jsonData = null;
    refs.copyJsonButton.disabled = true;
    refs.json.setAttribute("aria-busy", "true");
    refs.json.textContent = "Loading " + path + "...";
    syncJsonRouteOptions();
    const feedbackDelay = new Promise(function (resolve) {
        window.setTimeout(resolve, JSON_ROUTE_FEEDBACK_MS);
    });

    try {
        await new Promise(function (resolve) {
            window.requestAnimationFrame(resolve);
        });

        if (controller.signal.aborted) {
            return;
        }

        const response = await fetch(path, {
            cache: "no-store",
            signal: controller.signal,
        });

        if (!response.ok) {
            throw new Error("The server returned HTTP " + response.status + ".");
        }

        const data = await response.json();
        if (state.jsonController === controller) {
            showJsonResponse(path, data);
            await feedbackDelay;
        }
    } catch (error) {
        if (error && error.name === "AbortError") {
            return;
        }

        if (state.jsonController === controller) {
            const message = error instanceof Error
                ? error.message
                : "The route response could not be loaded.";
            refs.json.textContent = "Unable to load " + path + "." + String.fromCharCode(10, 10) + message;
            showToast("Could not load " + path);
            await feedbackDelay;
        }
    } finally {
        if (state.jsonController === controller) {
            state.jsonController = null;
            state.jsonLoadingRoute = null;
            refs.json.removeAttribute("aria-busy");
            syncJsonRouteOptions();
        }
    }
}

function renderSummary(data) {
    const frames = getFrames(data.http2);
    const http3Frames = getHttp3FrameCount(data.http3);

    setText("summary-address", valueOr(data.address, UNAVAILABLE_LABEL));
    setText(
        "summary-http",
        [data.method, data.http_version].filter(Boolean).join(" / ") || UNAVAILABLE_LABEL
    );
    setText(
        "summary-tls",
        data.tls && data.tls.tls_version_negotiated
            ? data.tls.tls_version_negotiated
            : UNAVAILABLE_LABEL
    );
    setText("summary-frames", String(frames.length + http3Frames));
}

function renderNavigationCounts(data) {
    const headers = getRequestHeaders(data);
    const ciphers = data.tls && Array.isArray(data.tls.cipher_suites)
        ? data.tls.cipher_suites
        : [];
    const frames = getFrames(data.http2);
    const http3Settings = getHttp3Settings(data.http3);
    const packets = isObject(data.tcp) && Array.isArray(data.tcp.packets)
        ? data.tcp.packets
        : [];

    setText("tls-count", String(ciphers.length));
    setText("http-count", String(headers.length));
    setText("h2-count", String(frames.length));
    setText("h3-count", String(http3Settings.length));
    setText("websocket-count", String(webSocketDataMessageCount()));
    setText("tcp-count", String(packets.length));
}

function activateView(view, updateHash) {
    if (!VIEW_ORDER.includes(view)) {
        return;
    }

    state.activeView = view;
    refs.navItems.forEach(function (item) {
        const active = item.dataset.view === view;
        item.classList.toggle("active", active);
        item.setAttribute("aria-selected", String(active));
        item.tabIndex = active ? 0 : -1;
    });

    refs.panels.forEach(function (panel) {
        panel.hidden = panel.dataset.panel !== view;
    });

    const meta = VIEW_META[view];
    setText("view-eyebrow", meta[0]);
    setText("view-title", meta[1]);

    if (updateHash) {
        window.history.replaceState(null, "", "#" + view);
    }
}

function renderOverview(data) {
    const root = document.getElementById("overview-content");
    const tls = isObject(data.tls) ? data.tls : {};
    const http2 = isObject(data.http2) ? data.http2 : {};
    const http3 = isObject(data.http3) ? data.http3 : {};

    const fingerprintItems = [
        fingerprintItem("JA4", tls.ja4, tls.ja4_r),
        fingerprintItem("JA3", tls.ja3_hash, tls.ja3),
        fingerprintItem(
            "Akamai HTTP/2",
            http2.akamai_fingerprint_hash,
            http2.akamai_fingerprint
        ),
        fingerprintItem(
            "HTTP/3",
            http3.h3_text_hash,
            http3.h3_text
        ),
    ].filter(function (item) {
        return item.primary || item.source;
    });

    const request = createSection("Connection", "Request details", "");
    request.append(
        createDetailGrid([
            ["Remote address", valueOr(data.address, UNAVAILABLE_LABEL), true],
            ["Method", valueOr(data.method, UNAVAILABLE_LABEL), true],
            ["HTTP version", valueOr(data.http_version, UNAVAILABLE_LABEL), true],
            [
                "Negotiated TLS",
                valueOr(tls.tls_version_negotiated, UNAVAILABLE_LABEL),
                true,
            ],
            ["Client TLS record", valueOr(tls.tls_version, UNAVAILABLE_LABEL), true],
            ["ALPN", extractAlpn(tls).join(", ") || "Not offered", true],
            [
                "Supported TLS",
                extractSupportedVersions(tls).join(", ") || UNAVAILABLE_LABEL,
                true,
            ],
            ["User-Agent", valueOr(data.user_agent, "Not provided"), false],
        ])
    );

    const sections = [];
    if (fingerprintItems.length > 0) {
        sections.push(createFingerprintSection("Client identity", fingerprintItems));
    }
    sections.push(request, createServerRoutesSection());
    root.replaceChildren(...sections);
}

function createServerRoutesSection() {
    const section = createSection(
        "API",
        "Server routes",
        SERVER_ROUTES.length + " routes"
    );
    const rows = SERVER_ROUTES.map(function (route) {
        let path;
        if (route.method === "WS") {
            path = create("code", "font-monospace fw-semibold", route.path);
        } else {
            path = create("a", "font-monospace fw-semibold", route.path);
            path.href = route.path;
            path.target = "_blank";
            path.rel = "noreferrer";
        }

        return {
            cells: [
                create("code", "badge font-monospace route-method", route.method),
                path,
                route.purpose,
                route.availability,
            ],
        };
    });
    section.append(
        createTable(["Method", "Path", "Purpose", "Availability"], rows, [])
    );
    return section;
}

function fingerprintItem(label, primary, source) {
    return {
        label: label,
        primary: primary,
        source: source,
    };
}

function createFingerprintSection(title, items) {
    const section = createSection("Fingerprints", title, "");
    const grid = create("div", "row g-3");
    let columnClass = "col-12 col-xl-6";

    if (items.length >= 4) {
        columnClass = "col-12 col-lg-6";
    } else if (items.length === 3) {
        columnClass = "col-12 col-md-6 col-xl-4";
    } else if (items.length === 2) {
        columnClass = "col-12 col-md-6";
    }

    items.forEach(function (item) {
        const column = create("div", columnClass);
        column.append(createFingerprintCard(item));
        grid.append(column);
    });

    section.append(grid);
    return section;
}

function createFingerprintCard(item) {
    const primary = item.primary;
    const source = item.source;
    const card = create("article", "card fingerprint-card");
    const body = create("div", "card-body p-3 fingerprint-card-body");
    const header = create("div", "d-flex align-items-center gap-2 mb-2");
    header.append(
        create(
            "h3",
            "badge mb-0 fingerprint-label",
            item.label
        )
    );

    if (primary) {
        const actions = create("div", "ms-auto flex-shrink-0");
        actions.append(
            createCopyButton(String(primary), "Copy " + item.label + " fingerprint")
        );
        header.append(actions);
    } else {
        card.classList.add("opacity-50");
    }

    const value = create("div", "fingerprint-value-box");
    value.append(createFingerprintValue(item.label, valueOr(primary, "Not available")));
    body.append(header, value);

    if (source && source !== primary) {
        const sourceBlock = create("div", "mt-3 pt-3 border-top fingerprint-source");
        sourceBlock.append(
            create(
                "div",
                "text-secondary small fw-medium",
                "Source string"
            )
        );
        const row = create("div", "d-flex align-items-start gap-2 mt-2");
        row.append(
            create(
                "code",
                "font-monospace small text-break flex-fill user-select-all",
                String(source)
            ),
            createCopyButton(
                String(source),
                "Copy " + item.label + " source string"
            )
        );
        sourceBlock.append(row);
        body.append(sourceBlock);
    }

    card.append(body);
    return card;
}

function createFingerprintValue(label, value) {
    const text = String(value);
    const chunks = label === "JA4" ? text.split("_") : [];

    if (chunks.length === 3) {
        const grouped = create(
            "div",
            "d-flex flex-wrap align-items-center gap-1 font-monospace fw-semibold user-select-all"
        );
        chunks.forEach(function (chunk, index) {
            if (index > 0) {
                grouped.append(create("span", "text-secondary", "_"));
            }
            grouped.append(create("code", "text-body text-break", chunk));
        });
        return grouped;
    }

    return create(
        "code",
        "d-block font-monospace fw-semibold text-body text-break user-select-all",
        text
    );
}

function renderTls(tls) {
    const root = document.getElementById("tls-content");
    if (!isObject(tls)) {
        root.replaceChildren(createEmptyState("TLS data is unavailable", "shield-off"));
        return;
    }

    root.replaceChildren(...createTlsSections(tls));
}

function createTlsSections(tls) {
    const handshake = createSection("TLS", "Handshake", "");
    handshake.append(
        createDetailGrid([
            ["Record version", valueOr(tls.tls_version, UNAVAILABLE_LABEL), true],
            [
                "Negotiated version",
                valueOr(tls.tls_version_negotiated, UNAVAILABLE_LABEL),
                true,
            ],
            ["Client random", valueOr(tls.client_random, UNAVAILABLE_LABEL), false],
            ["Session ID", valueOr(tls.session_id, "Not provided"), false],
            [
                "Compression",
                Array.isArray(tls.compression_algorithms)
                    ? tls.compression_algorithms.join(", ")
                    : UNAVAILABLE_LABEL,
                true,
            ],
            ["ALPN", extractAlpn(tls).join(", ") || "Not offered", true],
        ])
    );

    const fingerprints = createFingerprintSection("TLS signatures", [
        fingerprintItem("JA4", tls.ja4, tls.ja4_r),
        fingerprintItem("JA3", tls.ja3_hash, tls.ja3),
    ]);

    const suites = Array.isArray(tls.cipher_suites) ? tls.cipher_suites : [];
    const cipherSection = createSection(
        "Client hello",
        "Cipher suites",
        suites.length + " entries"
    );
    if (suites.length === 0) {
        cipherSection.append(createEmptyState("No cipher suites were captured", "list-x"));
    } else {
        const rows = suites.map(function (suite, index) {
            const id = isObject(suite) ? suite.id : null;
            const name = isObject(suite) ? suite.name : String(suite);
            return {
                className: String(name).toUpperCase() === "GREASE" ? "table-active" : "",
                cells: [
                    String(index + 1),
                    id === null || id === undefined ? "-" : String(id),
                    id === null || id === undefined ? "-" : formatHex(id),
                    valueOr(name, "Other"),
                ],
            };
        });
        cipherSection.append(
            createTable(["#", "ID", "Hex", "Name"], rows, ["text-secondary text-center", "", "", ""])
        );
    }

    const extensions = Array.isArray(tls.extensions) ? tls.extensions : [];
    const extensionSection = createSection(
        "Client hello",
        "Extensions",
        extensions.length + " entries"
    );
    if (extensions.length === 0) {
        extensionSection.append(createEmptyState("No TLS extensions were captured", "list-x"));
    } else {
        extensionSection.append(renderProtocolItems(extensions, "extension"));
    }

    return [handshake, fingerprints, cipherSection, extensionSection];
}

function renderProtocolItems(items, kind) {
    const list = create("div", "list-group mb-3 protocol-list");

    items.forEach(function (item, index) {
        const normalized = kind === "extension"
            ? normalizeExtension(item)
            : {
                name: valueOr(item.frame_type, "Unknown"),
                payload: item,
                id: null,
            };
        const details = create("details", "list-group-item p-0 protocol-item");
        const summary = create(
            "summary",
            "d-flex align-items-center gap-2 p-3 cursor-pointer protocol-summary"
        );
        summary.append(
            create("span", "badge bg-secondary-lt text-secondary", padIndex(index + 1)),
            create("span", "fw-semibold text-break", normalized.name)
        );

        const meta = create("span", "ms-auto text-secondary font-monospace small text-end");
        if (normalized.id !== null && normalized.id !== undefined) {
            meta.textContent = "ID " + normalized.id + " / " + formatHex(normalized.id);
        } else if (kind === "frame") {
            meta.textContent =
                "stream " + valueOr(item.stream_id, "-") +
                " / " + valueOr(item.length, 0) + " bytes";
        }
        summary.append(meta);
        details.append(summary);

        const body = create("div", "border-top bg-body-tertiary p-3 protocol-body");
        const payload = kind === "extension"
            ? withoutKey(normalized.payload, "value")
            : withoutKeys(item, ["frame_type", "stream_id", "length"]);
        body.append(createValueNode(payload));
        details.append(body);
        list.append(details);
    });

    return list;
}

function normalizeExtension(extension) {
    if (!isObject(extension)) {
        return {
            name: "unknown",
            payload: extension,
            id: null,
        };
    }

    const name = Object.keys(extension)[0] || "unknown";
    const payload = extension[name];

    return {
        name: name,
        payload: payload,
        id: isObject(payload) && payload.value !== undefined ? payload.value : null,
    };
}

function extractSupportedVersions(tls) {
    const extension = findExtension(tls, "supported_versions");
    if (!extension || !isObject(extension.data)) {
        return [];
    }

    const versions = extension.data.versions;
    if (!Array.isArray(versions)) {
        return [];
    }

    return versions.map(function (version) {
        return isObject(version) ? valueOr(version.name, version.id) : String(version);
    });
}

function extractAlpn(tls) {
    const extension = findExtension(tls, "application_layer_protocol_negotiation");
    return extension && Array.isArray(extension.data) ? extension.data.map(String) : [];
}

function findExtension(tls, name) {
    if (!tls || !Array.isArray(tls.extensions)) {
        return null;
    }

    for (const extension of tls.extensions) {
        if (isObject(extension) && Object.prototype.hasOwnProperty.call(extension, name)) {
            return extension[name];
        }
    }

    return null;
}

function renderHttp(data) {
    const root = document.getElementById("http-content");
    const headers = getRequestHeaders(data);
    const source = getHeaderSource(data);

    const request = createSection("Request", "Request line", source);
    request.append(
        createDetailGrid([
            ["Method", valueOr(data.method, UNAVAILABLE_LABEL), true],
            ["HTTP version", valueOr(data.http_version, UNAVAILABLE_LABEL), true],
            ["Header source", source || UNAVAILABLE_LABEL, true],
            ["User-Agent", valueOr(data.user_agent, "Not provided"), false],
        ])
    );

    const headerSection = createSection(
        source || "HTTP",
        "Header order",
        headers.length + " entries"
    );
    if (headers.length === 0) {
        headerSection.append(createEmptyState("No HTTP headers were captured", "rows-3"));
    } else {
        headerSection.append(renderHeaderTable(headers));
    }

    root.replaceChildren(request, headerSection);
}

function getHeaderSource(data) {
    if (Array.isArray(data.http1)) {
        return "HTTP/1";
    }

    if (isObject(data.http1) && Array.isArray(data.http1.headers)) {
        return "HTTP/1";
    }

    if (getHttp3Headers(data.http3).length > 0) {
        return "HTTP/3";
    }

    if (getFrames(data.http2).some(function (frame) {
        return frame.frame_type === "Headers" && Array.isArray(frame.headers);
    })) {
        return "HTTP/2";
    }

    return "";
}

function getRequestHeaders(data) {
    if (Array.isArray(data.http1)) {
        return normalizeHeaders(data.http1);
    }

    if (isObject(data.http1) && Array.isArray(data.http1.headers)) {
        return normalizeHeaders(data.http1.headers);
    }

    const http3Headers = getHttp3Headers(data.http3);
    if (http3Headers.length > 0) {
        return normalizeHeaders(http3Headers);
    }

    const frames = getFrames(data.http2);
    for (let index = frames.length - 1; index >= 0; index -= 1) {
        const frame = frames[index];
        if (frame.frame_type === "Headers" && Array.isArray(frame.headers)) {
            return normalizeHeaders(frame.headers);
        }
    }

    return [];
}

function normalizeHeaders(headers) {
    return headers.map(function (header) {
        if (isObject(header)) {
            return {
                name: valueOr(header.name, ""),
                value: valueOr(header.value, ""),
            };
        }

        const text = String(header);
        const separator = text.startsWith(":") ? text.indexOf(":", 1) : text.indexOf(":");
        if (separator < 0) {
            return {
                name: "",
                value: text,
            };
        }

        return {
            name: text.slice(0, separator),
            value: text.slice(separator + 1).trim(),
        };
    });
}

function renderHeaderTable(headers) {
    const rows = headers.map(function (header, index) {
        const name = valueOr(header.name, "");
        return {
            className: name.startsWith(":") ? "table-active" : "",
            cells: [
                String(index + 1),
                create(
                    "code",
                    "font-monospace fw-semibold text-body text-break",
                    name || "(unnamed)"
                ),
                createValueNode(valueOr(header.value, "")),
            ],
        };
    });

    return createTable(
        ["#", "Name", "Value"],
        rows,
        ["text-secondary text-center", "", ""]
    );
}

function renderHttp2(http2) {
    const root = document.getElementById("h2-content");
    if (!isObject(http2)) {
        root.replaceChildren(createEmptyState("HTTP/2 data is unavailable", "network"));
        return;
    }

    const fingerprint = createFingerprintSection("HTTP/2 fingerprint", [
        fingerprintItem(
            "Akamai HTTP/2",
            http2.akamai_fingerprint_hash,
            http2.akamai_fingerprint
        ),
    ]);

    const frames = getFrames(http2);
    const frameSection = createSection(
        "Client connection",
        "Sent frames",
        frames.length + " entries"
    );
    if (frames.length === 0) {
        frameSection.append(createEmptyState("No HTTP/2 frames were captured", "network"));
    } else {
        frameSection.append(renderFrames(frames));
    }

    root.replaceChildren(
        fingerprint,
        renderPriorityProbeSection("http2"),
        renderChromiumResourcePrioritySection(),
        frameSection
    );
}

function renderHttp3(http3, tls) {
    const root = document.getElementById("h3-content");
    if (!isObject(http3)) {
        root.replaceChildren(createEmptyState("HTTP/3 data is unavailable", "radio-tower"));
        return;
    }

    const settings = getHttp3Settings(http3);
    const headers = getHttp3Headers(http3);
    const transportParameters = getHttp3TransportParameters(tls);
    const fingerprint = createFingerprintSection("HTTP/3 fingerprint", [
        fingerprintItem(
            "HTTP/3",
            http3.h3_text_hash,
            http3.h3_text
        ),
    ]);

    const settingsSection = createSection(
        "Control stream",
        "SETTINGS",
        http3FrameMeta(http3.settings, settings.length)
    );
    if (settings.length === 0) {
        settingsSection.append(
            createEmptyState("No HTTP/3 settings were captured", "sliders-horizontal")
        );
    } else {
        settingsSection.append(createValueNode(settings));
    }

    const headersSection = createSection(
        "Request stream",
        "QPACK headers",
        http3FrameMeta(http3.headers, headers.length)
    );
    if (headers.length === 0) {
        headersSection.append(
            createEmptyState("No HTTP/3 headers were captured", "rows-3")
        );
    } else {
        headersSection.append(renderHeaderTable(normalizeHeaders(headers)));
    }

    const transportSection = createSection(
        "QUIC handshake",
        "Transport parameters",
        transportParameters.length + " entries"
    );
    if (transportParameters.length === 0) {
        transportSection.append(
            createEmptyState("No QUIC transport parameters were captured", "radio-tower")
        );
    } else {
        transportSection.append(createValueNode(transportParameters));
    }

    root.replaceChildren(
        fingerprint,
        renderPriorityProbeSection("http3"),
        settingsSection,
        headersSection,
        transportSection
    );
}

function getHttp3Settings(http3) {
    return isObject(http3)
        && isObject(http3.settings)
        && Array.isArray(http3.settings.settings)
        ? http3.settings.settings
        : [];
}

function getHttp3Headers(http3) {
    return isObject(http3)
        && isObject(http3.headers)
        && Array.isArray(http3.headers.headers)
        ? http3.headers.headers
        : [];
}

function getHttp3TransportParameters(tls) {
    if (!isObject(tls) || !Array.isArray(tls.extensions)) {
        return [];
    }

    for (const extension of tls.extensions) {
        if (!isObject(extension)) {
            continue;
        }

        const payload = extension.quic_transport_parameters;
        if (isObject(payload) && Array.isArray(payload.data)) {
            return payload.data;
        }
    }

    return [];
}

function getHttp3FrameCount(http3) {
    if (!isObject(http3)) {
        return 0;
    }

    return Number(isObject(http3.settings)) + Number(isObject(http3.headers));
}

function http3FrameMeta(frame, entryCount) {
    const parts = [entryCount + " entries"];
    if (isObject(frame) && Number.isInteger(frame.length)) {
        parts.push(frame.length + " bytes");
    }
    return parts.join(" / ");
}

function renderPriorityProbeSection(protocol) {
    const isHttp3 = protocol === "http3";
    const section = createSection(
        "Request scenarios",
        isHttp3 ? "Request priority" : "HEADERS priority",
        isHttp3 ? "RFC 9218 field value" : "effective 1-256 / wire 0-255"
    );
    const toolbar = create(
        "div",
        "d-flex flex-column flex-lg-row align-items-lg-center justify-content-between gap-3 mb-3"
    );
    const actions = create("div", "d-flex flex-wrap gap-2");
    actions.setAttribute("role", "group");
    actions.setAttribute(
        "aria-label",
        isHttp3 ? "HTTP/3 priority probes" : "HTTP/2 priority probes"
    );

    const probeRunning = state.priorityProbeRunning.size > 0;
    PRIORITY_PROBES.forEach(function (scenario) {
        const probeId = protocol + ":" + scenario.id;
        const button = create("button", "btn btn-outline-secondary btn-sm");
        button.type = "button";
        button.title = "Capture " + scenario.label.toLowerCase() + " priority";
        button.setAttribute("aria-label", button.title);

        const running = state.priorityProbeRunning.has(probeId);
        button.disabled = probeRunning;
        if (running) {
            button.setAttribute("aria-busy", "true");
            button.append(create("span", "spinner-border spinner-border-sm"));
        } else {
            const icon = document.createElement("i");
            icon.className = "icon";
            icon.dataset.lucide = scenario.icon;
            icon.setAttribute("aria-hidden", "true");
            button.append(icon);
        }

        button.append(create("span", "", scenario.label));
        button.addEventListener("click", function () {
            runPriorityProbe(protocol, scenario);
        });
        actions.append(button);
    });

    toolbar.append(
        actions,
        create(
            "span",
            "text-secondary small",
            isHttp3 ? "Observed QPACK field section" : "Observed HEADERS payload"
        )
    );
    section.append(toolbar);

    const records = orderedPriorityProbeRecords(protocol);
    if (records.length === 0) {
        section.append(create("p", "text-secondary mb-3", "No priority samples"));
    } else {
        section.append(renderPriorityProbeTable(protocol, records));
    }

    return section;
}

function orderedPriorityProbeRecords(protocol) {
    const probes = state.priorityProbes[protocol];
    const records = [];
    const current = probes.get("current");
    if (current) {
        records.push(current);
    }

    PRIORITY_PROBES.forEach(function (scenario) {
        const record = probes.get(scenario.id);
        if (record) {
            records.push(record);
        }
    });

    return records;
}

function renderPriorityProbeTable(protocol, records) {
    const isHttp3 = protocol === "http3";
    const headers = isHttp3
        ? ["Scenario", "Request context", "RFC 9218 priority"]
        : [
            "Scenario",
            "Request context",
            "RFC 9218 priority",
            "Blink / net",
            "Weight",
            "Wire",
            "Depends",
            "Exclusive",
            "Stream",
        ];
    const rows = records.map(function (record) {
        if (record.status !== "ok") {
            const statusClass = record.status === "running"
                ? "badge bg-secondary-lt text-secondary text-wrap text-start"
                : "badge bg-red-lt text-red text-wrap text-start";
            const status = create(
                "span",
                statusClass,
                record.status === "running" ? "Capturing" : record.error
            );
            const cells = [record.label, record.context, status];
            while (cells.length < headers.length) {
                cells.push("-");
            }
            return {
                cells: cells,
            };
        }

        const observation = record.observation;
        if (isHttp3) {
            return {
                cells: [
                    create("span", "fw-semibold", record.label),
                    monoPriorityValue(observation.requestContext),
                    monoPriorityValue(observation.priorityHeader || "-"),
                ],
            };
        }

        return {
            cells: [
                create("span", "fw-semibold", record.label),
                monoPriorityValue(observation.requestContext),
                monoPriorityValue(observation.priorityHeader || "-"),
                observation.chromiumPriority,
                monoPriorityValue(observation.weight),
                monoPriorityValue(observation.wireWeight),
                monoPriorityValue(observation.dependsOn),
                monoPriorityValue(observation.exclusive),
                monoPriorityValue(observation.streamId),
            ],
        };
    });

    return createTable(headers, rows, headers.map(function () {
        return "";
    }));
}

function renderChromiumResourcePrioritySection() {
    const section = createSection(
        "Chromium baseline",
        "Resource priorities",
        "before hints and loading heuristics"
    );
    const rows = CHROMIUM_RESOURCE_DEFAULTS.map(function (entry) {
        return {
            cells: [
                entry.resource,
                monoPriorityValue(entry.blink),
                monoPriorityValue(entry.net),
                monoPriorityValue(entry.weight),
                monoPriorityValue(entry.weight - 1),
            ],
        };
    });
    const table = createTable(
        ["Resource type", "Blink", "net", "Weight", "Wire"],
        rows,
        ["", "", "", "", ""]
    );
    section.append(table);
    return section;
}

function monoPriorityValue(value) {
    const text = value === null || value === undefined ? "-" : String(value);
    return create("code", "font-monospace small text-break", text);
}

async function runPriorityProbe(protocol, scenario) {
    if (state.priorityProbeRunning.size > 0) {
        return;
    }

    const probes = state.priorityProbes[protocol];
    const probeId = protocol + ":" + scenario.id;
    const path = createPriorityProbePath(protocol, scenario.id);
    state.priorityProbeRunning.add(probeId);
    probes.set(scenario.id, {
        label: scenario.label,
        context: scenario.context,
        status: "running",
    });
    refreshPriorityProbeViews();

    try {
        const data = scenario.kind === "navigation"
            ? await captureNavigationPriorityProbe(path)
            : await captureFetchPriorityProbe(path, scenario.priority);
        probes.set(scenario.id, {
            label: scenario.label,
            context: scenario.context,
            status: "ok",
            observation: extractPriorityObservation(protocol, data, path),
        });
    } catch (error) {
        const message = error instanceof Error ? error.message : "Priority probe failed";
        probes.set(scenario.id, {
            label: scenario.label,
            context: scenario.context,
            status: "error",
            error: message,
        });
        showToast(message);
    } finally {
        state.priorityProbeRunning.delete(probeId);
        refreshPriorityProbeViews();
    }
}

function createPriorityProbePath(protocol, id) {
    const query = new URLSearchParams();
    query.set("priority_protocol", protocol);
    query.set("priority_probe", id);
    query.set("nonce", Date.now().toString(36));
    return "/api/all?" + query.toString();
}

async function captureFetchPriorityProbe(path, priority) {
    // Give the previous probe time to finish before the browser schedules another request.
    await new Promise((resolve) => window.setTimeout(resolve, PRIORITY_PROBE_SETTLE_MS));

    const controller = new AbortController();
    const timeout = window.setTimeout(function () {
        controller.abort();
    }, PRIORITY_PROBE_TIMEOUT_MS);

    try {
        const response = await fetch(path, {
            cache: "no-store",
            credentials: "same-origin",
            priority: priority,
            signal: controller.signal,
        });

        if (!response.ok) {
            throw new Error("The probe returned HTTP " + response.status + ".");
        }

        return await response.json();
    } catch (error) {
        if (error && error.name === "AbortError") {
            throw new Error("The fetch priority probe timed out.");
        }
        throw error;
    } finally {
        window.clearTimeout(timeout);
    }
}

function captureNavigationPriorityProbe(path) {
    const popup = window.open(
        "about:blank",
        "_blank",
        "popup,width=680,height=720"
    );
    if (!popup) {
        return Promise.reject(new Error("The navigation probe popup was blocked."));
    }

    return new Promise(function (resolve, reject) {
        let interval;
        let navigation;
        let timeout;

        function finish(error, data) {
            window.clearInterval(interval);
            window.clearTimeout(navigation);
            window.clearTimeout(timeout);
            if (!popup.closed) {
                popup.close();
            }

            if (error) {
                reject(error);
            } else {
                resolve(data);
            }
        }

        navigation = window.setTimeout(function () {
            try {
                popup.location.replace(path);
            } catch (error) {
                finish(error);
            }
        }, PRIORITY_PROBE_SETTLE_MS);

        interval = window.setInterval(function () {
            if (popup.closed) {
                finish(new Error("The navigation probe was closed."));
                return;
            }

            try {
                const currentPath = popup.location.pathname + popup.location.search;
                if (currentPath !== path || popup.document.readyState !== "complete") {
                    return;
                }

                finish(null, parsePriorityProbeDocument(popup.document));
            } catch (_) {
                // The response document may still be loading or formatting JSON.
            }
        }, 80);

        timeout = window.setTimeout(function () {
            finish(new Error("The navigation priority probe timed out."));
        }, PRIORITY_PROBE_TIMEOUT_MS);
    });
}

function parsePriorityProbeDocument(documentNode) {
    const text = documentNode.body ? documentNode.body.textContent.trim() : "";
    const start = text.indexOf("{");
    const end = text.lastIndexOf("}");
    if (start < 0 || end < start) {
        throw new SyntaxError("The navigation response is not ready.");
    }

    return JSON.parse(text.slice(start, end + 1));
}

function recordCurrentPriorityProbes(data) {
    recordCurrentPriorityProbe("http2", data);
    recordCurrentPriorityProbe("http3", data);
}

function recordCurrentPriorityProbe(protocol, data) {
    const probes = state.priorityProbes[protocol];
    try {
        probes.set("current", {
            label: "Current fetch",
            context: "fetch(auto)",
            status: "ok",
            observation: extractPriorityObservation(protocol, data, "/api/all"),
        });
    } catch (_) {
        probes.delete("current");
    }
}

function extractPriorityObservation(protocol, data, path) {
    return protocol === "http3"
        ? extractHttp3PriorityObservation(data, path)
        : extractHttp2PriorityObservation(data, path);
}

function extractHttp2PriorityObservation(data, path) {
    const frames = getFrames(data.http2);
    let matchedFrame;
    let matchedHeaders;

    for (let index = frames.length - 1; index >= 0; index -= 1) {
        const frame = frames[index];
        if (frame.frame_type !== "Headers" || !Array.isArray(frame.headers)) {
            continue;
        }

        const headers = normalizeHeaders(frame.headers);
        if (priorityHeaderValue(headers, ":path") === path) {
            matchedFrame = frame;
            matchedHeaders = headers;
            break;
        }
    }

    if (!matchedFrame) {
        throw new Error("The matching HEADERS frame was not captured.");
    }

    const dependency = isObject(matchedFrame.priority) ? matchedFrame.priority : null;
    let weight = null;
    if (dependency) {
        weight = Number(dependency.weight);
        if (!Number.isInteger(weight) || weight < 1 || weight > 256) {
            throw new Error("The captured HTTP/2 weight is invalid.");
        }
    }

    // RFC 7540, Section 5.3.2 stores effective weight minus one on the wire:
    // <https://www.rfc-editor.org/rfc/rfc7540.html#section-5.3.2>
    const wireWeight = weight === null ? null : weight - 1;
    return {
        requestContext: priorityRequestContext(matchedHeaders),
        priorityHeader: priorityHeaderValue(matchedHeaders, "priority"),
        chromiumPriority: weight === null
            ? "Not sent"
            : valueOr(CHROMIUM_PRIORITY_BY_WEIGHT.get(weight), "Other"),
        weight: weight,
        wireWeight: wireWeight,
        dependsOn: dependency ? dependency.depends_on : null,
        exclusive: dependency ? dependency.exclusive : null,
        streamId: matchedFrame.stream_id,
    };
}

function extractHttp3PriorityObservation(data, path) {
    const headers = normalizeHeaders(getHttp3Headers(data.http3));
    if (priorityHeaderValue(headers, ":path") !== path) {
        throw new Error("The matching HTTP/3 HEADERS frame was not captured.");
    }

    // HTTP/3 carries the initial priority signal in the protocol-independent Priority field
    // defined by RFC 9218, Section 5:
    // <https://www.rfc-editor.org/rfc/rfc9218.html#section-5>
    return {
        requestContext: priorityRequestContext(headers),
        priorityHeader: priorityHeaderValue(headers, "priority"),
    };
}

function priorityRequestContext(headers) {
    const fetchMode = priorityHeaderValue(headers, "sec-fetch-mode") || "-";
    const fetchDestination =
        priorityHeaderValue(headers, "sec-fetch-dest") || "empty";
    return fetchMode + " / " + fetchDestination;
}

function priorityHeaderValue(headers, name) {
    const normalizedName = name.toLowerCase();
    const header = headers.find(function (candidate) {
        return String(candidate.name).toLowerCase() === normalizedName;
    });
    return header ? String(header.value) : "";
}

function refreshPriorityProbeViews() {
    if (!state.data) {
        return;
    }

    renderHttp2(state.data.http2);
    renderHttp3(state.data.http3, state.data.tls);
    paintIcons();
}

function renderFrames(frames) {
    const list = create("div", "list-group mb-3 protocol-list");

    frames.forEach(function (frame, index) {
        const details = create("details", "list-group-item p-0 protocol-item");
        const summary = create(
            "summary",
            "d-flex align-items-center gap-2 p-3 cursor-pointer protocol-summary"
        );
        summary.append(
            create("span", "badge bg-secondary-lt text-secondary", padIndex(index + 1)),
            create("span", "fw-semibold text-break", valueOr(frame.frame_type, "Unknown frame"))
        );

        const meta = create("span", "ms-auto text-secondary font-monospace small text-end");
        const metaParts = [
            "stream " + valueOr(frame.stream_id, "-"),
            valueOr(frame.length, 0) + " bytes",
        ];
        const flags = summarizeFlags(frame.flags);
        if (flags) {
            metaParts.push(flags);
        }
        meta.textContent = metaParts.join(" / ");
        summary.append(meta);
        details.append(summary);

        const body = create("div", "border-top bg-body-tertiary p-3 protocol-body");
        body.append(
            createValueNode(
                withoutKeys(frame, ["frame_type", "stream_id", "length"])
            )
        );
        details.append(body);
        list.append(details);
    });

    return list;
}

function summarizeFlags(flags) {
    if (!isObject(flags)) {
        return "";
    }

    if (Array.isArray(flags.values) && flags.values.length > 0) {
        return flags.values.map(function (flag) {
            return isObject(flag) ? valueOr(flag.name, flag.id) : String(flag);
        }).join(", ");
    }

    if (flags.raw !== undefined) {
        return "flags " + flags.raw;
    }

    return "";
}

function getFrames(http2) {
    return isObject(http2) && Array.isArray(http2.sent_frames)
        ? http2.sent_frames
        : [];
}

function renderTcp(tcp) {
    const root = document.getElementById("tcp-content");
    const analysis = isObject(tcp) ? tcp : {};
    const fingerprint = isObject(analysis.fingerprint) ? analysis.fingerprint : null;
    const packets = Array.isArray(analysis.packets) ? analysis.packets : [];
    const content = [];

    if (fingerprint) {
        const ja4t = isObject(fingerprint.ja4t) ? fingerprint.ja4t : {};
        const satori = isObject(fingerprint.satori) ? fingerprint.satori : {};
        content.push(
            createFingerprintSection("TCP client", [
                fingerprintItem("JA4T", ja4t.fingerprint, null),
                fingerprintItem("Satori", satori.fingerprint, null),
            ])
        );

        const network = isObject(fingerprint.network) ? fingerprint.network : {};
        const link = isObject(fingerprint.link) ? fingerprint.link : {};
        const networkSection = createSection(
            "Passive estimate",
            "Network characteristics",
            "Initial SYN"
        );
        networkSection.append(
            createDetailGrid([
                ["Observed hop limit", valueOr(network.observed_hop_limit, UNAVAILABLE_LABEL), true],
                ["Estimated initial hop limit", valueOr(network.initial_hop_limit, UNAVAILABLE_LABEL), true],
                ["Estimated distance", formatHopCount(network.distance_hops), true],
                ["Estimated MTU", formatMtu(link.mtu), true],
                ["Probable link", valueOr(link.kind, UNAVAILABLE_LABEL), false],
                ["Satori quirks", valueOr(satori.quirks, "None"), true],
            ])
        );
        content.push(networkSection);
    }

    if (packets.length === 0) {
        content.push(
            createEmptyState(
                "No TCP packets were captured",
                "waypoints",
                "Packet capture is available when the Linux server enables it."
            )
        );
        root.replaceChildren(...content);
        return;
    }

    const packetSection = createSection(
        "Captured connection",
        "TCP packets",
        packets.length + " entries"
    );
    packetSection.append(renderPackets(packets));
    content.push(packetSection);
    root.replaceChildren(...content);
}

function formatHopCount(value) {
    if (!hasNumericValue(value)) {
        return UNAVAILABLE_LABEL;
    }

    const count = Number(value);
    return count >= 0 ? count + (count === 1 ? " hop" : " hops") : UNAVAILABLE_LABEL;
}

function formatMtu(value) {
    if (!hasNumericValue(value)) {
        return UNAVAILABLE_LABEL;
    }

    const mtu = Number(value);
    return mtu > 0 ? mtu + " bytes" : UNAVAILABLE_LABEL;
}

function websocketUrl() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    return protocol + "//" + window.location.host + WEBSOCKET_PATH;
}

function toggleWebSocket() {
    if (state.websocket.prepareController) {
        cancelWebSocketPreparation();
        return;
    }

    const socket = state.websocket.socket;
    if (socket &&
        [WebSocket.CONNECTING, WebSocket.OPEN].includes(socket.readyState)) {
        disconnectWebSocket();
        return;
    }

    if (!socket || socket.readyState === WebSocket.CLOSED) {
        void connectWebSocket();
    }
}

async function connectWebSocket() {
    const inspector = state.websocket;
    const current = inspector.socket;
    if (inspector.prepareController ||
        (current && current.readyState !== WebSocket.CLOSED)) {
        return;
    }

    inspector.address = "";
    inspector.closeRequested = false;
    inspector.error = "";
    inspector.headers = [];
    inspector.httpVersion = "";
    inspector.maxMessageSize = WEBSOCKET_DEFAULT_MAX_MESSAGE_SIZE;
    inspector.messages = [];
    inspector.receivedConnectionInfo = false;
    inspector.socket = null;
    inspector.tls = null;

    const controller = new AbortController();
    inspector.prepareController = controller;
    inspector.status = "preparing";
    renderWebSocket();
    appendWebSocketSystemMessage(
        "Preparing " + WEBSOCKET_TRANSPORT_LABELS[inspector.transport]
    );

    try {
        await prepareWebSocketTransport(inspector.transport, controller.signal);
    } catch (error) {
        if (inspector.prepareController !== controller) {
            return;
        }

        inspector.prepareController = null;
        inspector.error = error instanceof Error
            ? error.message
            : "Connection preparation failed";
        inspector.status = "error";
        renderWebSocketState();
        renderWebSocketComposer();
        appendWebSocketSystemMessage(inspector.error);
        return;
    }

    if (inspector.prepareController !== controller || controller.signal.aborted) {
        return;
    }
    inspector.prepareController = null;
    inspector.status = "connecting";

    let socket;
    try {
        socket = new WebSocket(websocketUrl());
    } catch (error) {
        inspector.error = error instanceof Error ? error.message : "Connection failed";
        inspector.status = "error";
        renderWebSocketState();
        renderWebSocketComposer();
        appendWebSocketSystemMessage("Connection failed");
        return;
    }

    inspector.socket = socket;
    socket.binaryType = "arraybuffer";
    renderWebSocketState();
    renderWebSocketComposer();

    socket.addEventListener("open", function () {
        if (inspector.socket !== socket) {
            return;
        }

        inspector.status = "analyzing";
        renderWebSocketState();
        renderWebSocketComposer();
        appendWebSocketSystemMessage("Connection opened");
    });
    socket.addEventListener("message", function (event) {
        void receiveWebSocketMessage(socket, event);
    });
    socket.addEventListener("error", function () {
        if (inspector.socket !== socket) {
            return;
        }
        if (inspector.closeRequested) {
            return;
        }

        inspector.error = "Connection failed";
        inspector.status = "error";
        renderWebSocketState();
        renderWebSocketComposer();
        appendWebSocketSystemMessage("Connection error");
    });
    socket.addEventListener("close", function (event) {
        if (inspector.socket !== socket) {
            return;
        }

        const closedNormally = inspector.closeRequested ||
            (event.wasClean && [1000, 1001].includes(event.code));
        inspector.socket = null;
        inspector.closeRequested = false;
        inspector.status = closedNormally ? "closed" : "error";
        inspector.error = closedNormally
            ? ""
            : event.reason || "Connection closed unexpectedly";
        renderWebSocketState();
        renderWebSocketComposer();

        const code = event.code ? " (" + event.code + ")" : "";
        const reason = event.reason ? ": " + event.reason : "";
        appendWebSocketSystemMessage("Connection closed" + code + reason);
    });
}

async function prepareWebSocketTransport(transport, signal) {
    if (!WEBSOCKET_PREPARE_PATHS[transport]) {
        throw new Error("Unknown WebSocket HTTP version");
    }

    if (transport === "http2") {
        // HTTP/2 can carry many streams on one connection. Close a reusable connection first so
        // the next capture belongs to this WebSocket handshake.
        // https://www.rfc-editor.org/rfc/rfc8441#section-1
        await requestWebSocketPreparation("http1", signal);
    }
    await requestWebSocketPreparation(transport, signal);
}

async function requestWebSocketPreparation(transport, signal) {
    const path = WEBSOCKET_PREPARE_PATHS[transport];
    for (let attempt = 0; attempt < 2; attempt += 1) {
        const response = await fetch(path, {
            cache: "no-store",
            signal: signal,
        });
        await response.arrayBuffer();

        if (response.status === WEBSOCKET_PREPARE_RETRY_STATUS && attempt === 0) {
            continue;
        }
        if (response.ok) {
            return;
        }

        const label = WEBSOCKET_TRANSPORT_LABELS[transport];
        throw new Error(
            label + " WebSocket preparation failed (HTTP " + response.status + ")"
        );
    }

    throw new Error("Could not move the WebSocket connection from HTTP/3 to TCP");
}

function cancelWebSocketPreparation() {
    const controller = state.websocket.prepareController;
    if (!controller) {
        return;
    }

    state.websocket.prepareController = null;
    state.websocket.status = "closed";
    controller.abort();
    renderWebSocketState();
    renderWebSocketComposer();
    appendWebSocketSystemMessage("Connection canceled");
}

function disconnectWebSocket() {
    const socket = state.websocket.socket;
    if (!socket ||
        ![WebSocket.CONNECTING, WebSocket.OPEN].includes(socket.readyState)) {
        return;
    }

    state.websocket.closeRequested = true;
    state.websocket.status = "closing";
    renderWebSocketState();
    renderWebSocketComposer();

    try {
        socket.close(1000, "Inspector closed");
    } catch (_) {
        state.websocket.socket = null;
        state.websocket.closeRequested = false;
        state.websocket.status = "closed";
        renderWebSocketState();
        renderWebSocketComposer();
    }
}

function closeWebSocketForUnload() {
    const socket = state.websocket.socket;
    if (!socket || socket.readyState === WebSocket.CLOSED) {
        return;
    }

    try {
        socket.close(1001, "Page closed");
    } catch (_) {
        // The page is already leaving, so no recovery is needed.
    }
}

async function receiveWebSocketMessage(socket, event) {
    if (state.websocket.socket !== socket) {
        return;
    }

    if (typeof event.data === "string") {
        if (receiveWebSocketConnectionInfo(event.data)) {
            return;
        }

        appendWebSocketTextMessage("inbound", event.data);
        return;
    }

    let data = event.data;
    if (data instanceof Blob) {
        data = await data.arrayBuffer();
        if (state.websocket.socket !== socket) {
            return;
        }
    }

    if (data instanceof ArrayBuffer) {
        appendWebSocketBinaryMessage("inbound", new Uint8Array(data));
    }
}

function receiveWebSocketConnectionInfo(value) {
    if (state.websocket.receivedConnectionInfo) {
        return false;
    }

    let event;
    try {
        event = JSON.parse(value);
    } catch (_) {
        return false;
    }

    if (!isObject(event) || event.type !== "connected") {
        return false;
    }

    const maxMessageSize = Number(event.max_message_size);
    state.websocket.address = typeof event.address === "string" ? event.address : "";
    state.websocket.headers = Array.isArray(event.headers)
        ? normalizeHeaders(event.headers)
        : [];
    state.websocket.httpVersion = typeof event.http_version === "string"
        ? event.http_version
        : "";
    state.websocket.maxMessageSize = Number.isSafeInteger(maxMessageSize) &&
        maxMessageSize > 0
        ? maxMessageSize
        : WEBSOCKET_DEFAULT_MAX_MESSAGE_SIZE;
    state.websocket.receivedConnectionInfo = true;
    state.websocket.status = "open";
    state.websocket.tls = isObject(event.tls) ? event.tls : null;
    renderWebSocketState();
    renderWebSocketComposer();
    renderWebSocketAnalysis();
    appendWebSocketSystemMessage(
        state.websocket.httpVersion
            ? "Connected over " + state.websocket.httpVersion
            : "Connection ready"
    );
    return true;
}

function sendWebSocketMessage() {
    const socket = state.websocket.socket;
    if (!socket || socket.readyState !== WebSocket.OPEN) {
        return;
    }

    let payload;
    try {
        payload = createWebSocketPayload();
        socket.send(payload.data);
    } catch (error) {
        showToast(error instanceof Error ? error.message : "Message could not be sent");
        return;
    }

    if (payload.kind === "text") {
        appendWebSocketTextMessage("outbound", payload.data, payload.bytes);
    } else {
        appendWebSocketBinaryMessage("outbound", payload.data);
    }
}

function createWebSocketPayload() {
    const value = refs.websocketInput.value;
    if (state.websocket.mode === "text") {
        const bytes = UTF8_ENCODER.encode(value).byteLength;
        validateWebSocketMessageSize(bytes);
        return { data: value, bytes: bytes, kind: "text" };
    }

    const compact = value.replace(/\s+/g, "");
    if (!/^[0-9a-f]*$/i.test(compact)) {
        throw new Error("Binary messages require hexadecimal bytes");
    }
    if (compact.length % 2 !== 0) {
        throw new Error("Hexadecimal input needs complete byte pairs");
    }

    const length = compact.length / 2;
    validateWebSocketMessageSize(length);
    const bytes = new Uint8Array(length);
    for (let index = 0; index < length; index += 1) {
        bytes[index] = Number.parseInt(compact.slice(index * 2, index * 2 + 2), 16);
    }
    return { data: bytes, bytes: bytes.byteLength, kind: "binary" };
}

function validateWebSocketMessageSize(bytes) {
    if (bytes > state.websocket.maxMessageSize) {
        throw new Error(
            "Message exceeds the " +
            formatByteSize(state.websocket.maxMessageSize) +
            " limit"
        );
    }
}

function setWebSocketMode(mode) {
    if (!["text", "binary"].includes(mode) || state.websocket.mode === mode) {
        return;
    }

    state.websocket.mode = mode;
    renderWebSocketComposer();
    refs.websocketInput.focus();
}

function setWebSocketTransport(transport) {
    const inspector = state.websocket;
    const socket = inspector.socket;
    const active = inspector.prepareController ||
        (socket && socket.readyState !== WebSocket.CLOSED);
    if (!(transport in WEBSOCKET_TRANSPORT_LABELS) ||
        inspector.transport === transport ||
        active) {
        return;
    }

    inspector.error = "";
    inspector.headers = [];
    inspector.httpVersion = "";
    inspector.receivedConnectionInfo = false;
    inspector.status = "idle";
    inspector.tls = null;
    inspector.transport = transport;
    renderWebSocketState();
    renderWebSocketAnalysis();
}

function clearWebSocketMessages() {
    state.websocket.messages = [];
    renderWebSocketMessages();
}

function appendWebSocketTextMessage(direction, value, knownBytes) {
    const bytes = knownBytes ?? UTF8_ENCODER.encode(value).byteLength;
    const truncated = value.length > WEBSOCKET_TEXT_PREVIEW_LIMIT;
    appendWebSocketMessage({
        bytes: bytes,
        direction: direction,
        kind: "Text",
        preview: truncated ? value.slice(0, WEBSOCKET_TEXT_PREVIEW_LIMIT) : value,
        truncated: truncated,
    });
}

function appendWebSocketBinaryMessage(direction, value) {
    const limit = Math.min(value.byteLength, WEBSOCKET_BINARY_PREVIEW_LIMIT);
    let preview = "";
    for (let index = 0; index < limit; index += 1) {
        if (index > 0) {
            preview += " ";
        }
        preview += value[index].toString(16).padStart(2, "0");
    }

    appendWebSocketMessage({
        bytes: value.byteLength,
        direction: direction,
        kind: "Binary",
        preview: preview,
        truncated: value.byteLength > WEBSOCKET_BINARY_PREVIEW_LIMIT,
    });
}

function appendWebSocketSystemMessage(value) {
    appendWebSocketMessage({
        bytes: null,
        direction: "system",
        kind: "Event",
        preview: value,
        truncated: false,
    });
}

function appendWebSocketMessage(message) {
    state.websocket.messages.push({
        ...message,
        timestamp: Date.now(),
    });

    if (state.websocket.messages.length > WEBSOCKET_HISTORY_LIMIT) {
        state.websocket.messages.splice(
            0,
            state.websocket.messages.length - WEBSOCKET_HISTORY_LIMIT
        );
    }
    renderWebSocketMessages();
}

function renderWebSocket() {
    renderWebSocketState();
    renderWebSocketComposer();
    renderWebSocketMessages();
    renderWebSocketAnalysis();
}

function renderWebSocketState() {
    const inspector = state.websocket;
    const labels = {
        analyzing: "Analyzing connection",
        closed: "Closed",
        closing: "Closing",
        connecting: "Connecting",
        error: "Failed",
        idle: "Ready",
        open: "Connected",
        preparing: "Preparing " + WEBSOCKET_TRANSPORT_LABELS[inspector.transport],
    };
    refs.websocketStatus.dataset.state = inspector.status;
    refs.websocketStatusLabel.textContent = labels[inspector.status] || "Ready";
    refs.websocketStatus.title = inspector.error;
    refs.websocketStatusDot.classList.toggle(
        "status-dot-animated",
        ["analyzing", "connecting", "closing", "preparing"].includes(inspector.status)
    );

    const socket = inspector.socket;
    const preparing = Boolean(inspector.prepareController);
    const connecting = socket && socket.readyState === WebSocket.CONNECTING;
    const open = socket && socket.readyState === WebSocket.OPEN;
    const closing = socket && socket.readyState === WebSocket.CLOSING;
    const label = closing
        ? "Closing"
        : preparing || connecting
            ? "Cancel"
            : open
                ? "Disconnect"
                : "Connect";
    const iconName = preparing || connecting ? "x" : open || closing ? "unplug" : "plug";
    const icon = document.createElement("i");
    icon.dataset.lucide = iconName;
    icon.setAttribute("aria-hidden", "true");
    refs.websocketConnectButton.className = open || connecting
        ? "btn btn-outline-secondary"
        : "btn btn-primary";
    refs.websocketConnectButton.disabled = Boolean(closing);
    refs.websocketConnectButton.replaceChildren(
        icon,
        create("span", "", label)
    );
    refs.websocketUrl.textContent = websocketUrl();
    refs.websocketTransportButtons.forEach(function (button) {
        const active = button.dataset.websocketTransport === inspector.transport;
        button.classList.toggle("active", active);
        button.setAttribute("aria-pressed", String(active));
        button.disabled = Boolean(
            preparing || connecting || open || closing
        );
    });
    paintIcons();
}

function renderWebSocketComposer() {
    refs.websocketModeButtons.forEach(function (button) {
        const active = button.dataset.websocketMode === state.websocket.mode;
        button.classList.toggle("active", active);
        button.setAttribute("aria-pressed", String(active));
    });

    refs.websocketInput.placeholder = state.websocket.mode === "binary"
        ? "Hex bytes"
        : "Message text";
    refs.websocketInput.maxLength = state.websocket.mode === "binary"
        ? state.websocket.maxMessageSize * 3
        : state.websocket.maxMessageSize;

    const metrics = websocketInputMetrics();
    refs.websocketInputSize.textContent = metrics.error
        ? metrics.error
        : formatByteSize(metrics.bytes) +
            " / " +
            formatByteSize(state.websocket.maxMessageSize);

    const socket = state.websocket.socket;
    refs.websocketSendButton.disabled = !socket ||
        socket.readyState !== WebSocket.OPEN ||
        Boolean(metrics.error) ||
        metrics.bytes > state.websocket.maxMessageSize;
}

function websocketInputMetrics() {
    const value = refs.websocketInput.value;
    if (state.websocket.mode === "text") {
        return { bytes: UTF8_ENCODER.encode(value).byteLength, error: "" };
    }

    const compact = value.replace(/\s+/g, "");
    if (!/^[0-9a-f]*$/i.test(compact)) {
        return { bytes: 0, error: "Invalid hex" };
    }
    if (compact.length % 2 !== 0) {
        return { bytes: 0, error: "Incomplete byte" };
    }
    return { bytes: compact.length / 2, error: "" };
}

function renderWebSocketMessages() {
    const messages = state.websocket.messages;
    const count = webSocketDataMessageCount();
    setText("websocket-count", String(count));
    refs.websocketMessageCount.textContent =
        count + (count === 1 ? " message" : " messages");
    refs.websocketClearButton.disabled = messages.length === 0;

    if (messages.length === 0) {
        refs.websocketMessageLog.replaceChildren(
            create("div", "websocket-log-empty", "No messages")
        );
        return;
    }

    const fragment = document.createDocumentFragment();
    messages.forEach(function (message) {
        const item = create("article", "websocket-message");
        item.dataset.direction = message.direction;
        const header = create("div", "websocket-message-header");
        const direction = message.direction === "inbound"
            ? "Received"
            : message.direction === "outbound"
                ? "Sent"
                : "Session";
        header.append(
            create("span", "websocket-message-direction", direction),
            create("span", "", message.kind)
        );
        if (message.bytes !== null) {
            header.append(create("span", "", formatByteSize(message.bytes)));
        }
        header.append(
            create(
                "time",
                "websocket-message-time",
                new Date(message.timestamp).toLocaleTimeString()
            )
        );
        item.append(header, create("pre", "", message.preview || "(empty message)"));
        if (message.truncated) {
            item.append(create("span", "websocket-message-note", "Preview truncated"));
        }
        fragment.append(item);
    });

    refs.websocketMessageLog.replaceChildren(fragment);
    refs.websocketMessageLog.scrollTop = refs.websocketMessageLog.scrollHeight;
}

function webSocketDataMessageCount() {
    return state.websocket.messages.filter(function (message) {
        return message.direction !== "system";
    }).length;
}

function renderWebSocketAnalysis() {
    const inspector = state.websocket;
    if (!isObject(inspector.tls)) {
        const section = createSection("Handshake", "WebSocket TLS", "");
        const message = inspector.receivedConnectionInfo
            ? "No ClientHello captured"
            : ["connecting", "analyzing"].includes(inspector.status)
                ? "Waiting for TLS analysis"
                : "Waiting for connection";
        section.append(create("p", "text-secondary mb-0", message));
        const sections = inspector.receivedConnectionInfo
            ? [
                createWebSocketConnectionSection(),
                createWebSocketHeadersSection(),
                section,
            ]
            : [section];
        refs.websocketAnalysis.replaceChildren(...sections);
        paintIcons();
        return;
    }

    refs.websocketAnalysis.replaceChildren(
        createWebSocketConnectionSection(),
        createWebSocketHeadersSection(),
        ...createTlsSections(inspector.tls)
    );
    paintIcons();
}

function createWebSocketConnectionSection() {
    const inspector = state.websocket;
    const section = createSection("WebSocket", "Connection details", "");
    section.append(
        createDetailGrid([
            ["Remote address", valueOr(inspector.address, UNAVAILABLE_LABEL), true],
            ["HTTP version", valueOr(inspector.httpVersion, UNAVAILABLE_LABEL), true],
            ["Message limit", formatByteSize(inspector.maxMessageSize), true],
        ])
    );
    return section;
}

function createWebSocketHeadersSection() {
    const inspector = state.websocket;
    const isHttp2 = inspector.httpVersion.startsWith("HTTP/2");
    const section = createSection(
        "Opening handshake",
        isHttp2 ? "Extended CONNECT headers" : "Upgrade request headers",
        inspector.headers.length + " entries"
    );

    if (inspector.headers.length === 0) {
        section.append(createEmptyState("No handshake headers were captured", "rows-3"));
    } else {
        section.append(renderHeaderTable(inspector.headers));
    }

    return section;
}

function formatByteSize(bytes) {
    if (bytes < 1024) {
        return bytes + " B";
    }
    if (bytes < 1024 * 1024) {
        return (bytes / 1024).toFixed(bytes < 10 * 1024 ? 1 : 0) + " KiB";
    }
    return (bytes / (1024 * 1024)).toFixed(1) + " MiB";
}

function renderProxy() {
    const root = document.getElementById("proxy-content");
    const controlSection = createSection(
        "Live measurement",
        "Browser latency probe",
        state.proxyRunning ? "In progress" : "WebSocket"
    );
    const control = create("div", "proxy-probe-control p-3 mb-4");
    const row = create("div", "d-flex flex-wrap align-items-center gap-3");
    const status = create("div", "d-flex align-items-center gap-2 flex-fill");
    const statusDot = create("span", "status-dot");
    const probeStatus = proxyProbeStatus();
    status.setAttribute("role", "status");
    status.setAttribute("aria-live", "polite");
    statusDot.classList.add(probeStatus.color);
    statusDot.classList.toggle("status-dot-animated", state.proxyRunning);
    status.append(statusDot, create("span", "text-secondary", probeStatus.text));

    const button = create("button", "btn btn-primary d-inline-flex align-items-center gap-2");
    button.type = "button";
    button.disabled = state.proxyRunning;
    if (state.proxyRunning) {
        const spinner = create("span", "spinner-border spinner-border-sm");
        spinner.setAttribute("aria-hidden", "true");
        button.append(spinner, create("span", "", "Measuring"));
    } else {
        const icon = document.createElement("i");
        icon.className = "icon";
        icon.dataset.lucide = "activity";
        icon.setAttribute("aria-hidden", "true");
        button.append(icon, create("span", "", state.proxyAnalysis ? "Measure again" : "Measure latency"));
    }
    button.addEventListener("click", runProxyProbe);
    row.append(status, button);

    const progress = create("div", "proxy-progress mt-3");
    const progressBar = create("div", "proxy-progress-bar");
    const progressValue = Math.min(100, Math.max(0, state.proxyProgress));
    progress.setAttribute("role", "progressbar");
    progress.setAttribute("aria-label", "Latency measurement");
    progress.setAttribute("aria-valuemin", "0");
    progress.setAttribute("aria-valuemax", "100");
    progress.setAttribute("aria-valuenow", String(progressValue));
    progressBar.style.width = progressValue + "%";
    progress.append(progressBar);
    control.append(row, progress);
    controlSection.append(control);

    const content = [controlSection];
    if (state.proxyAnalysis) {
        content.push(...createProxyResult(state.proxyAnalysis));
    }
    root.replaceChildren(...content);
    paintIcons();
}

function proxyProbeStatus() {
    if (state.proxyError) {
        return { text: state.proxyError, color: "bg-red" };
    }
    if (state.proxyRunning) {
        const progress = state.proxySamplesTotal > 0
            ? " " + state.proxySamplesCompleted + "/" + state.proxySamplesTotal
            : "";
        return { text: "Measuring browser RTT" + progress, color: "bg-blue" };
    }
    if (state.proxyAnalysis) {
        return { text: "Measurement complete", color: "bg-green" };
    }
    return { text: "Ready", color: "bg-secondary" };
}

function createProxyResult(analysis) {
    const measurements = isObject(analysis.measurements) ? analysis.measurements : {};
    const samples = Array.isArray(measurements.application_rtt_samples_ms)
        ? measurements.application_rtt_samples_ms
        : [];
    const measurementSection = createSection(
        "Server measured",
        "Latency comparison",
        samples.length + " samples"
    );
    measurementSection.append(
        createDetailGrid([
            ["Client address", valueOr(analysis.client_address, UNAVAILABLE_LABEL), true],
            ["TCP handshake RTT", formatMilliseconds(measurements.tcp_handshake_rtt_ms), true],
            ["TLS handshake", formatMilliseconds(measurements.tls_handshake_ms), true],
            ["Browser RTT", formatMilliseconds(measurements.application_rtt_ms), true],
            ["RTT gap", formatSignedMilliseconds(measurements.rtt_gap_ms), true],
            ["Relative gap", formatPercentage(measurements.rtt_gap_percent), true],
        ]),
        createProxyChart(measurements)
    );

    const classification = valueOr(analysis.classification, "Unknown");
    const tone = proxyTone(classification);
    const confidence = valueOr(analysis.confidence, UNAVAILABLE_LABEL);
    const verdictSection = createSection("Heuristic", "Proxy signal", confidence + " confidence");
    const verdict = create(
        "article",
        "proxy-verdict proxy-verdict-" + String(classification).toLowerCase() + " p-3 mb-3"
    );
    const title = create("div", "d-flex flex-wrap align-items-center gap-2 mb-2");
    title.append(
        create("span", "badge bg-" + tone + "-lt text-" + tone, classification),
        create("strong", "", confidence + " confidence")
    );
    verdict.append(
        title,
        create("p", "mb-2", valueOr(analysis.reason, "No analysis was returned.")),
        create("p", "mb-0 text-secondary small", "Latency is an indicator, not proof of proxy use.")
    );
    verdictSection.append(verdict);

    if (samples.length > 0) {
        const sampleSection = createSection("Raw timing", "WebSocket samples", "Milliseconds");
        sampleSection.append(
            createValueNode(samples.map(function (sample) {
                return formatMilliseconds(sample);
            }))
        );
        return [measurementSection, verdictSection, sampleSection];
    }

    return [measurementSection, verdictSection];
}

function createProxyChart(measurements) {
    const values = [
        ["TCP handshake RTT", measurements.tcp_handshake_rtt_ms, "tcp"],
        ["TLS handshake", measurements.tls_handshake_ms, "tls"],
        ["Browser RTT", measurements.application_rtt_ms, "application"],
    ].filter(function (entry) {
        return hasNumericValue(entry[1]);
    });
    const chart = create("div", "proxy-chart mt-4");
    if (values.length === 0) {
        chart.append(create("span", "text-secondary", "No latency measurements"));
        return chart;
    }

    const maximum = Math.max(...values.map(function (entry) {
        return Number(entry[1]);
    }), 0.001);
    values.forEach(function (entry) {
        const row = create("div", "proxy-chart-row");
        const track = create("div", "proxy-chart-track");
        const fill = create("div", "proxy-chart-fill proxy-chart-fill-" + entry[2]);
        fill.style.width = Math.max(1, Number(entry[1]) / maximum * 100) + "%";
        track.append(fill);
        row.append(
            create("span", "text-secondary small", entry[0]),
            track,
            create("code", "font-monospace small text-end", formatMilliseconds(entry[1]))
        );
        chart.append(row);
    });
    return chart;
}

function runProxyProbe() {
    if (state.proxyRunning) {
        return;
    }

    resetProxyProbe();
    state.proxyProgress = 2;
    state.proxyRunning = true;
    renderProxy();

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(protocol + "//" + window.location.host + LATENCY_PATH);
    state.proxySocket = socket;
    state.proxyTimer = window.setTimeout(function () {
        failProxyProbe(socket, "Measurement timed out");
    }, 20_000);

    socket.addEventListener("message", function (event) {
        let message;
        try {
            message = JSON.parse(event.data);
        } catch (_) {
            failProxyProbe(socket, "Invalid probe response");
            return;
        }

        if (message.type === "probe") {
            const sequence = Number(message.sequence);
            const total = Number(message.total);
            if (!Number.isInteger(sequence) ||
                !Number.isInteger(total) ||
                sequence < 1 ||
                total < 1 ||
                sequence > total) {
                failProxyProbe(socket, "Invalid probe sequence");
                return;
            }

            socket.send(event.data);
            state.proxySamplesCompleted = sequence;
            state.proxySamplesTotal = total;
            state.proxyProgress = Math.min(90, sequence / total * 90);
            window.requestAnimationFrame(renderProxy);
            return;
        }

        if (message.type === "result" && isObject(message.analysis)) {
            clearProxyTimer();
            state.proxyAnalysis = message.analysis;
            state.proxyError = "";
            state.proxyProgress = 100;
            state.proxyRunning = false;
            renderProxy();
        }
    });
    socket.addEventListener("error", function () {
        failProxyProbe(socket, "Measurement unavailable");
    });
    socket.addEventListener("close", function () {
        clearProxyTimer();
        if (state.proxySocket === socket) {
            state.proxySocket = null;
        }
        if (state.proxyRunning) {
            failProxyProbe(socket, "Measurement disconnected");
        }
    });
}

function resetProxyProbe() {
    const socket = state.proxySocket;
    clearProxyTimer();
    state.proxySocket = null;
    state.proxyAnalysis = null;
    state.proxyError = "";
    state.proxyProgress = 0;
    state.proxyRunning = false;
    state.proxySamplesCompleted = 0;
    state.proxySamplesTotal = 0;
    socket?.close();
}

function clearProxyTimer() {
    window.clearTimeout(state.proxyTimer);
    state.proxyTimer = null;
}

function failProxyProbe(socket, message) {
    if (state.proxySocket !== socket || !state.proxyRunning) {
        return;
    }

    state.proxyRunning = false;
    state.proxyProgress = 0;
    state.proxyError = message;
    state.proxySocket = null;
    socket.close();
    renderProxy();
}

function proxyTone(classification) {
    switch (String(classification).toLowerCase()) {
        case "likely": return "red";
        case "possible": return "warning";
        case "unlikely": return "green";
        default: return "warning";
    }
}

function formatMilliseconds(value) {
    if (!hasNumericValue(value)) {
        return UNAVAILABLE_LABEL;
    }
    const numeric = Number(value);
    return numeric.toFixed(3) + " ms";
}

function formatSignedMilliseconds(value) {
    if (!hasNumericValue(value)) {
        return UNAVAILABLE_LABEL;
    }
    const numeric = Number(value);
    return (numeric > 0 ? "+" : "") + numeric.toFixed(3) + " ms";
}

function formatPercentage(value) {
    if (!hasNumericValue(value)) {
        return UNAVAILABLE_LABEL;
    }
    const numeric = Number(value);
    return numeric.toFixed(1) + "%";
}

function hasNumericValue(value) {
    return value !== null && value !== undefined && value !== "" && Number.isFinite(Number(value));
}

function renderPackets(packets) {
    const list = create("div", "list-group mb-3 protocol-list");

    packets.forEach(function (packet, index) {
        const details = create("details", "list-group-item p-0 protocol-item");
        const summary = create(
            "summary",
            "d-flex align-items-center gap-2 p-3 cursor-pointer protocol-summary"
        );
        summary.append(
            create("span", "badge bg-secondary-lt text-secondary", padIndex(index + 1)),
            create(
                "span",
                "fw-semibold text-break",
                summarizeTcpPacket(packet)
            )
        );

        const meta = create("span", "ms-auto text-secondary font-monospace small text-end");
        const endpoints =
            valueOr(packet.source, "?") +
            " to " +
            valueOr(packet.destination, "?");
        meta.textContent =
            valueOr(packet.direction, "unknown") + " / " +
            valueOr(packet.wire_length, 0) + " bytes / " +
            endpoints;
        summary.append(meta);
        details.append(summary);

        const payload = withoutKeys(packet, [
            "direction",
            "wire_length",
            "source",
            "destination",
            "timestamp_us",
        ]);
        if (packet.timestamp_us !== undefined) {
            payload.timestamp = formatPacketTime(packet.timestamp_us);
        }

        const body = create("div", "border-top bg-body-tertiary p-3 protocol-body");
        body.append(createValueNode(payload));
        details.append(body);
        list.append(details);
    });

    return list;
}

function summarizeTcpPacket(packet) {
    const tcp = isObject(packet.tcp) ? packet.tcp : {};
    const flags = isObject(tcp.flags) && Array.isArray(tcp.flags.values)
        ? tcp.flags.values
        : [];
    return flags.length > 0 ? flags.join(" + ") : "TCP packet";
}

function formatPacketTime(timestamp) {
    const numeric = Number(timestamp);
    if (!Number.isFinite(numeric)) {
        return String(timestamp);
    }

    try {
        return new Date(numeric / 1_000).toISOString();
    } catch (_) {
        return String(timestamp);
    }
}

function createValueNode(value) {
    if (value === null || value === undefined) {
        return create("span", "text-secondary font-monospace small", "null");
    }

    if (typeof value === "boolean") {
        return create(
            "span",
            value
                ? "badge bg-green-lt text-green"
                : "badge bg-red-lt text-red",
            String(value)
        );
    }

    if (typeof value === "number" || typeof value === "bigint") {
        return create("code", "font-monospace small text-break", String(value));
    }

    if (typeof value === "string") {
        if (value.length > 140) {
            return createLongValue(value);
        }
        return create("code", "font-monospace small text-break", value);
    }

    if (Array.isArray(value)) {
        return createArrayValue(value);
    }

    if (isObject(value)) {
        return createObjectValue(value);
    }

    return create("code", "font-monospace small text-break", String(value));
}

function createArrayValue(values) {
    if (values.length === 0) {
        return create("span", "text-secondary font-monospace small", "Empty");
    }

    if (values.every(isPrimitive)) {
        const tokens = create("div", "d-flex flex-wrap gap-2");
        values.forEach(function (value) {
            tokens.append(
                create(
                    "span",
                    "badge bg-blue-lt text-blue rounded-pill font-monospace text-wrap text-break protocol-token",
                    String(value)
                )
            );
        });
        return tokens;
    }

    if (values.every(isNamedValue)) {
        const rows = values.map(function (value, index) {
            const cells = [
                String(index + 1),
                value.id === undefined ? "-" : String(value.id),
                value.id === undefined ? "-" : formatHex(value.id),
                valueOr(value.name, "Other"),
            ];
            if (value.value !== undefined) {
                cells.push(createValueNode(value.value));
            }
            return {
                className: String(value.name).toUpperCase() === "GREASE"
                    ? "table-active"
                    : "",
                cells: cells,
            };
        });
        const hasValue = values.some(function (value) {
            return value.value !== undefined;
        });
        return createTable(
            hasValue
                ? ["#", "ID", "Hex", "Name", "Value"]
                : ["#", "ID", "Hex", "Name"],
            rows,
            []
        );
    }

    if (values.every(isHeaderValue)) {
        return renderHeaderTable(values);
    }

    const list = create("div", "vstack gap-3");
    values.forEach(function (value, index) {
        const item = create("div", "border rounded-2 p-3");
        item.append(
            create(
                "span",
                "text-secondary text-uppercase fw-bold small d-block mb-2",
                "Item " + (index + 1)
            ),
            createValueNode(value)
        );
        list.append(item);
    });
    return list;
}

function createObjectValue(value) {
    const entries = Object.entries(value);
    if (entries.length === 0) {
        return create("span", "text-secondary font-monospace small", "Empty");
    }

    const grid = create("dl", "list-group list-group-flush mb-0");
    entries.forEach(function (entry) {
        const row = create("div", "list-group-item px-0 py-2");
        row.append(
            create("dt", "text-secondary small fw-medium mb-1", formatKey(entry[0]))
        );
        const definition = create("dd", "mb-0 text-break");
        definition.append(createValueNode(entry[1]));
        row.append(definition);
        grid.append(row);
    });
    return grid;
}

function createLongValue(value) {
    const details = create("details", "mt-2");
    details.append(
        create(
            "summary",
            "text-secondary small fw-medium cursor-pointer",
            value.length.toLocaleString() + " characters"
        )
    );

    const row = create("div", "d-flex align-items-start gap-2 mt-2");
    row.append(
        create(
            "pre",
            "bg-body-tertiary border rounded-2 p-3 mb-0 flex-fill font-monospace small overflow-auto",
            value
        ),
        createCopyButton(value, "Copy full value")
    );
    details.append(row);
    return details;
}

function isPrimitive(value) {
    return value === null ||
        ["string", "number", "boolean", "bigint"].includes(typeof value);
}

function isNamedValue(value) {
    return isObject(value) &&
        Object.prototype.hasOwnProperty.call(value, "name") &&
        Object.prototype.hasOwnProperty.call(value, "id");
}

function isHeaderValue(value) {
    return isObject(value) &&
        Object.prototype.hasOwnProperty.call(value, "name") &&
        Object.prototype.hasOwnProperty.call(value, "value");
}

function createSection(eyebrow, title, meta) {
    const section = create("section", "mb-5 analysis-section");
    const heading = create(
        "div",
        "d-flex flex-wrap align-items-end justify-content-between gap-2 border-bottom pb-2 mb-3 section-heading"
    );
    const copy = create("div");
    copy.append(
        create("p", "page-pretitle mb-1", eyebrow),
        create("h2", "h3 mb-0", title)
    );
    heading.append(copy);

    if (meta) {
        heading.append(create("span", "text-secondary small", meta));
    }

    section.append(heading);
    return section;
}

function createDetailGrid(items) {
    const grid = create("dl", "row g-0 border rounded-2 overflow-hidden mb-4 detail-grid");

    items.forEach(function (item) {
        const row = create("div", "col-12 col-xl-6 p-3 border-bottom detail-item");
        row.append(create("dt", "text-secondary small fw-medium mb-1", item[0]));

        const definition = create("dd", "mb-0 text-break");
        if (item[2]) {
            definition.append(
                create("code", "font-monospace small text-break", String(item[1]))
            );
        } else {
            definition.append(createValueNode(item[1]));
        }

        row.append(definition);
        grid.append(row);
    });

    return grid;
}

function createTable(headers, rows, columnClasses) {
    const wrap = create("div", "table-responsive border rounded-2 mb-3 data-table-wrap");
    const table = create("table", "table table-vcenter table-hover mb-0 data-table");
    const head = document.createElement("thead");
    head.className = "data-table-head";
    const headRow = document.createElement("tr");

    headers.forEach(function (header) {
        const cell = create("th", "text-secondary text-uppercase small", header);
        cell.scope = "col";
        headRow.append(cell);
    });
    head.append(headRow);

    const body = document.createElement("tbody");
    rows.forEach(function (row) {
        const tableRow = document.createElement("tr");
        if (row.className) {
            tableRow.className = row.className;
        }

        row.cells.forEach(function (cell, index) {
            const tableCell = document.createElement("td");
            if (columnClasses[index]) {
                tableCell.className = columnClasses[index];
            }

            if (cell instanceof Node) {
                tableCell.append(cell);
            } else {
                tableCell.textContent = String(cell);
            }
            tableRow.append(tableCell);
        });
        body.append(tableRow);
    });

    table.append(head, body);
    wrap.append(table);
    return wrap;
}

function createCopyButton(value, label) {
    const button = create(
        "button",
        "btn btn-outline-secondary btn-sm p-2 flex-shrink-0"
    );
    button.type = "button";
    button.title = label;
    button.setAttribute("aria-label", label);

    const icon = document.createElement("i");
    icon.className = "icon";
    icon.dataset.lucide = "copy";
    icon.setAttribute("aria-hidden", "true");
    button.append(icon);

    button.addEventListener("click", function () {
        copyText(value, button);
    });

    return button;
}

async function copyText(value, button) {
    const text = String(value);

    try {
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(text);
        } else {
            copyWithTextArea(text);
        }

        showToast("Copied to clipboard");
        markCopied(button);
    } catch (_) {
        try {
            copyWithTextArea(text);
            showToast("Copied to clipboard");
            markCopied(button);
        } catch (_) {
            showToast("Copy failed");
        }
    }
}

function copyWithTextArea(value) {
    const textArea = document.createElement("textarea");
    textArea.value = value;
    textArea.readOnly = true;
    textArea.style.position = "fixed";
    textArea.style.opacity = "0";
    document.body.append(textArea);
    textArea.select();

    const copied = document.execCommand("copy");
    textArea.remove();
    if (!copied) {
        throw new Error("Clipboard copy was rejected.");
    }
}

function markCopied(button) {
    if (!button) {
        return;
    }

    const label = button.getAttribute("aria-label");
    button.classList.remove("btn-outline-secondary");
    button.classList.add("btn-success");
    button.setAttribute("aria-label", "Copied");
    window.setTimeout(function () {
        button.classList.remove("btn-success");
        button.classList.add("btn-outline-secondary");
        button.setAttribute("aria-label", label);
    }, 1200);
}

function downloadJson() {
    if (!state.data) {
        return;
    }

    const date = new Date();
    const stamp = [
        date.getFullYear(),
        String(date.getMonth() + 1).padStart(2, "0"),
        String(date.getDate()).padStart(2, "0"),
        "-",
        String(date.getHours()).padStart(2, "0"),
        String(date.getMinutes()).padStart(2, "0"),
        String(date.getSeconds()).padStart(2, "0"),
    ].join("");

    const blob = new Blob([JSON.stringify(state.data, null, 2) + "\n"], {
        type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "pingly-analysis-" + stamp + ".json";
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    showToast("Analysis downloaded");
}

function showToast(message) {
    window.clearTimeout(toastTimer);
    refs.toast.textContent = message;
    refs.toast.hidden = false;
    toastTimer = window.setTimeout(function () {
        refs.toast.hidden = true;
    }, 2200);
}

function createEmptyState(title, iconName, detail) {
    const root = create("div", "empty py-5");
    const iconWrap = create("div", "empty-icon");
    const icon = document.createElement("i");
    icon.className = "icon";
    icon.dataset.lucide = iconName;
    icon.setAttribute("aria-hidden", "true");
    iconWrap.append(icon);
    root.append(iconWrap, create("p", "empty-title", title));

    if (detail) {
        root.append(create("p", "empty-subtitle text-secondary", detail));
    }

    return root;
}

function create(tag, className, text) {
    const element = document.createElement(tag);
    if (className) {
        element.className = className;
    }
    if (text !== undefined) {
        element.textContent = String(text);
    }
    return element;
}

function setText(id, value) {
    const element = document.getElementById(id);
    if (element) {
        element.textContent = String(value);
    }
}

function valueOr(value, fallback) {
    return value === null || value === undefined || value === "" ? fallback : value;
}

function isObject(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}

function withoutKey(value, key) {
    return withoutKeys(value, [key]);
}

function withoutKeys(value, keys) {
    if (!isObject(value)) {
        return value;
    }

    const omitted = new Set(keys);
    const result = {};
    Object.entries(value).forEach(function (entry) {
        if (!omitted.has(entry[0])) {
            result[entry[0]] = entry[1];
        }
    });
    return result;
}

function formatKey(value) {
    const text = String(value).replaceAll("_", " ");
    return text.charAt(0).toUpperCase() + text.slice(1);
}

function formatHex(value) {
    let numeric;

    if (typeof value === "number") {
        if (!Number.isSafeInteger(value) || value < 0) {
            return "-";
        }
        numeric = BigInt(value);
    } else if (typeof value === "string" && /^\d+$/.test(value)) {
        numeric = BigInt(value);
    } else {
        return "-";
    }

    return "0x" + numeric.toString(16).padStart(4, "0");
}

function padIndex(value) {
    return String(value).padStart(2, "0");
}
