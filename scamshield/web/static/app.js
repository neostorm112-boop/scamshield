/* ScamShield workspace behaviour: no build step. Delegated handlers survive htmx swaps. */
(function () {
  var root = document.documentElement, css = getComputedStyle(root);
  function tok(name) { return css.getPropertyValue(name).trim(); }

  // --- live banner stale guard: htmx keeps the old DOM when the server dies, so a frozen green LIVE must flip to red on its own.
  var lastOk = Date.now(), lost = false, banner = document.getElementById("live-banner");
  function gst(ms) { var d = new Date(ms + 4 * 3600 * 1000); return ("0" + d.getUTCHours()).slice(-2) + ":" + ("0" + d.getUTCMinutes()).slice(-2); }
  function flip() {
    if (lost || !banner) return;
    lost = true;
    banner.classList.add("live-red");
    banner.innerHTML = "<strong>Connection to ScamShield lost at " + gst(lastOk) + " GST — data below is from before</strong>";
  }
  document.body.addEventListener("htmx:afterRequest", function (e) {
    if (e.detail.successful) { lastOk = Date.now(); if (lost) { lost = false; banner.classList.remove("live-red"); } } else flip();
  });
  setInterval(function () {
    if (Date.now() - lastOk > 30000) flip();
  }, 1000);

  // --- case: decide needs a verdict and a reason; AI text clamps to 4 lines
  function reasonReady(form) {
    var ok = !!form.querySelector('input[name="verdict"]').value && !!form.querySelector('input[name="reason"]').value.trim();
    form.querySelector(".save").disabled = !ok;
    return ok;
  }
  function clampAi() {
    var p = document.getElementById("ai-text"), btn = document.querySelector("#ai-explanation .all");
    if (p && btn) btn.hidden = !(p.scrollHeight > p.clientHeight + 1) && p.parentNode.className.indexOf("open") < 0;
  }
  document.addEventListener("click", function (e) {
    var t = e.target.closest("button, a");
    if (!t) return;
    if (t.classList.contains("all")) {
      var box = t.closest(".ai"), open = box.classList.toggle("open");
      t.setAttribute("aria-expanded", open); t.textContent = open ? "Show less" : "Read all";
    }
    if (t.classList.contains("choice")) {
      var form = t.closest("form");
      form.querySelectorAll(".choice").forEach(function (o) { o.setAttribute("aria-checked", o === t); o.tabIndex = o === t ? 0 : -1; });
      form.querySelector('input[name="verdict"]').value = t.dataset.v;
      reasonReady(form);
    }
    if (t.tagName === "A" && /^#E\d+$/.test(t.getAttribute("href"))) { var det = document.getElementById("details"); if (det) det.open = true; }
  });
  // radiogroup keyboard: arrows move and select, only the chosen (or first) option is a tab stop
  document.addEventListener("keydown", function (e) {
    var t = e.target.closest && e.target.closest(".choice");
    var step = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[e.key];
    if (!t || !step) return;
    var all = Array.prototype.slice.call(t.parentNode.querySelectorAll(".choice")), next = all[(all.indexOf(t) + step + all.length) % all.length];
    e.preventDefault(); next.focus(); next.click();
  });
  document.addEventListener("input", function (e) { var f = e.target.closest("#decide"); if (f) reasonReady(f); });
  document.addEventListener("submit", function (e) { if (e.target.id === "decide" && !reasonReady(e.target)) e.preventDefault(); });
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") closeGraph(); });
  document.body.addEventListener("htmx:afterSwap", clampAi);
  clampAi(); window.addEventListener("resize", clampAi);
  var sel = document.querySelector(".q-list .row[aria-current]"); if (sel && sel.scrollIntoView) sel.scrollIntoView({block: "nearest"});

  // --- links graph (cytoscape, vendored)
  var dataEl = document.getElementById("graph-data"), overlay = document.getElementById("graph-overlay"), bigCy = null;
  function closeGraph() { if (overlay) overlay.hidden = true; }
  function palette(tone) {
    var map = {high: [tok("--risk-review-tint"), tok("--risk-high"), "solid"], review: [tok("--risk-review-tint"), tok("--risk-review"), "solid"],
      scam: [tok("--state-scam-fill"), tok("--state-scam"), "solid"], nodata: [tok("--state-nodata-tint"), tok("--state-nodata"), "dashed"]};
    return map[tone] || map.nodata;
  }
  function draw(el, big) {
    var data = JSON.parse(dataEl.textContent), names = {};
    data.edges.forEach(function (e) { names[e.a] = 1; names[e.b] = 1; });
    var cy = cytoscape({
      container: el, userZoomingEnabled: big, userPanningEnabled: big, boxSelectionEnabled: false,
      elements: Object.keys(names).map(function (n) {
        var p = palette(data.tones[n]);
        return {data: {id: n, label: n, fill: p[0], line: p[1], dash: p[2], center: n === data.center ? 1 : 0}};
      }).concat(data.edges.map(function (e, i) {
        return {data: {id: "e" + i, source: e.a, target: e.b, label: data.edges.length > 8 ? "" : (big ? e.sentence : e.title), sentence: e.sentence, level: e.level}};
      })),
      layout: {name: "cose", animate: false, idealEdgeLength: big ? 220 : 110, nodeRepulsion: 60000, padding: 12, nodeDimensionsIncludeLabels: true,
        boundingBox: {x1: 0, y1: 0, w: el.clientWidth || 700, h: el.clientHeight || 400}},
      style: [
        {selector: "node", style: {label: "data(label)", color: tok("--text-2"), "font-size": 11, "font-family": "ui-monospace, Menlo, monospace", "text-wrap": "ellipsis", "text-max-width": big ? 260 : 150,
          "text-valign": "bottom", "text-margin-y": 4, width: 18, height: 18, "background-color": "data(fill)", "border-width": 2, "border-color": "data(line)", "border-style": "data(dash)",
          "text-background-color": tok("--bg"), "text-background-opacity": 1, "text-background-padding": 2}},
        {selector: "node[center = 1]", style: {width: 26, height: 26, color: tok("--text"), "overlay-color": tok("--accent"), "border-width": 3, "underlay-color": tok("--accent"), "underlay-opacity": 0.35, "underlay-padding": 4}},
        {selector: "edge", style: {label: "data(label)", color: tok("--text-3"), "font-size": 10, "text-wrap": "wrap", "text-max-width": big ? 240 : 130, width: 2, "line-color": tok("--accent"), "line-opacity": 0.6,
          "curve-style": "bezier", "text-background-color": tok("--bg"), "text-background-opacity": 1, "text-background-padding": 2, "text-rotation": "autorotate"}},
        {selector: "edge[level = 'medium']", style: {"line-style": "dashed"}}
      ]
    });
    var note = document.getElementById("graph-note");
    cy.on("tap", "edge", function (ev) { if (note && big) note.textContent = ev.target.data("sentence"); });
    cy.on("tap", "node", function (ev) { if (ev.target.id() !== data.center) window.location = "/d/" + ev.target.id(); });
    return cy;
  }
  var details = document.getElementById("details"), drawn = false;
  function drawInline() { if (!drawn && details && details.open) { drawn = true; draw(document.getElementById("graph-inline"), false); } }
  if (dataEl && window.cytoscape) {
    drawInline(); if (details) details.addEventListener("toggle", drawInline);
    document.getElementById("graph-expand").onclick = function () {
      overlay.hidden = false;
      if (!bigCy) bigCy = draw(document.getElementById("graph-big"), true); else { bigCy.resize(); bigCy.fit(undefined, 20); }
    };
    document.getElementById("graph-close").onclick = closeGraph;
    overlay.querySelector(".backdrop").onclick = closeGraph;
    document.getElementById("zoom-in").onclick = function () { bigCy.zoom({level: bigCy.zoom() * 1.25, renderedPosition: {x: bigCy.width() / 2, y: bigCy.height() / 2}}); };
    document.getElementById("zoom-out").onclick = function () { bigCy.zoom({level: bigCy.zoom() / 1.25, renderedPosition: {x: bigCy.width() / 2, y: bigCy.height() / 2}}); };
    document.getElementById("zoom-fit").onclick = function () { bigCy.fit(undefined, 20); };
  }
})();
