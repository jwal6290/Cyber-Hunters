/* =========================================================
   ScamShield AI — History page
========================================================= */
(function () {
    "use strict";

    const S = window.ScamShield;
    const $ = function (id) { return document.getElementById(id); };
    const PAGE_SIZE = 5;
    const LEVEL_LABEL = { high: "High Risk", medium: "Medium Risk", low: "Low Risk" };

    let page = 1;
    let undoData = null;
    let toastTimer = null;
    let clearArmed = false;

    function filtered() {
        const q = $("searchInput").value.trim().toLowerCase();
        const level = $("riskFilter").value;
        return S.getHistory().filter(function (r) {
            if (level !== "all" && r.level !== level) return false;
            if (!q) return true;
            const hay = [r.title, r.excerpt, r.file ? r.file.name : "", r.email ? r.email.subject : "", LEVEL_LABEL[r.level]].join(" ").toLowerCase();
            return hay.indexOf(q) >= 0;
        });
    }

    function renderStats(all) {
        const count = function (lvl) { return all.filter(function (r) { return r.level === lvl; }).length; };
        $("statTotal").textContent = all.length;
        $("statHigh").textContent = count("high");
        $("statMedium").textContent = count("medium");
        $("statLow").textContent = count("low");
    }

    function render() {
        const all = S.getHistory();
        renderStats(all);

        const items = filtered();
        const pages = Math.max(1, Math.ceil(items.length / PAGE_SIZE));
        if (page > pages) page = pages;
        const start = (page - 1) * PAGE_SIZE;
        const visible = items.slice(start, start + PAGE_SIZE);

        const list = $("historyList");
        list.innerHTML = "";
        visible.forEach(function (r) { list.appendChild(renderRow(r)); });

        const empty = $("emptyState");
        empty.hidden = items.length > 0;
        $("historyFooter").hidden = items.length === 0;
        if (!all.length) {
            $("emptyTitle").textContent = "No scans yet";
            $("emptyText").textContent = "Messages and files you scan will appear here so you can review them later.";
            $("emptyAction").hidden = false;
        } else if (!items.length) {
            $("emptyTitle").textContent = "No matching scans";
            $("emptyText").textContent = "Try a different search or risk level.";
            $("emptyAction").hidden = true;
        }

        $("showingText").textContent = items.length
            ? "Showing " + (start + 1) + "–" + (start + visible.length) + " of " + items.length + " scan" + (items.length === 1 ? "" : "s")
            : "";
        renderPagination(pages);
    }

    function renderRow(r) {
        const li = document.createElement("li");
        li.className = "history-row";
        const quote = r.excerpt ? "“" + r.excerpt + (r.excerpt.length >= 140 ? "…" : "") + "”" : "No readable text";
        li.innerHTML =
            '<span class="row-icon ' + r.level + '"><i class="fa-solid ' + (r.icon || "fa-comment-dots") + '"></i></span>' +
            '<div class="row-title"><strong></strong><span class="row-date"></span></div>' +
            '<div class="row-excerpt"><span class="row-file" hidden><i class="fa-solid fa-paperclip"></i> <span></span></span><span class="row-quote"></span></div>' +
            '<div class="row-risk"><span class="risk-pill ' + r.level + '">' + LEVEL_LABEL[r.level] + '</span><span class="row-score">Risk Score: <b>' + r.score + "</b>/100</span></div>" +
            '<a class="view-button" href="results.html?id=' + encodeURIComponent(r.id) + '">View Results <i class="fa-solid fa-arrow-right"></i></a>' +
            '<button type="button" class="delete-button" aria-label="Delete scan"><i class="fa-regular fa-trash-can"></i></button>';
        li.querySelector("strong").textContent = r.title;
        li.querySelector(".row-date").textContent = S.formatDate(r.createdAt);
        li.querySelector(".row-quote").textContent = quote;
        if (r.file) {
            const f = li.querySelector(".row-file");
            f.hidden = false;
            f.querySelector("span").textContent = r.file.name;
        }
        li.querySelector(".delete-button").addEventListener("click", function () { removeScan(r.id); });
        return li;
    }

    function renderPagination(pages) {
        const nav = $("pagination");
        nav.innerHTML = "";
        if (pages <= 1) return;
        const make = function (label, target, opts) {
            const b = document.createElement("button");
            b.type = "button";
            b.innerHTML = label;
            if (opts && opts.active) { b.className = "active"; b.setAttribute("aria-current", "page"); }
            if (opts && opts.aria) b.setAttribute("aria-label", opts.aria);
            b.disabled = target < 1 || target > pages;
            b.addEventListener("click", function () { page = target; render(); });
            nav.appendChild(b);
        };
        make('<i class="fa-solid fa-chevron-left"></i>', page - 1, { aria: "Previous page" });
        let from = Math.max(1, page - 2);
        let to = Math.min(pages, from + 4);
        from = Math.max(1, to - 4);
        for (let p = from; p <= to; p++) make(String(p), p, { active: p === page });
        make('<i class="fa-solid fa-chevron-right"></i>', page + 1, { aria: "Next page" });
    }

    function removeScan(id) {
        const removed = S.deleteRecord(id);
        if (!removed) return;
        undoData = [removed];
        showToast("Scan deleted");
        render();
    }

    function showToast(text) {
        $("toastText").textContent = text;
        $("toast").hidden = false;
        clearTimeout(toastTimer);
        toastTimer = setTimeout(function () { $("toast").hidden = true; undoData = null; }, 6000);
    }

    $("undoButton").addEventListener("click", function () {
        if (undoData) {
            // restore in original order
            undoData.slice().sort(function (a, b) { return a.index - b.index; }).forEach(function (u) { S.restoreRecord(u.record, u.index); });
        }
        undoData = null;
        $("toast").hidden = true;
        render();
    });

    $("clearAllButton").addEventListener("click", function () {
        const btn = $("clearAllButton");
        if (!clearArmed) {
            clearArmed = true;
            btn.classList.add("armed");
            btn.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> Click again to clear all';
            setTimeout(function () {
                clearArmed = false;
                btn.classList.remove("armed");
                btn.innerHTML = '<i class="fa-regular fa-trash-can"></i> Clear history';
            }, 4000);
            return;
        }
        const all = S.getHistory();
        undoData = all.map(function (r, i) { return { record: r, index: i }; });
        S.clearHistory();
        clearArmed = false;
        btn.classList.remove("armed");
        btn.innerHTML = '<i class="fa-regular fa-trash-can"></i> Clear history';
        showToast("History cleared");
        page = 1;
        render();
    });

    $("searchInput").addEventListener("input", function () { page = 1; render(); });
    $("riskFilter").addEventListener("change", function () { page = 1; render(); });

    // Keep in sync if another tab adds a scan
    window.addEventListener("storage", function (e) {
        if (e.key === "scamshield-history") render();
    });

    render();
})();
