/* =========================================================
   ScamShield AI — Scanner / Results page
========================================================= */
(function () {
    "use strict";

    const S = window.ScamShield;
    const $ = function (id) { return document.getElementById(id); };

    const scanView = $("scanView");
    const progressView = $("progressView");
    const resultView = $("resultView");
    const dropzone = $("dropzone");
    const fileInput = $("fileInput");
    const fileList = $("fileList");
    const messageInput = $("messageInput");
    const analyzeButton = $("analyzeButton");
    const scanStatus = $("scanStatus");

    let selectedFiles = [];
    let currentBatch = [];

    const EXAMPLES = {
        delivery: "USPS: Your package is delayed. Pay $2.99 to reschedule delivery here: http://usps-track-update.com",
        bank: "Dear Customer, your account requires verification to avoid interruption. Please confirm your details within 24 hours to keep your online banking active.",
        prize: "Congratulations! You've won a free gift card! Click here to claim your reward before it expires today: bit.ly/claim-gift-now",
        safe: "Hi Sam, your order #4471 has shipped and is on the way. It should arrive Thursday. You can track it anytime in the Amazon app. Thanks for shopping with us!"
    };

    const LEVEL_TEXT = {
        high: { pill: "High Risk", title: "Potential Scam Detected", icon: "fa-triangle-exclamation", summary: "This {thing} contains multiple suspicious indicators commonly used in scams." },
        medium: { pill: "Medium Risk", title: "Be Careful With This One", icon: "fa-circle-exclamation", summary: "This {thing} has some suspicious characteristics. Verify it before you act." },
        low: { pill: "Low Risk", title: "No Major Red Flags Found", icon: "fa-circle-check", summary: "We didn't find significant warning signs in this {thing}. Still be cautious." }
    };

    const KIND_ICON = {
        image: "fa-file-image", pdf: "fa-file-pdf", document: "fa-file-word", email: "fa-envelope-open-text",
        html: "fa-file-code", archive: "fa-file-zipper", program: "fa-file-circle-exclamation", text: "fa-file-lines", file: "fa-file"
    };

    /* ---------------- VIEWS ---------------- */
    function showView(view) {
        scanView.hidden = view !== "scan";
        progressView.hidden = view !== "progress";
        resultView.hidden = view !== "result";
        const isResult = view === "result";
        $("pageTitle").textContent = isResult ? "Scan Results" : view === "progress" ? "Scanning…" : "Scan a Message or File";
        $("pageSubtitle").textContent = isResult
            ? "Here's what ScamShield AI found in your " + (currentRecordIsFile() ? "file." : "message.")
            : "Upload a suspicious file or paste a message, and ScamShield AI will check it for scam warning signs.";
        window.scrollTo({ top: 0, behavior: "smooth" });
    }

    let shownRecord = null;
    function currentRecordIsFile() {
        return !!(shownRecord && shownRecord.file);
    }

    function resetScanner() {
        selectedFiles = [];
        renderFileList();
        messageInput.value = "";
        scanStatus.textContent = "";
        $("notFoundNote").hidden = true;
        history.pushState(null, "", "results.html");
        shownRecord = null;
        showView("scan");
        messageInput.focus({ preventScroll: true });
    }

    /* ---------------- FILE SELECTION ---------------- */
    function addFiles(list) {
        Array.from(list || []).forEach(function (f) {
            const dup = selectedFiles.some(function (s) { return s.name === f.name && s.size === f.size; });
            if (!dup) selectedFiles.push(f);
        });
        scanStatus.textContent = "";
        renderFileList();
    }

    function renderFileList() {
        fileList.innerHTML = "";
        selectedFiles.forEach(function (f, i) {
            const li = document.createElement("li");
            const tooBig = f.size > S.MAX_FILE_SIZE;
            li.innerHTML =
                '<i class="fa-solid fa-file"></i>' +
                '<span class="fl-name"></span>' +
                '<span class="fl-size">' + S.formatBytes(f.size) + (tooBig ? " · only the file type will be checked" : "") + "</span>" +
                '<button type="button" class="fl-remove" aria-label="Remove file"><i class="fa-solid fa-xmark"></i></button>';
            li.querySelector(".fl-name").textContent = f.name;
            li.querySelector(".fl-remove").addEventListener("click", function () {
                selectedFiles.splice(i, 1);
                renderFileList();
            });
            fileList.appendChild(li);
        });
    }

    dropzone.addEventListener("click", function () { fileInput.click(); });
    dropzone.addEventListener("keydown", function (e) {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); }
    });
    fileInput.addEventListener("change", function () {
        addFiles(fileInput.files);
        fileInput.value = "";
    });
    ["dragenter", "dragover"].forEach(function (evt) {
        dropzone.addEventListener(evt, function (e) { e.preventDefault(); dropzone.classList.add("dragging"); });
    });
    ["dragleave", "drop"].forEach(function (evt) {
        dropzone.addEventListener(evt, function (e) { e.preventDefault(); dropzone.classList.remove("dragging"); });
    });
    dropzone.addEventListener("drop", function (e) {
        if (e.dataTransfer && e.dataTransfer.files) addFiles(e.dataTransfer.files);
    });
    // Allow dropping anywhere on the scan panel without the browser opening the file
    window.addEventListener("dragover", function (e) { e.preventDefault(); });
    window.addEventListener("drop", function (e) {
        e.preventDefault();
        if (!scanView.hidden && e.dataTransfer && e.dataTransfer.files.length && !dropzone.contains(e.target)) addFiles(e.dataTransfer.files);
    });
    // Paste an image (e.g. a screenshot) straight into the page
    document.addEventListener("paste", function (e) {
        if (scanView.hidden || !e.clipboardData) return;
        const files = Array.from(e.clipboardData.files || []);
        if (files.length) {
            e.preventDefault();
            addFiles(files.map(function (f, i) {
                return f.name && f.name !== "image.png" ? f : new File([f], "pasted-screenshot-" + (i + 1) + ".png", { type: f.type });
            }));
        }
    });

    document.querySelectorAll("[data-example]").forEach(function (btn) {
        btn.addEventListener("click", function () {
            messageInput.value = EXAMPLES[btn.dataset.example];
            scanStatus.textContent = "";
            messageInput.focus();
        });
    });

    messageInput.addEventListener("input", function () { scanStatus.textContent = ""; });

    /* ---------------- RUN SCAN ---------------- */
    analyzeButton.addEventListener("click", async function () {
        const text = messageInput.value.trim();
        if (!text && !selectedFiles.length) {
            scanStatus.textContent = "Please paste a message or upload a file first.";
            return;
        }
        showView("progress");
        try {
            const records = await S.scan({ text: text, files: selectedFiles }, function (msg) {
                $("progressText").textContent = msg;
            });
            selectedFiles = [];
            messageInput.value = "";
            renderFileList();
            const ids = records.map(function (r) { return r.id; });
            history.pushState(null, "", "results.html?ids=" + ids.join(","));
            showBatch(records, 0);
        } catch (err) {
            console.error(err);
            showView("scan");
            scanStatus.textContent = "Something went wrong while scanning. Please try again.";
        }
    });

    /* ---------------- RENDER RESULTS ---------------- */
    function showBatch(records, index) {
        currentBatch = records;
        renderBatchStrip(index);
        renderRecord(records[index]);
        showView("result");
    }

    function renderBatchStrip(activeIndex) {
        const strip = $("batchStrip");
        if (currentBatch.length < 2) {
            strip.hidden = true;
            return;
        }
        strip.hidden = false;
        strip.innerHTML = '<span class="batch-label">' + currentBatch.length + " items scanned</span>";
        currentBatch.forEach(function (r, i) {
            const b = document.createElement("button");
            b.type = "button";
            b.className = "batch-item" + (i === activeIndex ? " active" : "");
            b.innerHTML = '<span class="dot ' + r.level + '"></span><span class="bi-name"></span><span class="bi-score">' + r.score + "</span>";
            b.querySelector(".bi-name").textContent = r.file ? r.file.name : "Pasted message";
            b.addEventListener("click", function () {
                renderBatchStrip(i);
                renderRecord(r);
            });
            strip.appendChild(b);
        });
    }

    function renderRecord(r) {
        shownRecord = r;
        const L = LEVEL_TEXT[r.level];
        const thing = r.file ? "file" : "message";

        const verdict = $("verdict");
        verdict.className = "verdict " + r.level;
        $("verdictIcon").className = "fa-solid " + L.icon;
        $("verdictTitle").textContent = L.title;
        $("verdictSummary").textContent = L.summary.replace("{thing}", thing);
        const pill = $("riskPill");
        pill.className = "risk-pill " + r.level;
        pill.textContent = L.pill;
        $("scoreValue").textContent = r.score;

        // Flags
        const flagList = $("flagList");
        flagList.innerHTML = "";
        $("flagsTitle").textContent = r.indicators.length ? "Why Was This Flagged?" : "What We Checked";
        if (r.indicators.length) {
            const MAX_SHOWN = 6;
            r.indicators.forEach(function (ind, idx) {
                const li = document.createElement("li");
                li.className = "flag " + ind.severity + (idx >= MAX_SHOWN ? " extra" : "");
                li.hidden = idx >= MAX_SHOWN;
                li.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i><span><strong></strong> <span class="flag-detail"></span></span>';
                li.querySelector("strong").textContent = ind.title;
                li.querySelector(".flag-detail").textContent = "(" + ind.detail + ")";
                flagList.appendChild(li);
            });
            if (r.indicators.length > MAX_SHOWN) {
                const more = document.createElement("li");
                more.innerHTML = '<button type="button" class="text-button show-more"></button>';
                const btn = more.querySelector("button");
                const extra = r.indicators.length - MAX_SHOWN;
                btn.textContent = "Show " + extra + " more warning sign" + (extra === 1 ? "" : "s");
                btn.addEventListener("click", function () {
                    const open = btn.dataset.open === "1";
                    flagList.querySelectorAll(".flag.extra").forEach(function (el) { el.hidden = open; });
                    btn.dataset.open = open ? "" : "1";
                    btn.textContent = open ? "Show " + extra + " more warning sign" + (extra === 1 ? "" : "s") : "Show fewer";
                });
                flagList.appendChild(more);
            }
        } else {
            [
                "No pressure or urgent language",
                "No request for money, gift cards, or card details",
                "No request for passwords or personal information",
                r.links && r.links.length ? "Links didn't match known scam patterns" : "No links found"
            ].forEach(function (t) {
                const li = document.createElement("li");
                li.className = "flag safe";
                li.innerHTML = '<i class="fa-solid fa-circle-check"></i><span></span>';
                li.querySelector("span").textContent = t;
                flagList.appendChild(li);
            });
        }

        $("explanationText").textContent = r.explanation;

        const actionList = $("actionList");
        actionList.innerHTML = "";
        r.actions.forEach(function (a) {
            const li = document.createElement("li");
            li.textContent = a;
            actionList.appendChild(li);
        });

        // Side: what was analyzed
        $("analyzedTitle").textContent = r.file ? "File Analyzed" : "Message Analyzed";
        const chip = $("fileChip");
        if (r.file) {
            chip.hidden = false;
            chip.innerHTML = '<i class="fa-solid ' + (KIND_ICON[r.file.kind] || "fa-file") + '"></i><div><strong></strong><span></span></div>';
            chip.querySelector("strong").textContent = r.file.name;
            chip.querySelector("span").textContent = S.formatBytes(r.file.size) + (r.email && r.email.from ? " · From: " + r.email.from : "");
        } else {
            chip.hidden = true;
        }

        const analyzed = $("analyzedText");
        if (r.text) {
            analyzed.hidden = false;
            analyzed.innerHTML = highlightLinks(r.text) + (r.textTruncated ? '<span class="truncated">… (shortened)</span>' : "");
        } else {
            analyzed.hidden = !!r.file;
            analyzed.innerHTML = '<span class="muted">No readable text.</span>';
        }

        const notes = $("notesList");
        notes.innerHTML = "";
        notes.hidden = !(r.notes && r.notes.length);
        (r.notes || []).forEach(function (n) {
            const li = document.createElement("li");
            li.innerHTML = '<i class="fa-solid fa-circle-info"></i><span></span>';
            li.querySelector("span").textContent = n;
            notes.appendChild(li);
        });

        $("scanMeta").textContent = "Scanned " + S.formatDate(r.createdAt);
    }

    // Shows links in the text, but never as clickable links
    function highlightLinks(text) {
        const urls = S.findUrls(text);
        let html = "";
        let pos = 0;
        urls.forEach(function (u) {
            const i = text.indexOf(u, pos);
            if (i < 0) return;
            html += S.escapeHtml(text.slice(pos, i));
            html += '<span class="flagged-link" title="Link disabled for your safety">' + S.escapeHtml(u) + "</span>";
            pos = i + u.length;
        });
        html += S.escapeHtml(text.slice(pos));
        return html;
    }

    $("scanAnotherButton").addEventListener("click", resetScanner);
    $("navScanButton").addEventListener("click", function (e) {
        e.preventDefault();
        resetScanner();
    });

    /* ---------------- ROUTING ---------------- */
    function route() {
        const params = new URLSearchParams(location.search);
        const ids = (params.get("ids") || params.get("id") || "").split(",").filter(Boolean);
        if (!ids.length) {
            shownRecord = null;
            showView("scan");
            return;
        }
        const records = ids.map(S.getRecord).filter(Boolean);
        if (!records.length) {
            showView("scan");
            $("notFoundNote").hidden = false;
            return;
        }
        showBatch(records, 0);
    }

    window.addEventListener("popstate", route);
    route();
})();
