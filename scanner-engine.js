/* =========================================================
   ScamShield AI — Scan Engine
   Runs entirely in the browser. Reads pasted text and uploaded
   files, looks for common scam warning signs, scores the risk,
   and saves every scan to the user's History (localStorage).
   Exposes: window.ScamShield
========================================================= */
(function () {
    "use strict";

    const STORAGE_KEY = "scamshield-history";
    const MAX_HISTORY = 200;
    const MAX_FILE_SIZE = 15 * 1024 * 1024; // 15 MB
    const MAX_STORED_TEXT = 6000;

    const LIBS = {
        tesseract: "https://cdn.jsdelivr.net/npm/tesseract.js@5/dist/tesseract.min.js",
        pdfjs: "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js",
        pdfWorker: "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js",
        mammoth: "https://cdnjs.cloudflare.com/ajax/libs/mammoth/1.6.0/mammoth.browser.min.js"
    };

    /* ---------------------------------------------------------
       TEXT RULES
       weight = how much the sign adds to the risk score
       explain = phrase used to build the written explanation
    --------------------------------------------------------- */
    const TEXT_RULES = [
        {
            id: "urgency",
            title: "Urgent language",
            detail: "pressures you to act quickly",
            weight: 22,
            explain: "creates a sense of urgency",
            patterns: [
                /\b(urgent(ly)?|immediately|right away|act now|asap|as soon as possible|today only|time[- ]sensitive|don'?t delay|before it'?s too late|last chance|final (notice|warning|reminder|attempt))\b/i,
                /\bwithin \d+\s?(hours?|hrs?|minutes?|mins?|days?)\b/i,
                /\b(expires?|expiring|will expire) (today|soon|tonight|in)\b/i,
                /\b(is|was|has been|have been) (delayed|on hold|suspended|locked|disabled|restricted|deactivated|frozen|blocked)\b/i,
                /\b(avoid|prevent) (interruption|suspension|closure|deactivation|cancellation|penalt(y|ies))\b/i,
                /\bwill be (closed|cancelled|canceled|terminated|deleted|suspended|locked|returned to sender)\b/i
            ]
        },
        {
            id: "payment",
            title: "Suspicious payment request",
            detail: "asks for money or card details",
            weight: 26,
            explain: "asks for a payment",
            patterns: [
                /\b(pay|payment|repay|remit)\b.{0,40}?(\$|€|£|usd|fee|now|here|today|below|online)/i,
                /(\$|€|£)\s?\d+([.,]\d{2})?\b.{0,40}\b(fee|charge|pay|payment|due|owed|outstanding|reschedul|release|redeliver)/i,
                /\b(processing|delivery|shipping|customs|release|redelivery|handling|small|admin(istration)?) (fee|charge|duty|payment)\b/i,
                /\b(send|transfer|lend|wire|need)\b.{0,25}(\$|€|£)\s?\d/i,
                /\b(bank transfer|money transfer|send (me )?(the )?money)\b/i,
                /\b(card (details|number|info(rmation)?)|cvv|cvc|expiry date|bank details|routing number|sort code|billing (details|information))\b/i
            ]
        },
        {
            id: "untraceable",
            title: "Untraceable payment method",
            detail: "gift cards, crypto, or wire transfers",
            weight: 30,
            explain: "asks to be paid with gift cards, crypto, or wire transfers, which can't be refunded",
            patterns: [
                /\b(buy|purchase|send|pay (with|in|using|via)|in the form of)\b.{0,30}\b(gift ?cards?|itunes|google play|steam cards?|bitcoin|btc|crypto(currency)?|usdt|ethereum)\b/i,
                /\b(wire transfer|western union|moneygram|bitcoin atm|crypto wallet|wallet address)\b/i,
                /\b(zelle|venmo|cash ?app)\b.{0,40}\b(send|pay|transfer)\b/i
            ]
        },
        {
            id: "credentials",
            title: "Request for personal information",
            detail: "asks for passwords, codes, or account details",
            weight: 26,
            explain: "asks you to verify or share personal account information",
            patterns: [
                /\b(verify|confirm|validate|update|re-?activate|unlock|restore|secure)\b.{0,15}\b(your )?(account|identity|information|details|payment|billing|profile|login|credentials)\b/i,
                /\b(requires?|needs?|pending) (verification|validation|confirmation)\b/i,
                /\bverification (required|needed)\b/i,
                /\b(password|passcode|\bpin\b|one[- ]time (code|password|passcode)|\botp\b|verification code|security code|2fa code|login code)\b/i,
                /\b(social security( number)?|\bssn\b|date of birth|mother'?s maiden name|account number|online banking (login|details))\b/i
            ]
        },
        {
            id: "prize",
            title: "Too-good-to-be-true offer",
            detail: "unexpected prizes, rewards, or free money",
            weight: 30,
            explain: "promises an unexpected prize or reward",
            patterns: [
                /\bcongratulations\b/i,
                /\byou('ve| have)? (won|been selected|been chosen|qualified)\b/i,
                /\b(winner|lottery|sweepstakes|jackpot|cash prize|grand prize)\b/i,
                /\bclaim (your|the|a)? ?(free )?(prize|reward|gift|money|refund|bonus|winnings)\b/i,
                /\bfree (gift|iphone|ipad|prize|money|vacation|trip|cruise|gift ?card)\b/i,
                /\b(unclaimed (funds|money|inheritance)|inheritance|beneficiary of)\b/i
            ]
        },
        {
            id: "threat",
            title: "Threats or intimidation",
            detail: "mentions arrest, legal action, or penalties",
            weight: 25,
            explain: "threatens legal action or penalties",
            patterns: [
                /\b(arrest(ed)?|warrant|lawsuit|legal action|prosecut(e|ion)|police|sheriff|court (date|order|summons))\b/i,
                /\b(irs|tax (refund|debt|evasion)|back taxes|social security administration)\b/i,
                /\b(penalt(y|ies)|fines?|late fee)\b.{0,30}\b(if|unless|will)\b/i
            ]
        },
        {
            id: "investment",
            title: "Unrealistic money-making promise",
            detail: "easy income or guaranteed returns",
            weight: 22,
            explain: "promises easy money or guaranteed returns",
            patterns: [
                /\b(guaranteed (returns?|profits?|income)|double your (money|investment)|risk[- ]free (investment|returns?)|passive income|get rich)\b/i,
                /\bearn (up to )?(\$|€|£)?\s?\d[\d,]*\s?(\+|k)?\s?(per|a|an|\/)\s?(day|week|hour|month)\b/i,
                /\b(work from home|no experience (needed|required)|easy money|be your own boss)\b/i
            ]
        },
        {
            id: "impersonation-family",
            title: "Possible family impersonation",
            detail: "\"new number\" or emergency from a relative",
            weight: 22,
            explain: "claims to be a family member using a new number",
            patterns: [
                /\b(hi|hey|hello) (mum|mom|dad|mother|father|grandma|grandpa)\b/i,
                /\b(this is|it'?s) my new (number|phone)\b/i,
                /\bi (lost|broke|dropped) my phone\b/i
            ]
        },
        {
            id: "techsupport",
            title: "Fake tech-support alert",
            detail: "claims your device is infected or hacked",
            weight: 25,
            explain: "claims your device has been infected or hacked",
            patterns: [
                /\b(virus|malware|trojan|spyware)\b.{0,30}\b(detected|found|infected)\b/i,
                /\byour (computer|device|pc|phone|mac) (is|has been) (infected|locked|hacked|compromised)\b/i,
                /\b(call|contact) (microsoft|apple|windows|norton|mcafee|geek squad) (support|help ?desk|technician)\b/i
            ]
        },
        {
            id: "secrecy",
            title: "Asks you to keep it secret",
            detail: "scammers isolate victims from help",
            weight: 15,
            explain: "asks you to keep the request secret",
            patterns: [
                /\b(don'?t|do not) (tell|inform|share this with) (anyone|anybody|your (bank|family|friends|parents)|(mum|mom|dad|my (mum|mom|dad)|the bank))\b/i,
                /\bkeep (this|it) (secret|confidential|between us)\b/i
            ]
        },
        {
            id: "generic-greeting",
            title: "Generic greeting",
            detail: "doesn't use your name",
            weight: 8,
            explain: "uses a generic greeting instead of your name",
            patterns: [
                /\bdear (customer|user|client|member|account ?holder|sir\s?(\/|or)\s?madam|valued|friend|beneficiary)\b/i,
                /\bvalued (customer|member|client)\b/i
            ]
        },
        {
            id: "call-to-action",
            title: "Pushes you to click or reply",
            detail: "instructions to tap a link or respond",
            weight: 10,
            explain: "pushes you to click a link or reply",
            patterns: [
                /\b(click|tap|press) (here|the link|this link|below|on the link|to (claim|verify|confirm|pay|update|reschedule))\b/i,
                /\b(follow|visit|use) (this|the) link\b/i,
                /\breply (yes|y|stop|with your)\b/i,
                /\b(download|open|enable) (the |this )?(attached|attachment|file|macros?|content|editing)\b/i
            ]
        }
    ];

    /* ---------------------------------------------------------
       LINK DATA
    --------------------------------------------------------- */
    const BRANDS = {
        usps: ["usps.com"], fedex: ["fedex.com"], ups: ["ups.com"], dhl: ["dhl.com", "dhl.de"],
        amazon: ["amazon.com", "amazon.co.uk", "amazon.ca", "amazon.de", "amazon.in", "amzn.to", "amazon.jobs"],
        paypal: ["paypal.com", "paypal.me"], apple: ["apple.com", "icloud.com"],
        icloud: ["icloud.com", "apple.com"], microsoft: ["microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com"],
        office365: ["office.com", "microsoft.com"], outlook: ["outlook.com", "live.com", "microsoft.com"],
        netflix: ["netflix.com"], google: ["google.com", "goo.gl", "youtube.com"], gmail: ["google.com", "gmail.com"],
        facebook: ["facebook.com", "fb.com", "meta.com"], instagram: ["instagram.com"], whatsapp: ["whatsapp.com", "wa.me"],
        chase: ["chase.com"], wellsfargo: ["wellsfargo.com"], bankofamerica: ["bankofamerica.com", "bofa.com"], boa: ["bankofamerica.com"],
        citi: ["citi.com", "citibank.com"], capitalone: ["capitalone.com"], amex: ["americanexpress.com", "amex.com"],
        irs: ["irs.gov"], coinbase: ["coinbase.com"], binance: ["binance.com"], venmo: ["venmo.com"], zelle: ["zellepay.com"],
        walmart: ["walmart.com"], ebay: ["ebay.com"], dropbox: ["dropbox.com"], docusign: ["docusign.com", "docusign.net"],
        steam: ["steampowered.com", "steamcommunity.com"], att: ["att.com"], verizon: ["verizon.com"], tmobile: ["t-mobile.com"]
    };

    const BRAND_NAMES = {
        usps: "USPS", fedex: "FedEx", ups: "UPS", dhl: "DHL", amazon: "Amazon", paypal: "PayPal", apple: "Apple", icloud: "iCloud",
        microsoft: "Microsoft", office365: "Office 365", outlook: "Outlook", netflix: "Netflix", google: "Google", gmail: "Gmail",
        facebook: "Facebook", instagram: "Instagram", whatsapp: "WhatsApp", chase: "Chase", wellsfargo: "Wells Fargo",
        bankofamerica: "Bank of America", boa: "Bank of America", citi: "Citi", capitalone: "Capital One", amex: "American Express",
        irs: "IRS", coinbase: "Coinbase", binance: "Binance", venmo: "Venmo", zelle: "Zelle", walmart: "Walmart", ebay: "eBay",
        dropbox: "Dropbox", docusign: "DocuSign", steam: "Steam", att: "AT&T", verizon: "Verizon", tmobile: "T-Mobile"
    };

    const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
        "shorturl.at", "tiny.cc", "rb.gy", "s.id", "t.ly", "bl.ink", "short.io", "v.gd", "lnkd.in", "qrco.de"];

    const RISKY_TLDS = ["xyz", "top", "click", "link", "ru", "cn", "tk", "ml", "ga", "cf", "gq", "online", "site", "shop",
        "live", "icu", "buzz", "vip", "cyou", "sbs", "lol", "rest", "fit", "support", "zip", "mov", "work", "quest", "monster", "cam"];

    const SUSPICIOUS_HOST_WORDS = /(login|log-in|signin|sign-in|verify|verification|secure|account|update|confirm|billing|wallet|unlock|redeliver|reschedule|track-?update|refund|support)/i;

    const DANGEROUS_EXT = ["exe", "scr", "bat", "cmd", "com", "pif", "msi", "msp", "vbs", "vbe", "js", "jse", "wsf", "wsh",
        "ps1", "jar", "apk", "app", "dmg", "pkg", "hta", "lnk", "reg", "cpl", "iso", "img", "vhd", "xll", "sh", "run"];
    const MACRO_EXT = ["docm", "xlsm", "pptm", "dotm", "xltm", "potm", "xlam", "ppam"];
    const ARCHIVE_EXT = ["zip", "rar", "7z", "gz", "tar", "tgz", "cab"];
    const IMAGE_EXT = ["png", "jpg", "jpeg", "gif", "bmp", "webp", "tif", "tiff"];
    const TEXT_EXT = ["txt", "text", "md", "csv", "json", "xml", "log", "rtf", "vcf", "ics"];
    const HTML_EXT = ["html", "htm", "xhtml", "shtml", "svg"];

    /* ---------------------------------------------------------
       CATEGORIES (title + icon used on Results and History)
    --------------------------------------------------------- */
    const CATEGORIES = [
        { id: "prize", title: "Prize Claim Message", icon: "fa-gift", tactic: "prize and reward scams", test: /\b(congratulations|you('ve| have)? won|winner|prize|lottery|sweepstakes|reward|free gift)\b/i },
        { id: "techsupport", title: "Tech Support Alert", icon: "fa-laptop-medical", tactic: "tech-support scams", test: /\b(virus|malware|infected|hacked|tech support|technician)\b/i },
        { id: "government", title: "Government or Tax Notice", icon: "fa-landmark", tactic: "government impersonation scams", test: /\b(irs|tax|social security|government|department of|court|warrant|police)\b/i },
        { id: "family", title: "Family Emergency Message", icon: "fa-people-roof", tactic: "family impersonation scams", test: /\b(hi|hey|hello) (mum|mom|dad)\b|\bmy new (number|phone)\b/i },
        { id: "investment", title: "Investment or Crypto Offer", icon: "fa-chart-line", tactic: "investment and crypto scams", test: /\b(invest(ment)?|crypto|bitcoin|trading|returns?|profit)\b/i },
        { id: "job", title: "Job Offer Message", icon: "fa-briefcase", tactic: "fake job offer scams", test: /\b(job|position|hiring|recruit(er|ment)?|salary|work from home|interview)\b/i },
        { id: "delivery", title: "Package Delivery Message", icon: "fa-envelope", tactic: "phishing and delivery scams", test: /\b(package|parcel|delivery|deliver|courier|usps|fedex|dhl|redeliver|tracking number)\b/i },
        { id: "bank", title: "Bank Account Notification", icon: "fa-building-columns", tactic: "banking and phishing scams", test: /\b(bank|account|card|transaction|credit union|debit|statement|paypal|zelle|venmo)\b/i },
        { id: "shopping", title: "Online Shopping Message", icon: "fa-cart-shopping", tactic: "online shopping scams", test: /\b(order|shipped|purchase|cart|amazon|ebay|walmart|refund|invoice|receipt|subscription|netflix)\b/i },
        { id: "login", title: "Account Security Alert", icon: "fa-user-lock", tactic: "credential phishing", test: /\b(password|log ?in|sign ?in|security alert|verify)\b/i }
    ];

    /* ---------------------------------------------------------
       HELPERS
    --------------------------------------------------------- */
    function uid() {
        return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
    }

    function extOf(name) {
        const m = /\.([a-z0-9]+)$/i.exec(name || "");
        return m ? m[1].toLowerCase() : "";
    }

    function formatBytes(bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
        return (bytes / (1024 * 1024)).toFixed(1) + " MB";
    }

    function escapeHtml(str) {
        return String(str == null ? "" : str)
            .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
    }

    function loadScript(src) {
        return new Promise(function (resolve, reject) {
            const existing = document.querySelector('script[data-src="' + src + '"]');
            if (existing) {
                if (existing.dataset.loaded) return resolve();
                existing.addEventListener("load", function () { resolve(); });
                existing.addEventListener("error", function () { reject(new Error("Failed to load " + src)); });
                return;
            }
            const s = document.createElement("script");
            s.src = src;
            s.async = true;
            s.dataset.src = src;
            s.onload = function () { s.dataset.loaded = "1"; resolve(); };
            s.onerror = function () { reject(new Error("Failed to load " + src)); };
            document.head.appendChild(s);
        });
    }

    function readAsArrayBuffer(file) {
        if (file.arrayBuffer) return file.arrayBuffer();
        return new Promise(function (resolve, reject) {
            const r = new FileReader();
            r.onload = function () { resolve(r.result); };
            r.onerror = function () { reject(r.error); };
            r.readAsArrayBuffer(file);
        });
    }

    function bytesToText(bytes) {
        try {
            return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
        } catch (e) {
            return "";
        }
    }

    // latin1 view of bytes: safe for searching ASCII markers inside binary files
    function bytesToLatin1(bytes, limit) {
        const n = Math.min(bytes.length, limit || bytes.length);
        let out = "";
        const CHUNK = 0x8000;
        for (let i = 0; i < n; i += CHUNK) {
            out += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + CHUNK, n)));
        }
        return out;
    }

    function looksBinary(bytes) {
        const n = Math.min(bytes.length, 4096);
        if (!n) return false;
        let odd = 0;
        for (let i = 0; i < n; i++) {
            const b = bytes[i];
            if (b === 0) return true;
            if (b < 9 || (b > 13 && b < 32)) odd++;
        }
        return odd / n > 0.1;
    }

    function htmlToText(html, links) {
        const doc = new DOMParser().parseFromString(html, "text/html");
        doc.querySelectorAll("script, style, noscript, head").forEach(function (el) { el.remove(); });
        doc.querySelectorAll("a[href]").forEach(function (a) {
            links.push({ href: a.getAttribute("href") || "", text: (a.textContent || "").trim() });
        });
        doc.querySelectorAll("br, p, div, li, tr, h1, h2, h3, h4, h5, h6").forEach(function (el) {
            el.insertAdjacentText("afterend", "\n");
        });
        const text = (doc.body ? doc.body.textContent : doc.documentElement.textContent) || "";
        return {
            text: text.replace(/[ \t ]+/g, " ").replace(/\n\s*\n+/g, "\n\n").trim(),
            hasPasswordField: !!doc.querySelector('input[type="password"]'),
            hasForm: !!doc.querySelector("form"),
            formActions: Array.from(doc.querySelectorAll("form[action]")).map(function (f) { return f.getAttribute("action"); })
        };
    }

    /* ---------------------------------------------------------
       EMAIL (.eml) PARSING
    --------------------------------------------------------- */
    function decodeQuotedPrintable(str) {
        const s = str.replace(/=\r?\n/g, "");
        const bytes = [];
        for (let i = 0; i < s.length; i++) {
            if (s[i] === "=" && /^[0-9A-F]{2}$/i.test(s.substr(i + 1, 2))) {
                bytes.push(parseInt(s.substr(i + 1, 2), 16));
                i += 2;
            } else {
                bytes.push(s.charCodeAt(i) & 0xff);
            }
        }
        return bytesToText(new Uint8Array(bytes));
    }

    function decodeBase64(str) {
        try {
            const bin = atob(str.replace(/[^A-Za-z0-9+/=]/g, ""));
            const bytes = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
            return bytesToText(bytes);
        } catch (e) {
            return "";
        }
    }

    function decodeEncodedWords(str) {
        return String(str || "").replace(/=\?([^?]+)\?([BQ])\?([^?]*)\?=/gi, function (_, charset, enc, data) {
            if (enc.toUpperCase() === "B") return decodeBase64(data);
            return decodeQuotedPrintable(data.replace(/_/g, " "));
        });
    }

    function parseHeaders(block) {
        const headers = {};
        block.replace(/\r?\n[ \t]+/g, " ").split(/\r?\n/).forEach(function (line) {
            const i = line.indexOf(":");
            if (i > 0) {
                const key = line.slice(0, i).trim().toLowerCase();
                const val = line.slice(i + 1).trim();
                headers[key] = headers[key] ? headers[key] + "\n" + val : val;
            }
        });
        return headers;
    }

    function headerParam(value, name) {
        const re = new RegExp(name + '\\*?=\\s*"?([^";]+)"?', "i");
        const m = re.exec(value || "");
        return m ? decodeEncodedWords(m[1].trim()) : "";
    }

    function parseMimePart(raw, out, depth) {
        if (depth > 8) return;
        const split = raw.search(/\r?\n\r?\n/);
        const headerBlock = split >= 0 ? raw.slice(0, split) : raw;
        const body = split >= 0 ? raw.slice(split).replace(/^\r?\n\r?\n/, "") : "";
        const headers = parseHeaders(headerBlock);
        const ctype = (headers["content-type"] || "text/plain").toLowerCase();
        const encoding = (headers["content-transfer-encoding"] || "").toLowerCase();
        const disposition = headers["content-disposition"] || "";
        const filename = headerParam(disposition, "filename") || headerParam(headers["content-type"], "name");

        if (ctype.indexOf("multipart/") === 0) {
            const boundary = headerParam(headers["content-type"], "boundary");
            if (!boundary) return;
            const parts = body.split("--" + boundary);
            parts.slice(1).forEach(function (p) {
                if (p.indexOf("--") === 0) return; // closing boundary
                parseMimePart(p.replace(/^\r?\n/, ""), out, depth + 1);
            });
            return;
        }

        if (filename || /attachment/i.test(disposition)) {
            out.attachments.push(filename || "unnamed attachment");
            if (/\.html?$/i.test(filename) || ctype.indexOf("text/html") === 0) {
                let decoded = body;
                if (encoding === "base64") decoded = decodeBase64(body);
                else if (encoding === "quoted-printable") decoded = decodeQuotedPrintable(body);
                out.htmlAttachments.push(decoded);
            }
            return;
        }

        if (ctype.indexOf("message/rfc822") === 0) {
            parseMimePart(body, out, depth + 1);
            return;
        }

        let decoded = body;
        if (encoding === "base64") decoded = decodeBase64(body);
        else if (encoding === "quoted-printable") decoded = decodeQuotedPrintable(body);

        if (ctype.indexOf("text/html") === 0) out.html.push(decoded);
        else if (ctype.indexOf("text/") === 0) out.plain.push(decoded);
    }

    function parseEml(raw) {
        const split = raw.search(/\r?\n\r?\n/);
        const headers = parseHeaders(split >= 0 ? raw.slice(0, split) : raw);
        const out = { plain: [], html: [], attachments: [], htmlAttachments: [] };
        parseMimePart(raw, out, 0);
        return {
            headers: {
                from: decodeEncodedWords(headers["from"] || ""),
                replyTo: decodeEncodedWords(headers["reply-to"] || ""),
                returnPath: headers["return-path"] || "",
                subject: decodeEncodedWords(headers["subject"] || ""),
                auth: headers["authentication-results"] || headers["arc-authentication-results"] || "",
                spf: headers["received-spf"] || ""
            },
            plain: out.plain.join("\n\n"),
            html: out.html.join("\n"),
            attachments: out.attachments,
            htmlAttachments: out.htmlAttachments
        };
    }

    function emailDomain(addr) {
        const m = /@([a-z0-9.-]+\.[a-z]{2,})/i.exec(addr || "");
        return m ? m[1].toLowerCase() : "";
    }

    function displayName(addr) {
        const m = /^\s*"?([^"<]*?)"?\s*</.exec(addr || "");
        return m ? m[1].trim() : "";
    }

    /* ---------------------------------------------------------
       FILE EXTRACTION
       Returns { text, links:[{href,text}], kind, flags:[indicator], notes:[], email }
    --------------------------------------------------------- */
    async function extractFromFile(file, onProgress) {
        const ext = extOf(file.name);
        const result = { text: "", links: [], kind: "file", flags: [], notes: [], email: null };
        const report = function (msg) { if (onProgress) onProgress(msg); };

        if (file.size > MAX_FILE_SIZE) {
            result.notes.push("This file is larger than " + formatBytes(MAX_FILE_SIZE) + ", so only its type was checked.");
            fileTypeChecks(file, ext, new Uint8Array(0), result);
            return result;
        }

        report("Reading " + file.name + "…");
        const buffer = await readAsArrayBuffer(file);
        const bytes = new Uint8Array(buffer);

        fileTypeChecks(file, ext, bytes, result);

        try {
            if (IMAGE_EXT.indexOf(ext) >= 0 || /^image\//.test(file.type)) {
                result.kind = "image";
                report("Reading text from image (this can take a few seconds)…");
                result.text = await ocrImage(file, report);
                if (!result.text.trim()) result.notes.push("No readable text was found in this image.");
            } else if (ext === "pdf" || file.type === "application/pdf") {
                result.kind = "pdf";
                pdfChecks(bytes, result);
                report("Extracting text from PDF…");
                const pdf = await extractPdf(buffer);
                result.text = pdf.text;
                result.links = result.links.concat(pdf.links);
            } else if (ext === "docx" || ext === "docm" || ext === "dotx") {
                result.kind = "document";
                report("Extracting text from Word document…");
                const doc = await extractDocx(buffer);
                result.text = doc.text;
                result.links = result.links.concat(doc.links);
            } else if (ext === "eml" || file.type === "message/rfc822") {
                result.kind = "email";
                report("Parsing email…");
                emailExtract(bytesToText(bytes), result);
            } else if (HTML_EXT.indexOf(ext) >= 0 || file.type === "text/html") {
                result.kind = "html";
                const parsed = htmlToText(bytesToText(bytes), result.links);
                result.text = parsed.text;
                htmlFormChecks(parsed, result, "This web page");
            } else if (ARCHIVE_EXT.indexOf(ext) >= 0) {
                result.kind = "archive";
                archiveChecks(bytes, result);
            } else if (DANGEROUS_EXT.indexOf(ext) >= 0) {
                result.kind = "program";
                result.notes.push("Program files aren't opened or run — only their type was checked.");
            } else if (TEXT_EXT.indexOf(ext) >= 0 || /^text\//.test(file.type) || !looksBinary(bytes)) {
                result.kind = "text";
                const raw = bytesToText(bytes);
                // A text file might actually be a saved email
                if (/^(received|from|return-path|delivered-to|message-id|mime-version):/im.test(raw.slice(0, 2000)) && /\r?\n\r?\n/.test(raw)) {
                    result.kind = "email";
                    emailExtract(raw, result);
                } else if (ext === "rtf") {
                    result.text = raw.replace(/\\par[d]?/g, "\n").replace(/\{\\[^{}]*\}|\\[a-z]+-?\d* ?|[{}]/gi, "").trim();
                } else {
                    result.text = raw;
                }
            } else {
                result.notes.push("This file type can't be read as text, so only its type and structure were checked.");
            }
        } catch (err) {
            console.warn("[ScamShield] extraction failed:", err);
            result.notes.push("We couldn't read the contents of this file (" + (err && err.message ? err.message : "unknown error") + "). Only its type was checked.");
        }

        return result;
    }

    function emailExtract(raw, result) {
        const email = parseEml(raw);
        result.email = email.headers;
        let text = email.plain;
        if (email.html) {
            const parsed = htmlToText(email.html, result.links);
            if (!text.trim()) text = parsed.text;
            htmlFormChecks(parsed, result, "This email");
        }
        email.htmlAttachments.forEach(function (h) {
            const parsed = htmlToText(h, result.links);
            htmlFormChecks(parsed, result, "An attached web page");
        });
        result.text = (email.headers.subject ? email.headers.subject + "\n\n" : "") + text;
        result.attachments = email.attachments;

        // Sender checks
        const from = email.headers.from;
        const fromDomain = emailDomain(from);
        const name = displayName(from).toLowerCase().replace(/[^a-z0-9]/g, "");
        if (fromDomain && name) {
            Object.keys(BRANDS).forEach(function (brand) {
                if (brand.length >= 4 && name.indexOf(brand) >= 0 && !hostMatches(fromDomain, BRANDS[brand]) && !result.flags.some(function (f) { return f.id === "sender-mismatch"; })) {
                    result.flags.push(indicator("sender-mismatch", "Sender name doesn't match address",
                        "claims to be " + displayName(from) + " but was sent from " + fromDomain, 28,
                        "comes from an address that doesn't belong to the company it claims to be"));
                }
            });
        }
        const replyDomain = emailDomain(email.headers.replyTo);
        if (fromDomain && replyDomain && replyDomain !== fromDomain) {
            result.flags.push(indicator("reply-to", "Replies go somewhere else",
                "reply-to address is " + replyDomain + ", not " + fromDomain, 15,
                "sends your replies to a different address than the sender"));
        }
        const auth = (email.headers.auth + " " + email.headers.spf).toLowerCase();
        if (/\b(spf=(fail|softfail)|dkim=fail|dmarc=fail)\b|^\s*(fail|softfail)\b/.test(auth)) {
            result.flags.push(indicator("auth-fail", "Failed sender verification",
                "the email didn't pass SPF/DKIM/DMARC checks", 25,
                "failed the email system's sender verification checks"));
        }

        const badAttachments = email.attachments.filter(function (a) {
            const e = extOf(a);
            return DANGEROUS_EXT.indexOf(e) >= 0 || MACRO_EXT.indexOf(e) >= 0 || /\.(pdf|docx?|xlsx?|jpe?g|png|txt)\.[a-z0-9]{2,4}$/i.test(a);
        });
        if (badAttachments.length) {
            result.flags.push(indicator("dangerous-attachment", "Dangerous attachment",
                badAttachments.slice(0, 3).join(", "), 40,
                "includes an attachment that could install malware"));
        } else if (email.htmlAttachments.length) {
            result.flags.push(indicator("html-attachment", "Web page sent as attachment",
                "a common trick to show fake login pages", 18,
                "includes a web page attachment, a common way to show fake login forms"));
        }
    }

    function htmlFormChecks(parsed, result, label) {
        if (parsed.hasPasswordField) {
            result.flags.push(indicator("password-form", "Asks for a password in a form",
                label.toLowerCase() + " contains a login form", 30,
                "contains a form that collects passwords"));
        } else if (parsed.hasForm && parsed.formActions.some(function (a) { return /^https?:/i.test(a || ""); })) {
            result.flags.push(indicator("external-form", "Form sends data to another site",
                "information you type is sent elsewhere", 18,
                "contains a form that sends your information to an outside website"));
        }
    }

    function fileTypeChecks(file, ext, bytes, result) {
        const name = file.name || "";
        if (DANGEROUS_EXT.indexOf(ext) >= 0) {
            result.flags.push(indicator("dangerous-file", "Dangerous file type",
                "." + ext + " files can install software or run code", 55,
                "is a type of file that can run programs on your device"));
        }
        if (/\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|mp3|mp4|zip)\s*\.[a-z0-9]{2,4}$/i.test(name) && DANGEROUS_EXT.indexOf(ext) >= 0) {
            result.flags.push(indicator("double-extension", "Disguised file name",
                "\"" + name + "\" pretends to be a different file type", 35,
                "uses a disguised file name to hide what it really is"));
        }
        if (bytes.length > 2 && bytes[0] === 0x4d && bytes[1] === 0x5a && ["exe", "dll", "scr", "com", "msi", "sys", "cpl"].indexOf(ext) < 0) {
            result.flags.push(indicator("hidden-program", "Hidden program inside",
                "the file is really a Windows program", 55,
                "is really a Windows program disguised as another file type"));
        }
        if (MACRO_EXT.indexOf(ext) >= 0) {
            result.flags.push(indicator("macros", "Macro-enabled document",
                "macros can run hidden code when enabled", 35,
                "is a macro-enabled document that can run hidden code"));
        } else if (bytes.length > 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && ["docx", "xlsx", "pptx"].indexOf(ext) >= 0) {
            if (bytesToLatin1(bytes, 4 * 1024 * 1024).indexOf("vbaProject.bin") >= 0) {
                result.flags.push(indicator("macros", "Contains hidden macros",
                    "this document includes macro code", 35,
                    "contains hidden macro code"));
            }
        }
    }

    function pdfChecks(bytes, result) {
        const raw = bytesToLatin1(bytes, 8 * 1024 * 1024);
        const found = [];
        if (/\/JavaScript|\/JS\s*[(<\[]/.test(raw)) found.push("JavaScript");
        if (/\/Launch\b/.test(raw)) found.push("launch actions");
        if (/\/EmbeddedFile\b/.test(raw)) found.push("embedded files");
        if (/\/SubmitForm\b/.test(raw)) found.push("form submission");
        if (found.length) {
            result.flags.push(indicator("pdf-actions", "Hidden actions inside PDF",
                "contains " + found.join(", "), 30,
                "contains hidden actions (" + found.join(", ") + ") that can run when opened"));
        }
    }

    function archiveChecks(bytes, result) {
        // Zip central directories store file names as plain text, so we can list them without unzipping.
        const names = zipFileNames(bytes);
        const risky = DANGEROUS_EXT.concat(MACRO_EXT);
        const list = names.filter(function (n) { return risky.indexOf(extOf(n)) >= 0; });
        if (names.length) {
            result.text = "Files inside this archive:\n" + names.slice(0, 40).join("\n") + (names.length > 40 ? "\n…and " + (names.length - 40) + " more" : "");
        }
        if (list.length) {
            result.flags.push(indicator("archive-program", "Archive contains a program",
                list.slice(0, 3).join(", "), 45,
                "is an archive that contains program files"));
        } else {
            result.notes.push(names.length
                ? "No program files were found among the " + names.length + " file(s) inside. Files inside an archive aren't opened, so scan them separately after extracting if unsure."
                : "This archive's contents couldn't be listed (it may be a non-zip or password-protected archive), so only its type was checked.");
        }
    }

    // Reads the file names listed in a .zip without unzipping it
    function zipFileNames(bytes) {
        const names = {};
        const n = bytes.length;
        for (let i = 0; i + 46 < n; i++) {
            if (bytes[i] !== 0x50 || bytes[i + 1] !== 0x4b) continue;
            let len = 0, start = 0;
            if (bytes[i + 2] === 0x01 && bytes[i + 3] === 0x02) { // central directory entry
                len = bytes[i + 28] | (bytes[i + 29] << 8);
                start = i + 46;
            } else if (bytes[i + 2] === 0x03 && bytes[i + 3] === 0x04) { // local file header
                len = bytes[i + 26] | (bytes[i + 27] << 8);
                start = i + 30;
            } else {
                continue;
            }
            if (len > 0 && len < 512 && start + len <= n) {
                const name = bytesToText(bytes.subarray(start, start + len));
                if (!/\/$/.test(name) && !/[\u0000-\u001f]/.test(name)) names[name] = true;
            }
            if (Object.keys(names).length >= 500) break;
        }
        return Object.keys(names);
    }

    /* ---------------------------------------------------------
       LIBRARY-BACKED EXTRACTORS (loaded only when needed)
    --------------------------------------------------------- */
    async function ocrImage(file, report) {
        await loadScript(LIBS.tesseract);
        const worker = await window.Tesseract.createWorker("eng", 1, {
            logger: function (m) {
                if (m.status === "recognizing text" && report) {
                    report("Reading text from image… " + Math.round((m.progress || 0) * 100) + "%");
                }
            }
        });
        try {
            const res = await worker.recognize(file);
            return (res && res.data && res.data.text) || "";
        } finally {
            worker.terminate();
        }
    }

    async function extractPdf(buffer) {
        await loadScript(LIBS.pdfjs);
        const lib = window.pdfjsLib;
        lib.GlobalWorkerOptions.workerSrc = LIBS.pdfWorker;
        const pdf = await lib.getDocument({ data: new Uint8Array(buffer), isEvalSupported: false }).promise;
        const pages = Math.min(pdf.numPages, 30);
        const parts = [];
        const links = [];
        for (let i = 1; i <= pages; i++) {
            const page = await pdf.getPage(i);
            const content = await page.getTextContent();
            parts.push(content.items.map(function (it) { return it.str; }).join(" "));
            try {
                const annots = await page.getAnnotations();
                annots.forEach(function (a) {
                    if (a.url) links.push({ href: a.url, text: "" });
                });
            } catch (e) { /* ignore */ }
        }
        return { text: parts.join("\n\n"), links: links };
    }

    async function extractDocx(buffer) {
        await loadScript(LIBS.mammoth);
        const res = await window.mammoth.convertToHtml({ arrayBuffer: buffer });
        const links = [];
        const parsed = htmlToText(res.value || "", links);
        return { text: parsed.text, links: links };
    }

    /* ---------------------------------------------------------
       LINK ANALYSIS
    --------------------------------------------------------- */
    const URL_RE = /(?:https?:\/\/|www\.)[^\s<>"'`)\]}]+|\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|info|xyz|top|click|link|co|io|ru|cn|tk|ml|ga|cf|gq|online|site|shop|live|app|me|us|biz|cc|vip|icu|buzz|support|help|club|work|rest|fit|cyou|sbs|lol|mobi|ly|gl|gd|at|to|zip|mov|quest|monster|cam|gov|edu|uk|ca|de|in)(?:\/[^\s<>"'`)\]}]*)?/gi;

    function findUrls(text) {
        const out = [];
        let m;
        URL_RE.lastIndex = 0;
        while ((m = URL_RE.exec(text))) {
            const prev = text[m.index - 1];
            if (prev === "@" || /[a-z0-9]/i.test(prev || "")) continue; // email address or part of a word
            out.push(m[0].replace(/[.,;:!?]+$/, ""));
        }
        return out;
    }

    function parseHost(url) {
        let u = url.trim();
        if (!/^[a-z][a-z0-9+.-]*:/i.test(u)) u = "http://" + u;
        try {
            const parsed = new URL(u);
            return { host: parsed.hostname.toLowerCase(), protocol: parsed.protocol, raw: url, hasAt: /^[a-z]+:\/\/[^/]*@/i.test(u) };
        } catch (e) {
            return null;
        }
    }

    function hostMatches(host, domains) {
        return domains.some(function (d) { return host === d || host.slice(-(d.length + 1)) === "." + d; });
    }

    function analyzeLinks(urls, anchorLinks) {
        const flags = [];
        const seen = {};
        const add = function (f) {
            if (!seen[f.id]) { seen[f.id] = true; flags.push(f); }
        };

        const hosts = [];
        urls.forEach(function (url) {
            if (/^(mailto|tel|sms|#|javascript:)/i.test(url)) {
                if (/^javascript:/i.test(url)) add(indicator("js-link", "Link runs hidden code", "a javascript: link", 25, "contains a link that runs hidden code"));
                return;
            }
            const info = parseHost(url);
            if (info && info.host) hosts.push(info);
        });

        if (!hosts.length) return { flags: flags, hosts: [] };

        add(indicator("link", "Unverified link", "may lead to a fake website", 12, "includes a link you can't verify"));

        hosts.forEach(function (h) {
            const host = h.host;
            const tokens = host.split(/[.-]/);
            const tld = tokens[tokens.length - 1];

            // brand name in the address, but not the brand's real website
            Object.keys(BRANDS).forEach(function (brand) {
                const inHost = tokens.indexOf(brand) >= 0 || (brand.length >= 5 && host.replace(/[.-]/g, "").indexOf(brand) >= 0);
                if (inHost && !hostMatches(host, BRANDS[brand])) {
                    add(indicator("lookalike", "Lookalike website address",
                        host + " is not the official " + (BRAND_NAMES[brand] || brand) + " website", 30,
                        "links to a website that imitates " + (BRAND_NAMES[brand] || brand)));
                }
            });

            if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || /^\[[0-9a-f:]+\]$/.test(host)) {
                add(indicator("ip-link", "Link uses a raw IP address", host, 25, "links to a bare IP address instead of a named website"));
            }
            if (host.indexOf("xn--") >= 0) {
                add(indicator("punycode", "Disguised characters in link", "uses look-alike letters", 25, "uses look-alike characters to disguise a web address"));
            }
            if (hostMatches(host, SHORTENERS)) {
                add(indicator("shortener", "Shortened link", "hides the real destination", 16, "uses a shortened link that hides where it really goes"));
            }
            if (RISKY_TLDS.indexOf(tld) >= 0) {
                add(indicator("risky-tld", "Unusual domain ending", "." + tld + " sites are often used by scammers", 15, "links to a domain ending (." + tld + ") that scammers often use"));
            }
            if (h.hasAt) {
                add(indicator("at-link", "Misleading link format", "an @ sign hides the real address", 22, "uses a misleading link format"));
            }
            if (SUSPICIOUS_HOST_WORDS.test(host) && !Object.keys(BRANDS).some(function (b) { return hostMatches(host, BRANDS[b]); })) {
                add(indicator("host-words", "Suspicious words in web address", "e.g. \"verify\", \"secure\", \"login\"", 10, "has a web address stuffed with words like \"secure\" or \"verify\""));
            }
            if ((host.match(/-/g) || []).length >= 3 || host.split(".").length > 5) {
                add(indicator("long-host", "Overly complicated web address", host, 8, "uses an unusually complicated web address"));
            }
            if (h.protocol === "http:" && /^http:/i.test(h.raw)) {
                add(indicator("no-https", "Insecure link", "doesn't use HTTPS", 6, "uses an insecure (non-HTTPS) link"));
            }
        });

        // Visible link text shows one site but the link goes to another
        (anchorLinks || []).forEach(function (a) {
            const shown = findUrls(a.text || "")[0];
            if (!shown || !a.href) return;
            const s = parseHost(shown);
            const t = parseHost(a.href);
            if (s && t && s.host && t.host && s.host.replace(/^www\./, "") !== t.host.replace(/^www\./, "")) {
                add(indicator("mismatch-link", "Link text doesn't match destination",
                    "shows " + s.host + " but opens " + t.host, 28,
                    "shows one web address but actually links to another"));
            }
        });

        return { flags: flags, hosts: hosts.map(function (h) { return h.host; }) };
    }

    /* ---------------------------------------------------------
       CORE ANALYSIS
    --------------------------------------------------------- */
    function indicator(id, title, detail, weight, explain) {
        return { id: id, title: title, detail: detail, weight: weight, explain: explain, severity: weight >= 25 ? "high" : weight >= 12 ? "medium" : "low" };
    }

    function detectCategory(text, meta) {
        for (let i = 0; i < CATEGORIES.length; i++) {
            if (CATEGORIES[i].test.test(text)) return CATEGORIES[i];
        }
        if (meta && meta.kind === "email") return { id: "email", title: "Email Message", icon: "fa-envelope-open-text", tactic: "phishing scams" };
        const KIND = {
            archive: ["Archive File", "fa-file-zipper"], program: ["Program File", "fa-file-circle-exclamation"],
            pdf: ["PDF Document", "fa-file-pdf"], document: ["Word Document", "fa-file-word"], image: ["Screenshot / Image", "fa-file-image"],
            html: ["Web Page File", "fa-file-code"], text: ["Text Document", "fa-file-lines"]
        };
        if (meta && meta.fileName) {
            const k = KIND[meta.kind] || ["Uploaded File", "fa-file-shield"];
            return { id: "file", title: k[0], icon: k[1], tactic: "malware and phishing scams" };
        }
        return { id: "message", title: "Text Message", icon: "fa-comment-dots", tactic: "phishing scams" };
    }

    function joinPhrases(list) {
        if (list.length <= 1) return list.join("");
        if (list.length === 2) return list[0] + " and " + list[1];
        return list.slice(0, -1).join(", ") + ", and " + list[list.length - 1];
    }

    function buildExplanation(level, indicators, category, meta, hasText) {
        const subject = meta && meta.kind === "email" ? "This email" : meta && meta.fileName ? "This file" : "The message";
        const top = indicators.slice().sort(function (a, b) { return b.weight - a.weight; }).slice(0, 4).map(function (i) { return i.explain; });

        if (!indicators.length) {
            if (!hasText) {
                return "We couldn't find any readable text to analyze, and the file type itself didn't raise any red flags. If you weren't expecting this file, check with the sender before opening it.";
            }
            return subject + " doesn't show common scam warning signs — it doesn't pressure you, ask for money or personal details, or include risky links. Still, if it was unexpected, confirm with the sender through a channel you already trust.";
        }
        if (level === "high") {
            return subject + " " + joinPhrases(top) + ". These are common tactics used in " + category.tactic + ".";
        }
        if (level === "medium") {
            return subject + " " + joinPhrases(top) + ". This could be legitimate, but these are also patterns seen in " + category.tactic + ", so verify it independently before you act.";
        }
        return subject + " has only minor warning signs: it " + joinPhrases(top) + ". It's probably fine, but stay cautious if you weren't expecting it.";
    }

    function buildActions(level, indicators, meta) {
        const ids = {};
        indicators.forEach(function (i) { ids[i.id] = true; });
        const actions = [];
        const isFile = !!(meta && meta.fileName);
        const fileDanger = ids["dangerous-file"] || ids["hidden-program"] || ids["macros"] || ids["archive-program"] || ids["pdf-actions"] || ids["dangerous-attachment"] || ids["double-extension"];

        if (fileDanger) actions.push("Do not open, run, or enable content in this file. Delete it if you weren't expecting it.");
        if (ids["link"] || ids["lookalike"] || ids["shortener"] || ids["mismatch-link"]) {
            actions.push(ids["payment"] || ids["untraceable"] ? "Do not click the link or provide any payment information." : "Do not click the link — type the company's web address yourself instead.");
        } else if (ids["payment"] || ids["untraceable"]) {
            actions.push("Do not send money, gift cards, or card details.");
        }
        if (ids["credentials"] || ids["password-form"]) actions.push("Never share passwords, one-time codes, or personal details in response to a message.");
        if (ids["impersonation-family"]) actions.push("Call your family member on the number you already have for them.");
        if (ids["techsupport"]) actions.push("Don't call the number or let anyone remotely access your device.");

        if (level !== "low" || indicators.length) {
            actions.push("Verify the message through the company's official website or phone number.");
        }
        if (level === "high") {
            actions.push(isFile
                ? "Report it to your email provider or IT team, and at reportfraud.ftc.gov."
                : "Report the message if possible (e.g., forward scam texts to 7726, or report at reportfraud.ftc.gov).");
        }
        if (!actions.length) {
            actions.push("No action needed — but stay alert for unexpected requests for money or information.");
            actions.push("If anything feels off, contact the sender through a channel you already trust.");
        }
        return actions.slice(0, 4);
    }

    function analyze(input) {
        const text = (input.text || "").slice(0, 200000);
        const meta = input.meta || {};
        const indicators = [];

        TEXT_RULES.forEach(function (rule) {
            if (rule.patterns.some(function (p) { return p.test(text); })) {
                indicators.push(indicator(rule.id, rule.title, rule.detail, rule.weight, rule.explain));
            }
        });

        // Shouting / excessive punctuation
        const letters = text.replace(/[^A-Za-z]/g, "");
        const caps = text.replace(/[^A-Z]/g, "");
        if ((letters.length > 30 && caps.length / letters.length > 0.6) || /!{3,}/.test(text)) {
            indicators.push(indicator("formatting", "Unusual formatting", "lots of capitals or exclamation marks", 6, "uses attention-grabbing capitals or exclamation marks"));
        }

        const anchorLinks = input.links || [];
        const urls = findUrls(text).concat(anchorLinks.map(function (l) { return l.href; }).filter(Boolean));
        const linkResult = analyzeLinks(urls, anchorLinks);
        linkResult.flags.forEach(function (f) { indicators.push(f); });

        (input.flags || []).forEach(function (f) {
            if (!indicators.some(function (i) { return i.id === f.id; })) indicators.push(f);
        });

        // A lone link with nothing else suspicious is only a mild signal
        const total = indicators.reduce(function (sum, i) { return sum + i.weight; }, 0);
        let score = Math.round(100 * (1 - Math.exp(-total / 45)));
        score = Math.max(score, indicators.length ? 8 : 3);
        score = Math.min(score, 99);
        // Dangerous file types are always high risk
        if (indicators.some(function (i) { return i.weight >= 45; })) score = Math.max(score, 85);

        const level = score >= 70 ? "high" : score >= 35 ? "medium" : "low";
        indicators.sort(function (a, b) { return b.weight - a.weight; });
        const category = detectCategory(text, meta);

        return {
            score: score,
            level: level,
            indicators: indicators,
            category: { id: category.id, title: category.title, icon: category.icon },
            explanation: buildExplanation(level, indicators, category, meta, !!text.trim()),
            actions: buildActions(level, indicators, meta),
            links: linkResult.hosts
        };
    }

    /* ---------------------------------------------------------
       PUBLIC SCAN API
       scan({ text, files }, onProgress) -> Promise<[record]>
       Every record is saved to History.
    --------------------------------------------------------- */
    async function scanText(text, extra) {
        const analysis = analyze({ text: text, links: [], flags: [], meta: {} });
        return buildRecord(analysis, { source: "text", text: text, notes: [] }, extra);
    }

    async function scanFile(file, onProgress) {
        const ex = await extractFromFile(file, onProgress);
        if (ex.attachments && ex.attachments.length) {
            ex.notes.push("Attachments: " + ex.attachments.join(", "));
        }
        const meta = { fileName: file.name, kind: ex.kind };
        const analysis = analyze({ text: ex.text, links: ex.links, flags: ex.flags, meta: meta });
        return buildRecord(analysis, {
            source: "file",
            text: ex.text,
            notes: ex.notes,
            file: { name: file.name, size: file.size, type: file.type || extOf(file.name).toUpperCase(), kind: ex.kind },
            email: ex.email
        });
    }

    function buildRecord(analysis, src) {
        const cleanText = (src.text || "").replace(/\s+\n/g, "\n").trim();
        const excerpt = cleanText.replace(/\s+/g, " ").slice(0, 140);
        return {
            id: uid(),
            createdAt: new Date().toISOString(),
            source: src.source,
            title: analysis.category.title,
            icon: analysis.category.icon,
            category: analysis.category.id,
            file: src.file || null,
            email: src.email ? { from: src.email.from, subject: src.email.subject } : null,
            excerpt: excerpt,
            text: cleanText.slice(0, MAX_STORED_TEXT),
            textTruncated: cleanText.length > MAX_STORED_TEXT,
            notes: src.notes || [],
            score: analysis.score,
            level: analysis.level,
            indicators: analysis.indicators.map(function (i) { return { id: i.id, title: i.title, detail: i.detail, severity: i.severity }; }),
            explanation: analysis.explanation,
            actions: analysis.actions,
            links: analysis.links
        };
    }

    async function scan(input, onProgress) {
        const records = [];
        const text = (input.text || "").trim();
        if (text) {
            if (onProgress) onProgress("Analyzing message…");
            records.push(await scanText(text));
        }
        const files = Array.from(input.files || []);
        for (let i = 0; i < files.length; i++) {
            const prefix = files.length > 1 ? "(" + (i + 1) + "/" + files.length + ") " : "";
            records.push(await scanFile(files[i], function (msg) { if (onProgress) onProgress(prefix + msg); }));
        }
        records.forEach(saveRecord);
        return records;
    }

    /* ---------------------------------------------------------
       HISTORY STORAGE
    --------------------------------------------------------- */
    let memoryHistory = [];

    function getHistory() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            const list = raw ? JSON.parse(raw) : [];
            return Array.isArray(list) ? list : [];
        } catch (e) {
            return memoryHistory.slice();
        }
    }

    function setHistory(list) {
        memoryHistory = list.slice(0, MAX_HISTORY);
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(memoryHistory));
        } catch (e) {
            // Storage full: drop stored text from older scans and try again
            try {
                const slim = memoryHistory.map(function (r, i) { return i < 20 ? r : Object.assign({}, r, { text: r.excerpt, textTruncated: true }); });
                localStorage.setItem(STORAGE_KEY, JSON.stringify(slim));
            } catch (e2) { /* keep in memory only */ }
        }
    }

    function saveRecord(record) {
        const list = getHistory();
        list.unshift(record);
        setHistory(list);
    }

    function getRecord(id) {
        return getHistory().find(function (r) { return r.id === id; }) || null;
    }

    function deleteRecord(id) {
        const list = getHistory();
        const index = list.findIndex(function (r) { return r.id === id; });
        if (index < 0) return null;
        const removed = list.splice(index, 1)[0];
        setHistory(list);
        return { record: removed, index: index };
    }

    function restoreRecord(record, index) {
        const list = getHistory();
        list.splice(Math.min(index, list.length), 0, record);
        setHistory(list);
    }

    function clearHistory() {
        setHistory([]);
    }

    function formatDate(iso) {
        const d = new Date(iso);
        const date = d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
        const time = d.toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit" });
        return date + " · " + time;
    }

    window.ScamShield = {
        scan: scan,
        analyze: analyze,
        findUrls: findUrls,
        getHistory: getHistory,
        getRecord: getRecord,
        deleteRecord: deleteRecord,
        restoreRecord: restoreRecord,
        clearHistory: clearHistory,
        formatDate: formatDate,
        formatBytes: formatBytes,
        escapeHtml: escapeHtml,
        MAX_FILE_SIZE: MAX_FILE_SIZE
    };
})();
