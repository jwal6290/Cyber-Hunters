const messageInput = document.getElementById("messageInput");
const analyzeButton = document.getElementById("analyzeButton");
const fileUpload = document.getElementById("fileUpload");
const fileName = document.getElementById("fileName");
const scannerStatus = document.getElementById("scannerStatus");

// Display selected file(s)
fileUpload.addEventListener("change", function () {
    const files = Array.from(fileUpload.files);
    if (files.length === 1) {
        fileName.textContent = "Selected file: " + files[0].name;
    } else if (files.length > 1) {
        fileName.textContent = "Selected files: " + files.map(function (f) { return f.name; }).join(", ");
    } else {
        fileName.textContent = "";
    }
    scannerStatus.textContent = "";
});

// Analyze the message and/or files, then open the results page
analyzeButton.addEventListener("click", async function () {
    const message = messageInput.value.trim();
    const files = Array.from(fileUpload.files);

    if (!message && !files.length) {
        scannerStatus.textContent = "Please enter a message or upload a file first.";
        return;
    }

    analyzeButton.disabled = true;
    scannerStatus.textContent = "Analyzing…";

    try {
        const records = await window.ScamShield.scan({ text: message, files: files }, function (msg) {
            scannerStatus.textContent = msg;
        });
        window.location.href = "results.html?ids=" + records.map(function (r) { return r.id; }).join(",");
    } catch (err) {
        console.error(err);
        scannerStatus.textContent = "Something went wrong while scanning. Please try again.";
        analyzeButton.disabled = false;
    }
});

// Clear status when user edits input
messageInput.addEventListener("input", function () {
    scannerStatus.textContent = "";
});
