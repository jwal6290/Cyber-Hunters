const messageInput = document.getElementById("messageInput");
const analyzeButton = document.getElementById("analyzeButton");
const fileUpload = document.getElementById("fileUpload");
const fileName = document.getElementById("fileName");
const scannerStatus = document.getElementById("scannerStatus");

// Display selected screenshot
fileUpload.addEventListener("change", function () {
    if (fileUpload.files.length > 0) {
        fileName.textContent = "Selected file: " + fileUpload.files[0].name;
        scannerStatus.textContent = "";
    }
});

// Handle message submission
analyzeButton.addEventListener("click", function () {
    const message = messageInput.value.trim();
    const file = fileUpload.files[0];

    if (!message && !file) {
        scannerStatus.textContent =
            "Please enter a message or upload a screenshot first.";
        return;
    }

    scannerStatus.textContent =
        "Your submission is ready. Scam analysis will be available once the backend is connected.";
});

// Clear status when user edits input
messageInput.addEventListener("input", function () {
    scannerStatus.textContent = "";
});
