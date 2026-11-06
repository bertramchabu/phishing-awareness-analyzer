const fileInput = document.querySelector("#email-file");
const dropZone = document.querySelector("#drop-zone");
const filePrompt = document.querySelector("#file-prompt");
const selectedFile = document.querySelector("#selected-file");
const fileName = document.querySelector("#file-name");
const fileSize = document.querySelector("#file-size");
const analyzeButton = document.querySelector("#analyze-button");
const removeFileButton = document.querySelector("#remove-file");
const uploadError = document.querySelector("#upload-error");
const reportStatus = document.querySelector("#report-status");
const emptyState = document.querySelector("#empty-state");
const report = document.querySelector("#report");
let currentFile = null;

const MAX_FILE_BYTES = 1_048_576;

function formatBytes(bytes) {
  return bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KB`;
}

function setError(message) {
  uploadError.textContent = message;
  uploadError.hidden = !message;
}

function setFile(file) {
  setError("");
  if (!file) return;
  if (!file.name.toLowerCase().endsWith(".eml")) {
    setError("Please choose an .eml email file.");
    return;
  }
  if (file.size > MAX_FILE_BYTES) {
    setError("Files must be 1 MB or smaller.");
    return;
  }
  if (file.size === 0) {
    setError("The selected file is empty.");
    return;
  }

  currentFile = file;
  fileName.textContent = file.name;
  fileSize.textContent = formatBytes(file.size);
  filePrompt.textContent = "Sample ready to analyze";
  selectedFile.hidden = false;
  analyzeButton.disabled = false;
}

function clearFile() {
  currentFile = null;
  fileInput.value = "";
  filePrompt.textContent = "Drop your email sample here";
  selectedFile.hidden = true;
  analyzeButton.disabled = true;
  setError("");
}

function setLoading(loading) {
  analyzeButton.disabled = loading || !currentFile;
  analyzeButton.classList.toggle("loading", loading);
  analyzeButton.querySelector("span").textContent = loading ? "Analyzing" : "Analyze email";
  if (loading) reportStatus.textContent = "ANALYZING";
}

function renderReport(result) {
  const score = Math.max(0, Math.min(100, Number(result.score) || 0));
  const level = result.level;
  const levelClass = level === "High risk" ? "high" : level === "Suspicious" ? "suspicious" : "";
  const ring = document.querySelector("#risk-ring");
  const levelHeading = document.querySelector("#risk-level");
  const findingList = document.querySelector("#finding-list");

  emptyState.hidden = true;
  report.hidden = false;
  reportStatus.textContent = "ANALYSIS COMPLETE";
  document.querySelector("#risk-score").textContent = String(score);
  document.querySelector("#risk-summary").textContent =
    level === "High risk"
      ? "Several warning signs were detected. Treat this message with extra caution."
      : level === "Suspicious"
        ? "Some signals deserve a closer look before you trust this message."
        : "Few strong warning signs were detected. Always verify unexpected requests.";
  document.querySelector("#sender-value").textContent = result.from || "Sender not provided";
  document.querySelector("#finding-count").textContent = String(result.findings.length);
  ring.className = `risk-ring ${levelClass}`.trim();
  ring.style.setProperty("--score-angle", `${score * 3.6}deg`);
  levelHeading.textContent = level;
  levelHeading.className = levelClass;
  document.querySelector("#scale-fill").style.marginLeft = `calc(${score}% - ${score > 92 ? "7px" : "0px"})`;

  findingList.replaceChildren();
  const findings = result.findings.length ? result.findings : ["No strong indicators found in this sample."];
  for (const finding of findings) {
    const item = document.createElement("div");
    item.className = `finding-item${result.findings.length ? "" : " empty"}`;
    const marker = document.createElement("span");
    marker.className = "finding-marker";
    marker.textContent = result.findings.length ? "!" : "✓";
    const text = document.createElement("span");
    text.textContent = finding;
    item.append(marker, text);
    findingList.append(item);
  }
}

async function analyze(file) {
  if (!file) return;
  setError("");
  setLoading(true);
  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body: file,
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || "Unable to analyze this sample.");
    renderReport(payload);
  } catch (error) {
    setError(error instanceof Error ? error.message : "Unable to analyze this sample.");
    reportStatus.textContent = "ANALYSIS FAILED";
  } finally {
    setLoading(false);
  }
}

fileInput.addEventListener("change", () => setFile(fileInput.files?.[0]));
analyzeButton.addEventListener("click", () => analyze(currentFile));
removeFileButton.addEventListener("click", clearFile);

for (const eventName of ["dragenter", "dragover"]) {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.add("dragging");
  });
}
for (const eventName of ["dragleave", "drop"]) {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.remove("dragging");
  });
}
dropZone.addEventListener("drop", (event) => setFile(event.dataTransfer?.files?.[0]));

for (const button of document.querySelectorAll(".sample-button")) {
  button.addEventListener("click", async () => {
    setError("");
    button.disabled = true;
    try {
      const response = await fetch(`/samples/${encodeURIComponent(button.dataset.sample)}`);
      if (!response.ok) throw new Error("Unable to load the sample.");
      const blob = await response.blob();
      const file = new File([blob], button.dataset.sample, { type: "message/rfc822" });
      setFile(file);
      await analyze(file);
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unable to load the sample.");
    } finally {
      button.disabled = false;
    }
  });
}
