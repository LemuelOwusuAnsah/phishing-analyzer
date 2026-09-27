const $ = (id) => document.getElementById(id);

const input = $("url");
const btn = $("analyzeBtn");
const result = $("result");
const list = $("findingsList");

const SEVERITY_COLORS = {
  high: "#ff3b5c",
  medium: "#ff9f1c",
  low: "#ffd60a",
  safe: "#00ff9c",
};

async function analyze() {
  const url = input.value.trim();
  if (!url) return;

  btn.disabled = true;
  btn.textContent = "...";

  try {
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const data = await res.json();
    render(data);
  } catch (err) {
    alert("Analysis failed: " + err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "ANALYZE";
  }
}

function render(data) {
  result.classList.remove("hidden");

  const color = SEVERITY_COLORS[
    data.color === "green" ? "safe" : data.color
  ] || "#c9d6e3";

  const badge = $("verdictBadge");
  badge.textContent = data.verdict;
  badge.style.color = color;
  badge.style.background = color + "18";

  const scoreEl = $("scoreValue");
  scoreEl.textContent = data.score;
  scoreEl.style.color = color;

  $("metaHost").textContent = data.hostname || "—";
  $("metaDomain").textContent = data.registered_domain || "—";
  $("metaScheme").textContent = data.scheme || "—";
  $("metaEntropy").textContent = data.entropy;

  list.innerHTML = "";

  if (!data.findings.length) {
    const li = document.createElement("li");
    li.className = "no-findings";
    li.textContent = "✓ No suspicious indicators detected.";
    list.appendChild(li);
    return;
  }

  data.findings.forEach((f, i) => {
    const li = document.createElement("li");
    li.className = "sev-" + f.severity;
    li.style.animationDelay = i * 40 + "ms";
    li.innerHTML =
      '<div class="finding-title">[' +
      f.severity.toUpperCase() +
      "] " +
      escapeHtml(f.title) +
      "</div>" +
      '<div class="finding-detail">' +
      escapeHtml(f.detail) +
      "</div>";
    list.appendChild(li);
  });
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (ch) => {
    return {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    }[ch];
  });
}

btn.addEventListener("click", analyze);

input.addEventListener("keydown", (e) => {
  if (e.key === "Enter") analyze();
});

document.querySelectorAll(".sample").forEach((b) => {
  b.addEventListener("click", () => {
    input.value = b.dataset.url;
    analyze();
  });
});
