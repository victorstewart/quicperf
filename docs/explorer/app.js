"use strict";

const CAMPAIGN =
  "ca3fc47654e15b3c42a79c6c24a6477952e3a37ac8fc01ee2e8b85ce7d2d5492";
const DATA_ROOT = `../results/v2/${CAMPAIGN}`;
const PAGE_SIZE = 50;

const SCENARIO_ORDER = [
  "bidi",
  "close_reset_cleanup",
  "connect",
  "datagram",
  "download",
  "flow_control",
  "loss_recovery",
  "multistream_download",
  "multistream_upload",
  "reqresp",
  "resumed_connect",
  "small_payload_pps",
  "stream_churn",
  "upload",
  "zero_rtt_reqresp",
];

const SCENARIOS = {
  bidi: {
    title: "Bidirectional transfer",
    eyebrow: "Throughput",
    description: "Concurrent application data in both directions.",
  },
  close_reset_cleanup: {
    title: "Close & reset cleanup",
    eyebrow: "Lifecycle",
    description:
      "Combined FIN, RESET_STREAM, STOP_SENDING, and close cleanup rate.",
  },
  connect: {
    title: "Fresh connection",
    eyebrow: "Handshake",
    description: "Completed new QUIC connections per second.",
  },
  datagram: {
    title: "Datagram",
    eyebrow: "Packets",
    description: "Validated QUIC DATAGRAM operations per second.",
  },
  download: {
    title: "Download",
    eyebrow: "Throughput",
    description: "Validated server-to-client application body throughput.",
  },
  flow_control: {
    title: "Flow control",
    eyebrow: "Throughput",
    description: "Transfer throughput while exercising flow-control updates.",
  },
  loss_recovery: {
    title: "Loss recovery",
    eyebrow: "Impaired path",
    description: "Validated throughput through the campaign loss profile.",
  },
  multistream_download: {
    title: "Multistream download",
    eyebrow: "Concurrency",
    description:
      "Aggregate server-to-client throughput across concurrent streams.",
  },
  multistream_upload: {
    title: "Multistream upload",
    eyebrow: "Concurrency",
    description:
      "Aggregate client-to-server throughput across concurrent streams.",
  },
  reqresp: {
    title: "Request / response",
    eyebrow: "Transactions",
    description: "Completed request-response exchanges per second.",
  },
  resumed_connect: {
    title: "Resumed connection",
    eyebrow: "Handshake",
    description: "Completed session-resumption connections per second.",
  },
  small_payload_pps: {
    title: "Small-payload packet rate",
    eyebrow: "Packets",
    description: "Validated small-payload operations per second.",
  },
  stream_churn: {
    title: "Stream churn",
    eyebrow: "Lifecycle",
    description: "Rapid stream creation and completion operations per second.",
  },
  upload: {
    title: "Upload",
    eyebrow: "Throughput",
    description: "Validated client-to-server application body throughput.",
  },
  zero_rtt_reqresp: {
    title: "0-RTT request / response",
    eyebrow: "Early data",
    description: "Completed early-data request-response operations per second.",
  },
};

const SERVER_NAMES = {
  lsperf: "LSQUIC",
  mvfstperf: "mvfst",
  neqoperf: "Neqo",
  ngtcp2perf: "ngtcp2",
  noqperf: "noq",
  picoperf: "picoquic",
  quicheperf: "quiche",
  quiczigperf: "quiczig",
  quinnperf: "Quinn",
  s2nperf: "s2n-quic",
  tquicperf: "TQUIC",
  xquicperf: "XQUIC",
};

const EVIDENCE = [
  ["Aggregated results", "180 complete result rows · TSV", "row-results.tsv"],
  [
    "Statistical comparisons",
    "1,155 baseline and all-pairs contrasts · TSV",
    "comparisons.tsv",
  ],
  [
    "Per-sample quality audit",
    "4,320 compact validity records · TSV",
    "quality-audit.tsv",
  ],
  [
    "Scenario coverage",
    "Capability and interoperability evidence · TSV",
    "scenario-coverage.tsv",
  ],
  [
    "Cleanup strata",
    "Detailed close/reset lifecycle results · TSV",
    "cleanup-strata.tsv",
  ],
  ["Campaign analysis", "Publication status and runtime efficiency · JSON", "analysis.json"],
  [
    "Host qualification",
    "Hardware-stability qualification summary · JSON",
    "qualification/host-stability.json",
  ],
  [
    "Client headroom",
    "Four-client-core qualification evidence · JSON",
    "qualification/client-headroom.json",
  ],
  [
    "Native interoperability",
    "Cross-implementation capability evidence · JSON",
    "qualification/native-interoperability.json",
  ],
  [
    "Runtime sessions",
    "Qualified duration and measurement-efficiency records · JSON",
    "runtime/session-1.json",
  ],
  [
    "Compact manifest",
    "Checksums for every committed public artifact · JSON",
    "public-bundle-manifest.json",
  ],
  [
    "Full evidence inventory",
    "Prepared checksummed release assets; excluded from Git · JSON",
    "release-assets.json",
  ],
];

let results = [];
let comparisons = [];
let comparisonPage = 0;

function parseTsv(text) {
  const lines = text.trimEnd().split(/\r?\n/);
  const headers = lines.shift().split("\t");
  return lines.filter(Boolean).map((line) =>
    Object.fromEntries(
      line.split("\t").map((value, index) => [headers[index], value]),
    ),
  );
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function serverName(server) {
  return SERVER_NAMES[server] || server;
}

function scenarioFromComparison(row) {
  return row.family.split("|")[1] || "";
}

function formatValue(row) {
  const value = Number(row.geometric_mean);
  if (row.metric.includes("bits_per_second")) {
    return `${(value / 1_000_000_000).toFixed(3)} Gbit/s`;
  }
  return `${value.toLocaleString("en-US", {
    minimumFractionDigits: 1,
    maximumFractionDigits: 1,
  })} ops/s`;
}

function rawValue(row) {
  const value = Number(row.geometric_mean);
  const unit = row.metric.includes("bits_per_second") ? "bit/s" : "ops/s";
  return `${value.toLocaleString("en-US", {
    minimumFractionDigits: 3,
    maximumFractionDigits: 3,
  })} ${unit}`;
}

function orientedComparison(row, leader) {
  const [left, right] = row.contrast.split("/");
  const point = Number(row.point_ratio);
  const low = Number(row.low_ratio);
  const high = Number(row.high_ratio);

  if (left === leader) {
    return { classification: row.classification, point, low, high };
  }
  if (right !== leader) return null;
  const inverse = {
    superior: "inferior",
    inferior: "superior",
    equivalent: "equivalent",
    inconclusive: "inconclusive",
  };
  return {
    classification: inverse[row.classification],
    point: 1 / point,
    low: 1 / high,
    high: 1 / low,
  };
}

function decisionSummary(ranked, scenarioComparisons) {
  const leader = ranked[0]?.server;
  const runner = ranked[1]?.server;
  if (!leader || !runner) {
    return { label: "Unavailable", tone: "neutral", detail: "" };
  }
  const decisions = scenarioComparisons
    .filter((row) => row.contrast.split("/").includes(leader))
    .map((row) => ({
      row,
      oriented: orientedComparison(row, leader),
    }))
    .filter(({ oriented }) => oriented);
  const runnerDecision = decisions.find(({ row }) =>
    row.contrast.split("/").includes(runner),
  )?.oriented?.classification;
  const unresolved = decisions.filter(
    ({ oriented }) => oriented.classification !== "superior",
  ).length;

  if (decisions.length === 11 && unresolved === 0) {
    return {
      label: "Confirmed winner",
      tone: "confirmed",
      detail: "Superior to all 11 rivals",
    };
  }
  if (runnerDecision === "equivalent") {
    return {
      label: "No unique winner",
      tone: "equivalent",
      detail: `Equivalent to ${serverName(runner)}`,
    };
  }
  if (runnerDecision === "inconclusive") {
    return {
      label: "Observed leader",
      tone: "observed",
      detail: "Runner-up contrast inconclusive",
    };
  }
  return {
    label: "Observed leader",
    tone: "observed",
    detail: `${unresolved} lower-rival contrast${unresolved === 1 ? "" : "s"} gated`,
  };
}

function decisionLabel(classification) {
  return {
    superior: "Leader superior",
    inferior: "Leader inferior",
    equivalent: "Equivalent",
    inconclusive: "Inconclusive",
  }[classification] || classification;
}

function allPairsForScenario(scenario) {
  return comparisons.filter(
    (row) =>
      row.comparison_family === "all_pairs" &&
      scenarioFromComparison(row) === scenario,
  );
}

function rankedRowsForScenario(scenario) {
  return results
    .filter((row) => row.scenario === scenario)
    .toSorted(
      (left, right) =>
        Number(right.geometric_mean) - Number(left.geometric_mean),
    );
}

function renderLeaderSummary() {
  const leaders = SCENARIO_ORDER.map((scenario) => {
    const ranked = rankedRowsForScenario(scenario);
    const verdict = decisionSummary(ranked, allPairsForScenario(scenario));
    return { server: ranked[0].server, confirmed: verdict.tone === "confirmed" };
  });
  const counts = [...new Set(leaders.map(({ server }) => server))]
    .map((server) => ({
      server,
      observed: leaders.filter((leader) => leader.server === server).length,
      confirmed: leaders.filter(
        (leader) => leader.server === server && leader.confirmed,
      ).length,
    }))
    .toSorted(
      (left, right) =>
        right.observed - left.observed || left.server.localeCompare(right.server),
    );

  const cards = counts
    .map(
      (leader, index) => `
        <article class="winner-card">
          <div class="winner-number">${String(index + 1).padStart(2, "0")}</div>
          <p class="eyebrow">Observed scenario leads</p>
          <h3>${escapeHtml(serverName(leader.server))}</h3>
          <code>${escapeHtml(leader.server)}</code>
          <div class="winner-score">
            <strong>${leader.observed}</strong>
            <span>of 15 observed leads</span>
          </div>
          <div class="winner-meter">
            <span style="width: ${(leader.observed / 15) * 100}%"></span>
          </div>
          <p><strong>${leader.confirmed}</strong> fully confirmed scenario
            ${leader.confirmed === 1 ? "win" : "wins"}</p>
        </article>`,
    )
    .join("");

  document.querySelector("#leader-summary").innerHTML = `${cards}
    <aside class="interpretation-card">
      <p class="eyebrow">How to read this</p>
      <h3>Fastest is not always statistically confirmed.</h3>
      <p>
        A contrast can be inconclusive when its variance-quality gate misses,
        even if its observed interval is far from equality. The tables show
        both the measured ranking and the formal decision.
      </p>
      <dl>
        <div><dt>Primary estimand</dt><dd>Equal ngtcp2 / picoquic client mixture</dd></div>
        <div><dt>Execution</dt><dd>io_uring · one server core · four client cores</dd></div>
        <div><dt>Replication</dt><dd>24 / 24 valid observations per result cell</dd></div>
      </dl>
    </aside>`;
}

function resultRowMarkup(row, index, leader, scenarioComparisons) {
  const relative = Number(row.geometric_mean) / Number(leader.geometric_mean);
  const comparison =
    index === 0
      ? null
      : scenarioComparisons.find((candidate) => {
          const servers = candidate.contrast.split("/");
          return servers.includes(leader.server) && servers.includes(row.server);
        });
  const oriented = comparison
    ? orientedComparison(comparison, leader.server)
    : null;
  let decision = '<span class="decision">Not available</span>';
  if (index === 0) {
    decision =
      '<span class="decision decision-leader">Observed leader</span>';
  } else if (oriented && comparison) {
    decision = `
      <span class="decision decision-${escapeHtml(oriented.classification)}">
        ${escapeHtml(decisionLabel(oriented.classification))}
      </span>
      <small class="interval">
        ${oriented.point.toFixed(3)}× · [${oriented.low.toFixed(3)},
        ${oriented.high.toFixed(3)}]
        ${comparison.variance_miss === "1" ? " · variance gate" : ""}
      </small>`;
  }
  return `
    <tr class="${index === 0 ? "is-leader" : ""}">
      <td><span class="rank">${String(index + 1).padStart(2, "0")}</span></td>
      <th scope="row">
        <span class="implementation-name">${escapeHtml(serverName(row.server))}</span>
        <code>${escapeHtml(row.server)}</code>
      </th>
      <td class="numeric">
        <strong>${escapeHtml(formatValue(row))}</strong>
        <small>${escapeHtml(rawValue(row))}</small>
      </td>
      <td class="relative-cell">
        <div class="relative-track"
          title="${(relative * 100).toFixed(1)}% of the observed leader">
          <span style="width: ${Math.max(2, relative * 100)}%"></span>
        </div>
        <small>${(relative * 100).toFixed(1)}%</small>
      </td>
      <td>${decision}</td>
      <td><span class="valid-count">${escapeHtml(row.valid)}/${escapeHtml(row.planned)}</span></td>
    </tr>`;
}

function renderScenarioResults() {
  document.querySelector("#scenario-results").innerHTML = SCENARIO_ORDER.map(
    (scenario) => {
      const ranked = rankedRowsForScenario(scenario);
      const scenarioComparisons = allPairsForScenario(scenario);
      const leader = ranked[0];
      const runner = ranked[1];
      const verdict = decisionSummary(ranked, scenarioComparisons);
      const lead =
        (Number(leader.geometric_mean) / Number(runner.geometric_mean) - 1) *
        100;
      const meta = SCENARIOS[scenario];
      return `
        <article class="scenario-card" id="scenario-${scenario}">
          <header class="scenario-header">
            <div>
              <p class="eyebrow">${escapeHtml(meta.eyebrow)}</p>
              <h3>${escapeHtml(meta.title)}</h3>
              <p class="scenario-description">${escapeHtml(meta.description)}</p>
            </div>
            <div class="verdict verdict-${escapeHtml(verdict.tone)}">
              <span>${escapeHtml(verdict.label)}</span>
              <strong>${escapeHtml(serverName(leader.server))}</strong>
              <small>${escapeHtml(verdict.detail)}</small>
            </div>
          </header>
          <div class="scenario-callout">
            <span class="winner-mark">01</span>
            <div>
              <strong>${escapeHtml(serverName(leader.server))}</strong>
              <code>${escapeHtml(leader.server)}</code>
            </div>
            <div class="winner-result">
              <strong>${escapeHtml(formatValue(leader))}</strong>
              <span>${lead.toFixed(1)}% ahead of the observed runner-up</span>
            </div>
          </div>
          <div class="table-scroll">
            <table class="ranking-table">
              <thead>
                <tr>
                  <th scope="col">Rank</th>
                  <th scope="col">Implementation</th>
                  <th scope="col">Geometric mean</th>
                  <th scope="col">Relative result</th>
                  <th scope="col">Decision vs leader</th>
                  <th scope="col">Valid</th>
                </tr>
              </thead>
              <tbody>
                ${ranked
                  .map((row, index) =>
                    resultRowMarkup(
                      row,
                      index,
                      leader,
                      scenarioComparisons,
                    ),
                  )
                  .join("")}
              </tbody>
            </table>
          </div>
        </article>`;
    },
  ).join("");
}

function filteredComparisons() {
  const scenario = document.querySelector("#scenario-filter").value;
  const family = document.querySelector("#family-filter").value;
  const classification = document.querySelector(
    "#classification-filter",
  ).value;
  const search = document
    .querySelector("#comparison-search")
    .value.trim()
    .toLowerCase();
  return comparisons.filter((row) => {
    const rowScenario = scenarioFromComparison(row);
    return (
      (scenario === "all" || scenario === rowScenario) &&
      (family === "all" || family === row.comparison_family) &&
      (classification === "all" || classification === row.classification) &&
      (!search ||
        row.contrast.toLowerCase().includes(search) ||
        (SCENARIOS[rowScenario]?.title || rowScenario)
          .toLowerCase()
          .includes(search))
    );
  });
}

function renderComparisons() {
  const filtered = filteredComparisons();
  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  comparisonPage = Math.min(comparisonPage, pageCount - 1);
  const first = comparisonPage * PAGE_SIZE;
  const page = filtered.slice(first, first + PAGE_SIZE);

  document.querySelector("#comparison-count").textContent =
    filtered.length.toLocaleString("en-US");
  document.querySelector("#page-label").textContent =
    `Page ${comparisonPage + 1} of ${pageCount}`;
  document.querySelector("#previous-page").disabled = comparisonPage === 0;
  document.querySelector("#next-page").disabled =
    comparisonPage >= pageCount - 1;
  document.querySelector("#comparison-rows").innerHTML =
    page.length === 0
      ? '<tr><td colspan="7">No comparisons match these filters.</td></tr>'
      : page
          .map((row) => {
            const scenario = scenarioFromComparison(row);
            return `
              <tr>
                <th scope="row">${escapeHtml(SCENARIOS[scenario]?.title || scenario)}</th>
                <td>${row.comparison_family === "all_pairs" ? "All pairs" : "Baseline"}</td>
                <td><code>${escapeHtml(row.contrast)}</code></td>
                <td class="numeric">${Number(row.point_ratio).toFixed(4)}×</td>
                <td class="numeric">[${Number(row.low_ratio).toFixed(4)},
                  ${Number(row.high_ratio).toFixed(4)}]</td>
                <td>
                  <span class="decision decision-${escapeHtml(row.classification)}">
                    ${escapeHtml(row.classification)}
                  </span>
                </td>
                <td>
                  <span class="quality-line">
                    ${row.variance_miss === "1" ? "Variance gate missed" : "Variance gate passed"}
                  </span>
                  <small>${escapeHtml(row.client_sensitivity.replaceAll("_", " "))} ·
                    ${escapeHtml(row.session_sensitivity.replaceAll("_", " "))}</small>
                </td>
              </tr>`;
          })
          .join("");
}

function initializeControls() {
  const scenarioFilter = document.querySelector("#scenario-filter");
  SCENARIO_ORDER.forEach((scenario) => {
    const option = document.createElement("option");
    option.value = scenario;
    option.textContent = SCENARIOS[scenario].title;
    scenarioFilter.append(option);
  });
  document
    .querySelector("#comparison-filters")
    .addEventListener("input", () => {
      comparisonPage = 0;
      renderComparisons();
    });
  document.querySelector("#previous-page").addEventListener("click", () => {
    comparisonPage = Math.max(0, comparisonPage - 1);
    renderComparisons();
  });
  document.querySelector("#next-page").addEventListener("click", () => {
    comparisonPage += 1;
    renderComparisons();
  });
}

function renderEvidence() {
  document.querySelector("#evidence-files").innerHTML = EVIDENCE.map(
    ([title, detail, path]) => `
      <a href="${DATA_ROOT}/${escapeHtml(path)}" class="evidence-card">
        <span>Open file</span>
        <h3>${escapeHtml(title)}</h3>
        <p>${escapeHtml(detail)}</p>
      </a>`,
  ).join("");
}

async function load() {
  renderEvidence();
  initializeControls();
  try {
    const [resultResponse, comparisonResponse] = await Promise.all([
      fetch(`${DATA_ROOT}/row-results.tsv`),
      fetch(`${DATA_ROOT}/comparisons.tsv`),
    ]);
    if (!resultResponse.ok || !comparisonResponse.ok) {
      throw new Error("The committed campaign evidence could not be loaded.");
    }
    [results, comparisons] = await Promise.all([
      resultResponse.text().then(parseTsv),
      comparisonResponse.text().then(parseTsv),
    ]);
    if (results.length !== 180 || comparisons.length !== 1155) {
      throw new Error(
        `Evidence count mismatch: ${results.length} results and ${comparisons.length} comparisons.`,
      );
    }
    renderLeaderSummary();
    renderScenarioResults();
    renderComparisons();
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "The results failed to load.";
    document.querySelector("#leader-summary").innerHTML = "";
    document.querySelector("#scenario-results").innerHTML = "";
    const banner = document.querySelector("#load-error");
    banner.textContent = message;
    banner.hidden = false;
  }
}

load();
