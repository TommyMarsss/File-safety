"use strict";

const fileInput = document.getElementById("file-input");
const uploadBtn = document.getElementById("upload-btn");
const uploadForm = document.getElementById("upload-form");
const resultBox = document.getElementById("result");
const historyList = document.getElementById("history");
const samplesBox = document.getElementById("samples");

fileInput.addEventListener("change", () => {
  uploadBtn.disabled = !fileInput.files.length;
});

uploadForm.addEventListener("submit", (e) => {
  e.preventDefault();
  const file = fileInput.files[0];
  if (file) uploadFile(file, file.name);
});

// 解码服务端 RFC 5987 编码的自定义头
function decodeRfc5987(value) {
  if (!value) return "";
  const prefix = "UTF-8''";
  const encoded = value.startsWith(prefix) ? value.slice(prefix.length) : value;
  try {
    return decodeURIComponent(encoded);
  } catch {
    return encoded;
  }
}

async function uploadFile(blob, filename) {
  setBusy(true);
  renderResult({ pending: true, filename });
  try {
    const form = new FormData();
    // 文件名原样放进 multipart 头，由服务端做安全判定
    form.append("file", blob, filename);
    const resp = await fetch("/upload", { method: "POST", body: form });
    const verdict = await resp.json();
    renderResult(verdict);
    appendHistory(verdict);
  } catch (err) {
    renderResult({ error: String(err) });
  } finally {
    setBusy(false);
  }
}

async function uploadSample(key, btn) {
  setBusy(true);
  try {
    const resp = await fetch("/api/samples/" + encodeURIComponent(key));
    if (!resp.ok) throw new Error("样本获取失败: " + resp.status);
    const filename = decodeRfc5987(resp.headers.get("X-Sample-Filename")) || key;
    const blob = await resp.blob();
    await uploadFile(blob, filename);
  } catch (err) {
    renderResult({ error: String(err) });
    setBusy(false);
  }
}

function setBusy(busy) {
  uploadBtn.disabled = busy || !fileInput.files.length;
  document.querySelectorAll(".sample-btn").forEach((b) => (b.disabled = busy));
}

function renderResult(v) {
  resultBox.className = "result";
  if (v.pending) {
    resultBox.classList.add("empty");
    resultBox.textContent = `正在上传 ${v.filename} …`;
    return;
  }
  if (v.error) {
    resultBox.classList.add("rejected");
    resultBox.innerHTML = "";
    const badge = el("span", "badge bad", "错误");
    resultBox.append(badge, document.createTextNode("请求失败：" + v.error));
    return;
  }
  resultBox.classList.add(v.accepted ? "accepted" : "rejected");
  resultBox.innerHTML = "";

  const badge = el("span", "badge " + (v.accepted ? "ok" : "bad"),
                   v.accepted ? "已接受" : "已拒绝");
  const fname = el("strong", "", v.original_filename || "(未命名)");
  resultBox.append(badge, fname);

  const meta = el("div", "meta");
  const parts = [];
  if (v.detected_type) parts.push("魔数识别类型：" + v.detected_type);
  if (v.stored_as) parts.push("服务端存储名：" + v.stored_as);
  meta.textContent = parts.join("　|　");
  if (parts.length) resultBox.append(meta);

  const ul = el("ul");
  for (const reason of v.reasons || []) {
    ul.append(el("li", "", reason));
  }
  resultBox.append(ul);

  if (v.extracted && v.extracted.length) {
    const div = el("div", "meta");
    div.textContent = "已安全解压：" + v.extracted.join(", ");
    resultBox.append(div);
  }
}

function appendHistory(v) {
  if (!v || v.accepted === undefined) return;
  const li = el("li");
  const tag = el("span", "tag " + (v.accepted ? "ok" : "bad"),
                 v.accepted ? "✓ 接受" : "✗ 拒绝");
  const name = el("span", "fname", v.original_filename || "(未命名)");
  const reason = el("span", "", (v.reasons && v.reasons[0]) || "");
  li.append(tag, name, reason);
  historyList.prepend(li);
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

async function loadSamples() {
  try {
    const resp = await fetch("/api/samples");
    const data = await resp.json();
    samplesBox.innerHTML = "";
    for (const s of data.samples) {
      const btn = el("button", "sample-btn");
      const malicious = /伪造|穿越|炸弹|符号链接|绝对路径|Zip Slip/.test(s.description);
      btn.classList.add(malicious ? "malicious" : "safe");
      btn.append(el("span", "name", s.filename));
      btn.append(el("span", "desc", s.description));
      btn.addEventListener("click", () => uploadSample(s.key, btn));
      samplesBox.append(btn);
    }
  } catch (err) {
    samplesBox.textContent = "样本列表加载失败：" + err;
  }
}

loadSamples();
