(function () {
  var form = document.querySelector(".editor form");
  if (!form) return;

  var editor = document.getElementById("editor");
  var output = document.getElementById("content-input");
  var toolbar = document.getElementById("rich-toolbar");
  var fileInput = document.getElementById("image-input");
  var statusEl = document.getElementById("upload-status");
  var csrfInput = form.querySelector('input[name="_csrf"]');
  var blockSelect = document.getElementById("block-select");
  var fontSelect = document.getElementById("font-select");
  var sizeSelect = document.getElementById("size-select");
  var linkBtn = document.getElementById("link-btn");
  var clearBtn = document.getElementById("clear-format");
  var inlineCodeBtn = document.getElementById("inline-code");
  var codeBlockBtn = document.getElementById("code-block");
  var codeLangSelect = document.getElementById("code-lang");

  var richMode = document.getElementById("rich-mode");
  var markdownMode = document.getElementById("markdown-mode");
  var markdownInput = document.getElementById("markdown-input");
  var markdownPreview = document.getElementById("markdown-preview");
  var markdownStatus = document.getElementById("markdown-status");
  var markdownFileInput = document.getElementById("markdown-image-input");
  var formatInput = document.getElementById("content-format");
  var modeTabs = document.querySelectorAll(".mode-tab");

  if (!editor || !output || !csrfInput) return;

  var mode = formatInput && formatInput.value === "markdown" ? "markdown" : "html";
  var savedRange = null;
  var previewTimer = null;
  var previewRequest = 0;
  var FONT_SIZE_MAP = {
    "1": "12px",
    "2": "14px",
    "3": "16px",
    "4": "18px",
    "5": "22px",
    "6": "28px",
    "7": "36px",
  };
  var TEXT_COLORS = [
    "#1f2937",
    "#dc2626",
    "#ea580c",
    "#ca8a04",
    "#16a34a",
    "#0891b2",
    "#2563eb",
    "#7c3aed",
    "#db2777",
    "#6b7280",
    "#ffffff",
    "#000000",
  ];
  var HIGHLIGHT_COLORS = [
    "#fff59d",
    "#fecaca",
    "#fed7aa",
    "#bbf7d0",
    "#bfdbfe",
    "#e9d5ff",
    "#fbcfe8",
    "#e5e7eb",
    "transparent",
  ];

  function setStatusOn(el, message, isError) {
    if (!el) return;
    el.textContent = message;
    el.classList.toggle("error", !!isError);
  }

  function setStatus(message, isError) {
    setStatusOn(statusEl, message, isError);
  }

  function setMarkdownStatus(message, isError) {
    setStatusOn(markdownStatus, message, isError);
  }

  function saveSelection() {
    var sel = window.getSelection();
    if (!sel || !sel.rangeCount) return;
    var range = sel.getRangeAt(0);
    if (editor.contains(range.commonAncestorContainer)) {
      savedRange = range.cloneRange();
    }
  }

  function restoreSelection() {
    editor.focus();
    if (
      !savedRange ||
      !savedRange.commonAncestorContainer ||
      !savedRange.commonAncestorContainer.isConnected ||
      !editor.contains(savedRange.commonAncestorContainer)
    ) {
      return;
    }
    var sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(savedRange);
  }

  function placeCaretFromPoint(x, y) {
    var range = null;
    if (document.caretRangeFromPoint) {
      range = document.caretRangeFromPoint(x, y);
    } else if (document.caretPositionFromPoint) {
      var pos = document.caretPositionFromPoint(x, y);
      if (pos) {
        range = document.createRange();
        range.setStart(pos.offsetNode, pos.offset);
        range.collapse(true);
      }
    }
    if (range && editor.contains(range.commonAncestorContainer)) {
      savedRange = range.cloneRange();
      var sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
    }
  }

  function run(command, value) {
    editor.focus();
    document.execCommand("styleWithCSS", false, true);
    document.execCommand(command, false, value === undefined ? null : value);
    saveSelection();
    updateActiveStates();
  }

  function normalizeFontTags() {
    var fonts = editor.querySelectorAll("font");
    for (var i = 0; i < fonts.length; i++) {
      var font = fonts[i];
      var span = document.createElement("span");
      var size = FONT_SIZE_MAP[font.getAttribute("size")];
      if (size) span.style.fontSize = size;
      var face = font.getAttribute("face");
      if (face) span.style.fontFamily = face;
      var color = font.getAttribute("color");
      if (color) span.style.color = color;
      while (font.firstChild) span.appendChild(font.firstChild);
      font.parentNode.replaceChild(span, font);
    }
  }

  function syncOutput() {
    normalizeFontTags();
    output.value = editor.innerHTML.trim();
  }

  function handleSubmit() {
    if (mode === "markdown" && markdownInput) {
      output.value = markdownInput.value;
    } else {
      syncOutput();
    }
  }

  form.addEventListener("submit", handleSubmit);
  editor.addEventListener("input", saveSelection);
  document.addEventListener("selectionchange", saveSelection);

  toolbar.addEventListener("mousedown", function (e) {
    var target = e.target;
    if (target.closest("button")) {
      e.preventDefault();
    }
  });

  toolbar.addEventListener("click", function (e) {
    var button = e.target.closest("button[data-command]");
    if (!button) return;
    restoreSelection();
    run(button.getAttribute("data-command"));
    syncOutput();
  });

  blockSelect.addEventListener("change", function () {
    if (!blockSelect.value) return;
    restoreSelection();
    run("formatBlock", blockSelect.value);
    blockSelect.value = "p";
    syncOutput();
  });

  fontSelect.addEventListener("change", function () {
    if (!fontSelect.value) return;
    restoreSelection();
    run("fontName", fontSelect.value);
    fontSelect.value = "";
    syncOutput();
  });

  sizeSelect.addEventListener("change", function () {
    if (!sizeSelect.value) return;
    restoreSelection();
    run("fontSize", sizeSelect.value);
    normalizeFontTags();
    sizeSelect.value = "";
    syncOutput();
  });

  linkBtn.addEventListener("mousedown", function (e) {
    e.preventDefault();
  });

  linkBtn.addEventListener("click", function () {
    var url = window.prompt("请输入链接地址（http:// 或 https://）", "https://");
    if (!url) return;
    if (!/^https?:\/\//i.test(url)) {
      window.alert("仅支持 http:// 或 https:// 开头的链接。");
      return;
    }
    restoreSelection();
    run("createLink", url);
    var sel = window.getSelection();
    var node = sel && sel.anchorNode;
    if (node && node.nodeType === 3) node = node.parentElement;
    var anchor = node && node.closest ? node.closest("a") : null;
    if (anchor) {
      anchor.target = "_blank";
      anchor.rel = "noopener noreferrer";
    }
    syncOutput();
  });

  clearBtn.addEventListener("mousedown", function (e) {
    e.preventDefault();
  });

  clearBtn.addEventListener("click", function () {
    restoreSelection();
    run("removeFormat");
    run("unlink");
    syncOutput();
  });

  function escapeHtml(text) {
    return text
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function selectedText() {
    var sel = window.getSelection();
    if (!sel || !sel.rangeCount) return "";
    return sel.toString();
  }

  function focusMarker(markerId) {
    var marker = document.getElementById(markerId);
    if (!marker) {
      editor.focus();
      return;
    }
    var range = document.createRange();
    range.setStartBefore(marker);
    range.collapse(true);
    if (marker.parentNode) marker.parentNode.removeChild(marker);
    var sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    editor.focus();
    saveSelection();
  }

  function insertInlineCode() {
    restoreSelection();
    var text = escapeHtml(selectedText());
    var markerId = "__inline_code_" + Date.now();
    document.execCommand(
      "insertHTML",
      false,
      "<code>" + text + '<span id="' + markerId + '"></span></code>'
    );
    focusMarker(markerId);
    syncOutput();
  }

  function insertCodeBlock() {
    restoreSelection();
    var text = escapeHtml(selectedText());
    if (text && !/\n$/.test(text)) text += "\n";
    var lang = codeLangSelect ? codeLangSelect.value : "";
    var cls = lang ? ' class="language-' + lang + '"' : "";
    var markerId = "__code_block_" + Date.now();
    document.execCommand(
      "insertHTML",
      false,
      "<pre><code" +
        cls +
        ">" +
        text +
        '<span id="' +
        markerId +
        '"></span></code></pre><p><br></p>'
    );
    focusMarker(markerId);
    syncOutput();
  }

  [inlineCodeBtn, codeBlockBtn].forEach(function (button) {
    if (!button) return;
    button.addEventListener("mousedown", function (e) {
      e.preventDefault();
    });
  });

  if (inlineCodeBtn) {
    inlineCodeBtn.addEventListener("click", insertInlineCode);
  }
  if (codeBlockBtn) {
    codeBlockBtn.addEventListener("click", insertCodeBlock);
  }

  editor.addEventListener("keydown", function (e) {
    if (e.key !== "Tab" || e.ctrlKey || e.metaKey || e.altKey) return;
    var sel = window.getSelection();
    if (!sel || !sel.anchorNode) return;
    var node = sel.anchorNode;
    var element = node.nodeType === 3 ? node.parentElement : node;
    if (element && element.closest && element.closest("pre")) {
      e.preventDefault();
      document.execCommand("insertText", false, "    ");
      saveSelection();
    }
  });

  function closeColorMenus(except) {
    var open = document.querySelectorAll(".color-dropdown.open");
    for (var i = 0; i < open.length; i++) {
      if (open[i] !== except) open[i].classList.remove("open");
    }
  }

  function buildColorDropdown(dropdown) {
    var command = dropdown.getAttribute("data-command");
    var menu = dropdown.querySelector(".color-menu");
    var colors = command === "hiliteColor" ? HIGHLIGHT_COLORS : TEXT_COLORS;

    colors.forEach(function (color) {
      var swatch = document.createElement("button");
      swatch.type = "button";
      swatch.className = "color-swatch";
      if (color === "transparent") {
        swatch.classList.add("transparent");
        swatch.title = "清除背景色";
      } else {
        swatch.style.backgroundColor = color;
        swatch.title = color;
      }
      swatch.addEventListener("click", function () {
        restoreSelection();
        run(command, color);
        syncOutput();
        dropdown.classList.remove("open");
      });
      menu.appendChild(swatch);
    });

    var toggle = dropdown.querySelector(".color-toggle");
    toggle.addEventListener("click", function () {
      var willOpen = !dropdown.classList.contains("open");
      closeColorMenus(dropdown);
      dropdown.classList.toggle("open", willOpen);
    });
  }

  var dropdowns = document.querySelectorAll(".color-dropdown");
  for (var i = 0; i < dropdowns.length; i++) {
    buildColorDropdown(dropdowns[i]);
  }

  document.addEventListener("mousedown", function (e) {
    if (!e.target.closest || !e.target.closest(".color-dropdown")) {
      closeColorMenus();
    }
  });

  function insertImage(url) {
    restoreSelection();
    document.execCommand(
      "insertHTML",
      false,
      '<img src="' + url + '" alt="图片">'
    );
    saveSelection();
  }

  function upload(file, options) {
    options = options || {};
    var status = options.status || statusEl;
    var insert = options.insert || insertImage;
    var after = options.after || syncOutput;

    if (!file || file.type.indexOf("image/") !== 0) {
      setStatusOn(status, "只能上传图片文件。", true);
      return;
    }

    var data = new FormData();
    data.append("image", file);
    data.append("_csrf", csrfInput.value);
    setStatusOn(status, "正在上传 " + file.name + " …", false);

    fetch("/upload", { method: "POST", body: data })
      .then(function (res) {
        return res
          .json()
          .catch(function () {
            return {};
          })
          .then(function (body) {
            if (!res.ok) {
              throw new Error(body.error || "上传失败，请重试。");
            }
            return body;
          });
      })
      .then(function (body) {
        insert(body.url);
        after();
        setStatusOn(status, "已插入图片：" + file.name, false);
      })
      .catch(function (err) {
        setStatusOn(status, err.message || "上传失败，请重试。", true);
      });
  }

  fileInput.addEventListener("change", function () {
    if (fileInput.files && fileInput.files[0]) {
      upload(fileInput.files[0]);
    }
    fileInput.value = "";
  });

  ["dragenter", "dragover"].forEach(function (name) {
    editor.addEventListener(name, function (e) {
      e.preventDefault();
      editor.classList.add("drag-over");
    });
  });

  ["dragleave", "drop"].forEach(function (name) {
    editor.addEventListener(name, function (e) {
      e.preventDefault();
      editor.classList.remove("drag-over");
    });
  });

  editor.addEventListener("drop", function (e) {
    placeCaretFromPoint(e.clientX, e.clientY);
    var files = e.dataTransfer && e.dataTransfer.files;
    if (files && files[0]) upload(files[0]);
  });

  editor.addEventListener("paste", function (e) {
    var items = e.clipboardData && e.clipboardData.items;
    if (!items) return;
    for (var idx = 0; idx < items.length; idx++) {
      if (items[idx].type.indexOf("image/") === 0) {
        var file = items[idx].getAsFile();
        if (file) {
          e.preventDefault();
          upload(file);
        }
        break;
      }
    }
  });

  function updateActiveStates() {
    var map = {
      bold: "bold",
      italic: "italic",
      underline: "underline",
      strikeThrough: "strikeThrough",
      justifyLeft: "justifyLeft",
      justifyCenter: "justifyCenter",
      justifyRight: "justifyRight",
      justifyFull: "justifyFull",
      insertUnorderedList: "insertUnorderedList",
      insertOrderedList: "insertOrderedList",
    };
    Object.keys(map).forEach(function (command) {
      var button = toolbar.querySelector('[data-command="' + command + '"]');
      if (!button) return;
      var active = false;
      try {
        active = document.queryCommandState(map[command]);
      } catch (err) {
        active = false;
      }
      button.classList.toggle("active", !!active);
    });
  }

  document.addEventListener("selectionchange", function () {
    if (document.activeElement === editor) updateActiveStates();
  });

  function postForm(path, fields) {
    var body = new URLSearchParams();
    body.append("_csrf", csrfInput.value);
    Object.keys(fields).forEach(function (key) {
      body.append(key, fields[key]);
    });
    return fetch(path, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
      },
      body: body,
    }).then(function (res) {
      return res
        .json()
        .catch(function () {
          return {};
        })
        .then(function (data) {
          if (!res.ok) {
            throw new Error(data.error || "操作失败，请重试。");
          }
          return data;
        });
    });
  }

  function refreshPreview() {
    if (!markdownInput || !markdownPreview) return;
    var seq = ++previewRequest;
    setMarkdownStatus("预览更新中…", false);
    postForm("/markdown/preview", { content: markdownInput.value })
      .then(function (data) {
        if (seq !== previewRequest) return;
        markdownPreview.innerHTML = data.html || "";
        setMarkdownStatus("预览已更新", false);
      })
      .catch(function (err) {
        if (seq !== previewRequest) return;
        setMarkdownStatus(err.message || "预览失败", true);
      });
  }

  function schedulePreview() {
    clearTimeout(previewTimer);
    previewTimer = setTimeout(refreshPreview, 500);
  }

  function insertMarkdownRaw(text) {
    if (!markdownInput) return;
    var start = markdownInput.selectionStart;
    var end = markdownInput.selectionEnd;
    var value = markdownInput.value;
    markdownInput.value = value.slice(0, start) + text + value.slice(end);
    var pos = start + text.length;
    markdownInput.selectionStart = pos;
    markdownInput.selectionEnd = pos;
    markdownInput.focus();
    schedulePreview();
  }

  function insertMarkdownWrap(before, after, placeholder) {
    if (!markdownInput) return;
    var start = markdownInput.selectionStart;
    var end = markdownInput.selectionEnd;
    var value = markdownInput.value;
    var selected = value.slice(start, end) || placeholder || "";
    var replacement = before + selected + after;
    markdownInput.value = value.slice(0, start) + replacement + value.slice(end);
    markdownInput.selectionStart = start + before.length;
    markdownInput.selectionEnd = start + before.length + selected.length;
    markdownInput.focus();
    schedulePreview();
  }

  function insertMarkdownImage(url) {
    insertMarkdownRaw("![图片](" + url + ")");
  }

  function insertMarkdownCodeBlock() {
    if (!markdownInput) return;
    var selected = markdownInput.value.slice(
      markdownInput.selectionStart,
      markdownInput.selectionEnd
    );
    var bodyText = selected || "代码";
    insertMarkdownRaw("\n```\n" + bodyText + "\n```\n");
  }

  var mdButtons = document.querySelectorAll("[data-md]");
  for (var m = 0; m < mdButtons.length; m++) {
    (function (button) {
      button.addEventListener("mousedown", function (e) {
        e.preventDefault();
      });
      button.addEventListener("click", function () {
        var action = button.getAttribute("data-md");
        if (action === "bold") {
          insertMarkdownWrap("**", "**", "加粗文字");
        } else if (action === "heading") {
          insertMarkdownWrap("\n## ", "", "标题");
        } else if (action === "link") {
          insertMarkdownWrap("[", "](https://)", "链接文字");
        } else if (action === "inline-code") {
          insertMarkdownWrap("`", "`", "code");
        } else if (action === "code-block") {
          insertMarkdownCodeBlock();
        }
      });
    })(mdButtons[m]);
  }

  if (markdownInput) {
    markdownInput.addEventListener("input", schedulePreview);
  }

  if (markdownFileInput) {
    markdownFileInput.addEventListener("change", function () {
      if (markdownFileInput.files && markdownFileInput.files[0]) {
        upload(markdownFileInput.files[0], {
          status: markdownStatus,
          insert: insertMarkdownImage,
          after: schedulePreview,
        });
      }
      markdownFileInput.value = "";
    });
  }

  function setModeUI(next) {
    mode = next;
    if (formatInput) formatInput.value = next;
    if (richMode) richMode.hidden = next === "markdown";
    if (markdownMode) markdownMode.hidden = next !== "markdown";
    for (var idx = 0; idx < modeTabs.length; idx++) {
      modeTabs[idx].classList.toggle(
        "active",
        modeTabs[idx].getAttribute("data-mode") === next
      );
    }
  }

  function switchMode(next) {
    if (next === mode) return;

    if (next === "markdown") {
      var html = editor.innerHTML.trim();
      if (
        html &&
        !window.confirm(
          "切换为 Markdown 会丢失颜色、对齐等富文本样式，确定继续吗？"
        )
      ) {
        return;
      }
      setMarkdownStatus("正在转换…", false);
      if (html) {
        postForm("/markdown/from-html", { html: html })
          .then(function (data) {
            markdownInput.value = data.markdown || "";
            setModeUI("markdown");
            refreshPreview();
          })
          .catch(function (err) {
            setMarkdownStatus(err.message || "转换失败", true);
          });
      } else {
        setModeUI("markdown");
        if (markdownInput.value.trim()) refreshPreview();
      }
    } else {
      var markdown = markdownInput ? markdownInput.value : "";
      if (markdown.trim()) {
        setMarkdownStatus("正在生成富文本…", false);
        postForm("/markdown/preview", { content: markdown })
          .then(function (data) {
            editor.innerHTML = data.html || "";
            setModeUI("html");
            editor.focus();
          })
          .catch(function (err) {
            setMarkdownStatus(err.message || "转换失败", true);
          });
      } else {
        setModeUI("html");
        editor.focus();
      }
    }
  }

  for (var t = 0; t < modeTabs.length; t++) {
    (function (tab) {
      tab.addEventListener("click", function () {
        switchMode(tab.getAttribute("data-mode"));
      });
    })(modeTabs[t]);
  }

  setModeUI(mode);
  if (mode === "markdown" && markdownInput && markdownInput.value.trim()) {
    refreshPreview();
  } else {
    syncOutput();
  }
})();
