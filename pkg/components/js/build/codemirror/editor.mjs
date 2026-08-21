import {basicSetup} from "codemirror"
import {EditorView, keymap} from "@codemirror/view"
import {indentWithTab} from "@codemirror/commands"

// Wrap in IIFE so we can call return if something is not setup as expected
// without getting "Return statement is not allowed here" error from rollup.
;(function() {
  // The console's <body> uses hx-boost="true": htmx swaps body innerHTML
  // on navigation instead of doing a full page load, so window/document
  // and any document-level listeners survive across pages, while this
  // <script> (allowScriptTags is on) re-executes each time a page
  // containing it is swapped in. Reaching the create-service-version page
  // several times in one session (e.g. cloning one version, navigating
  // elsewhere, then cloning another) therefore runs this code repeatedly
  // in the SAME JavaScript environment. State that must survive across those
  // re-executions - the textarea->EditorView map, and "have we already
  // registered our document-level listeners" - is therefore kept on
  // `window` rather than as plain closure locals: closure locals would give
  // every execution its own independent Map and its own independent set of
  // document/body listeners, so a second visit would leave two live
  // "htmx:afterSettle" listeners (and two submit listeners) running side by
  // side, each attaching its own CodeMirror instance to any later
  // htmx-added textarea - i.e. stacked duplicate editors that grow with
  // every visit.
  const state = window.__cdnEditorState || (window.__cdnEditorState = {
    editors: new Map(), // textarea -> EditorView, shared across script re-executions
    listenersInstalled: false
  })
  const editors = state.editors

  // attachEditor turns a single plain-HTML textarea into a CodeMirror
  // editor: it inserts a sibling container right after the textarea, mounts
  // a CM6 view in it seeded with the textarea's current value, and hides
  // the textarea. The textarea stays in the DOM (hidden, not removed) so
  // form submission still works if CodeMirror never loaded or fails, and so
  // the submit handler below has something to sync content back onto.
  function attachEditor(textarea) {
    if (editors.has(textarea)) return
    let container = document.createElement("div")
    container.className = "cm-editor-container"
    textarea.after(container)
    let editor = new EditorView({
      doc: textarea.value,
      extensions: [
        basicSetup,
        keymap.of([indentWithTab])
      ],
      parent: container
    })

    // Transfer each <label> associated with the textarea over to the
    // editor: clicking the label focuses the editor instead of the
    // hidden textarea, and the label's own text (its direct text nodes,
    // excluding nested elements like the textarea itself in wrapping
    // labels) becomes the editor's accessible name. aria-label is used
    // rather than aria-labelledby so the association survives the form's
    // renumbering hyperscript, which rewrites id attributes on reorder.
    let caption = ""
    for (let label of textarea.labels ?? []) {
      label.removeAttribute("for")
      label.addEventListener("click", () => editor.focus())
      for (let node of label.childNodes) {
        if (node.nodeType === Node.TEXT_NODE) caption += node.textContent
      }
    }
    caption = caption.trim()
    if (caption !== "") {
      editor.contentDOM.setAttribute("aria-label", caption)
    }

    const hint = document.getElementById("vcl-hint")
    if (hint) {
      editor.contentDOM.setAttribute("aria-describedby", hint.id)
    }

    // Hide the plain HTML textarea now that codemirror is taking over
    textarea.hidden = true
    editors.set(textarea, editor)
  }

  // Add a way for hyperscript in templ code to destroy editors when user
  // clicks the remove button in the console.
  state.destroyEditorsIn = function destroyEditorsIn(root) {
    for (const [textarea, editor] of state.editors) {
      if (root.contains(textarea)) {
        editor.destroy()
        state.editors.delete(textarea)
      }
    }
  }

  // attachAll finds every textarea under root that should get a CodeMirror
  // instance and attaches one (attachEditor is a no-op for textareas that
  // already have one, whether from earlier in this execution or from a
  // previous script execution against the same DOM). root may be the whole
  // document on initial load, or a htmx swap target for fieldsets added
  // later.
  function attachAll(root) {
    let vclTemplate = root.querySelector?.("#vcl_template")
    if (root.id === "vcl_template") vclTemplate = root
    if (vclTemplate) attachEditor(vclTemplate)

    let conditionEditors = root.querySelectorAll?.("textarea.condition-editor") ?? []
    for (let ta of conditionEditors) {
      attachEditor(ta)
    }
    if (root.matches?.("textarea.condition-editor")) {
      attachEditor(root)
    }
  }

  // Run on every execution of this script, including boosted revisits: a
  // boosted navigation swaps in a fresh DOM (a fresh #vcl_template and
  // fresh .condition-editor textareas) that needs its own editors attached,
  // and attachEditor's `editors.has(textarea)` check keeps this a no-op for
  // any textarea that's already wired up (there is no such textarea on a
  // genuinely fresh DOM, since old ones were destroyed by the beforeSwap
  // handler below before the swap completed).
  attachAll(document)

  // Update hint and aria wiring so they match behaviour of codemirror, for
  // the main vcl_template editor only - the condition editors have no
  // equivalent hint/label affordances. Also runs on every execution, for
  // the same boosted-revisit reason as attachAll above.
  // Label transfer and the accessible name are handled generically in
  // attachEditor; only the vcl_template editor has a hint element to wire
  // up as its description.
  let mainTextarea = document.getElementById("vcl_template")
  if (mainTextarea && editors.has(mainTextarea)) {
    let hint = document.getElementById("vcl-hint")
    if (hint) {
      hint.textContent = "Press Escape+Tab to move focus out of the editor."
    }

    editors.get(mainTextarea).contentDOM.setAttribute("aria-describedby", "vcl-hint")
  }

  // The three document-level listeners below must be registered exactly
  // once per document, no matter how many times this script executes
  // (see the comment on `state` above), since they all operate on the
  // shared `editors` map rather than an execution-local one.
  if (!state.listenersInstalled) {
    state.listenersInstalled = true

    // Attach editors to fieldsets htmx inserts later (new conditional
    // origin groups, in particular). The move-up/move-down buttons' own
    // click handlers move whole <article> nodes around with the DOM
    // before/after primitives (manager:formchanged itself only renumbers
    // name/id/for attributes and toggles disabled state - it does not move
    // anything) - either way, no textarea value is ever touched and no
    // node under a .cm-editor-container is recreated, so an
    // already-attached EditorView simply gets reparented along with its
    // container and keeps its content.
    // Registered on document (not document.body): both events bubble, and
    // a listener on the body element would be silently lost if body itself
    // were ever swapped with outerHTML while listenersInstalled stays true.
    document.addEventListener("htmx:afterSettle", (e) => {
      if (e.detail?.target) attachAll(e.detail.target)
    })

    // Make every editor write its current contents out to its textarea on
    // submit, so the textarea value htmx/the browser actually submits
    // matches what's in CodeMirror. Runs in the capture phase so it fires
    // before hyperscript/htmx's own submit-time handling.
    document.addEventListener("submit", (e) => {
      for (let [textarea, editor] of editors) {
        // The group (and its editor's textarea) may have been removed from
        // the DOM via the "Remove group" button; drop it instead of trying
        // to sync a value nothing will submit.
        if (!document.contains(textarea)) {
          editor.destroy()
          editors.delete(textarea)
          continue
        }

        // Only sync editors belonging to the form actually being
        // submitted: the page has other forms (e.g. logout in the header),
        // and without this check an over-length vcl_template would block
        // THEIR submits via the preventDefault below.
        if (textarea.form !== e.target) {
          continue
        }

        let content = editor.state.doc.toString()

        // Let the user know they have more content in the editor than we
        // allow for form submission. Only vcl_template enforces a max
        // length.
        if (textarea.id === "vcl_template") {
          let maxLength = textarea.maxLength > 0 ? textarea.maxLength : 1048576
          if (content.length > maxLength) {
            e.preventDefault()
            alert(`VCL template exceeds the maximum length of ${maxLength.toLocaleString()} characters.`)
            return
          }
        }

        textarea.value = content
      }
    }, true)

    // Cleanup if hx-boost replaces <body> via navigation etc. This handler
    // is installed once and serves every future body swap for the rest of
    // the page's lifetime (it must NOT remove itself after the first swap -
    // doing so would leave editors from a later swapped-in page never
    // cleaned up on the swap after that).
    // shouldSwap matters: htmx fires beforeSwap for EVERY response on a
    // boosted navigation, including error statuses it will NOT swap in.
    // Destroying the editors on a swap that never happens would leave the
    // current page with hidden textareas and dead editor containers.
    document.addEventListener("htmx:beforeSwap", (e) => {
      if (e.detail.target === document.body && e.detail.shouldSwap) {
        for (let editor of editors.values()) editor.destroy()
        editors.clear()
      }
    })
  }
})()
