import {basicSetup} from "codemirror"
import {EditorView, keymap} from "@codemirror/view"
import {indentWithTab} from "@codemirror/commands"

// Wrap in IIFE so we can call return if something is not setup as expected
// without getting "Return statement is not allowed here" error from rollup.
;(function() {
  let textarea = document.getElementById("vcl_template")
  if (!textarea) return

  let editorDiv = document.getElementById("editor")
  if (!editorDiv) return

  let editor = new EditorView({
    doc: textarea.value,
    extensions: [
      basicSetup,
      keymap.of([indentWithTab])
    ],
    parent: editorDiv
  })

  // Hide the plain HTML textarea now that codemirror is taking over
  textarea.hidden = true

  // Update hint so it matches behaviour of codemirror
  let hint = document.getElementById("vcl-hint")
  if (hint) {
    hint.textContent = "Press Escape+Tab to move focus out of the editor."
  }

  // Update aria hints to point to codemirror editor instead of the plain HTML textarea
  editor.contentDOM.setAttribute("aria-describedby", "vcl-hint")
  editor.contentDOM.setAttribute("aria-labelledby", "vcl-template-label")

  // Point label to the editor instead of the now hidden textarea
  let label = document.getElementById("vcl-template-label")
  if (label) {
    label.removeAttribute("for")
    label.addEventListener("click", () => editor.focus())
  }

  // Make the editor write out current contents to the textarea on submit.
  let form = textarea.closest("form")
  if (form) {
    form.addEventListener("submit", (e) => {
      // Let the user know they have more content in the editor than we allow
      // for form submission
      let maxLength = textarea.maxLength > 0 ? textarea.maxLength : 1048576
      let content = editor.state.doc.toString()
      if (content.length > maxLength) {
        e.preventDefault()
        alert(`VCL template exceeds the maximum length of ${maxLength.toLocaleString()} characters.`)
        return
      }
      textarea.value = content
    })
  }

  // Cleanup if hx-boost replaces <body> via navigation etc.
  document.body.addEventListener("htmx:beforeSwap", function handler(e) {
    if (e.detail.target === document.body) {
      editor.destroy()
      document.body.removeEventListener("htmx:beforeSwap", handler)
    }
  })
})()
