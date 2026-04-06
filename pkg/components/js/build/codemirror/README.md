# CodeMirror 6

Used for editing the VCL templates for service versions. Steps based on example
at https://codemirror.net/examples/bundle/. CodeMirror expects you to create your own bundle so this is done here.

You need to have `npm` installed to handle the instructions below.

The codemirror docs mentioned the use of `terser` to minify the bundled code.
For the initial build the `editor.bundle.js` size was 1061077 bytes and the
minified `editor.bundle.min.js` became 380702 bytes. Having to only serve about
36% of the original file size to users seems good both for us and users so the
steps below include `terser` as well.

# Initial bootstrapping steps
Initial installation was done this way:

* Install the necessary npm packages, creating `package.json`, `package-lock.json` and `node_modules`:
```
npm install codemirror
npm install rollup @rollup/plugin-node-resolve
npm install terser
```
* Write the `editor.mjs` file
* Write the `rollup.config.mjs` for use with `rollup -c`
* Add "build" script to `package.json` so we can run "npm run build" to bundle
  and minify the codemirror code. Also add "private" property since we are not
  expecting to ever publish anything from this `package.json`.
* Create the bundle `editor.bundle.js` and the corresponding minified
  `editor.bundle.min.js`.
```
npm run build
```

# Updating the codemirror code
* Re-create `node_modules` dir if fresh clone:
```
npm install
```
* Update `editor.mjs` as needed
* Rebuild `editor.bundle.min.js`:
```
npm run build
```
* Commit the updated minified bundle to the repo
```
git add ../../dist/codemirror/editor.bundle.min.js
git commit -v
```
