#!/usr/bin/env node
// Checks the bundled dashboard for calls to functions that do not exist.
//
// The dashboard is one inline script with no build step and no test runner, so
// a typo in a function name is only found by clicking the button that calls it.
// This catches it instead: every bare `name(` call must resolve to something
// declared in the script, a browser global, or a JavaScript builtin.
//
// Usage: node scripts/check-dashboard.js [path/to/dashboard.html]

const fs = require('fs');

const file = process.argv[2] || 'src/dashboard.html';
const html = fs.readFileSync(file, 'utf8');

// Every inline block, joined: the page has more than one, and a function
// defined in the last is routinely called from the first.
const blocks = [...html.matchAll(/<script(?![^>]*\ssrc=)[^>]*>([\s\S]*?)<\/script>/g)];
if (blocks.length === 0) {
    console.error(`${file}: no inline <script> block found`);
    process.exit(1);
}
const source = blocks.map((block) => block[1]).join('\n');

// Only comments are stripped. String contents are deliberately kept: the page
// builds its markup with template literals, so `onclick="doThing(this)"` lives
// inside a string and is exactly the kind of call that breaks silently.
const code = source
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1 ');

const declared = new Set();
for (const re of [
    /\bfunction\s+([A-Za-z_$][\w$]*)/g,
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b|\()/g,
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)/g,
]) {
    let m;
    while ((m = re.exec(code)) !== null) declared.add(m[1]);
}

// Anything the browser or the language provides, plus the keywords that are
// followed by a parenthesis and would otherwise read as a call.
const known = new Set([
    'if', 'for', 'while', 'switch', 'catch', 'return', 'typeof', 'function',
    'await', 'new', 'do', 'else', 'in', 'of', 'delete', 'void', 'yield',
    'fetch', 'alert', 'confirm', 'prompt', 'setTimeout', 'setInterval',
    'clearTimeout', 'clearInterval', 'requestAnimationFrame', 'encodeURIComponent',
    'decodeURIComponent', 'encodeURI', 'decodeURI', 'parseInt', 'parseFloat',
    'isNaN', 'isFinite', 'String', 'Number', 'Boolean', 'Array', 'Object',
    'Date', 'Math', 'JSON', 'Map', 'Set', 'Promise', 'Error', 'RegExp',
    'Blob', 'URL', 'FormData', 'Headers', 'Request', 'Response', 'Intl',
    'console', 'document', 'window', 'navigator', 'localStorage', 'sessionStorage',
    'structuredClone', 'queueMicrotask', 'btoa', 'atob',
    // CSS functions: inline styles are built inside template literals, so they
    // reach this scan as text.
    'var', 'calc', 'rgb', 'rgba', 'hsl', 'hsla', 'url', 'clamp', 'min', 'max',
    'translate', 'translateX', 'translateY', 'scale', 'rotate', 'blur',
]);

// Inline handlers in the static markup call the same functions, so the whole
// document is scanned, not only the script.
const markup = html
    .replace(/<script[\s\S]*?<\/script>/g, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ');
const handlers = [...markup.matchAll(/\son[a-z]+\s*=\s*"([^"]*)"/g)]
    .map((h) => h[1])
    .join(';\n');

const calls = new Map();
const callRe = /(^|[^.\w$])([A-Za-z_$][\w$]*)\s*\(/g;
let m;
while ((m = callRe.exec(code + ';\n' + handlers)) !== null) {
    const name = m[2];
    if (declared.has(name) || known.has(name)) continue;
    if (!calls.has(name)) {
        calls.set(name, code.slice(0, m.index).split('\n').length);

    }
}

if (calls.size === 0) {
    console.log(`${file}: every called function is defined`);
    process.exit(0);
}

for (const [name, line] of calls) {
    console.error(`${file}: calls ${name}() which is not defined (near script line ${line})`);
}
console.error(
    '\nIf one of these is a browser global, add it to `known` in this script.'
);
process.exit(1);
