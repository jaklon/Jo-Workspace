import assert from 'node:assert/strict'
import {createRequire} from 'node:module'
import {fileURLToPath} from 'node:url'
import {build} from '../desktop-app/node_modules/esbuild/lib/main.js'
import React from '../desktop-app/node_modules/react/index.js'
import {renderToStaticMarkup} from '../desktop-app/node_modules/react-dom/server.node.js'

const compiled=await build({entryPoints:[fileURLToPath(new URL('../desktop-app/src/renderer/src/components/OrchestrationReview.tsx',import.meta.url))],bundle:true,platform:'node',format:'cjs',jsx:'automatic',write:false})
const module={exports:{}}
new Function('module','exports','require',compiled.outputFiles[0].text)(module,module.exports,createRequire(import.meta.url))
const {OrchestrationReview}=module.exports
const render=(reviewer)=>renderToStaticMarkup(React.createElement(OrchestrationReview,{reviewer}))
assert.match(render(null),/menunggu seluruh job/)
const html=render({summary:'<script>alert("synthetic")</script>',uncertainties:['<img src=x onerror=synthetic>'],evidence_ids:['<a href="https://synthetic.invalid">fake</a>'],needs_human_review:true,finding_status:'candidate_only'})
assert(!html.includes('<script>'))
assert(!html.includes('<img '))
assert(!html.includes('<a '))
assert.match(html,/&lt;script&gt;/)
assert.match(html,/Interpretasi AI belum diverifikasi/)
assert.match(html,/candidate_only/)
assert.match(html,/tidak mengubah status finding atau severity/)
console.log('8 orchestration UI assertions passed: waiting state, untrusted AI text escaping, and human-review boundary.')
