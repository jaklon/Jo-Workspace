import assert from 'node:assert/strict'
import {createRequire} from 'node:module'
import {fileURLToPath} from 'node:url'
import {build} from '../desktop-app/node_modules/esbuild/lib/main.js'
import React from '../desktop-app/node_modules/react/index.js'
import {renderToStaticMarkup} from '../desktop-app/node_modules/react-dom/server.node.js'

async function component(path, name) {
  const compiled=await build({entryPoints:[fileURLToPath(new URL(path,import.meta.url))],bundle:true,platform:'node',format:'cjs',jsx:'automatic',write:false,
    external:['react','react-dom','react/jsx-runtime'],define:{'import.meta.env.VITE_API_BASE_URL':JSON.stringify('http://127.0.0.1:8027')}})
  const module={exports:{}}
  new Function('module','exports','require',compiled.outputFiles[0].text)(module,module.exports,createRequire(new URL('../desktop-app/package.json',import.meta.url)))
  return module.exports[name]
}
const Results=await component('../desktop-app/src/renderer/src/components/SpecialistResults.tsx','SpecialistResults')
const Agents=await component('../desktop-app/src/renderer/src/components/SecurityAgents.tsx','SecurityAgents')
const profile={title:'Auth/BOLA',context:'Separate synthetic sessions',version:'1.0.0',hash:'a'.repeat(64)}
const agent={role:'auth_bola',profile,permissions:['lab.auth'],status:'completed',context_tokens:6000,output_tokens:512,
  active_seconds:1.2,active_seconds_limit:120,calls:1,max_calls:1,token_reserved:2500,max_tokens:12000,evidence_ids:['e1'],job_id:'job-1',error:null,
  lab_result:[{case_id:'bola-open',expected_assessment:'candidate',observed:{separate_sessions:true}}],
  output:{summary:'<script>untrusted</script>',assessments:[{case_id:'bola-open',assessment:'candidate',reason:'<img src=x onerror=x>'}],
    evidence_ids:['e1'],uncertainties:['<a href="https://external.invalid">injection</a>']}}
const team={agents:[agent],request:{max_calls:1,max_tokens:12000,active_seconds:120,plans:{auth_bola:{steps:[{target:{value:'https://10.30.0.25/'},ports:[]}]}}},
  metrics:{case_count:2,coverage_percent:25,true_positives:1,false_positives:0,accuracy:1,inconclusive:0,evidence_count:1,evidence_completeness:1,completed_agents:1,
    measured_input_tokens:100,measured_output_tokens:50,token_reserved:2500,calls:1,active_seconds:1.2}}
const html=renderToStaticMarkup(React.createElement(Results,{team}))
assert(!html.includes('<script>'))
assert(!html.includes('<img '))
assert(!html.includes('<a '))
assert.match(html,/&lt;script&gt;/)
assert.match(html,/Interpretasi AI belum diverifikasi/)
assert.match(html,/candidate_only/)
assert.match(html,/lab.auth/)
assert.match(html,/2\/8 kasus/)
assert.match(html,/kelengkapan 100%/)
assert.match(html,/https:\/\/10.30.0.25/)
const waiting=renderToStaticMarkup(React.createElement(Results,{team:{...team,agents:[{...agent,status:'paused',output:null}]}}))
assert.match(waiting,/Bukti yang sudah tersimpan tetap dipertahankan/)
const page=renderToStaticMarkup(React.createElement(Agents,{engagement:{id:'e',project_id:'p',revision:1,versions:[{version:1,content_hash:'h',content:{test_account_refs:[]}}]},onRuns:()=>{}}))
assert.match(page,/Daftarkan lab/)
assert.match(page,/Buat tim spesialis/)
assert.match(page,/approval setiap job di Runs/)
assert.match(page,/pentest terkunci/)
console.log('16 specialist UI assertions passed: budgets, scope, preserved evidence, lab labels and untrusted output escaping.')
