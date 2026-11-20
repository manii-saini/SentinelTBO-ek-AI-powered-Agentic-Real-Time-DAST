import { Orchestrator } from './index.js';

const orchestrator = new Orchestrator();
if (process.argv.includes('--reset')) await orchestrator.reset();
const change = await orchestrator.fireTrigger('deploy', 'seed-script');
const run = await orchestrator.runLoop({ mode: 'full', autoApprove: true, change });
const state = orchestrator.getState();
console.log(`Seeded run ${run.runId}: ${state.findings.filter((f) => f.status !== 'false-positive').length} findings, ${state.tickets.length} tickets, ${state.counters.requestsSent} requests.`);
console.log(`Endpoints: ${state.endpoints.length} · Events: ${state.events.length} · Open the web app at http://127.0.0.1:5173`);
orchestrator.store.close();
