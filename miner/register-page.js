// One-time helper: register the Sentinel miner on Telegraph's Ethereum Sepolia
// Diamond straight from the owner's browser wallet. Telegraph's console still
// offered the pre-migration intent names (Oct 31), which the Diamond rejects.
// Two transactions: approve the MACHINA bond, then registerMiner.
import { encodeFunctionData, parseAbi, parseEther } from "viem";

export const REGISTRATION = {
  chainId: 11155111,
  diamond: "0x3624EB012B5E998BB57B6bE6C9Cfc9c4bc5eb99b",
  machina: "0xd68305cA83C7AF42A4F720144E7416fB53F8AaF4",
  owner: "0xFb49DF5c009e60749776bF3CBed3D1C25Dde0297",
  yamlUrl: "https://pr-guard-sentinel.pr-guard.workers.dev/miner.yaml",
  yamlHash: "0x9c079634c9f821e47c1b3eac49b0f2aa7103a5bdfe28dd8d4b1c6487783c2bab",
  minPriceUsdc: 10000n,
  intents: ["SECURITY_REVIEW_GENERAL"],
  bondAllowance: parseEther("3"), // the bond is $1 at the pool price (~1.3 MACHINA); only that is taken
};

const r = REGISTRATION;
export const APPROVE_DATA = encodeFunctionData({
  abi: parseAbi(["function approve(address spender, uint256 amount) returns (bool)"]),
  functionName: "approve",
  args: [r.diamond, r.bondAllowance],
});
export const REGISTER_DATA = encodeFunctionData({
  abi: parseAbi(["function registerMiner(string yamlUrl, bytes32 yamlHash, address feeAddress, uint256 minPriceUsdc, string[] supportedIntents) returns (uint256)"]),
  functionName: "registerMiner",
  args: [r.yamlUrl, r.yamlHash, r.owner, r.minPriceUsdc, r.intents],
});

const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);

export const REGISTER_PAGE = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Register PR Guard Sentinel</title>
<style>
:root{--bg:#fff;--fg:#1a1a1a;--muted:#5c5c5c;--card:#f5f5f4;--line:#dedcd8;--ok:#1a7f37;--bad:#b42318;--btn:#1a1a1a;--btnfg:#fff}
@media (prefers-color-scheme:dark){:root{--bg:#141414;--fg:#ececec;--muted:#a3a3a3;--card:#1f1f1f;--line:#333;--ok:#4ac26b;--bad:#ff7b72;--btn:#ececec;--btnfg:#141414}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif}
main{max-width:640px;margin:0 auto;padding:32px 16px}
h1{font-size:1.5rem;margin:0 0 4px}.muted{color:var(--muted)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin:16px 0}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 12px;margin:0;font-size:.875rem}dt{color:var(--muted)}dd{margin:0;word-break:break-all;font-family:ui-monospace,monospace}
button{background:var(--btn);color:var(--btnfg);border:0;border-radius:8px;padding:12px 16px;font-size:1rem;cursor:pointer;width:100%}
button:disabled{opacity:.4;cursor:default}
.status{margin-top:8px;font-size:.9rem;word-break:break-all}.ok{color:var(--ok)}.bad{color:var(--bad)}
a{color:inherit}
</style></head><body><main>
<h1>Register PR Guard Sentinel</h1>
<p class="muted">A one-time helper from the PR Guard project (not a Telegraph page). It sends two transactions from your MetaMask to Telegraph's testnet contract on Ethereum Sepolia.</p>
<div class="card"><dl>
<dt>Network</dt><dd>Ethereum Sepolia (${r.chainId})</dd>
<dt>Contract</dt><dd>${esc(r.diamond)}</dd>
<dt>Owner wallet</dt><dd>${esc(r.owner)}</dd>
<dt>Miner YAML</dt><dd>${esc(r.yamlUrl)}</dd>
<dt>YAML hash</dt><dd>${esc(r.yamlHash)}</dd>
<dt>Intent</dt><dd>${esc(r.intents.join(", "))}</dd>
<dt>Floor price</dt><dd>$0.01 per request</dd>
<dt>Bond</dt><dd>$1 in MACHINA (refundable on deregistering)</dd>
</dl></div>
<div class="card"><strong>Step 1: approve the bond</strong><p class="muted">Lets the contract take the $1 MACHINA bond.</p>
<button id="b1">Approve bond</button><div class="status" id="s1"></div></div>
<div class="card"><strong>Step 2: register the miner</strong><p class="muted">Unlocks after step 1 confirms.</p>
<button id="b2" disabled>Register miner</button><div class="status" id="s2"></div></div>
<script>
const CHAIN="0xaa36a7", OWNER=${JSON.stringify(r.owner)};
const TXS={1:{to:${JSON.stringify(r.machina)},data:${JSON.stringify(APPROVE_DATA)}},2:{to:${JSON.stringify(r.diamond)},data:${JSON.stringify(REGISTER_DATA)}}};
// Low but sufficient fees: Sepolia's base fee is near zero, so MetaMask's
// default 1+ gwei tip would reserve more ETH than the wallet holds.
const FEES={maxFeePerGas:"0xbebc200",maxPriorityFeePerGas:"0x2faf080"};
const $=(id)=>document.getElementById(id);
function say(n,msg,cls){$("s"+n).className="status "+(cls||"");$("s"+n).innerHTML=msg;}
async function wallet(){
  if(!window.ethereum) throw new Error("MetaMask not found in this browser.");
  const [from]=await ethereum.request({method:"eth_requestAccounts"});
  if(from.toLowerCase()!==OWNER.toLowerCase()) throw new Error("Switch MetaMask to account "+OWNER+" (connected: "+from+").");
  const chain=await ethereum.request({method:"eth_chainId"});
  if(chain!==CHAIN) await ethereum.request({method:"wallet_switchEthereumChain",params:[{chainId:CHAIN}]});
  return from;
}
async function waitFor(hash){
  for(;;){const r=await ethereum.request({method:"eth_getTransactionReceipt",params:[hash]});if(r) return r;await new Promise(s=>setTimeout(s,3000));}
}
async function run(n){
  $("b"+n).disabled=true;
  try{
    const from=await wallet();
    say(n,"Confirm in MetaMask…");
    const hash=await ethereum.request({method:"eth_sendTransaction",params:[{from,...TXS[n],...FEES}]});
    say(n,'Sent, waiting for confirmation… <a target="_blank" rel="noopener" href="https://sepolia.etherscan.io/tx/'+hash+'">view</a>');
    const r=await waitFor(hash);
    if(r.status!=="0x1") throw new Error("Transaction failed on-chain: "+hash);
    say(n,'Done ✓ <a target="_blank" rel="noopener" href="https://sepolia.etherscan.io/tx/'+hash+'">'+hash+'</a>',"ok");
    if(n===1) $("b2").disabled=false;
  }catch(e){say(n,(e&&e.message)||String(e),"bad");$("b"+n).disabled=false;}
}
$("b1").onclick=()=>run(1);$("b2").onclick=()=>run(2);
</script></main></body></html>`;
