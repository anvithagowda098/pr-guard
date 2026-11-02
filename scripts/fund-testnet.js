#!/usr/bin/env node
// Testnet funding for PR Guard on Telegraph's Ethereum Sepolia deployment
// (addresses from docs.telegraphprotocol.com, "Addresses & Parameters", Oct 30 2026).
// Uses the burner key in .env; it needs a little Sepolia ETH for gas first.
//
//   node scripts/fund-testnet.js mint <usdc> [recipient]         mint test USDC (to the burner by default)
//   node scripts/fund-testnet.js machina <usdc> <recipient>      swap burner USDC -> MACHINA, sent to recipient
//   node scripts/fund-testnet.js eth <amount> <recipient>        send Sepolia ETH (for gas)
//   node scripts/fund-testnet.js balance [address]
import { createPublicClient, createWalletClient, http, parseUnits, parseEther, formatUnits, formatEther, erc20Abi, getAddress } from "viem";
import { sepolia } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";

try { process.loadEnvFile(".env"); } catch {}

const RPC = process.env.SEPOLIA_RPC_URL || "https://ethereum-sepolia-rpc.publicnode.com";
const USDC = "0xcc194e1a843B658526D0D5C431f670028582Ae17"; // Telegraph test USDC: anyone can mint
const MACHINA = "0xd68305cA83C7AF42A4F720144E7416fB53F8AaF4";
const ROUTER = "0x3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E"; // Uniswap SwapRouter02, MACHINA/USDC pool at 0.3%

const mintAbi = [{ type: "function", name: "mint", stateMutability: "nonpayable", inputs: [{ name: "to", type: "address" }, { name: "amount", type: "uint256" }], outputs: [] }];
const routerAbi = [{
  type: "function", name: "exactInputSingle", stateMutability: "payable",
  inputs: [{ name: "params", type: "tuple", components: [
    { name: "tokenIn", type: "address" }, { name: "tokenOut", type: "address" }, { name: "fee", type: "uint24" },
    { name: "recipient", type: "address" }, { name: "amountIn", type: "uint256" }, { name: "amountOutMinimum", type: "uint256" },
    { name: "sqrtPriceLimitX96", type: "uint160" },
  ] }],
  outputs: [{ name: "amountOut", type: "uint256" }],
}];

const pub = createPublicClient({ chain: sepolia, transport: http(RPC) });

async function balances(address) {
  const [eth, usdc, machina] = await Promise.all([
    pub.getBalance({ address }),
    pub.readContract({ address: USDC, abi: erc20Abi, functionName: "balanceOf", args: [address] }),
    pub.readContract({ address: MACHINA, abi: erc20Abi, functionName: "balanceOf", args: [address] }),
  ]);
  return `${address}: ${formatEther(eth)} ETH, ${formatUnits(usdc, 6)} USDC, ${formatUnits(machina, 18)} MACHINA`;
}

// One readable line instead of viem's full error dump.
process.on("uncaughtException", (e) => {
  console.error(`failed: ${e.shortMessage ?? e.message}${e.details ? ` (${e.details})` : ""}`);
  process.exit(1);
});

const [cmd, amount, to] = process.argv.slice(2);
if (cmd === "balance") {
  console.log(await balances(getAddress(amount ?? privateKeyToAccount(process.env.TELEGRAPH_PRIVATE_KEY).address)));
  process.exit(0);
}

const account = privateKeyToAccount(process.env.TELEGRAPH_PRIVATE_KEY);
const wallet = createWalletClient({ account, chain: sepolia, transport: http(RPC) });
const send = async (label, req) => {
  const hash = await wallet.writeContract(req);
  const r = await pub.waitForTransactionReceipt({ hash });
  if (r.status !== "success") throw new Error(`${label} reverted: ${hash}`);
  console.log(`${label}: ${hash}`);
};

if (cmd === "mint") {
  const recipient = to ? getAddress(to) : account.address;
  await send(`mint ${amount} USDC to ${recipient}`, { address: USDC, abi: mintAbi, functionName: "mint", args: [recipient, parseUnits(amount, 6)] });
  if (to) console.log(await balances(recipient));
} else if (cmd === "machina") {
  const amountIn = parseUnits(amount, 6);
  await send(`approve ${amount} USDC to the router`, { address: USDC, abi: erc20Abi, functionName: "approve", args: [ROUTER, amountIn] });
  await send(`swap ${amount} USDC -> MACHINA for ${to}`, {
    address: ROUTER, abi: routerAbi, functionName: "exactInputSingle",
    args: [{ tokenIn: USDC, tokenOut: MACHINA, fee: 3000, recipient: getAddress(to), amountIn, amountOutMinimum: 1n, sqrtPriceLimitX96: 0n }],
  });
  console.log(await balances(getAddress(to)));
} else if (cmd === "eth") {
  const hash = await wallet.sendTransaction({ to: getAddress(to), value: parseEther(amount) });
  await pub.waitForTransactionReceipt({ hash });
  console.log(`sent ${amount} ETH to ${to}: ${hash}`);
} else {
  console.error("usage: fund-testnet.js mint <usdc> [recipient] | machina <usdc> <recipient> | eth <amount> <recipient> | balance [address]");
  process.exit(2);
}
console.log(await balances(account.address));
