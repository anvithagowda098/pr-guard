#!/usr/bin/env node
// Burner testnet wallet for x402 payments on Telegraph's testnet (Ethereum Sepolia since Oct 30 2026).
//
//   node scripts/wallet.js            create .env with a new key (refuses to overwrite)
//   node scripts/wallet.js balance    print address and USDC balance
//
// The key never leaves .env. Fund it: a little Sepolia ETH from a faucet, then
// `node scripts/fund-testnet.js mint 20` (Telegraph's test USDC is free to mint).
import { existsSync, writeFileSync } from "node:fs";
import { createPublicClient, http, erc20Abi, formatUnits } from "viem";
import { sepolia } from "viem/chains";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const USDC = "0xcc194e1a843B658526D0D5C431f670028582Ae17"; // Telegraph test USDC on Ethereum Sepolia
const ENV_FILE = ".env";

if (process.argv[2] === "balance") {
  try { process.loadEnvFile(ENV_FILE); } catch {}
  const key = process.env.TELEGRAPH_PRIVATE_KEY;
  if (!key) {
    console.error(`no TELEGRAPH_PRIVATE_KEY in ${ENV_FILE} or env; run: node scripts/wallet.js`);
    process.exit(1);
  }
  const { address } = privateKeyToAccount(key);
  const client = createPublicClient({ chain: sepolia, transport: http(process.env.SEPOLIA_RPC_URL || "https://ethereum-sepolia-rpc.publicnode.com") });
  const raw = await client.readContract({ address: USDC, abi: erc20Abi, functionName: "balanceOf", args: [address] });
  console.log(`address: ${address}`);
  console.log(`USDC:    ${formatUnits(raw, 6)} (Ethereum Sepolia)`);
} else {
  if (existsSync(ENV_FILE)) {
    console.error(`${ENV_FILE} already exists; not overwriting. Use \`node scripts/wallet.js balance\`.`);
    process.exit(1);
  }
  const key = generatePrivateKey();
  const { address } = privateKeyToAccount(key);
  writeFileSync(
    ENV_FILE,
    `# BURNER testnet key for PR Guard. Never fund with real assets. Never commit.\nTELEGRAPH_PRIVATE_KEY=${key}\nTELEGRAPH_NODE_URL=https://devnode.telegraphprotocol.com\n`,
    { mode: 0o600 },
  );
  console.log(`wrote ${ENV_FILE}`);
  console.log(`address: ${address}`);
  console.log("fund it: Sepolia ETH from a faucet to the address above, then: node scripts/fund-testnet.js mint 20");
}
