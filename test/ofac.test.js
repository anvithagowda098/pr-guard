// The OFAC snapshot: how scripts/update-ofac.js reads the SDN list, and the
// snapshot shipped in src/ofac-addresses.js.
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseCsv, extractAddresses } from "../scripts/update-ofac.js";
import { OFAC_ADDRESSES, OFAC_SNAPSHOT_DATE } from "../src/ofac-addresses.js";

// Shaped like SDN.CSV and SDN_COMMENTS.CSV: "-0-" for empty, programs joined
// by "] [", remarks that continue in the comments file.
const SDN = [
  '100,"EXAMPLE GROUP",-0- ,"DPRK3",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"a.k.a. ""EG""; Digital Currency Address - ETH 0xAbCdEf0123456789abcdef0123456789ABCDEF01; Digital Currency Address - XBT 1BoatSLRHtKNngkdXEeobR76b53LETtpyT"',
  '200,"OTHER, Person",-0- ,"SDGT] [ILLICIT-DRUGS-EO14059",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"DOB 1970; Digital Currency Address - USDT 0x2222222222222222222222222222222222222222;"',
  '300,"NO CRYPTO LTD",-0- ,"CUBA",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ',
].join("\r\n");
const COMMENTS = '100,"Digital Currency Address - ETH 0x3333333333333333333333333333333333333333; Digital Currency Address - ETH 0xabcdef0123456789abcdef0123456789abcdef01."\r\n';

test("parseCsv: quotes, doubled quotes, CRLF", () => {
  assert.deepEqual(parseCsv('a,"b, ""c""",d\r\n1,2,3'), [["a", 'b, "c"', "d"], ["1", "2", "3"]]);
});

test("extractAddresses: Ethereum-format addresses only, lower-cased, overflow remarks included, programs cleaned", () => {
  assert.deepEqual(extractAddresses(SDN, COMMENTS), {
    "0x2222222222222222222222222222222222222222": ["OTHER, Person", "SDGT, ILLICIT-DRUGS-EO14059", "USDT"],
    "0x3333333333333333333333333333333333333333": ["EXAMPLE GROUP", "DPRK3", "ETH"],
    "0xabcdef0123456789abcdef0123456789abcdef01": ["EXAMPLE GROUP", "DPRK3", "ETH"],
  });
});

test("the shipped snapshot: dated, lower-case keys, includes the Lazarus Group's Ronin wallet", () => {
  assert.match(OFAC_SNAPSHOT_DATE, /^\d{4}-\d{2}-\d{2}$/);
  const keys = Object.keys(OFAC_ADDRESSES);
  assert.ok(keys.length > 50);
  assert.ok(keys.every((k) => /^0x[0-9a-f]{40}$/.test(k)));
  assert.deepEqual(OFAC_ADDRESSES["0x098b716b8aaf21512996dc57eb0615e2383e2f96"], ["LAZARUS GROUP", "DPRK3", "ETH"]);
});
