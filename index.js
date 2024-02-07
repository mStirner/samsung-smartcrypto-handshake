const fetch = require('node-fetch').default;
const crypto = require('crypto');
const { exec } = require("child_process");
const readline = require("readline");

const shared = require("./shared.js");

function sha1(input) {
    return crypto.createHash('sha1').update(input).digest('hex');
}

function hex2bin(hexString) {
    return Buffer.from(hexString, 'hex');
}


const UserId = "654321";
const AppId = "12345";
//let dest_hash = "";
//let SKPrime = "";
//let ctx = "";
// const Guid = "7e509404-9d7c-46b4-8f6a-e2a9668ad184";
const deviceId = "784c5390-73a2-441e-91d6-1980b114e866";
//let hash = "";
//let AES_key = "";
let lastRequestId = "";
//let sessionId = 0;
const tvIP = "192.168.2.100";
const tvPort = "8080";

function getFullUrl(urlPath) {
    return `http://${tvIP}:${tvPort}${urlPath}`;
}

function getFullRequestUri(step, appId, deviceId) {
    return getFullUrl(`/ws/pairing?step=${step}&app_id=${appId}&device_id=${deviceId}`);
}


function runSmartCrypto(args) {
    return new Promise((resolve, reject) => {
        exec(`./bin/smartcrypto ${args}`, (err, stdout, stderr) => {
            if (err || stderr) {

                reject(err || stderr);

            } else {

                //console.log("stdout", stdout.toString());
                resolve(JSON.parse(stdout));

            }
        });
    });
}

async function checkPinPageOnTv() {
    const fullUrl = getFullUrl("/ws/apps/CloudPINPage");
    const response = await fetch(fullUrl);
    const page = await response.text();

    const stateMatch = page.match(/<state>([^<>]*)<\/state>/si);

    console.log("Current state: ", stateMatch[1]);

    return stateMatch[1] === "stopped";
}

async function showPinPageOnTv() {
    await fetch(getFullUrl("/ws/apps/CloudPINPage"), {
        method: "POST",
        body: "pin4"
    });
}

async function startPairing() {
    lastRequestId = 0;

    if (await checkPinPageOnTv()) {
        console.log("Pin NOT on TV");
        await showPinPageOnTv();
    } else {
        console.log("Pin ON TV");
    }
}

async function firstStepOfPairing() {
    const firstStepURL = getFullRequestUri(0, AppId, deviceId) + "&type=1";
    const firstStepResponse = await fetch(firstStepURL);
    // Process the response if needed
}

async function generateServerHello(pin) {

    const res = await runSmartCrypto(`generateServerHello ${UserId} ${pin}`);
    const { AES_key, hash, ServerHello } = res;

    console.log();
    console.group("generateServerHello:");
    console.log("AES_key:", AES_key);
    console.log("hash:", hash);
    console.log("ServerHello:", ServerHello);
    console.groupEnd();
    console.log();

    shared.AES_key = AES_key;
    shared.hash = hash;

    //const match = res.match(/AES key: ([^ \n]*).*hash: ([^ \n]*).*ServerHello: ([^ \n]*)/si);

    //AES_key = match[1];
    //hash = match[2];
    //return match[3];
    return ServerHello;

}

async function parseClientHello(clientHello) {

    const res = await runSmartCrypto(`parseClientHello ${clientHello} ${shared.hash} ${shared.AES_key} ${UserId}`);
    const { dest_hash, SKPrime, ctx } = res;

    console.log();
    console.group("parseClientHello:");
    console.log("dest_hash", dest_hash);
    console.log("SKPrime", SKPrime);
    console.log("ctx", ctx);
    console.groupEnd();
    console.log();

    //const match = res.match(/dest_hash: ([^ \n]*).*SKPrime: ([^ \n]*).*ctx: ([^ \n]*)/si);

    //dest_hash = match[1];
    //SKPrime = match[2];
    //ctx = match[3];
    shared.dest_hash = dest_hash;
    shared.SKPrime = SKPrime;
    shared.ctx = ctx;

    //console.log("dest_hash: ", dest_hash);
    //console.log("SKPrime: ", SKPrime);
    //console.log("ctx: ", ctx);

    return true;
}

async function helloExchange(serverHello) {

    //const serverHello = await generateServerHello(pin);

    if (!serverHello) {
        return false;
    }

    const content = JSON.stringify({
        auth_Data: {
            auth_type: "SPC",
            GeneratorServerHello: serverHello
        }
    });

    const secondStepURL = getFullRequestUri(1, AppId, deviceId);

    const secondStepResponse = await fetch(secondStepURL, {
        method: "POST",
        body: content
    });

    const body = await secondStepResponse.text();
    const match = body.match(/request_id.*?(\d).*?GeneratorClientHello.*?:.*?(\d[0-9a-zA-Z]*)/si);

    const requestId = match[1];
    const clientHello = match[2];

    lastRequestId = requestId;

    return clientHello;
    //return parseClientHello(clientHello);
}

function generateServerAcknowledge() {
    const SKPrimeHash = sha1(hex2bin(shared.SKPrime + "01"));
    return "0103000000000000000014" + SKPrimeHash.toUpperCase() + "0000000000";
}

function parseClientAcknowledge(clientAck) {
    const SKPrimeHash = sha1(hex2bin(shared.SKPrime + "02"));
    const tmpClientAck = "0104000000000000000014" + SKPrimeHash.toUpperCase() + "0000000000";
    return clientAck === tmpClientAck;
}

async function acknowledgeExchange() {

    const serverAckMessage = generateServerAcknowledge();
    const thirdStepURL = getFullRequestUri(2, AppId, deviceId);

    const content = JSON.stringify({
        auth_Data: {
            auth_type: "SPC",
            request_id: lastRequestId,
            ServerAckMsg: serverAckMessage
        }
    });

    const thirdStepResponse = await fetch(thirdStepURL, {
        method: "POST",
        body: content
    });

    const body = await thirdStepResponse.text();

    if (body.includes("secure-mode")) {
        console.log("TODO: Implement handling of encryption flag!!!!");
        process.exit(-1);
    }

    const match = body.match(/ClientAckMsg.*?:.*?(\d[0-9a-zA-Z]*).*?session_id.*?(\d)/si);

    if (!match) {
        console.log("Unable to get session_id and/or ClientAckMsg!!!");
        process.exit(-1);
    }

    const clientAck = match[1];
    const sessionId = match[2];

    console.log("sessionId: ", sessionId);

    if (!parseClientAcknowledge(clientAck)) {
        console.log("Parse client ac message failed.");
        process.exit(-1);
    }

    // needed for auth
    return sessionId;
}

async function closePinPageOnTv() {
    await fetch(getFullUrl("/ws/apps/CloudPINPage/run"), { method: "DELETE" });
}

async function main() {

    await startPairing();

    let rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    rl.question("PIN:", async (pin) => {

        console.log("Got pin: ", pin);

        await firstStepOfPairing();

        let serverHello = await generateServerHello(pin);
        let exchange = await helloExchange(serverHello);
        let pinAccepted = await parseClientHello(exchange);

        if (pinAccepted) {
            console.log("Pin accepted :)\n\n");
        } else {
            console.log("Pin incorrect. Please try again...\n\n");
        }



        await acknowledgeExchange();
        await closePinPageOnTv();

        console.log("Authorization successful :)\n\n");

        rl.close();

    });

}

main();
