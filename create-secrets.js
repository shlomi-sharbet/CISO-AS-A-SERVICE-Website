const fs = require('fs');

const secrets = {};

const web3Key = process.env.WEB3FORMS_ACCESS_KEY;
if (web3Key) {
    secrets.WEB3FORMS_ACCESS_KEY = web3Key;
}

const turnstileSecret = process.env.TURNSTILE_SECRET_KEY || process.env.TURNSTILE_SECRET;
if (turnstileSecret) {
    secrets.TURNSTILE_SECRET_KEY = turnstileSecret;
}

fs.writeFileSync('.secrets.json', JSON.stringify(secrets));

if (Object.keys(secrets).length > 0) {
    console.log(`✅ Successfully generated .secrets.json with ${Object.keys(secrets).length} secret(s) for Wrangler deployment.`);
} else {
    console.log("ℹ️ No secret environment variables detected; generated empty .secrets.json.");
}
