const fs = require('fs');

const key = process.env.WEB3FORMS_ACCESS_KEY;

if (key) {
    fs.writeFileSync('.secrets.json', JSON.stringify({
        WEB3FORMS_ACCESS_KEY: key
    }));
    console.log("✅ Successfully created .secrets.json for Wrangler encrypted secret deployment");
} else {
    fs.writeFileSync('.secrets.json', JSON.stringify({}));
    console.log("ℹ️ No WEB3FORMS_ACCESS_KEY in process.env, created empty .secrets.json");
}
