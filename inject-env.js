const fs = require('fs');

const key = process.env.WEB3FORMS_ACCESS_KEY;

if (key) {
    try {
        const configPath = 'wrangler.json';
        if (fs.existsSync(configPath)) {
            const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
            config.vars = config.vars || {};
            config.vars.WEB3FORMS_ACCESS_KEY = key;
            fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
            console.log("✅ Injected WEB3FORMS_ACCESS_KEY into wrangler.json for deployment!");
        }
    } catch (err) {
        console.error("Error updating wrangler.json:", err);
    }
} else {
    console.log("ℹ️ No WEB3FORMS_ACCESS_KEY found in build environment.");
}
