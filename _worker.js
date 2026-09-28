/**
 * Cloudflare Worker / Pages Advanced Mode entrypoint
 * Handles /api/contact securely and serves static assets for all other routes.
 */
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        // ניתוב עבור טופס יצירת הקשר
        if (url.pathname === "/api/contact" && request.method === "POST") {
            try {
                const data = await request.json();

                // הגנת ספאם (Honeypot) - זיהוי בוטים
                if (data.botcheck) {
                    return new Response(JSON.stringify({
                        success: true,
                        message: "Spam check triggered"
                    }), {
                        status: 200,
                        headers: { "Content-Type": "application/json; charset=utf-8" }
                    });
                }

                // שליפת המפתח הסודי ממשתנה הסביבה של Cloudflare (תמיכה בשמות ובפורמטים שונים)
                const accessKey = env?.WEB3FORMS_ACCESS_KEY
                    || env?.WEB3FORMS_ACCES
                    || env?.web3forms_access_key
                    || env?.web3forms_acces
                    || env?.WEB3FORMS_KEY
                    || (typeof WEB3FORMS_ACCESS_KEY !== 'undefined' ? WEB3FORMS_ACCESS_KEY : null)
                    || (typeof WEB3FORMS_ACCES !== 'undefined' ? WEB3FORMS_ACCES : null)
                    || (typeof globalThis !== 'undefined' ? (globalThis.WEB3FORMS_ACCESS_KEY || globalThis.WEB3FORMS_ACCES) : null);

                if (!accessKey) {
                    const availableKeys = Object.keys(env || {}).filter(k => k !== "ASSETS");
                    return new Response(JSON.stringify({
                        success: false,
                        message: `משתנה הסביבה WEB3FORMS_ACCESS_KEY אינו מוגדר בהגדרות Cloudflare. (משתנים שנמצאו: ${availableKeys.length ? availableKeys.join(', ') : 'אף משתנה'})`
                    }), {
                        status: 500,
                        headers: { "Content-Type": "application/json; charset=utf-8" }
                    });
                }

                // הרכבת הנתונים עבור Web3Forms
                const payload = {
                    ...data,
                    access_key: accessKey,
                    subject: data.subject || "פנייה חדשה מאתר CISO as a Service",
                    from_name: "CISO Website"
                };

                // שליחה לשרת של Web3Forms
                const response = await fetch("https://api.web3forms.com/submit", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Accept": "application/json"
                    },
                    body: JSON.stringify(payload)
                });

                const result = await response.json();

                return new Response(JSON.stringify(result), {
                    status: response.status,
                    headers: { "Content-Type": "application/json; charset=utf-8" }
                });

            } catch (error) {
                return new Response(JSON.stringify({
                    success: false,
                    message: "אירעה שגיאה בשרת בעת עיבוד הבקשה",
                    error: error.message
                }), {
                    status: 500,
                    headers: { "Content-Type": "application/json; charset=utf-8" }
                });
            }
        }

        // נקודת בדיקה מאובטחת לבדיקת משתני סביבה (ללא חשיפת ערכים)
        if (url.pathname === "/api/debug") {
            const protoKeys = env ? Object.getOwnPropertyNames(Object.getPrototypeOf(env) || {}) : [];
            const ownKeys = Object.getOwnPropertyNames(env || {});
            const allKeys = [...new Set([...ownKeys, ...protoKeys])];
            const safeSummary = {};
            for (const k of allKeys) {
                if (k !== "ASSETS") {
                    safeSummary[k] = typeof env[k];
                }
            }
            return new Response(JSON.stringify({
                status: "live",
                allKeysFound: allKeys.filter(k => k !== "ASSETS"),
                keysTypes: safeSummary
            }), {
                headers: { "Content-Type": "application/json" }
            });
        }

        // הגשת קבצים סטטיים (index.html וכו')
        if (env.ASSETS) {
            return env.ASSETS.fetch(request);
        }

        return new Response("Not Found", { status: 404 });
    }
};
