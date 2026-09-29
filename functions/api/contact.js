/**
 * Cloudflare Pages Function: /api/contact
 * Handles contact form submissions securely by proxying to Web3Forms.
 * The access_key is retrieved from Cloudflare Pages Environment Variables (Secrets).
 */
export async function onRequestPost(context) {
    try {
        const data = await context.request.json();

        // הגנת ספאם (Honeypot field) - אם בוט מילא את השדה הנסתר
        if (data.botcheck) {
            return new Response(JSON.stringify({
                success: true,
                message: "Spam check triggered"
            }), {
                status: 200,
                headers: { "Content-Type": "application/json; charset=utf-8" }
            });
        }

        // שליפת המפתח הסודי ממשתנה הסביבה של Cloudflare Pages
        const accessKey = context.env.WEB3FORMS_ACCESS_KEY;

        if (!accessKey) {
            return new Response(JSON.stringify({
                success: false,
                message: "שרת: משתנה הסביבה WEB3FORMS_ACCESS_KEY אינו מוגדר ב-Cloudflare Pages"
            }), {
                status: 500,
                headers: { "Content-Type": "application/json; charset=utf-8" }
            });
        }

        // ניקוי טוקנים טכניים של קאפצ'ה לפני העברה ל-Web3Forms
        const cleanPayload = { ...data };
        delete cleanPayload['cf-turnstile-response'];
        delete cleanPayload['h-captcha-response'];
        delete cleanPayload['g-recaptcha-response'];

        // הרכבת הנתונים עבור Web3Forms
        const payload = {
            ...cleanPayload,
            access_key: accessKey,
            subject: data.subject || "פנייה חדשה מאתר CISO as a Service",
            from_name: "CISO Website"
        };

        // שליחה מאובטחת מצד השרת ל-Web3Forms
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
