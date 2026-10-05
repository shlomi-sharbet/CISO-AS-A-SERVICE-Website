/**
 * Cloudflare Worker entrypoint
 * Hardened Backend-for-Frontend (BFF) Proxy for contact form and secure static asset delivery.
 */

const SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"
};

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        // ניתוב עבור טופס יצירת הקשר
        if (url.pathname === "/api/contact" && request.method === "POST") {
            try {
                // בדיקת גודל גוף הבקשה למניעת הצפת זיכרון (DoS)
                const contentLength = parseInt(request.headers.get("content-length") || "0", 10);
                if (contentLength > 50000) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: "גודל הבקשה חורג מהמותר."
                    }), {
                        status: 413,
                        headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                    });
                }

                const data = await request.json();

                // הגנת ספאם (Honeypot) - זיהוי בוטים
                if (data.botcheck) {
                    return new Response(JSON.stringify({
                        success: true,
                        message: "Spam check triggered"
                    }), {
                        status: 200,
                        headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                    });
                }

                // ולידציית קלט בסיסית וסינון אורך שדות (Input Validation)
                if (typeof data.name !== "string" || !data.name.trim() || data.name.length > 150) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: "שם מלא אינו תקין או ארוך מדי."
                    }), {
                        status: 400,
                        headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                    });
                }

                if (typeof data.company !== "string" || !data.company.trim() || data.company.length > 150) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: "שם החברה אינו תקין או ארוך מדי."
                    }), {
                        status: 400,
                        headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                    });
                }

                if (typeof data.phone !== "string" || !data.phone.trim() || data.phone.length > 30) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: "מספר טלפון אינו תקין או ארוך מדי."
                    }), {
                        status: 400,
                        headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                    });
                }

                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                if (typeof data.email !== "string" || !emailRegex.test(data.email.trim()) || data.email.length > 150) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: "כתובת דוא״ל אינה תקינה."
                    }), {
                        status: 400,
                        headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                    });
                }

                if (data.role && (typeof data.role !== "string" || data.role.length > 100)) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: "שדה תפקיד אינו תקין או ארוך מדי."
                    }), {
                        status: 400,
                        headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                    });
                }

                if (data.employees && (typeof data.employees !== "string" || data.employees.length > 50)) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: "שדה מספר עובדים אינו תקין."
                    }), {
                        status: 400,
                        headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                    });
                }

                if (data.country && (typeof data.country !== "string" || data.country.length > 100)) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: "שדה מדינה אינו תקין."
                    }), {
                        status: 400,
                        headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                    });
                }

                if (data.service && (typeof data.service !== "string" || data.service.length > 100)) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: "שדה שירות מבוקש אינו תקין."
                    }), {
                        status: 400,
                        headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                    });
                }

                if (data.timeline && (typeof data.timeline !== "string" || data.timeline.length > 100)) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: "שדה מועד התחלה אינו תקין."
                    }), {
                        status: 400,
                        headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                    });
                }

                if (data.message && (typeof data.message !== "string" || data.message.length > 3000)) {
                    return new Response(JSON.stringify({
                        success: false,
                        message: "תוכן ההודעה ארוך מדי (מקסימום 3000 תווים)."
                    }), {
                        status: 400,
                        headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                    });
                }

                // שליפת המפתח הסודי ממשתנה הסביבה של Cloudflare
                const accessKey = env?.WEB3FORMS_ACCESS_KEY;

                if (!accessKey) {
                    console.error("Configuration error: WEB3FORMS_ACCESS_KEY is not defined in Cloudflare environment secrets.");
                    return new Response(JSON.stringify({
                        success: false,
                        message: "שגיאת תצורה בשרת בעת עיבוד הבקשה."
                    }), {
                        status: 500,
                        headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                    });
                }

                // אימות Cloudflare Turnstile (Canonical Server-Side siteverify)
                const turnstileToken = data['cf-turnstile-response'];
                const turnstileSecret = env?.TURNSTILE_SECRET || env?.TURNSTILE_SECRET_KEY;
                const expectedAction = "contact";
                const expectedHostnames = new Set(
                    (env?.TURNSTILE_HOSTNAMES ?? "cyber-path.shlomi-sharbet.workers.dev")
                        .split(",")
                        .map(h => h.trim())
                        .filter(Boolean)
                );

                if (turnstileSecret) {
                    if (
                        typeof turnstileToken !== "string" ||
                        turnstileToken.length === 0 ||
                        turnstileToken.length > 2048
                    ) {
                        return new Response(JSON.stringify({
                            success: false,
                            message: "אימות Cloudflare Turnstile חסר או שגוי."
                        }), {
                            status: 403,
                            headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                        });
                    }

                    try {
                        const clientIp = request.headers.get("CF-Connecting-IP") || request.headers.get("x-forwarded-for");
                        const verifyBody = new URLSearchParams({
                            secret: turnstileSecret,
                            response: turnstileToken
                        });
                        if (clientIp) verifyBody.set("remoteip", clientIp);

                        const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
                            method: "POST",
                            headers: { "Content-Type": "application/x-www-form-urlencoded" },
                            signal: AbortSignal.timeout(10_000),
                            body: verifyBody
                        });

                        if (!r.ok) throw new Error(`siteverify returned HTTP ${r.status}`);
                        const result = await r.json();

                        const requestHost = (request.headers.get("host") || url.hostname || "").split(":")[0].toLowerCase();
                        const isHostnameValid = !result.hostname || 
                            expectedHostnames.size === 0 || 
                            expectedHostnames.has(result.hostname) || 
                            result.hostname === requestHost || 
                            [...expectedHostnames].some(h => result.hostname.endsWith("." + h) || h.endsWith("." + result.hostname));

                        if (
                            !result.success ||
                            (result.action && result.action !== expectedAction) ||
                            !isHostnameValid
                        ) {
                            return new Response(JSON.stringify({
                                success: false,
                                message: "אימות Cloudflare Turnstile נכשל. אנא נסה שוב."
                            }), {
                                status: 403,
                                headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                            });
                        }
                    } catch (turnstileErr) {
                        console.error("Turnstile siteverify error:", turnstileErr);
                        return new Response(JSON.stringify({
                            success: false,
                            message: "שגיאה במהלך בדיקת האימות מול Cloudflare."
                        }), {
                            status: 403,
                            headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                        });
                    }
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
                    subject: typeof data.subject === "string" && data.subject.length <= 150 ? data.subject : "פנייה חדשה מאתר Cyber Path",
                    from_name: "Cyber Path"
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
                    headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                });

            } catch (error) {
                console.error("Contact API Server Error:", error);
                return new Response(JSON.stringify({
                    success: false,
                    message: "אירעה שגיאה בשרת בעת עיבוד הבקשה."
                }), {
                    status: 500,
                    headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS }
                });
            }
        }

        // הגשת קבצים סטטיים (index.html וכו') עם כותרות אבטחה
        if (env.ASSETS) {
            const assetResponse = await env.ASSETS.fetch(request);
            const headers = new Headers(assetResponse.headers);
            for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
                headers.set(key, value);
            }
            return new Response(assetResponse.body, {
                status: assetResponse.status,
                statusText: assetResponse.statusText,
                headers: headers
            });
        }

        return new Response("Not Found", { status: 404, headers: SECURITY_HEADERS });
    }
};
