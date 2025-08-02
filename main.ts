// --- Deno Standard Library Imports ---
import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
// FINAL, VERIFIED CORRECT IMPORT: The function is 'encodeHex'.
import { encodeHex } from "https://deno.land/std@0.224.0/encoding/hex.ts";

// --- Constants ---
const GOOGLE_API_HOST = "https://generativelanguage.googleapis.com";
const PROXY_MASTER_KEY = Deno.env.get("API_KEY");
const BUILT_IN_GOOGLE_KEYS = Deno.env.get("TOKENS");

/**
 * In-memory storage for round-robin state.
 *  - Key: A SHA-256 hash of the list of API keys being used.
 *  - Value: The index of the next key to use from that list.
 */
const rotationState = new Map<string, number>();

// --- Helper Functions ---

/**
 * Creates a SHA-256 hash for a given string.
 * @param text The text to hash.
 * @returns A promise that resolves to the hex-encoded hash string.
 */
async function sha256(text: string): Promise<string> {
    const messageBuffer = new TextEncoder().encode(text);
    const hashBuffer = await crypto.subtle.digest("SHA-256", messageBuffer);
    // FINAL, VERIFIED CORRECT FUNCTION CALL: Use 'encodeHex' on the ArrayBuffer.
    return encodeHex(hashBuffer);
}

/**
 * The main request handler for the proxy server.
 * @param req The incoming Request object.
 * @returns A promise that resolves to a Response object.
 */
async function handler(req: Request): Promise<Response> {
    // --- CORS Preflight Request Handling ---
    if (req.method === "OPTIONS") {
        return new Response(null, {
            status: 204,
            headers: {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization, x-google-api-key",
            },
        });
    }

    // --- Header and Key Extraction ---
    const headers = new Headers(req.headers);
    const clientAuthToken = headers.get("Authorization")?.replace("Bearer ", "");
    const keysFromHeader = headers.get("x-google-api-key");
    
    // --- Security Check ---
    if (PROXY_MASTER_KEY && clientAuthToken !== PROXY_MASTER_KEY) {
        return new Response(JSON.stringify({ error: "Invalid API Key for proxy service." }), {
            status: 401,
            headers: { "Content-Type": "application/json" },
        });
    }

    // --- Determine and Validate Google API Keys ---
    const googleApiKeysString = keysFromHeader || BUILT_IN_GOOGLE_KEYS;
    if (!googleApiKeysString) {
        return new Response(JSON.stringify({ error: "No Google API Keys were provided." }), {
            status: 400,
            headers: { "Content-Type": "application/json" },
        });
    }
    const googleApiKeys = googleApiKeysString.split(",").map(k => k.trim()).filter(Boolean);
    if (googleApiKeys.length === 0) {
        return new Response(JSON.stringify({ error: "Google API Keys list is empty." }), {
            status: 400,
            headers: { "Content-Type": "application/json" },
        });
    }

    // --- URL Construction ---
    const url = new URL(req.url);
    const targetUrl = `${GOOGLE_API_HOST}${url.pathname}${url.search}`;

    // --- Key Rotation and Retries Logic ---
    const keysHash = await sha256(googleApiKeys.join());
    const startIndex = rotationState.get(keysHash) || 0;

    for (let i = 0; i < googleApiKeys.length; i++) {
        const keyIndex = (startIndex + i) % googleApiKeys.length;
        const currentGoogleKey = googleApiKeys[keyIndex];

        const proxyReqHeaders = new Headers(req.headers);
        proxyReqHeaders.set("host", new URL(GOOGLE_API_HOST).host);
        proxyReqHeaders.set("x-goog-api-key", currentGoogleKey);
        proxyReqHeaders.delete("Authorization");
        proxyReqHeaders.delete("x-google-api-key");
        
        try {
            const response = await fetch(targetUrl, {
                method: req.method,
                headers: proxyReqHeaders,
                body: req.body,
            });

            if (response.ok) {
                rotationState.set(keysHash, (keyIndex + 1) % googleApiKeys.length);
                const responseHeaders = new Headers(response.headers);
                responseHeaders.set("Access-Control-Allow-Origin", "*");
                return new Response(response.body, {
                    status: response.status,
                    statusText: response.statusText,
                    headers: responseHeaders,
                });
            }
            
            if (response.status >= 400 && response.status < 500) {
                console.warn(`Key at index ${keyIndex} failed with status ${response.status}. Trying next key.`);
            } else {
                const responseHeaders = new Headers(response.headers);
                responseHeaders.set("Access-Control-Allow-Origin", "*");
                 return new Response(response.body, {
                    status: response.status,
                    statusText: response.statusText,
                    headers: responseHeaders,
                });
            }
        } catch (error) {
            console.error(`Request failed with key at index ${keyIndex}:`, error);
        }
    }

    // --- All Keys Failed ---
    rotationState.set(keysHash, 0);
    return new Response(JSON.stringify({ error: "All provided Google API Keys failed." }), {
        status: 502,
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
    });
}

// --- Server Startup ---
console.log("Proxy server starting...");
serve(handler);
