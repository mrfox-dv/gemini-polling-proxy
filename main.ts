// --- Deno Standard Library Imports ---
// 'serve' is used to create the HTTP server.
// 'toHashString' is a utility to convert crypto hash buffers to strings.
import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { toHashString } from "https://deno.land/std@0.224.0/crypto/to_hash_string.ts";

// --- Constants ---
// The host for the Google Generative Language API.
const GOOGLE_API_HOST = "https://generativelanguage.googleapis.com";
// The master API key for this proxy service, retrieved from environment variables.
// This key acts as the password for your proxy.
const PROXY_MASTER_KEY = Deno.env.get("API_KEY");
// A comma-separated list of Google AI Studio API keys, retrieved from environment variables.
// This is the "built-in" mode for keys.
const BUILT_IN_GOOGLE_KEYS = Deno.env.get("TOKENS");

/**
 * In-memory storage for round-robin state.
 *  - Key: A SHA-256 hash of the list of API keys being used.
 *  - Value: The index of the next key to use from that list.
 */
const rotationState = new Map<string, number>();

// --- Helper Functions ---

/**
 * Creates a SHA-256 hash for a given string. This is used to create a unique
 * identifier for each list of API keys, so we can track their rotation state.
 * @param text The text to hash.
 * @returns A promise that resolves to the hex-encoded hash string.
 */
async function sha256(text: string): Promise<string> {
    const hashBuffer = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(text),
    );
    return toHashString(hashBuffer);
}

/**
 * The main request handler for the proxy server.
 * This function is called for every incoming HTTP request.
 * @param req The incoming Request object.
 * @returns A promise that resolves to a Response object.
 */
async function handler(req: Request): Promise<Response> {
    // --- CORS Preflight Request Handling ---
    // Handle OPTIONS requests, which are sent by browsers to check for CORS permissions.
    if (req.method === "OPTIONS") {
        return new Response(null, {
            status: 204, // No Content
            headers: {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization, x-google-api-key",
            },
        });
    }

    // --- Header and Key Extraction ---
    const headers = new Headers(req.headers);
    // The client's API key for this proxy service.
    const clientAuthToken = headers.get("Authorization")?.replace("Bearer ", "");
    // Google API keys can be provided via a custom header (Mode 1) or built-in (Mode 2).
    const keysFromHeader = headers.get("x-google-api-key");
    
    // --- Security Check ---
    // If a master key is configured for the proxy, the client must provide it.
    if (PROXY_MASTER_KEY && clientAuthToken !== PROXY_MASTER_KEY) {
        return new Response(JSON.stringify({ error: "Invalid API Key for proxy service." }), {
            status: 401, // Unauthorized
            headers: { "Content-Type": "application/json" },
        });
    }

    // --- Determine a   nd Validate Google API Keys ---
    // Use keys from the header if provided, otherwise fall back to environment variables.
    const googleApiKeysString = keysFromHeader || BUILT_IN_GOOGLE_KEYS;
    if (!googleApiKeysString) {
        return new Response(JSON.stringify({ error: "No Google API Keys were provided." }), {
            status: 400, // Bad Request
            headers: { "Content-Type": "application/json" },
        });
    }
    const googleApiKeys = googleApiKeysString.split(",").map(k => k.trim()).filter(Boolean);
    if (googleApiKeys.length === 0) {
        return new Response(JSON.stringify({ error: "Google API Keys list is empty." }), {
            status: 400, // Bad Request
            headers: { "Content-Type": "application/json" },
        });
    }

    // --- URL Construction ---
    // Reconstruct the target URL for the Google API.
    const url = new URL(req.url);
    const targetUrl = `${GOOGLE_API_HOST}${url.pathname}${url.search}`;

    // --- Key Rotation and Retries Logic ---
    const keysHash = await sha256(googleApiKeys.join());
    const startIndex = rotationState.get(keysHash) || 0;

    for (let i = 0; i < googleApiKeys.length; i++) {
        const keyIndex = (startIndex + i) % googleApiKeys.length;
        const currentGoogleKey = googleApiKeys[keyIndex];

        // Prepare the request to be forwarded to Google.
        const proxyReqHeaders = new Headers(req.headers);
        proxyReqHeaders.set("host", new URL(GOOGLE_API_HOST).host);
        proxyReqHeaders.set("x-goog-api-key", currentGoogleKey);
        // Remove headers that are specific to this proxy.
        proxyReqHeaders.delete("Authorization");
        proxyReqHeaders.delete("x-google-api-key");
        
        try {
            // Attempt to fetch the response from Google's API.
            const response = await fetch(targetUrl, {
                method: req.method,
                headers: proxyReqHeaders,
                body: req.body,
            });

            // If the request was successful, update rotation state for the next call.
            if (response.ok) {
                rotationState.set(keysHash, (keyIndex + 1) % googleApiKeys.length);
                // Return the successful response, adding CORS headers.
                const responseHeaders = new Headers(response.headers);
                responseHeaders.set("Access-Control-Allow-Origin", "*");
                return new Response(response.body, {
                    status: response.status,
                    statusText: response.statusText,
                    headers: responseHeaders,
                });
            }
            
            // If the key is invalid or rate-limited (4xx error), try the next key.
            if (response.status >= 400 && response.status < 500) {
                console.warn(`Key at index ${keyIndex} failed with status ${response.status}. Trying next key.`);
                // Continue to the next iteration of the loop.
            } else {
                // For server errors (5xx) or other unexpected issues, stop and return the error.
                return response;
            }
        } catch (error) {
            console.error(`Request failed with key at index ${keyIndex}:`, error);
            // If a network error occurs, try the next key.
        }
    }

    // --- All Keys Failed ---
    // If the loop completes without a successful response, all keys have failed.
    rotationState.set(keysHash, 0); // Reset for the next attempt
    return new Response(JSON.stringify({ error: "All provided Google API Keys failed." }), {
        status: 502, // Bad Gateway
        headers: { "Content-Type": "application/json" },
    });
}

// --- Server Startup ---
// Start the Deno HTTP server and pass all requests to the handler.
console.log("Proxy server starting on http://localhost:8000");
serve(handler);
