import {OidcConfigDbModel} from "./database.js";

export const pkceCodeVerifierSessionStorageKey = 'oauth_pkce_code_verifier';
export const stateSessionStorageKey = 'oauth_state';
export const idTokenSessionStorageKey = 'id_token';

export const codeQueryParamName = 'code';
export const stateQueryParamName = 'state';

export const invalidStateError = 'did not recognize state';
export const noCodeVerifier = 'no code verifier in session to use in token exchange';

/**
 * @param authConfig {OidcConfigDbModel}
 * @param accessToken {String}
 * @returns {Promise<*>}
 */
export function getUserInfo(authConfig, accessToken) {
    return callUserInfoEndpoint(authConfig.userInfoEndpoint, accessToken);
}

/**
 * @param authConfig {OidcConfigDbModel}
 * @returns {Promise<any>}
 */
export function logout(authConfig) {
    return callEndSessionEndpoint(authConfig.endSessionEndpoint);
}

/**
 * Starts the authorization code flow. This means this function will redirect the
 * application to the IDP for login. When that is done it will redirect back with
 * an authorization code which can be used to request a token.
 *
 * @param clientId {string}
 * @param redirectUri {URL}
 * @param authorizeEndpoint {URL}
 * @param scope {string}
 */
export async function startAuthorizationCodeFlow(clientId, redirectUri, authorizeEndpoint, scope) {
    console.log('start authorization code flow');
    const codeVerifier = generateRandomString(56);
    const codeChallenge = await createCodeChallenge(codeVerifier);
    const state = generateRandomString(16);

    sessionStorage.setItem(pkceCodeVerifierSessionStorageKey, codeVerifier);
    sessionStorage.setItem(stateSessionStorageKey, state);
    sessionStorage.setItem('oauth_pkce_code_challenge', codeChallenge);

    const authParams = new URLSearchParams({
        client_id: clientId,
        redirect_uri: redirectUri.toString(),
        scope: scope,
        response_type: 'code',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        state: state
    })

    const authUrl = `${authorizeEndpoint.protocol}//${authorizeEndpoint.host}${authorizeEndpoint.pathname}?${authParams.toString()}`;
    console.log(`navigating for auth: ${authUrl}`);
    window.location.href = authUrl;

    // return false needs to be here to make the redirect work...
    return false;
}

/**
 * @param authorizationCode {string}
 * @param receivedState {string}
 * @param tokenEndpoint {URL}
 * @param clientId {string}
 * @param redirectUri {URL}
 * @returns {Promise<TokenResponse>}
 */
export async function exchangeAuthorizationCodeForAccessToken(authorizationCode, receivedState, tokenEndpoint, clientId, redirectUri) {
    try {
        console.log('exchange authorization-code for access-token');

        const createdState = sessionStorage.getItem(stateSessionStorageKey);
        if (createdState == null || createdState !== receivedState) {
            throw invalidStateError;
        }

        const codeVerifier = sessionStorage.getItem(pkceCodeVerifierSessionStorageKey);
        if (codeVerifier == null) {
            throw noCodeVerifier;
        }

        const tokenResponse = await callTokenEndpoint(
            tokenEndpoint,
            TokenRequestParams.authorizationCode(clientId, redirectUri, authorizationCode, codeVerifier)
        );

        sessionStorage.setItem(idTokenSessionStorageKey, tokenResponse.id_token);
        return tokenResponse;
    } finally {
        sessionStorage.removeItem(pkceCodeVerifierSessionStorageKey);
        sessionStorage.removeItem(stateSessionStorageKey);
    }
}

/**
 * Makes a POST request to the token endpoint of the IDP and handles its
 * response.
 *
 * @param tokenEndpoint {URL} is the url to call.
 * @param authParams {TokenRequestParams} parameters to add to the request
 * @returns {Promise<TokenResponse>}
 */
export async function callTokenEndpoint(tokenEndpoint, authParams) {
    console.log()

    const init = {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: authParams.toUrlSearchParams().toString(),
    }
    if (authParams.clientSecret != null) {
        init.headers['Authorization'] = basicAuthHeaderValue(authParams.clientId, authParams.clientSecret);
    }

    const response = await fetch(tokenEndpoint, init);

    if (response.status >= 500) {
        throw `failed to call token endpoint (server error): ${response.status} ${response.statusText}: ${await response.text()}`;
    } else if (response.status >= 400) {
        throw `failed to call token endpoint: ${response.status} ${response.statusText}: ${await response.text()}`;
    }

    return await response.json();
}

/**
 * @param userInfoEndpoint {URL}
 * @param accessToken {string}
 * @returns {Promise<any>}
 */
export async function callUserInfoEndpoint(userInfoEndpoint, accessToken) {
    const response = await fetch(userInfoEndpoint, {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${accessToken}`
        }
    });

    if (response.status >= 500) {
        throw `failed to call user info endpoint (server error): ${response.status} ${response.statusText}: ${await response.text()}`;
    } else if (response.status >= 400) {
        throw `failed to call user info endpoint: ${response.status} ${response.statusText}: ${await response.text()}`;
    }

    return await response.json();
}

export async function callEndSessionEndpoint(endSessionEndpoint, clientId, accessToken) {
    const response = await fetch(endSessionEndpoint, {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${accessToken}`
        }
    });

    if (response.status >= 500) {
        throw `failed to call end session endpoint (server error): ${response.status} ${response.statusText}: ${await response.text()}`;
    } else if (response.status >= 400) {
        throw `failed to call end session endpoint: ${response.status} ${response.statusText}: ${await response.text()}`;
    }

    return await response.json();
}

export async function callDiscoveryEndpoint(discoveryEndpoint) {
    const response = await fetch(discoveryEndpoint, {
        method: 'GET',
    });

    if (response.status >= 500) {
        throw `failed to call end discovery endpoint (server error): ${response.status} ${response.statusText}: ${await response.text()}`;
    } else if (response.status >= 400) {
        throw `failed to call end discovery endpoint: ${response.status} ${response.statusText}: ${await response.text()}`;
    }

    const document = await response.json();
    return new DiscoveryDocument(
        document["authorization_endpoint"],
        document["token_endpoint"],
        document["userinfo_endpoint"],
        document["end_session_endpoint"]
    );
}

/**
 * @param userName {string}
 * @param password {string}
 */
export function basicAuthHeaderValue(userName, password) {
    userName = encodeURI(userName);
    password = encodeURI(password);
    const base64 = btoa(`${userName}:${password}`);
    return `Basic ${base64}`;
}

/**
 * @param {number} length is the length of requested string
 * @returns {string} A random string ([A-Za-z0-9]+)
 */
function generateRandomString(length) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array
        .from(array, n => chars[n % chars.length])
        .join('');
}

/**
 * @param {string} verifier is the verifier which should be used for the challenge
 * @returns {Promise<string>} The SHA256 hashed input.
 */
async function createCodeChallenge(verifier) {
    const verifierHash = await sha256(verifier)

    return btoa(verifierHash) // base64 encode
        .replace(/\+/g, '-')
        .replace(/\//g, '-')
        .replace(/=+$/, '');
}

/**
 * Hashes a given input string as a SHA256. This function exists because the
 * crypto functionality of a browser does not exist inside an "insecure context"
 * like our dev-evn.
 *
 * @param input {string}
 * @return {Promise<string>}
 */
async function sha256(input) {
    if (isSecureContext) {
        const buffer = new TextEncoder().encode(input);
        const hashBuff = await crypto.subtle.digest('SHA-256', buffer);
        return String.fromCharCode(...new Uint8Array(hashBuff));
    }

    console.warn('Running in insecure context. Using CryptoJS instead of browser built-in');
    if (!window.CryptoJS) {
        await new Promise((resolve, reject) => {
            const s = document.createElement('script');
            s.src = 'https://cdn.jsdelivr.net/npm/crypto-js@4.2.0/crypto-js.min.js';
            s.onload = resolve;
            s.onerror = reject;
            document.head.appendChild(s);
        });
    }
    return CryptoJS.SHA256(input).toString(CryptoJS.enc.Hex);
}

/**
 * @param input {string}
 * @returns {string}
 */
function base64Decode(input) {
    // Replace non-url compatible chars with base64 standard chars
    input = input
        .replace(/-/g, '+')
        .replace(/_/g, '/');

    // Pad out with standard base64 required padding characters
    const pad = input.length % 4;
    if (pad) {
        if (pad === 1) {
            throw new Error('InvalidLengthError: Input base64url string is the wrong length to determine padding');
        }
        input += new Array(5 - pad).join('=');
    }

    return atob(input);
}

// ----------------------------------------------------------------------------
// MODELS
// ----------------------------------------------------------------------------

/**
 * Response from the token endpoint after requesting a token from the IDP.
 */
class TokenResponse {
    /**
     * @param access_token {string}
     * @param refresh_token {string|null}
     * @param id_token {string}
     */
    constructor(
        access_token,
        refresh_token,
        id_token,
    ) {
        this.access_token = access_token;
        this.refresh_token = refresh_token;
        this.id_token = id_token;
    }
}

/**
 * Request with which a token can be requested from the IDP.
 */
export class TokenRequestParams {
    /**
     * @param client_id {string}
     * @param client_secret {string|null}
     * @param grant_type {"refresh_token"|"authorization_code"|"client_credentials"}
     * @param redirect_uri {URL|null}
     * @param scope {string|null}
     * @param refresh_token {string|null}
     * @param code {string|null}
     * @param code_verifier {string|null}
     */
    constructor(
        client_id,
        client_secret,
        grant_type,
        redirect_uri,
        scope,
        refresh_token,
        code,
        code_verifier) {
        this.clientId = client_id;
        this.clientSecret = client_secret;
        this.grantType = grant_type;
        this.redirectUri = redirect_uri;
        this.scope = scope;
        this.refreshToken = refresh_token;
        this.code = code;
        this.codeVerifier = code_verifier;
    }

    /**
     * @param clientId {string}
     * @param redirectUrl {URL}
     * @param code {string}
     * @param codeVerifier {string}
     */
    static authorizationCode(clientId, redirectUrl, code, codeVerifier) {
        return new TokenRequestParams(clientId, null, 'authorization_code', redirectUrl, null, null, code, codeVerifier);
    }

    /**
     * @param clientId {string}
     * @param redirectUrl {URL}
     * @param scope {string}
     * @param refreshToken {string}
     */
    static refreshToken(clientId, redirectUrl, scope, refreshToken) {
        return new TokenRequestParams(clientId, null, 'refresh_token', redirectUrl, scope, refreshToken, null, null);
    }

    /**
     * @param clientId {string}
     * @param clientSecret {string}
     * @param scope {string}
     * @returns {TokenRequestParams}
     */
    static clientCredentials(clientId, clientSecret, scope) {
        return new TokenRequestParams(clientId, clientSecret, 'client_credentials', null, scope, null, null, null);
    }

    toUrlSearchParams() {
        return new URLSearchParams({
            client_id: this.clientId,
            client_secret: this.clientSecret,
            grant_type: this.grantType,
            redirect_uri: this.redirectUri == null ? null : this.redirectUri.toString(),
            scope: this.scope,
            refresh_token: this.refreshToken,
            code: this.code,
            code_verifier: this.codeVerifier,
        });
    }
}

export class DiscoveryDocument {
    constructor(authorizationEndpoint, tokenEndpoint, userInfoEndpoint, endSessionEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
        this.tokenEndpoint = tokenEndpoint;
        this.userInfoEndpoint = userInfoEndpoint;
        this.endSessionEndpoint = endSessionEndpoint;
    }
}

export class Jwt {
    /**
     * @param encoded {string}
     * @param header {string}
     * @param payload {string}
     * @param signature {string}
     */
    constructor(encoded, header, payload, signature) {
        this.encoded = encoded;
        this.header = header;
        this.payload = payload;
        this.signature = signature
    }

    /**
     * @param encoded {string}
     */
    static parse(encoded) {
        const split = encoded.split('.');

        const headerJson = base64Decode(split[0]);
        const payloadJson = base64Decode(split[1]);
        return new Jwt(
            encoded,
            JSON.parse(headerJson),
            JSON.parse(payloadJson),
            split[2]
        );
    }
}