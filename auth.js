const pkceCodeVerifierSessionStorageKey = 'oauth_pkce_code_verifier';
const stateSessionStorageKey = 'oauth_state';
const idTokenSessionStorageKey = 'id_token';

const refreshTokenLocalStorageKey = 'refresh_token';

const codeQueryParamName = 'code';
const stateQueryParamName = 'state';

const authConfig = {
    tokenEndpoint: new URL('http://localhost:8080/oauth/v2/token'),
    authorizationEndpoint: new URL('http://localhost:8080/oauth/v2/authorize'),
    userInfoEndpoint: new URL('http://localhost:8080/oidc/v1/userinfo'),
    endSessionEndpoint: new URL('http://localhost:8080/oidc/v1/end_session'),
    clientId: '349564292321837244',
    redirectUri: new URL('http://localhost:37679/'),
    scopes: ['openid', 'email', 'profile', 'offline_access']
};


/**
 * The last received access token.
 * @type {TokenResponse|null} string
 */
let tokenResponse = null;

async function authorize() {
    if (tokenResponse != null) {
        return tokenResponse.access_token;
    }

    const urlParams = new URLSearchParams(window.location.search);
    const authorizationCode = urlParams.get(codeQueryParamName);
    const receivedState = urlParams.get(stateQueryParamName);

    const codeVerifier = sessionStorage.getItem(pkceCodeVerifierSessionStorageKey);
    const createdState = sessionStorage.getItem(stateSessionStorageKey);
    if (codeVerifier !== null
        && authorizationCode !== null && authorizationCode.length !== 0
        && createdState !== null && createdState === receivedState) {
        tokenResponse = await exchangeAuthorizationCodeForAccessToken(
            authorizationCode,
            receivedState,
            authConfig.tokenEndpoint,
            authConfig.clientId,
            authConfig.redirectUri
        );
        console.log('received token response', tokenResponse);
        return tokenResponse.access_token;
    }

    const refreshToken = localStorage.getItem(refreshTokenLocalStorageKey);
    if (refreshToken !== null) {
        tokenResponse = await exchangeRefreshTokenForAccessToken(
            authConfig.tokenEndpoint,
            authConfig.clientId,
            authConfig.redirectUri,
            authConfig.scopes
        );
        console.log('received token response', tokenResponse);
        return tokenResponse.access_token;
    }

    await startAuthorizationCodeFlow(
        authConfig.clientId,
        authConfig.redirectUri,
        authConfig.authorizationEndpoint,
        authConfig.scopes
    );
    return null;
}

function getUserInfo() {
    if (tokenResponse == null) {
        throw 'no token to get user info of, first login, than get user info';
    }
    return callUserInfoEndpoint( authConfig.userInfoEndpoint, tokenResponse.access_token);
}

function logout() {
    if (tokenResponse == null){
        throw 'no token to log user off for, first login then logout';
    }
    return callEndSessionEndpoint(authConfig.endSessionEndpoint, tokenResponse.access_token);
}

/**
 * Starts the authorization code flow. This means this function will redirect the
 * application to the IDP for login. When that is done it will redirect back with
 * an authorization code which can be used to request a token.
 *
 * @param clientId {string}
 * @param redirectUri {URL}
 * @param authorizationEndpoint {URL}
 * @param scope {string[]}
 */
async function startAuthorizationCodeFlow(clientId, redirectUri, authorizationEndpoint, scope) {
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
        scope: scope.join(' '),
        response_type: 'code',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        state: state
    })

    const authUrl = `${authorizationEndpoint.protocol}//${authorizationEndpoint.host}${authorizationEndpoint.pathname}?${authParams.toString()}`;
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
async function exchangeAuthorizationCodeForAccessToken(authorizationCode, receivedState, tokenEndpoint, clientId, redirectUri) {
    console.log('exchange authorization-code for access-token');

    if (authorizationCode == null || authorizationCode.length === 0) {
        throw 'no authorization code to exchange';
    }

    const codeVerifier = sessionStorage.getItem(pkceCodeVerifierSessionStorageKey);
    if (codeVerifier == null) {
        throw 'no code verifier in session to use in token exchange';
    }

    const createdState = sessionStorage.getItem(stateSessionStorageKey);
    if (createdState == null || createdState !== receivedState) {
        throw 'received no state to verify the redirect callback by';
    }

    const tokenResponse = await callTokenEndpoint(
        tokenEndpoint,
        TokenRequestParams.authorizationCode(clientId, redirectUri, authorizationCode, codeVerifier)
    );

    localStorage.setItem(refreshTokenLocalStorageKey, tokenResponse.refresh_token);
    sessionStorage.setItem(idTokenSessionStorageKey, tokenResponse.id_token);
    sessionStorage.removeItem(pkceCodeVerifierSessionStorageKey);
    sessionStorage.removeItem(stateSessionStorageKey);
    return tokenResponse;
}

/**
 * @param tokenEndpoint {URL}
 * @param clientId {string}
 * @param redirectUri {URL}
 * @param scopes {string[]}
 * @returns {Promise<TokenResponse>}
 */
async function exchangeRefreshTokenForAccessToken(tokenEndpoint, clientId, redirectUri, scopes) {
    console.log('exchange refresh-token for access-token')

    const refreshToken = localStorage.getItem(refreshTokenLocalStorageKey);
    if (refreshToken == null || refreshToken.length === 0) {
        throw 'no refresh token to exchange for access token';
    }

    const tokenResponse = await callTokenEndpoint(
        tokenEndpoint,
        TokenRequestParams.refreshToken(clientId, redirectUri, scopes, refreshToken)
    );

    localStorage.setItem(refreshTokenLocalStorageKey, tokenResponse.refresh_token);
    sessionStorage.setItem(idTokenSessionStorageKey, tokenResponse.id_token);
    return tokenResponse;
}

/**
 * Makes a POST request to the token endpoint of the IDP and handles its
 * response.
 *
 * @param tokenEndpoint {URL} is the url to call.
 * @param authParams {TokenRequestParams} parameters to add to the request
 * @returns {Promise<TokenResponse>}
 */
async function callTokenEndpoint(tokenEndpoint, authParams) {
    console.log()
    const response = await fetch(tokenEndpoint, {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: authParams.toUrlSearchParams().toString(),
    });

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
async function callUserInfoEndpoint(userInfoEndpoint, accessToken) {
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

async function callEndSessionEndpoint(endSessionEndpoint, clientId, accessToken) {
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
class TokenRequestParams {
    /**
     * @param client_id {string}
     * @param grant_type {"refresh_token"|"authorization_code"}
     * @param redirect_uri {URL}
     * @param scope {string[]|null}
     * @param refresh_token {string|null}
     * @param code {string|null}
     * @param code_verifier {string|null}
     */
    constructor(
        client_id,
        grant_type,
        redirect_uri,
        scope,
        refresh_token,
        code,
        code_verifier) {
        this.clientId = client_id;
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
        return new TokenRequestParams(clientId, 'authorization_code', redirectUrl, null, null, code, codeVerifier);
    }

    /**
     * @param clientId {string}
     * @param redirectUrl {URL}
     * @param scope {string[]}
     * @param refreshToken {string}
     */
    static refreshToken(clientId, redirectUrl, scope, refreshToken) {
        return new TokenRequestParams(clientId, 'refresh_token', redirectUrl, scope, refreshToken, null, null);
    }

    toUrlSearchParams() {
        return new URLSearchParams({
            client_id: this.clientId,
            grant_type: this.grantType,
            redirect_uri: this.redirectUri.toString(),
            scope: this.scope?.join(' '),
            refresh_token: this.refreshToken,
            code: this.code,
            code_verifier: this.codeVerifier,
        });
    }
}