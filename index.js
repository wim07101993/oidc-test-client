import {Database, OidcConfigDbModel} from "./database.js";
import {
    callDiscoveryEndpoint,
    codeQueryParamName,
    exchangeAuthorizationCodeForAccessToken,
    getUserInfo,
    Jwt,
    logout,
    startAuthorizationCodeFlow,
    stateQueryParamName,
    invalidStateError, noCodeVerifier
} from "./auth.js";

const lastUsedConfigSessionStorageKey = 'last_used_oidc_config';

const configNameQueryParamName = 'config_name';
const tokenEndpointQueryParamName = 'token_endpoint';
const authorizeEndpointQueryParamName = 'authorization_endpoint';
const userInfoEndpointQueryParamName = 'user_info_endpoint';
const endSessionEndpointQueryParamName = 'end_session_endpoint';
const clientIdQueryParamName = 'client_id';
const redirectUriQueryParamName = 'redirect_uri';
const scopeQueryParamName = 'scope';

const urlParams = new URLSearchParams(window.location.search);

await autoLoadConfig();

// ----------------------------------------------------------
// EVENT HANDLERS
// ----------------------------------------------------------

document.getElementById('authorizeButton').onclick = async () => {
    console.log('onLoginClicked');
    const oidcConfig = getOidcConfigFromFields();

    await startAuthorizationCodeFlow(oidcConfig.clientId, oidcConfig.redirectUri, oidcConfig.authorizeEndpoint, oidcConfig.scope);
}

document.getElementById('endSessionButton').onclick = async () => {
    console.log('onLogoutClicked');
    const oidcConfig = getOidcConfigFromFields();
    sessionStorage.setItem(lastUsedConfigSessionStorageKey, JSON.stringify(oidcConfig))

    await logout(oidcConfig);
}

document.getElementById('saveConfigurationButton').onclick = async () => {
    console.log('onSaveConfigurationClicked');
    const oidcConfig = getOidcConfigFromFields();
    sessionStorage.setItem(lastUsedConfigSessionStorageKey, JSON.stringify(oidcConfig))

    await db.connect();
    await db.addOidcConfig(oidcConfig);
}

document.getElementById('loadConfigButton').onclick = async () => {
    console.log('onLoadConfigurationClicked');
    const selector = document.getElementById('availableOidcConfigsSelector');
    const oidcConfig = JSON.parse(selector.value);
    sessionStorage.setItem(lastUsedConfigSessionStorageKey, JSON.stringify(oidcConfig))
    const searchParams = new URLSearchParams(window.location.search);
    searchParams.set(configNameQueryParamName, oidcConfig.id);
    searchParams.set(tokenEndpointQueryParamName, oidcConfig.tokenEndpoint);
    searchParams.set(authorizeEndpointQueryParamName, oidcConfig.authorizeEndpoint);
    searchParams.set(userInfoEndpointQueryParamName, oidcConfig.userInfoEndpoint);
    searchParams.set(endSessionEndpointQueryParamName, oidcConfig.endSessionEndpoint);
    searchParams.set(clientIdQueryParamName, oidcConfig.clientId);
    searchParams.set(redirectUriQueryParamName, oidcConfig.redirectUri);
    searchParams.set(scopeQueryParamName, oidcConfig.scope);
    window.location.search = searchParams.toString();
}

document.getElementById('discoverButton').onclick = async (e) => {
    e.preventDefault();
    const discoveryEndpoint = document.getElementById('discoveryEndpointInput').value;
    if (discoveryEndpoint == null || discoveryEndpoint === '') {
        alert('no discovery endpoint');
        return;
    }
    const discoveryDocument = await callDiscoveryEndpoint(discoveryEndpoint);
    document.getElementById('authEndpointInput').value = discoveryDocument.authorizationEndpoint;
    document.getElementById('tokenEndpointInput').value = discoveryDocument.tokenEndpoint;
    document.getElementById('userInfoEndpointInput').value = discoveryDocument.userInfoEndpoint;
    document.getElementById('endSessionEndpointInput').value = discoveryDocument.endSessionEndpoint;
}

// ----------------------------------------------------------
// FUNCTIONS
// ----------------------------------------------------------

async function autoLoadConfig() {
    console.log('loading the last used config');
    const fromQueryParams = {
        id: urlParams.get(configNameQueryParamName),
        tokenEndpoint: urlParams.get(tokenEndpointQueryParamName),
        authorizeEndpoint: urlParams.get(authorizeEndpointQueryParamName),
        userInfoEndpoint: urlParams.get(userInfoEndpointQueryParamName),
        endSessionEndpoint: urlParams.get(endSessionEndpointQueryParamName),
        clientId: urlParams.get(clientIdQueryParamName),
        redirectUri: urlParams.get(redirectUriQueryParamName),
        scope: urlParams.get(scopeQueryParamName),
    };
    const fromSession = JSON.parse(sessionStorage.getItem(lastUsedConfigSessionStorageKey));

    const discoveryEndpoint = document.getElementById('discoveryEndpointInput').value;
    let discoveryDocument = null;
    if (discoveryEndpoint != null && discoveryEndpoint !== '') {
        discoveryDocument = await callDiscoveryEndpoint(discoveryEndpoint);
        document.getElementById('authEndpointInput').value = discoveryDocument.authorizationEndpoint;
        document.getElementById('tokenEndpointInput').value = discoveryDocument.tokenEndpoint;
        document.getElementById('userInfoEndpointInput').value = discoveryDocument.userInfoEndpoint;
        document.getElementById('endSessionEndpointInput').value = discoveryDocument.endSessionEndpoint;
    }

    const defaultConfig = {
        id: 'default',
        tokenEndpoint: new URL('http://localhost:8080/oauth/v2/token'),
        authorizeEndpoint: new URL('http://localhost:8080/oauth/v2/authorize'),
        userInfoEndpoint: new URL('http://localhost:8080/oidc/v1/userinfo'),
        endSessionEndpoint: new URL('http://localhost:8080/oidc/v1/end_session'),
        clientId: '349564292321837244',
        redirectUri: new URL('http://localhost:5000/'),
        scope: 'openid email profile offline_access'
    };

    const config = new OidcConfigDbModel(
        fromQueryParams.id ?? fromSession?.id ?? defaultConfig.id,
        fromQueryParams.tokenEndpoint ?? fromSession?.tokenEndpoint ?? discoveryDocument?.tokenEndpoint ?? defaultConfig.tokenEndpoint,
        fromQueryParams.authorizeEndpoint ?? fromSession?.authorizeEndpoint ?? discoveryDocument?.authorizationEndpoint ?? defaultConfig.authorizeEndpoint,
        fromQueryParams.userInfoEndpoint ?? fromSession?.userInfoEndpoint ?? discoveryDocument?.userInfoEndpoint ?? defaultConfig.userInfoEndpoint,
        fromQueryParams.endSessionEndpoint ?? fromSession?.endSessionEndpoint ?? discoveryDocument?.endSessionEndpoint ?? defaultConfig.endSessionEndpoint,
        fromQueryParams.clientId ?? fromSession?.clientId ?? defaultConfig.clientId,
        fromQueryParams.redirectUri ?? fromSession?.redirectUri ?? defaultConfig.redirectUri,
        fromQueryParams.scope ?? fromSession?.scope ?? defaultConfig.scope
    );
    updateOidcConfigFields(config);
}

/**
 * @param config {OidcConfigDbModel|null}
 */
function updateOidcConfigFields(config) {
    document.getElementById('oidcConfigName').value = config.id;
    document.getElementById('tokenEndpointInput').value = config.tokenEndpoint;
    document.getElementById('authEndpointInput').value = config.authorizeEndpoint;
    document.getElementById('userInfoEndpointInput').value = config.userInfoEndpoint;
    document.getElementById('endSessionEndpointInput').value = config.endSessionEndpoint;
    document.getElementById('clientIdInput').value = config.clientId;
    document.getElementById('redirectUriInput').value = config.redirectUri;
    document.getElementById('scopesInput').value = config.scope;
}

function getOidcConfigFromFields() {
    return new OidcConfigDbModel(
        document.getElementById('oidcConfigName').value,
        new URL(document.getElementById('tokenEndpointInput').value),
        new URL(document.getElementById('authEndpointInput').value),
        new URL(document.getElementById('userInfoEndpointInput').value),
        new URL(document.getElementById('endSessionEndpointInput').value),
        document.getElementById('clientIdInput').value,
        new URL(document.getElementById('redirectUriInput').value),
        document.getElementById('scopesInput').value
    )
}

/**
 * @param configs {OidcConfigDbModel[]}
 */
function updateAvailableOidcConfigsSelectorOptions(configs) {
    console.log('updating available oidc configs');
    const selector = document.getElementById('availableOidcConfigsSelector');
    for (const config of configs) {
        selector.appendChild(new Option(config.id, JSON.stringify(config)));
    }
}

// ----------------------------------------------------------
// SCRIPT
// ----------------------------------------------------------

const db = new Database();
await db.connect();
const openIdConfigs = await db.getOidcConfigs();
console.log(openIdConfigs)
updateAvailableOidcConfigsSelectorOptions(openIdConfigs);

const authorizationCode = urlParams.get(codeQueryParamName);
const receivedState = urlParams.get(stateQueryParamName);
const isHandlingAuthCallback = authorizationCode != null && !receivedState != null;
if (isHandlingAuthCallback) {
    try {
        const authConfig = getOidcConfigFromFields();
        const tokenResponse = await exchangeAuthorizationCodeForAccessToken(authorizationCode, receivedState, authConfig.tokenEndpoint, authConfig.clientId, authConfig.redirectUri);
        console.log('handled callback, navigating back to index');

        document.getElementById('tokenResponse').innerText = JSON.stringify(tokenResponse, null, 2);
        document.getElementById('accessToken').innerText = tokenResponse.access_token;

        const idToken = Jwt.parse(tokenResponse.id_token);
        document.getElementById('idToken').innerText = JSON.stringify(idToken, null, 2);

        const userInfo = await getUserInfo(authConfig, tokenResponse.access_token);
        document.getElementById('userInfoText').innerText = JSON.stringify(userInfo, null, 2);
    } catch (e){
        switch (e){
            case invalidStateError:
            case noCodeVerifier:
                alert(e);
                break;
            default:
                throw e;
        }
    }
}


