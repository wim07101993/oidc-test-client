import {callDiscoveryEndpoint, callTokenEndpoint, Jwt, TokenRequestParams} from "./auth.js";

const configNameQueryParamName = 'config_name';
const tokenEndpointQueryParamName = 'token_endpoint';
const clientIdQueryParamName = 'client_id';
const clientSecretQueryParamName = 'client_secret';
const scopeQueryParamName = 'scope';

const urlParams = new URLSearchParams(window.location.search);

await autoLoadConfig();

// ----------------------------------------------------------
// MODELS
// ----------------------------------------------------------

class OidcClientCredentialsConfig {
    /**
     * @param clientId {string}
     * @param clientSecret {string}
     * @param tokenEndpoint {URL}
     * @param scope {string}
     */
    constructor(clientId, clientSecret, tokenEndpoint, scope) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.tokenEndpoint = tokenEndpoint;
        this.scope = scope
    }
}

// ----------------------------------------------------------
// EVENT HANDLERS
// ----------------------------------------------------------

document.getElementById('authorizeButton').onclick = async () => {
    console.log('onLoginClicked');
    const oidcConfig = getOidcConfigFromFields();

    await authorize(oidcConfig);
}

document.getElementById('discoverButton').onclick = async (e) => {
    e.preventDefault();
    const discoveryEndpoint = document.getElementById('discoveryEndpointInput').value;
    if (discoveryEndpoint == null || discoveryEndpoint === '') {
        alert('no discovery endpoint');
        return;
    }
    const discoveryDocument = await callDiscoveryEndpoint(discoveryEndpoint);
    document.getElementById('tokenEndpointInput').value = discoveryDocument.tokenEndpoint;
}

// ----------------------------------------------------------
// FUNCTIONS
// ----------------------------------------------------------

async function autoLoadConfig() {
    console.log('loading the last used config');
    const fromQueryParams = {
        id: urlParams.get(configNameQueryParamName),
        tokenEndpoint: urlParams.get(tokenEndpointQueryParamName),
        clientId: urlParams.get(clientIdQueryParamName),
        clientSecret: urlParams.get(clientSecretQueryParamName),
        scope: urlParams.get(scopeQueryParamName),
    };

    const discoveryEndpoint = document.getElementById('discoveryEndpointInput').value;
    let discoveryDocument = null;
    if (discoveryEndpoint != null && discoveryEndpoint !== '') {
        discoveryDocument = await callDiscoveryEndpoint(discoveryEndpoint);
        document.getElementById('tokenEndpointInput').value = discoveryDocument.tokenEndpoint;
    }

    const defaultConfig = {
        tokenEndpoint: new URL('http://localhost:8080/oauth/v2/token'),
        clientId: '349564292321837244',
        clientSecret: 'very-secret',
        scope: 'openid email profile offline_access'
    };

    updateOidcConfigFields({
        clientId: fromQueryParams.clientId ?? defaultConfig.clientId,
        clientSecret: fromQueryParams.clientSecret ?? defaultConfig.clientSecret,
        tokenEndpoint: fromQueryParams.tokenEndpoint ?? discoveryDocument?.tokenEndpoint ?? defaultConfig.tokenEndpoint,
        scope: fromQueryParams.scope ?? defaultConfig.scope
    });
}

/**
 * @param config {OidcClientCredentialsConfig|null}
 */
function updateOidcConfigFields(config) {
    document.getElementById('tokenEndpointInput').value = config.tokenEndpoint;
    document.getElementById('clientIdInput').value = config.clientId;
    document.getElementById('clientSecretInput').value = config.clientSecret;
    document.getElementById('scopesInput').value = config.scope;
}

function getOidcConfigFromFields() {
    return new OidcClientCredentialsConfig(
        document.getElementById('clientIdInput').value,
        document.getElementById('clientSecretInput').value,
        new URL(document.getElementById('tokenEndpointInput').value),
        document.getElementById('scopesInput').value
    )
}

/**
 * @param config {OidcClientCredentialsConfig}
 * @returns {Promise<void>}
 */
async function authorize(config) {
    const tokenResponse = await callTokenEndpoint(
        config.tokenEndpoint,
        TokenRequestParams.clientCredentials(config.clientId, config.clientSecret, config.scope)
    );


    document.getElementById('tokenResponse').innerText = JSON.stringify(tokenResponse, null, 2);
    document.getElementById('accessToken').innerText = tokenResponse.access_token;

    const idToken = Jwt.parse(tokenResponse.id_token);
    document.getElementById('idToken').innerText = JSON.stringify(idToken, null, 2);
}