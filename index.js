const urlParams = new URLSearchParams(window.location.search);
const authorizationCode = urlParams.get(codeQueryParamName);
const receivedState = urlParams.get(stateQueryParamName);
const isHandlingAuthCallback = authorizationCode != null && !receivedState != null;
if (isHandlingAuthCallback) {
    authorize().then(() => {
        console.log('handled callback, navigating back to index');
        if (tokenResponse == null || tokenResponse.access_token == null) {
            throw 'did not receive a token response';
        }

        getUserInfo().then(info =>{
            console.log(info);
        })
    });
}