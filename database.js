const oidConfigsStoreName = 'oidConfigs'

export class OidcConfigDbModel {
    /**
     * @param id {string}
     * @param tokenEndpoint {URL}
     * @param authorizeEndpoint {URL}
     * @param userInfoEndpoint {URL}
     * @param endSessionEndpoint {URL}
     * @param clientId {string}
     * @param redirectUri {URL}
     * @param scope {string}
     */
    constructor(
        id,
        tokenEndpoint,
        authorizeEndpoint,
        userInfoEndpoint,
        endSessionEndpoint,
        clientId,
        redirectUri,
        scope
    ) {
        this.id = id;
        this.tokenEndpoint = tokenEndpoint;
        this.authorizeEndpoint = authorizeEndpoint;
        this.userInfoEndpoint = userInfoEndpoint;
        this.endSessionEndpoint = endSessionEndpoint;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.scope = scope;
    }
}

export class Database {
    _isDisposed = false;

    /**
     * @type {IDBDatabase}
     * @private
     */
    _database = null;

    async connect() {
        if (this._database != null && !this._isDisposed) {
            return this._database;
        }
        this._database = await _openDatabase();
        this._isDisposed = false;
    }

    dispose() {
        this._database.close();
        this._isDisposed = true;
    }

    /**
     * @param config {OidcConfigDbModel}
     * @returns {Promise<void>}
     */
    async addOidcConfig(config) {
        const transaction = await this._database.transaction(oidConfigsStoreName, 'readwrite');
        const store = transaction.objectStore(oidConfigsStoreName);
        const transactionCompletePromise = new Promise((resolve, reject) => {
            transaction.oncomplete = () => resolve();
            transaction.onerror = (event) => reject(event);
            transaction.onabort = (event) => reject(event);
        });

        store.put({
            id: config.id,
            authorizeEndpoint: config.authorizeEndpoint.toString(),
            tokenEndpoint: config.tokenEndpoint.toString(),
            userInfoEndpoint: config.userInfoEndpoint.toString(),
            endSessionEndpoint: config.endSessionEndpoint.toString(),
            clientId: config.clientId,
            redirectUri: config.redirectUri.toString(),
            scope: config.scope,
        });

        await transactionCompletePromise;
    }

    /**
     * @returns {Promise<OidcConfigDbModel[]>}
     */
    getOidcConfigs() {
        console.log('getting oidc configs');
        return new Promise((resolve, reject) => {
            const request = this._database
                .transaction([oidConfigsStoreName])
                .objectStore(oidConfigsStoreName)
                .getAll();

            request.onerror = (event) => reject(event.target.result);
            request.onsuccess = (event) => resolve(event.target.result.map((config) => new OidcConfigDbModel(
                config.id,
                new URL(config.tokenEndpoint),
                new URL(config.authorizeEndpoint),
                new URL(config.userInfoEndpoint),
                new URL(config.endSessionEndpoint),
                config.clientId,
                new URL(config.redirectUri),
                config.scope
            )));
        })
    }
}

/**
 * @type {Promise<IDBDatabase>}
 * @private
 */
function _openDatabase() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open('database', 1);

        request.onerror = (event) => reject(event.target.error)
        request.onsuccess = (event) => resolve(event.target.result)

        request.onupgradeneeded = (event) => {
            console.log(`upgrade needed from version ${event.oldVersion} to ${event.newVersion}`, event);
            const db = event.target.result;

            if (!db.objectStoreNames.contains(oidConfigsStoreName)) {
                const store = db.createObjectStore(oidConfigsStoreName, {
                    keyPath: 'id',
                    autoIncrement: false
                });
                console.log(`created ${store.name} store`);
            }
        }
    });
}
