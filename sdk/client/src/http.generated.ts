export interface paths {
    "/v2/acquisitions/status": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["lookupAcquisitions"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/batches": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["prepareBatch"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/batches/{id}/items": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listBatchItems"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/browser-tools": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listBrowserTools"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/browser-tools/install": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["installBrowserTools"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/browser-tools/status": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getBrowserToolStatus"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/browser-tools/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getBrowserTool"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/browser-tools/{id}/activate": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["activateBrowserTools"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/browser-tools/{id}/cleanup": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["retryBrowserToolCleanup"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/browser-tools/{id}/remove": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["removeBrowserTools"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/clients": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["attachClient"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/clients/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["heartbeatClient"];
        delete: operations["detachClient"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/destination-checks": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listDestinationChecks"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/destination-checks/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getDestinationCheck"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/destination-checks/{id}/files": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listDestinationCheckFiles"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/destination-checks/{id}/{action}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["controlDestinationCheck"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/destinations": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listDestinations"];
        put?: never;
        post: operations["addDestination"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/destinations/default": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["ensureDefaultDestination"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/destinations/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getDestination"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/destinations/{id}/check": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["checkDestination"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/destinations/{id}/reconnect": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["reconnectDestination"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/destinations/{id}/relocate": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["relocateDestination"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/events": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["followEvents"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/file-operations": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listFileOperations"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/file-operations/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getFileOperation"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/file-operations/{id}/files": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listFileOperationEntries"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/file-operations/{id}/{action}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["controlFileOperation"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/groups": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listGroups"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/groups/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getGroup"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/groups/{id}/jobs": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listGroupJobs"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/groups/{id}/{action}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["controlGroup"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/inbox": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listInbox"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/inbox/{id}/{action}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["controlInboxItem"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/jobs": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listJobs"];
        put?: never;
        post: operations["enqueueAcquisition"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/jobs/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getJob"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/jobs/{id}/file-operations": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["createFileOperation"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/jobs/{id}/files": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listArtifacts"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/jobs/{id}/files/{artifact}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getArtifact"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/jobs/{id}/{action}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["controlJob"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/metadata/{kind}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put: operations["setMetadataOverride"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/metadata/{kind}/{provider}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getMetadataOverride"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/naming": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getNamingTemplates"];
        put: operations["setNamingTemplates"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/notifications": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getNotificationStatus"];
        put: operations["configureNotifications"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/notifications/history": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listNotificationHistory"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/notifications/history/{id}/{action}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["controlNotification"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/notifications/test": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["testNotification"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/openapi.json": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getContract"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/operations": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listOperations"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/preparations": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["prepareAcquisition"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/relocations": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listRelocations"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/relocations/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getRelocation"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/relocations/{id}/files": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listRelocationFiles"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/relocations/{id}/{action}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["controlRelocation"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/selections": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listSelections"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/selections/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getSelection"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/selections/{id}/{action}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["controlSelection"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/service": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getService"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/service/shutdown": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["shutdownService"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/settings": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getSettings"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch: operations["updateSettings"];
        trace?: never;
    };
    "/v2/sign-ins/{id}/actions": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["interactWithSignIn"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/sign-ins/{id}/close": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["closeSourceSignIn"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/sign-ins/{id}/complete": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["completeSourceSignIn"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/sign-ins/{id}/status": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["sourceSignInStatus"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/snapshots": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["createSnapshot"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/snapshots/{id}/releases": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listSnapshotReleases"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/source-catalog": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listSourceCatalog"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/source-removals": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listSourceRemovals"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/source-removals/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getSourceRemoval"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/source-removals/{id}/entries": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listSourceRemovalEntries"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/source-removals/{id}/retry": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["retrySourceRemoval"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/sources": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listSources"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/sources/install": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["installSource"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/sources/{id}/activate": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["activateSource"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/sources/{id}/artwork": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getArtwork"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/sources/{id}/credentials": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listSourceAccounts"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/sources/{id}/credentials/{profile}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put: operations["saveSourceAccount"];
        post?: never;
        delete: operations["revokeSourceAccount"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/sources/{id}/invoke": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["invokeSource"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/sources/{id}/remove": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["removeSource"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/sources/{id}/sign-ins": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["startSourceSignIn"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/sources/{id}/versions": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listSourceVersions"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/subscriptions": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listSubscriptions"];
        put?: never;
        post: operations["createSubscription"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/subscriptions/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch: operations["updateSubscription"];
        trace?: never;
    };
    "/v2/subscriptions/{id}/{action}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["controlSubscription"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/summary": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getSummary"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/tools": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listToolSets"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/tools/install": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["installToolSet"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/tools/status": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getToolStatus"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/tools/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getToolSet"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/tools/{id}/activate": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["activateToolSet"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/tools/{id}/remove": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["removeToolSet"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v2/tools/{id}/retry-cleanup": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["retryToolCleanup"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
}
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        Accepted: {
            accepted: boolean;
        };
        /** @enum {string} */
        AccountMode: "browser" | "cookies" | "header";
        AccountRevoked: {
            revoked: boolean;
        };
        AccountSaved: {
            profile: string;
            saved: boolean;
        };
        AcquisitionStatus: {
            /** Format: int64 */
            acquired_versions: number;
            /** @default null */
            file_state: string | null;
            last_acquired_at?: string | null;
            latest_job_id?: string | null;
            reference: components["schemas"]["SourceRef"];
            /**
             * Format: uint64
             * @default null
             */
            saved_bytes: number | null;
            /** @default null */
            source_revision: string | null;
        };
        Action: {
            action: components["schemas"]["ControlAction"];
            control: string;
            /** @constant */
            op: "control";
        } | {
            /** @constant */
            op: "navigate";
            url: string;
        } | {
            /** @constant */
            op: "wait";
            selector: string;
        } | {
            /** @constant */
            op: "click";
            selector: string;
        } | {
            /** @constant */
            op: "fill";
            selector: string;
            text: string;
        } | {
            /** @constant */
            op: "select";
            selector: string;
            value: string;
        } | {
            key: string;
            /** @constant */
            op: "press";
        } | {
            /** @constant */
            op: "pointer";
            /** Format: uint32 */
            x: number;
            /** Format: uint32 */
            y: number;
        } | {
            /** @constant */
            op: "type";
            text: string;
        } | {
            /** Format: int32 */
            delta: number;
            /** @constant */
            op: "scroll";
        } | {
            /** @constant */
            op: "snapshot";
        } | {
            /** @constant */
            op: "frame";
        };
        /** @enum {string} */
        ActionPolicy: "notify" | "download";
        ActivateSource: {
            digest: string;
        };
        AddDestination: {
            label: string;
            root: string;
        };
        AnyValue: unknown;
        Array_of_AcquisitionStatus: components["schemas"]["AcquisitionStatus"][];
        Array_of_Operation: components["schemas"]["Operation"][];
        Artifact: {
            id: string;
            job_id: string;
            media_type: string;
            relative_path: string;
            sha256: string;
            /** Format: uint64 */
            size: number;
            status: components["schemas"]["FileStatus"];
        };
        Artwork: {
            id: string;
            label: string;
            /** @default null */
            locale: string | null;
            url: string;
        };
        /**
         * @description Source-provided artwork geometry and collection navigation.
         * @enum {string}
         */
        ArtworkLayout: "portrait" | "landscape" | "square" | "banner";
        ArtworkQuery: {
            credential_profile?: string | null;
            url: string;
        };
        AttachQuery: {
            /**
             * @description When this client is the last to leave and background operation is off,
             *     keep the engine running until no download is queued or running, then
             *     stop. Without it, the engine stops soon after the last client leaves and
             *     unfinished downloads continue at its next start. Command-line and agent
             *     clients that submit work and leave set it; an interactive application
             *     whose window close should stop downloads leaves it unset.
             * @default false
             */
            finish_downloads: boolean;
        };
        /** @enum {string} */
        Availability: "available" | "external" | "authentication_required" | "unavailable" | "unknown";
        BatchRequest: {
            destination_id: string;
            /** @default skip_satisfied */
            duplicate_behavior: components["schemas"]["DuplicateBehavior"];
            policy: components["schemas"]["SelectionPolicy"];
            recipe: components["schemas"]["Recipe"];
            /**
             * @description Omit for all matching releases in the frozen snapshot.
             * @default null
             */
            releases: components["schemas"]["SourceRef"][] | null;
            snapshot_id: string;
        };
        BrowserInstallation: {
            installed?: components["schemas"]["BrowserPackage"] | null;
            review: components["schemas"]["BrowserPackageReview"];
            review_required: boolean;
        };
        BrowserPackage: {
            active: boolean;
            approval_digest: string;
            digest: string;
            installed_at: string;
            issue?: components["schemas"]["Problem"] | null;
            label: string;
            review: components["schemas"]["BrowserPackageReview"];
            state: string;
            updated_at: string;
        };
        BrowserPackageReview: {
            adapter: string;
            browser: string;
            digest: string;
            files: {
                [key: string]: components["schemas"]["FileIdentity"];
            };
            node: components["schemas"]["FileIdentity"];
            node_version: string;
            platform: string;
            version: string;
        };
        BrowserRemoval: {
            installed: components["schemas"]["BrowserPackage"];
            review_required: boolean;
        };
        BrowserStatus: {
            active?: components["schemas"]["BrowserPackage"] | null;
            bundled?: components["schemas"]["BrowserPackageReview"] | null;
            issue?: components["schemas"]["Problem"] | null;
            platform: string;
        };
        CatalogEntry: {
            description: string;
            id: string;
            name: string;
            package_path: string;
            version: string;
        };
        ClientDetached: {
            detached: boolean;
        };
        ClientHeartbeat: {
            id: string;
        };
        ClientLease: {
            /**
             * @description Whether the engine recorded `finish_downloads` for this client. Absent
             *     on engines released before that attach option.
             */
            finish_downloads?: boolean | null;
            /** Format: uint32 */
            heartbeat_seconds: number;
            id: string;
            /** Format: uint32 */
            lease_seconds: number;
        };
        Collection: {
            artwork_url?: string | null;
            canonical_url: string;
            description?: string | null;
            kind: components["schemas"]["CollectionKind"];
            reference: components["schemas"]["SourceRef"];
            summary?: components["schemas"]["CollectionSummary"] | null;
            title: string;
        };
        CollectionDetails: {
            alternative_titles: {
                [key: string]: string[];
            };
            creators: components["schemas"]["MetadataField"][];
            description?: string | null;
            facts: components["schemas"]["MetadataField"][];
            languages: string[];
            /** @description Honest explanation of source-provided or similarity-based recommendations. */
            recommendation_basis?: string | null;
            reference: components["schemas"]["SourceRef"];
            tags: components["schemas"]["DiscoveryOption"][];
        };
        CollectionKind: ("manga" | "playlist" | "channel") | "item";
        /** @description Small, source-provided discovery facts. No executable presentation or social actions. */
        CollectionLink: {
            canonical_url: string;
            kind: components["schemas"]["CollectionKind"];
            reference: components["schemas"]["SourceRef"];
            title: string;
        };
        CollectionSection: {
            kind: components["schemas"]["CollectionSectionKind"];
            label: string;
            reference: components["schemas"]["SourceRef"];
        };
        /** @enum {string} */
        CollectionSectionKind: "releases" | "collections";
        CollectionSummary: {
            artwork_layout?: components["schemas"]["ArtworkLayout"] | null;
            avatar_url?: string | null;
            banner_url?: string | null;
            content_rating?: string | null;
            content_rating_appearance?: components["schemas"]["LabelAppearance"] | null;
            creator_links?: components["schemas"]["CreatorLink"][];
            /** @default [] */
            creators: string[];
            /**
             * Format: uint64
             * @description Duration and audience facts supplied by a media source, including flat listings.
             */
            duration_seconds?: number | null;
            /** Format: uint64 */
            followers?: number | null;
            handle?: string | null;
            image?: components["schemas"]["ImageSummary"] | null;
            /** @default [] */
            languages: string[];
            original_language?: string | null;
            /** @description The containing collection, such as the channel that published a video. */
            parent?: components["schemas"]["CollectionLink"] | null;
            profile?: string | null;
            /** @description Source display text (for example “2 hours ago”); never treated as an exact date. */
            published_label?: string | null;
            /** Format: double */
            rating?: number | null;
            /** Format: double */
            rating_max?: number | null;
            sections?: components["schemas"]["CollectionSection"][];
            status?: string | null;
            status_appearance?: components["schemas"]["LabelAppearance"] | null;
            tag_appearances?: {
                [key: string]: components["schemas"]["LabelAppearance"];
            };
            /** @default [] */
            tags: string[];
            video_count_label?: string | null;
            /** Format: uint64 */
            view_count?: number | null;
            /** Format: uint16 */
            year?: number | null;
        };
        ControlAction: {
            /** @constant */
            kind: "click";
        } | {
            /** @constant */
            kind: "fill";
            text: string;
        } | {
            /** @constant */
            kind: "select";
            value: string;
        };
        Cookie: {
            domain: string;
            /** Format: int64 */
            expires_at?: number | null;
            host_only: boolean;
            http_only?: boolean;
            name: string;
            path: string;
            same_site?: components["schemas"]["SameSite"] | null;
            /** @description Absent attributes keep the earlier engine defaults: Secure and HttpOnly. */
            secure?: boolean;
            value: string;
        };
        CreatorLink: {
            collection: components["schemas"]["CollectionLink"];
            role: string;
        };
        Destination: {
            available: boolean;
            id: string;
            label: string;
            root: string;
            /** @default null */
            storage_operation: string | null;
        };
        DestinationCheck: {
            /** Format: int64 */
            blocked_jobs: number;
            /** Format: int64 */
            checked: number;
            /** Format: int64 */
            completed_jobs: number;
            created_at: string;
            destination_id: string;
            /** Format: int64 */
            detached: number;
            /** Format: int64 */
            files: number;
            id: string;
            issue?: components["schemas"]["Problem"] | null;
            /** Format: int64 */
            jobs: number;
            label: string;
            /** Format: int64 */
            missing: number;
            /** Format: int64 */
            modified: number;
            /** Format: int64 */
            present: number;
            state: string;
            updated_at: string;
        };
        DestinationCheckFile: {
            artifact_id: string;
            job_id: string;
            path: string;
            state: string;
        };
        DiscoveryFilter: {
            id: string;
            label: string;
            multiple: boolean;
            options: components["schemas"]["DiscoveryOption"][];
        };
        DiscoveryOption: {
            appearance?: components["schemas"]["LabelAppearance"] | null;
            id: string;
            label: string;
        };
        DiscoveryQuery: {
            feed?: string | null;
            /** @default {} */
            filters: {
                [key: string]: string[];
            };
            sort?: string | null;
        };
        DiscoverySchema: {
            feeds: components["schemas"]["DiscoveryOption"][];
            filters: components["schemas"]["DiscoveryFilter"][];
            sorts: components["schemas"]["DiscoveryOption"][];
            /** @description Query this discovery operation with a query (including empty for popular tags). */
            tag_search?: boolean;
            tags?: components["schemas"]["DiscoveryOption"][];
        };
        /** @enum {string} */
        DuplicateBehavior: "skip_satisfied" | "new_version";
        Enqueue: {
            preparation_id: string;
        };
        EnqueueResult: components["schemas"]["Enqueued"] | components["schemas"]["EnqueuedBatch"];
        Enqueued: {
            group_id: string;
            items: components["schemas"]["EnqueuedItem"][];
        };
        EnqueuedBatch: {
            /** Format: uint64 */
            created: number;
            /** Format: uint64 */
            existing: number;
            group_id: string;
            /** Format: uint64 */
            total: number;
        };
        EnqueuedItem: {
            created: boolean;
            job: components["schemas"]["Job"];
        };
        Event: {
            created_at: string;
            /** Format: int64 */
            id: number;
            kind: string;
            resource_id: string;
        };
        EventQuery: {
            /** Format: int64 */
            cursor?: number | null;
        };
        FileIdentity: {
            /** Format: uint64 */
            bytes: number;
            sha256: string;
        };
        FileOperation: {
            created_at: string;
            destination_check?: string | null;
            id: string;
            issue?: components["schemas"]["Problem"] | null;
            job_id: string;
            mode: components["schemas"]["FileOperationMode"];
            /** Format: int64 */
            processed: number;
            /** Format: int64 */
            retained: number;
            state: string;
            title: string;
            /** Format: int64 */
            total: number;
            updated_at: string;
        };
        FileOperationEntry: {
            artifact_id: string;
            path: string;
            sha256: string;
            /** Format: uint64 */
            size: number;
            state: string;
        };
        /** @enum {string} */
        FileOperationMode: "reconcile" | "remove_files" | "forget_history" | "remove_files_and_history";
        FileOperationRequest: {
            mode: components["schemas"]["FileOperationMode"];
        };
        /** @enum {string} */
        FileStatus: "present" | "missing" | "modified" | "detached" | "destination_unavailable";
        GroupAction: {
            /** Format: uint64 */
            changed: number;
            /** Format: uint64 */
            checkpointing: number;
            /** Format: uint64 */
            publishing: number;
            /** Format: uint64 */
            unchanged: number;
        };
        Header: {
            name: string;
            origin: string;
            value: string;
        };
        HostGrant: {
            credential: boolean;
            hosts: string[];
            id: string;
            methods: string[];
            /** @description Additional pacing for upstream endpoints with a stricter limit than ordinary browsing. */
            request_intervals?: {
                [key: string]: number;
            };
        };
        IdentifiedSource: {
            /** @constant */
            kind: "collection";
            reference: components["schemas"]["SourceRef"];
        } | {
            /** @constant */
            kind: "release";
            reference: components["schemas"]["SourceRef"];
        };
        /** @description A downloadable image post. One release contains every image in the post. */
        ImageSummary: {
            /** Format: uint64 */
            bytes?: number | null;
            /** Format: uint32 */
            count: number;
            format?: string | null;
            /** Format: uint32 */
            height?: number | null;
            /** @default [] */
            previews: string[];
            release_id: string;
            /** Format: uint32 */
            width?: number | null;
        };
        InboxItem: {
            created_at: string;
            id: string;
            issue?: components["schemas"]["Problem"] | null;
            job_id?: string | null;
            read_at?: string | null;
            release: components["schemas"]["Release"];
            state: string;
            subscription_id: string;
        };
        Install: {
            approve_digest?: string | null;
            package_path: string;
        };
        InstallBrowser: {
            approve_digest?: string | null;
            label: string;
            manifest_path?: string | null;
        };
        InstallResult: components["schemas"]["SourceReview"] | components["schemas"]["SourceInstalled"];
        InstallToolsRequest: {
            approve_digest?: string | null;
            label: string;
            manifest_path?: string | null;
        };
        /** @enum {string} */
        IntentOutcome: "download" | "new_version" | "already_acquired" | "existing_job";
        Job: {
            acquisition_key: string;
            /** Format: uint32 */
            attempt: number;
            /** Format: uint64 */
            bytes_done: number;
            /** Format: uint64 */
            bytes_total?: number | null;
            created_at: string;
            destination_id: string;
            group_id?: string | null;
            id: string;
            issue?: components["schemas"]["Problem"] | null;
            plan: components["schemas"]["Plan"];
            state: components["schemas"]["JobState"];
            title: string;
            updated_at: string;
        };
        JobGroup: {
            /** Format: int64 */
            active: number;
            /** Format: int64 */
            canceled: number;
            /** Format: int64 */
            completed: number;
            created_at: string;
            /** Format: int64 */
            failed: number;
            id: string;
            /** Format: int64 */
            paused: number;
            title: string;
            /** Format: int64 */
            total: number;
        };
        /** @enum {string} */
        JobState: "queued" | "resolving" | "transferring" | "verifying" | "publishing" | "completed" | "paused" | "failed" | "canceled";
        /** @description A source's label color, never arbitrary CSS or executable presentation. */
        LabelAppearance: {
            color: string;
        };
        List: {
            cursor?: string | null;
            /** Format: uint32 */
            limit?: number | null;
            /** @default  */
            q: string;
            state?: string | null;
        };
        Locator: {
            credential_profile?: string | null;
            /** @default {} */
            headers: {
                [key: string]: string;
            };
            /** @constant */
            kind: "http";
            permission: string;
            url: string;
        } | {
            credential_profile?: string | null;
            /** @constant */
            kind: "media";
            permission: string;
            url: string;
        };
        LogicalOutput: {
            expected_sha256?: string | null;
            /** Format: uint64 */
            expected_size?: number | null;
            id: string;
            locator: components["schemas"]["Locator"];
            media_type?: string | null;
            /** Format: uint32 */
            position: number;
            relative_path: string;
            role: string;
        };
        ManagedToolIdentity: {
            /** Format: uint64 */
            bytes: number;
            name: string;
            sha256: string;
            version: string;
        };
        ManagedToolReview: {
            digest: string;
            platform: string;
            tools: components["schemas"]["ManagedToolIdentity"][];
        };
        ManagedToolSet: {
            active: boolean;
            approval_digest: string;
            digest: string;
            installed_at: string;
            issue?: components["schemas"]["Problem"] | null;
            label: string;
            review: components["schemas"]["ManagedToolReview"];
            state: string;
            updated_at: string;
        };
        ManagedToolStatus: {
            bundled?: components["schemas"]["ManagedToolReview"] | null;
            issue?: components["schemas"]["Problem"] | null;
            platform: string;
        };
        MediaSelection: {
            /** Format: uint64 */
            duration_ms?: number | null;
            ffmpeg_digest: string;
            ffprobe_digest: string;
            format_ids: string[];
            node_digest?: string | null;
            /** Format: uint32 */
            selected_height?: number | null;
            source_signature: string;
            subtitles: string[];
            yt_dlp_digest: string;
        };
        MediaTools: {
            complete: boolean;
            configured: boolean;
            tools: components["schemas"]["ToolIdentity"][];
        };
        MetadataField: {
            appearance?: components["schemas"]["LabelAppearance"] | null;
            label: string;
            values: string[];
        };
        MetadataOverride: {
            /** @default null */
            chapter: string | null;
            /** @default null */
            description: string | null;
            /** @default null */
            title: string | null;
            /** @default null */
            volume: string | null;
        };
        MetadataQuery: {
            source_id: string;
        };
        MetadataWrite: {
            overrides: components["schemas"]["MetadataOverride"];
            reference: components["schemas"]["SourceRef"];
        };
        NamingTemplates: {
            /** @default {title} */
            collection: string;
            /** @default {title} */
            release: string;
        };
        NotificationBatch: {
            /** Format: int64 */
            count: number;
            created_at: string;
            id: string;
            issue?: components["schemas"]["Problem"] | null;
            state: string;
            updated_at: string;
        };
        NotificationSettings: {
            enabled: boolean;
        };
        NotificationStatus: {
            enabled: boolean;
            /** Format: int64 */
            failed: number;
            last?: components["schemas"]["NotificationBatch"] | null;
            /** Format: int64 */
            pending: number;
            /** Format: int64 */
            uncertain: number;
        };
        ObservationProgress: {
            /** Format: uint64 */
            processed: number;
            source_digest: string;
            started_at: string;
            state: string;
        };
        Operation: {
            method: string;
            path: string;
            scope: string;
        };
        /**
         * @description Page storage for one credential-authorized HTTPS origin, such as a site's
         *     signed-in session marker. Engine-owned like cookies; never sent to plugins.
         */
        OriginStorage: {
            local_storage: components["schemas"]["StorageItem"][];
            /** @description Serialized origin, for example `https://www.example.com`. */
            origin: string;
        };
        OutputMetadata: {
            /**
             * @default {
             *       "chapter": null,
             *       "description": null,
             *       "title": null,
             *       "volume": null
             *     }
             */
            collection: components["schemas"]["MetadataOverride"];
            /**
             * @default {
             *       "chapter": null,
             *       "description": null,
             *       "title": null,
             *       "volume": null
             *     }
             */
            release: components["schemas"]["MetadataOverride"];
        };
        Page_Artifact: {
            items: components["schemas"]["Artifact"][];
            next_cursor?: string | null;
        };
        Page_Artwork: {
            items: components["schemas"]["Artwork"][];
            next_cursor?: string | null;
        };
        Page_BrowserPackage: {
            items: components["schemas"]["BrowserPackage"][];
            next_cursor?: string | null;
        };
        Page_CatalogEntry: {
            items: components["schemas"]["CatalogEntry"][];
            next_cursor?: string | null;
        };
        Page_Collection: {
            items: components["schemas"]["Collection"][];
            next_cursor?: string | null;
        };
        Page_Destination: {
            items: components["schemas"]["Destination"][];
            next_cursor?: string | null;
        };
        Page_DestinationCheck: {
            items: components["schemas"]["DestinationCheck"][];
            next_cursor?: string | null;
        };
        Page_DestinationCheckFile: {
            items: components["schemas"]["DestinationCheckFile"][];
            next_cursor?: string | null;
        };
        Page_FileOperation: {
            items: components["schemas"]["FileOperation"][];
            next_cursor?: string | null;
        };
        Page_FileOperationEntry: {
            items: components["schemas"]["FileOperationEntry"][];
            next_cursor?: string | null;
        };
        Page_InboxItem: {
            items: components["schemas"]["InboxItem"][];
            next_cursor?: string | null;
        };
        Page_Job: {
            items: components["schemas"]["Job"][];
            next_cursor?: string | null;
        };
        Page_JobGroup: {
            items: components["schemas"]["JobGroup"][];
            next_cursor?: string | null;
        };
        Page_ManagedToolSet: {
            items: components["schemas"]["ManagedToolSet"][];
            next_cursor?: string | null;
        };
        Page_NotificationBatch: {
            items: components["schemas"]["NotificationBatch"][];
            next_cursor?: string | null;
        };
        Page_Preview: {
            items: components["schemas"]["Preview"][];
            next_cursor?: string | null;
        };
        Page_Release: {
            items: components["schemas"]["Release"][];
            next_cursor?: string | null;
        };
        Page_Relocation: {
            items: components["schemas"]["Relocation"][];
            next_cursor?: string | null;
        };
        Page_RelocationFile: {
            items: components["schemas"]["RelocationFile"][];
            next_cursor?: string | null;
        };
        Page_SelectionTask: {
            items: components["schemas"]["SelectionTask"][];
            next_cursor?: string | null;
        };
        Page_Source: {
            items: components["schemas"]["Source"][];
            next_cursor?: string | null;
        };
        Page_SourceAccount: {
            items: components["schemas"]["SourceAccount"][];
            next_cursor?: string | null;
        };
        Page_SourceRemoval: {
            items: components["schemas"]["SourceRemoval"][];
            next_cursor?: string | null;
        };
        Page_SourceRemovalEntry: {
            items: components["schemas"]["SourceRemovalEntry"][];
            next_cursor?: string | null;
        };
        Page_SourceVersion: {
            items: components["schemas"]["SourceVersion"][];
            next_cursor?: string | null;
        };
        Page_Subscription: {
            items: components["schemas"]["Subscription"][];
            next_cursor?: string | null;
        };
        Plan: {
            collection: components["schemas"]["Collection"];
            /** @default null */
            credential_profile: string | null;
            expires_at?: string | null;
            final_relative_path: string;
            /**
             * Format: uint32
             * @description Artifact-set version, assigned by the engine before confirmation.
             * @default 0
             */
            generation: number;
            /** @default null */
            media: components["schemas"]["MediaSelection"] | null;
            /**
             * @default {
             *       "collection": {
             *         "chapter": null,
             *         "description": null,
             *         "title": null,
             *         "volume": null
             *       },
             *       "release": {
             *         "chapter": null,
             *         "description": null,
             *         "title": null,
             *         "volume": null
             *       }
             *     }
             */
            metadata: components["schemas"]["OutputMetadata"];
            outputs: components["schemas"]["LogicalOutput"][];
            policy: components["schemas"]["SelectionPolicy"];
            provider_digest: string;
            recipe: components["schemas"]["Recipe"];
            release: components["schemas"]["Release"];
        };
        Preferences: {
            background: boolean;
            /**
             * Format: uint64
             * @default 0
             */
            bandwidth_bytes_per_second: number;
            languages: string[];
            /** @default false */
            onboarding_complete: boolean;
        };
        Preparation: {
            destination: components["schemas"]["Destination"];
            expires_at: string;
            id: string;
            items: components["schemas"]["Preview"][];
        };
        Prepare: {
            /** @default null */
            credential_profile: string | null;
            destination_id: string;
            /** @default skip_satisfied */
            duplicate_behavior: components["schemas"]["DuplicateBehavior"];
            policy: components["schemas"]["SelectionPolicy"];
            recipe: components["schemas"]["Recipe"];
            releases: components["schemas"]["SourceRef"][];
        };
        Preview: {
            /** Format: uint64 */
            estimated_bytes?: number | null;
            files: string[];
            outcome: components["schemas"]["IntentOutcome"];
            plan: components["schemas"]["Plan"];
        };
        Problem: {
            actions: string[];
            code: string;
            message: string;
            retryable: boolean;
        };
        ProviderManifest: {
            /**
             * @description Preferred reference-UI connection method. Imports store credentials without
             *     asserting authentication; browser completion remains engine-owned.
             */
            account_mode?: components["schemas"]["AccountMode"] | null;
            api: string;
            /** @default false */
            browser: boolean;
            /**
             * @description The operations this source implements (such as `search`, `releases`
             *     and `resolve`), plus `collection_hint` when its `resolve` reads the
             *     request's `collection_hint`.
             */
            capabilities: string[];
            description: string;
            grants: components["schemas"]["HostGrant"][];
            id: string;
            /** @default false */
            media_tools: boolean;
            name: string;
            /**
             * @description Used only by the interactive engine-owned sign-in browser. These grants
             *     are never handed to source HTTP, media, or browser broker operations.
             */
            sign_in?: components["schemas"]["SignIn"] | null;
            source_hosts: string[];
            version: string;
        };
        /** @enum {string} */
        Recipe: "cbz" | "image_folder" | "original_images" | "mp4" | "mkv" | "webm" | "m4a" | "mp3" | "opus";
        ReconnectDestination: {
            root: string;
        };
        Release: {
            availability: components["schemas"]["Availability"];
            canonical_url: string;
            chapter?: string | null;
            collection: components["schemas"]["SourceRef"];
            group?: string | null;
            language?: string | null;
            /** Format: uint64 */
            position: number;
            /** @description Metadata for browsing the release without fetching each item's details. */
            preview?: components["schemas"]["Collection"] | null;
            published_at?: string | null;
            reference: components["schemas"]["SourceRef"];
            revision?: string | null;
            title: string;
            unavailable_reason?: string | null;
            volume?: string | null;
        };
        /**
         * @description Explicit chapter browsing order. Absent for complete acquisition/subscription scans.
         * @enum {string}
         */
        ReleaseOrder: "asc" | "desc";
        Relocate: {
            target_root: string;
        };
        Relocation: {
            /** Format: int64 */
            bytes: number;
            /** Format: int64 */
            copied: number;
            created_at: string;
            destination_id: string;
            /** Format: int64 */
            files: number;
            id: string;
            issue?: components["schemas"]["Problem"] | null;
            /** Format: int64 */
            retained: number;
            source_marker: string;
            source_root: string;
            state: string;
            target_marker: string;
            target_root: string;
            updated_at: string;
        };
        RelocationFile: {
            kind: string;
            path: string;
            root_path: string;
            sha256: string;
            /** Format: uint64 */
            size: number;
            state: string;
        };
        RemoveBrowser: {
            approve_digest?: string | null;
        };
        RemoveSource: {
            approve_digest?: string | null;
        };
        RemoveToolsRequest: {
            approve_digest?: string | null;
        };
        ResolvedRelease: {
            collection: components["schemas"]["Collection"];
            expires_at?: string | null;
            release: components["schemas"]["Release"];
            resources: components["schemas"]["Resource"][];
        };
        Resource: {
            expected_sha256?: string | null;
            /** Format: uint64 */
            expected_size?: number | null;
            id: string;
            locator: components["schemas"]["Locator"];
            media_type?: string | null;
            /** Format: uint32 */
            position: number;
            role: string;
        };
        /**
         * @description Browser SameSite policy. An absent value keeps the earlier engine default (Lax).
         * @enum {string}
         */
        SameSite: "strict" | "lax" | "none";
        SaveCredentials: {
            label: string;
            session: components["schemas"]["Session"];
        };
        SelectionPolicy: {
            /** @default false */
            automatic_subtitles: boolean;
            /** @default [] */
            groups: string[];
            /**
             * @default [
             *       "en"
             *     ]
             */
            languages: string[];
            /**
             * Format: uint32
             * @default 1080
             */
            max_height: number;
            /** @default [] */
            subtitle_languages: string[];
        };
        SelectionTask: {
            created_at: string;
            cursor?: string | null;
            expires_at?: string | null;
            id: string;
            issue?: components["schemas"]["Problem"] | null;
            kind: string;
            /**
             * @description Checked release outcomes, independent of preview pagination.
             * @default {}
             */
            outcomes: {
                [key: string]: number;
            };
            /** Format: int64 */
            processed: number;
            request: components["schemas"]["SnapshotRequest"] | components["schemas"]["BatchRequest"];
            source_digest: string;
            state: string;
            /** Format: int64 */
            total: number;
            updated_at: string;
        };
        Service: {
            api: string;
            capabilities: string[];
            /** Format: int64 */
            event_cursor: number;
            /** @description Absent on engines released before manual-update handover support. */
            executable_sha256?: string | null;
            media_tools?: components["schemas"]["MediaTools"] | null;
            recipes: components["schemas"]["Recipe"][];
            scopes: string[];
            version: string;
        };
        Session: {
            cookies: components["schemas"]["Cookie"][];
            /** Format: int64 */
            expires_at?: number | null;
            headers: components["schemas"]["Header"][];
            /** @description Restored before page scripts run in engine-owned source browsers only. */
            origins?: components["schemas"]["OriginStorage"][];
        };
        Settings: {
            background: boolean;
            /**
             * Format: uint64
             * @default 0
             */
            bandwidth_bytes_per_second: number;
            languages: string[];
            /** @default false */
            onboarding_complete: boolean;
            startup: components["schemas"]["Startup"];
        };
        Shutdown: {
            state: string;
        };
        ShutdownQuery: {
            /**
             * @description Suspend this profile's startup registration for replacement/uninstall.
             *     The background preference is preserved and restored on the next launch.
             * @default false
             */
            for_update: boolean;
        };
        SignIn: {
            /**
             * @description Cookie names required before saving an authenticated source session.
             *     Values stay inside the engine and are never exposed to plugins or clients.
             * @default []
             */
            completion_cookies: string[];
            grants: components["schemas"]["HostGrant"][];
            url: string;
        };
        SignInAction: {
            action: components["schemas"]["Action"];
            client: string;
        };
        SignInClosed: {
            closed: boolean;
        };
        SignInControl: {
            checked: boolean;
            disabled: boolean;
            entered: boolean;
            id: string;
            kind: string;
            label: string;
            options: components["schemas"]["SignInOption"][];
            value: string;
        };
        SignInFrame: {
            controls: components["schemas"]["SignInControl"][];
            controls_truncated: boolean;
            /** Format: uint32 */
            height: number;
            origin: string;
            png: string;
            /** Format: uint32 */
            width: number;
        };
        SignInOption: {
            label: string;
            value: string;
        };
        SignInOwner: {
            client: string;
        };
        SignInReply: {
            frame?: components["schemas"]["SignInFrame"] | null;
            ready: boolean;
        };
        SignInSession: {
            /** Format: date-time */
            expires_at: string;
            id: string;
            label: string;
            profile: string;
            source_id: string;
            window: components["schemas"]["SignInWindow"];
        };
        /**
         * @description `isolated`: the engine's confined browser, shown to the client as frames.
         *     `native`: a window using the operating system's web view, opened by the
         *     engine on its desktop session. Native windows pass site checks that reject
         *     automated browsers, but the page uses the ordinary network connection.
         * @enum {string}
         */
        SignInWindow: "isolated" | "native";
        SnapshotRequest: {
            /** @default null */
            credential_profile: string | null;
            /**
             * @default {
             *       "automatic_subtitles": false,
             *       "groups": [],
             *       "languages": [
             *         "en"
             *       ],
             *       "max_height": 1080,
             *       "subtitle_languages": []
             *     }
             */
            policy: components["schemas"]["SelectionPolicy"];
            reference: components["schemas"]["SourceRef"];
            /** @description Explicit image posts selected in discovery, frozen one at a time. */
            release_refs?: components["schemas"]["SourceRef"][] | null;
            /** @default null */
            search: components["schemas"]["SubscriptionSearch"] | null;
        };
        Source: {
            digest: string;
            manifest: components["schemas"]["ProviderManifest"];
        };
        SourceAccount: {
            issue?: components["schemas"]["Problem"] | null;
            label: string;
            profile: string;
            status: string;
            updated_at: string;
        };
        SourceActivated: {
            activated: boolean;
            digest: string;
        };
        SourceInstalled: {
            digest: string;
            installed: boolean;
            manifest: components["schemas"]["ProviderManifest"];
        };
        /**
         * @description Frontends describe a source operation. The engine supplies its clock and all
         *     execution authority; clients need not construct the worker's internal request.
         */
        SourceInvocation: {
            credential_profile?: string | null;
            cursor?: string | null;
            /** @default null */
            discovery: components["schemas"]["DiscoveryQuery"] | null;
            operation: components["schemas"]["SourceOperation"];
            /**
             * Format: uint32
             * @default 100
             */
            page_size: number;
            /**
             * @default {
             *       "automatic_subtitles": false,
             *       "groups": [],
             *       "languages": [
             *         "en"
             *       ],
             *       "max_height": 1080,
             *       "subtitle_languages": []
             *     }
             */
            policy: components["schemas"]["SelectionPolicy"];
            query?: string | null;
            reference?: components["schemas"]["SourceRef"] | null;
            /** @default null */
            release_order: components["schemas"]["ReleaseOrder"] | null;
            url?: string | null;
        };
        /** @enum {string} */
        SourceOperation: "discovery" | "details" | "artwork" | "related" | "recommendations" | "search" | "browse" | "collection" | "releases" | "resolve" | "identify";
        SourceRef: {
            id: string;
            provider: string;
        };
        SourceRemoval: {
            created_at: string;
            id: string;
            issue?: components["schemas"]["Problem"] | null;
            /** Format: int64 */
            processed: number;
            /** Format: int64 */
            retained: number;
            review: components["schemas"]["SourceRemovalReview"];
            state: string;
            /** Format: int64 */
            total: number;
            updated_at: string;
        };
        SourceRemovalEntry: {
            issue?: components["schemas"]["Problem"] | null;
            item_key: string;
            kind: string;
            state: string;
        };
        SourceRemovalResponse: {
            operation?: components["schemas"]["SourceRemoval"] | null;
            review?: components["schemas"]["SourceRemovalReview"] | null;
            review_required: boolean;
        };
        SourceRemovalReview: {
            /** Format: int64 */
            accounts: number;
            approval_digest: string;
            enabled: boolean;
            /** Format: int64 */
            jobs: number;
            name: string;
            previous_removal?: string | null;
            provider: string;
            /** Format: int64 */
            subscriptions: number;
            /** Format: int64 */
            versions: number;
        };
        SourceResult: components["schemas"]["DiscoverySchema"] | components["schemas"]["CollectionDetails"] | components["schemas"]["Page_Artwork"] | components["schemas"]["Page_Collection"] | components["schemas"]["Page_Release"] | components["schemas"]["Collection"] | components["schemas"]["ResolvedRelease"] | components["schemas"]["IdentifiedSource"];
        SourceReview: {
            digest: string;
            manifest: components["schemas"]["ProviderManifest"];
            review_required: boolean;
        };
        SourceVersion: {
            active: boolean;
            digest: string;
            installed_at: string;
            manifest: components["schemas"]["ProviderManifest"];
        };
        StartSignIn: {
            client: string;
            label: string;
            profile: string;
            /** @default isolated */
            window: components["schemas"]["SignInWindow"];
        };
        Startup: {
            enabled: boolean;
            issue?: components["schemas"]["Problem"] | null;
        };
        StatusLookup: {
            references: components["schemas"]["SourceRef"][];
        };
        /** @description One local-storage entry restored only into its own HTTPS origin. */
        StorageItem: {
            name: string;
            value: string;
        };
        SubscribeRequest: {
            action: components["schemas"]["ActionPolicy"];
            credential_profile?: string | null;
            destination_id: string;
            include_existing: boolean;
            /** Format: uint32 */
            interval_minutes: number;
            /** @description Optional name shown in subscriptions, independent of the source title. */
            name?: string | null;
            policy: components["schemas"]["SelectionPolicy"];
            recipe: components["schemas"]["Recipe"];
            /** @description Saved discovery input. Search subscriptions observe matching items, not their releases. */
            search?: components["schemas"]["SubscriptionSearch"] | null;
            target: components["schemas"]["SourceRef"];
        };
        Subscription: {
            /** @default null */
            current_check: components["schemas"]["ObservationProgress"] | null;
            enabled: boolean;
            id: string;
            initialized: boolean;
            issue?: components["schemas"]["Problem"] | null;
            last_success?: string | null;
            next_check: string;
            request: components["schemas"]["SubscribeRequest"];
            /**
             * @description Cached source collection title with any user title override applied.
             * @default null
             */
            title: string | null;
        };
        SubscriptionSearch: {
            /** @default null */
            discovery: components["schemas"]["DiscoveryQuery"] | null;
            query: string;
        };
        Summary: {
            /** Format: uint64 */
            acquired: number;
            /** Format: uint64 */
            active_jobs: number;
            /** Format: uint64 */
            attention: number;
            /** Format: uint64 */
            following: number;
        };
        ToolIdentity: {
            name: string;
            sha256: string;
            version: string;
        };
        ToolInstallation: {
            installed?: components["schemas"]["ManagedToolSet"] | null;
            review: components["schemas"]["ManagedToolReview"];
            review_required: boolean;
        };
        ToolRemoval: {
            /** Format: int64 */
            affected_jobs: number;
            installed: components["schemas"]["ManagedToolSet"];
            review_required: boolean;
        };
        Updated: {
            updated: boolean;
        };
        string: string;
    };
    responses: never;
    parameters: never;
    requestBodies: never;
    headers: never;
    pathItems: never;
}
export type $defs = Record<string, never>;
export interface operations {
    lookupAcquisitions: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["StatusLookup"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Array_of_AcquisitionStatus"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    prepareBatch: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["BatchRequest"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SelectionTask"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    listBatchItems: {
        parameters: {
            query?: {
                cursor?: string | null;
                limit?: number | null;
                q?: string;
            };
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_Preview"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    listBrowserTools: {
        parameters: {
            query?: {
                cursor?: string | null;
                limit?: number | null;
                q?: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_BrowserPackage"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    installBrowserTools: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["InstallBrowser"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BrowserInstallation"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    getBrowserToolStatus: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BrowserStatus"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    getBrowserTool: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BrowserPackage"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    activateBrowserTools: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BrowserPackage"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    retryBrowserToolCleanup: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BrowserPackage"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    removeBrowserTools: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RemoveBrowser"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BrowserRemoval"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    attachClient: {
        parameters: {
            query?: {
                finish_downloads?: boolean;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ClientLease"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    heartbeatClient: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ClientHeartbeat"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    detachClient: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ClientDetached"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    listDestinationChecks: {
        parameters: {
            query?: {
                cursor?: string | null;
                limit?: number | null;
                q?: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_DestinationCheck"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    getDestinationCheck: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DestinationCheck"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    listDestinationCheckFiles: {
        parameters: {
            query?: {
                cursor?: string | null;
                limit?: number | null;
                q?: string;
            };
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_DestinationCheckFile"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    controlDestinationCheck: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
                action: "pause" | "resume" | "retry" | "cancel";
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DestinationCheck"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    listDestinations: {
        parameters: {
            query?: {
                cursor?: string | null;
                limit?: number | null;
                q?: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_Destination"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    addDestination: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["AddDestination"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Destination"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    ensureDefaultDestination: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Destination"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    getDestination: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Destination"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    checkDestination: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DestinationCheck"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    reconnectDestination: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ReconnectDestination"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Destination"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    relocateDestination: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["Relocate"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Relocation"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    followEvents: {
        parameters: {
            query?: {
                cursor?: number | null;
            };
            header?: {
                /** @description Last applied event cursor. Takes precedence over the query cursor. A 409 or resync_required event requires a new service snapshot and resource queries. */
                "Last-Event-ID"?: number;
            };
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "text/event-stream": string;
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    listFileOperations: {
        parameters: {
            query?: {
                cursor?: string | null;
                limit?: number | null;
                q?: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_FileOperation"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    getFileOperation: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["FileOperation"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    listFileOperationEntries: {
        parameters: {
            query?: {
                cursor?: string | null;
                limit?: number | null;
                q?: string;
            };
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_FileOperationEntry"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    controlFileOperation: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
                action: "start" | "retry" | "cancel";
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["FileOperation"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    listGroups: {
        parameters: {
            query?: {
                cursor?: string | null;
                limit?: number | null;
                q?: string;
                state?: string | null;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_JobGroup"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    getGroup: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["JobGroup"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    listGroupJobs: {
        parameters: {
            query?: {
                cursor?: string | null;
                limit?: number | null;
                q?: string;
            };
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_Job"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    controlGroup: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
                action: "pause" | "cancel" | "resume" | "retry";
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["GroupAction"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    listInbox: {
        parameters: {
            query?: {
                cursor?: string | null;
                limit?: number | null;
                q?: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_InboxItem"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    controlInboxItem: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
                action: "read" | "retry";
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Updated"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    listJobs: {
        parameters: {
            query?: {
                cursor?: string | null;
                limit?: number | null;
                q?: string;
                state?: string | null;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_Job"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    enqueueAcquisition: {
        parameters: {
            query?: never;
            header: {
                /** @description Replay is checked before preparation expiration. Reusing a key with another request returns 409. */
                "Idempotency-Key": string;
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["Enqueue"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EnqueueResult"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    getJob: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Job"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    createFileOperation: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["FileOperationRequest"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["FileOperation"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    listArtifacts: {
        parameters: {
            query?: {
                cursor?: string | null;
                limit?: number | null;
                q?: string;
            };
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_Artifact"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    getArtifact: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
                artifact: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Artifact"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    controlJob: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
                action: "pause" | "cancel" | "resume" | "retry";
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Job"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    setMetadataOverride: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                kind: "collection" | "release";
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["MetadataWrite"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["MetadataOverride"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    getMetadataOverride: {
        parameters: {
            query: {
                source_id: string;
            };
            header?: never;
            path: {
                kind: "collection" | "release";
                provider: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["MetadataOverride"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    getNamingTemplates: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["NamingTemplates"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    setNamingTemplates: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["NamingTemplates"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["NamingTemplates"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    getNotificationStatus: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["NotificationStatus"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    configureNotifications: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["NotificationSettings"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["NotificationStatus"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    listNotificationHistory: {
        parameters: {
            query?: {
                cursor?: string | null;
                limit?: number | null;
                q?: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_NotificationBatch"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    controlNotification: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
                action: "retry" | "dismiss";
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["NotificationStatus"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    testNotification: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Accepted"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    getContract: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": Record<string, never>;
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    listOperations: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Array_of_Operation"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    prepareAcquisition: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["Prepare"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Preparation"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    listRelocations: {
        parameters: {
            query?: {
                cursor?: string | null;
                limit?: number | null;
                q?: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_Relocation"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    getRelocation: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Relocation"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    listRelocationFiles: {
        parameters: {
            query?: {
                cursor?: string | null;
                limit?: number | null;
                q?: string;
            };
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_RelocationFile"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    controlRelocation: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
                action: "start" | "retry" | "cancel";
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Relocation"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    listSelections: {
        parameters: {
            query?: {
                cursor?: string | null;
                limit?: number | null;
                q?: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_SelectionTask"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    getSelection: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SelectionTask"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    controlSelection: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
                action: "retry" | "cancel";
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SelectionTask"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    getService: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Service"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    shutdownService: {
        parameters: {
            query?: {
                for_update?: boolean;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Shutdown"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    getSettings: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Settings"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    updateSettings: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["Preferences"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Preferences"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    interactWithSignIn: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["SignInAction"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SignInReply"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    closeSourceSignIn: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["SignInOwner"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SignInClosed"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    completeSourceSignIn: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["SignInOwner"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AccountSaved"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    sourceSignInStatus: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["SignInOwner"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SignInReply"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    createSnapshot: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["SnapshotRequest"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SelectionTask"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    listSnapshotReleases: {
        parameters: {
            query?: {
                cursor?: string | null;
                limit?: number | null;
                q?: string;
            };
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_Release"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    listSourceCatalog: {
        parameters: {
            query?: {
                cursor?: string | null;
                limit?: number | null;
                q?: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_CatalogEntry"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    listSourceRemovals: {
        parameters: {
            query?: {
                cursor?: string | null;
                limit?: number | null;
                q?: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_SourceRemoval"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    getSourceRemoval: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SourceRemoval"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    listSourceRemovalEntries: {
        parameters: {
            query?: {
                cursor?: string | null;
                limit?: number | null;
                q?: string;
            };
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_SourceRemovalEntry"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    retrySourceRemoval: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SourceRemoval"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    listSources: {
        parameters: {
            query?: {
                cursor?: string | null;
                limit?: number | null;
                q?: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_Source"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    installSource: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["Install"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["InstallResult"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    activateSource: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ActivateSource"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SourceActivated"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    getArtwork: {
        parameters: {
            query: {
                credential_profile?: string | null;
                url: string;
            };
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "image/*": string;
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    listSourceAccounts: {
        parameters: {
            query?: {
                cursor?: string | null;
                limit?: number | null;
                q?: string;
            };
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_SourceAccount"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    saveSourceAccount: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
                profile: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["SaveCredentials"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AccountSaved"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    revokeSourceAccount: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
                profile: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AccountRevoked"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    invokeSource: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["SourceInvocation"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SourceResult"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    removeSource: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RemoveSource"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SourceRemovalResponse"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    startSourceSignIn: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["StartSignIn"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SignInSession"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    listSourceVersions: {
        parameters: {
            query?: {
                cursor?: string | null;
                limit?: number | null;
                q?: string;
            };
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_SourceVersion"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    listSubscriptions: {
        parameters: {
            query?: {
                cursor?: string | null;
                limit?: number | null;
                q?: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_Subscription"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    createSubscription: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["SubscribeRequest"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Subscription"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    updateSubscription: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["SubscribeRequest"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Subscription"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    controlSubscription: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
                action: "pause" | "resume" | "check";
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Subscription"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    getSummary: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Summary"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    listToolSets: {
        parameters: {
            query?: {
                cursor?: string | null;
                limit?: number | null;
                q?: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_ManagedToolSet"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    installToolSet: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["InstallToolsRequest"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ToolInstallation"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    getToolStatus: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ManagedToolStatus"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    getToolSet: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ManagedToolSet"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    activateToolSet: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ManagedToolSet"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    removeToolSet: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RemoveToolsRequest"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ToolRemoval"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
    retryToolCleanup: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ManagedToolSet"];
                };
            };
            /** @description Structured engine error. Follow its recovery actions; retain stale UI data where applicable. */
            default: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Problem"];
                };
            };
        };
    };
}
