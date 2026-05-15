package com.atakmap.comms.app;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;

import com.atakmap.android.ipc.AtakBroadcast;
import com.atakmap.android.network.ui.CredentialsPreference;
import com.atakmap.app.R;
import com.atakmap.app.system.ResourceUtil;
import com.atakmap.comms.NetConnectString;
import com.atakmap.coremap.filesystem.FileSystemUtils;
import com.atakmap.coremap.log.Log;
import com.atakmap.net.AtakAuthenticationCredentials;
import com.atakmap.net.AtakAuthenticationDatabase;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * Demonstration-only OpenID Connect flow for TAK server credential enrollment.
 *
 * <p>This activity launches a hard-coded OIDC authorization request and treats a
 * redirect that includes an authorization code or token as successful. On success
 * it supplies the TAK server with the hard-coded demo username and password.
 * This intentionally does not exchange or validate OIDC tokens and must not be
 * used as production authentication.</p>
 */
public class DemoOidcAuthenticationActivity extends Activity {

    private static final String TAG = "DemoOidcAuthActivity";

    private static final String ACTION_START_DEMO_OIDC =
            "com.atakmap.comms.app.action.START_DEMO_OIDC";
    private static final String EXTRA_STATE = "state";

    private static final String OIDC_AUTHORIZATION_ENDPOINT =
            "https://login.example.com/realms/demo/protocol/openid-connect/auth";
    private static final String OIDC_CLIENT_ID = "atak-demo-client";
    private static final String OIDC_REDIRECT_URI = "atak-oidc-demo://callback";
    private static final String OIDC_SCOPE = "openid profile email";
    private static final String OIDC_RESPONSE_TYPE = "code";

    private static final String DEMO_USERNAME = "testtakuser";
    private static final String DEMO_PASSWORD = "testtakuser";

    private static final Map<String, PendingDemoAuthentication> pendingAuths =
            new HashMap<>();

    public static void beginDemoAuthentication(final String desc,
            final String connectString, final String cacheCreds,
            final Long expiration, final Context context,
            final CredentialsDialog.Callback callback) {
        final String state = UUID.randomUUID().toString();
        synchronized (pendingAuths) {
            pendingAuths.put(state, new PendingDemoAuthentication(desc,
                    connectString, cacheCreds, expiration, callback));
        }

        Intent intent = new Intent(context,
                DemoOidcAuthenticationActivity.class);
        intent.setAction(ACTION_START_DEMO_OIDC);
        intent.putExtra(EXTRA_STATE, state);
        context.startActivity(intent);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        handleIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIntent(intent);
    }

    private void handleIntent(Intent intent) {
        if (intent == null) {
            finish();
            return;
        }

        if (ACTION_START_DEMO_OIDC.equals(intent.getAction())) {
            launchAuthorizationRequest(intent.getStringExtra(EXTRA_STATE));
            finish();
            return;
        }

        Uri redirectUri = intent.getData();
        if (redirectUri != null
                && OIDC_REDIRECT_URI.equals(buildRedirectBase(redirectUri))) {
            completeAuthentication(redirectUri);
        }

        finish();
    }

    private void launchAuthorizationRequest(String state) {
        if (FileSystemUtils.isEmpty(state)) {
            Log.w(TAG, "Cannot start demo OIDC authentication without state");
            return;
        }

        Uri authorizationUri = Uri.parse(OIDC_AUTHORIZATION_ENDPOINT)
                .buildUpon()
                .appendQueryParameter("client_id", OIDC_CLIENT_ID)
                .appendQueryParameter("redirect_uri", OIDC_REDIRECT_URI)
                .appendQueryParameter("response_type", OIDC_RESPONSE_TYPE)
                .appendQueryParameter("scope", OIDC_SCOPE)
                .appendQueryParameter("state", state)
                .build();

        try {
            startActivity(new Intent(Intent.ACTION_VIEW, authorizationUri));
        } catch (ActivityNotFoundException e) {
            PendingDemoAuthentication pending = removePending(state);
            if (pending != null) {
                pending.cancel();
            }
            Log.w(TAG, "No activity available to launch demo OIDC URL", e);
        }
    }

    private void completeAuthentication(Uri redirectUri) {
        String state = getOidcParameter(redirectUri, "state");
        PendingDemoAuthentication pending = removePending(state);
        if (pending == null) {
            Log.w(TAG, "Ignoring demo OIDC redirect without matching state");
            return;
        }

        if (!hasSuccessfulOidcResponse(redirectUri)) {
            Log.w(TAG, "Demo OIDC redirect did not include a code or token");
            pending.cancel();
            return;
        }

        pending.complete(this);
    }

    private static boolean hasSuccessfulOidcResponse(Uri redirectUri) {
        return !FileSystemUtils.isEmpty(getOidcParameter(redirectUri, "code"))
                || !FileSystemUtils.isEmpty(
                        getOidcParameter(redirectUri, "id_token"))
                || !FileSystemUtils.isEmpty(
                        getOidcParameter(redirectUri, "access_token"));
    }

    private static String getOidcParameter(Uri uri, String name) {
        String value = uri.getQueryParameter(name);
        if (!FileSystemUtils.isEmpty(value)) {
            return value;
        }

        String fragment = uri.getFragment();
        if (FileSystemUtils.isEmpty(fragment)) {
            return null;
        }

        return Uri.parse("atak-oidc-demo://callback?" + fragment)
                .getQueryParameter(name);
    }

    private static PendingDemoAuthentication removePending(String state) {
        if (FileSystemUtils.isEmpty(state)) {
            return null;
        }
        synchronized (pendingAuths) {
            return pendingAuths.remove(state);
        }
    }

    private static String buildRedirectBase(Uri uri) {
        return uri.buildUpon().clearQuery().fragment(null).build().toString();
    }

    private static class PendingDemoAuthentication {
        private final String desc;
        private final String connectString;
        private final String cacheCreds;
        private final Long expiration;
        private final CredentialsDialog.Callback callback;

        PendingDemoAuthentication(String desc, String connectString,
                String cacheCreds, Long expiration,
                CredentialsDialog.Callback callback) {
            this.desc = desc;
            this.connectString = connectString;
            this.cacheCreds = cacheCreds;
            this.expiration = expiration;
            this.callback = callback;
        }

        void complete(Context context) {
            cacheCredentialsIfRequested(context);

            if (callback != null) {
                callback.onCredentialsEntered(connectString, cacheCreds, desc,
                        DEMO_USERNAME, DEMO_PASSWORD, expiration);
                return;
            }

            NetConnectString ncs = NetConnectString.fromString(connectString);
            String host = ncs == null ? null : ncs.getHost();
            AtakBroadcast.getInstance().sendBroadcast(new Intent(
                    CredentialsPreference.CREDENTIALS_UPDATED)
                            .putExtra("type",
                                    AtakAuthenticationCredentials.TYPE_COT_SERVICE)
                            .putExtra("host", host));
        }

        void cancel() {
            if (callback != null) {
                callback.onCredentialsCancelled(connectString);
            }
        }

        private void cacheCredentialsIfRequested(Context context) {
            if (FileSystemUtils.isEmpty(cacheCreds)) {
                return;
            }

            NetConnectString ncs = NetConnectString.fromString(connectString);
            if (ncs == null || FileSystemUtils.isEmpty(ncs.getHost())) {
                Log.w(TAG, "Unable to cache demo OIDC credentials without host");
                return;
            }

            String cacheUsername = (cacheCreds.equalsIgnoreCase(ResourceUtil
                    .getString(context, R.string.cache_creds_both, Locale.US))
                    || cacheCreds.equals(ResourceUtil.getString(context,
                            R.string.cache_creds_username, Locale.US)))
                                    ? DEMO_USERNAME
                                    : "";
            String cachePassword = cacheCreds.equals(ResourceUtil
                    .getString(context, R.string.cache_creds_both, Locale.US))
                            ? DEMO_PASSWORD
                            : "";

            AtakAuthenticationDatabase.saveCredentials(
                    AtakAuthenticationCredentials.TYPE_COT_SERVICE,
                    ncs.getHost(), cacheUsername, cachePassword, expiration);
        }
    }
}
