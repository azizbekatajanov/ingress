//go:build linux && cgo

// SAML login window for GlobalProtect on Linux (WebKitGTK); the macOS
// counterpart is saml_darwin.m. See saml.go for the protocol.
#include <gtk/gtk.h>
#include <webkit2/webkit2.h>
#include "_cgo_export.h"

static gboolean committed = FALSE;

static void on_destroy(GtkWidget *widget, gpointer data) {
    samlWindowClosed();
}

static gboolean on_decide_policy(WebKitWebView *view, WebKitPolicyDecision *decision,
                                 WebKitPolicyDecisionType type, gpointer data) {
    if (type == WEBKIT_POLICY_DECISION_TYPE_RESPONSE) {
        WebKitURIResponse *resp =
            webkit_response_policy_decision_get_response(WEBKIT_RESPONSE_POLICY_DECISION(decision));
        SoupMessageHeaders *headers = webkit_uri_response_get_http_headers(resp);
        if (headers) {
            GString *block = g_string_new(NULL);
            SoupMessageHeadersIter iter;
            const char *name, *value;
            soup_message_headers_iter_init(&iter, headers);
            while (soup_message_headers_iter_next(&iter, &name, &value)) {
                g_string_append_printf(block, "%s: %s\n", name, value);
            }
            samlGotHeaders(block->str);
            g_string_free(block, TRUE);
        }
    }
    return FALSE; // let WebKit apply its default decision
}

static void on_outer_html(GObject *source, GAsyncResult *res, gpointer data) {
    GError *error = NULL;
    JSCValue *value = webkit_web_view_evaluate_javascript_finish(WEBKIT_WEB_VIEW(source), res, &error);
    if (!value) {
        if (error) g_error_free(error);
        return;
    }
    if (jsc_value_is_string(value)) {
        char *html = jsc_value_to_string(value);
        samlGotBody(html);
        g_free(html);
    }
    g_object_unref(value);
}

static void on_load_changed(WebKitWebView *view, WebKitLoadEvent event, gpointer data) {
    if (event == WEBKIT_LOAD_COMMITTED) {
        committed = TRUE;
    } else if (event == WEBKIT_LOAD_FINISHED) {
        // The result can also arrive as tags inside an HTML comment on the
        // final page; outerHTML keeps comments.
        webkit_web_view_evaluate_javascript(view, "document.documentElement.outerHTML", -1,
                                            NULL, NULL, NULL, on_outer_html, NULL);
    }
}

static gboolean on_load_failed(WebKitWebView *view, WebKitLoadEvent event, char *uri,
                               GError *error, gpointer data) {
    // A navigation cancelled by the next one (IdP redirects) isn't a failure.
    if (g_error_matches(error, WEBKIT_NETWORK_ERROR, WEBKIT_NETWORK_ERROR_CANCELLED)) return FALSE;
    // Failing before anything was shown leaves an empty window with no way
    // forward; report it instead.
    if (!committed) samlLoadFailed(error->message);
    return FALSE;
}

void saml_run(const char *title, const char *url, const char *html, const char *baseURL) {
    gtk_init(NULL, NULL);

    // Persistent cookies: the IdP session survives between logins, so a
    // reconnect usually doesn't ask for the password/MFA again.
    char *cookies = g_build_filename(g_get_user_data_dir(), "ingress", "saml-cookies.sqlite", NULL);
    char *dir = g_path_get_dirname(cookies);
    g_mkdir_with_parents(dir, 0700);
    WebKitWebContext *context = webkit_web_context_get_default();
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    webkit_cookie_manager_set_persistent_storage(webkit_web_context_get_cookie_manager(context),
                                                 cookies, WEBKIT_COOKIE_PERSISTENT_STORAGE_SQLITE);
#pragma GCC diagnostic pop
    g_free(dir);
    g_free(cookies);

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), title ? title : "Вход");
    gtk_window_set_default_size(GTK_WINDOW(window), 520, 700);
    gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);

    WebKitWebView *view = WEBKIT_WEB_VIEW(webkit_web_view_new());
    // Some IdPs refuse "embedded browser" user agents; present as Safari.
    webkit_settings_set_user_agent(webkit_web_view_get_settings(view),
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15");
    gtk_container_add(GTK_CONTAINER(window), GTK_WIDGET(view));

    g_signal_connect(window, "destroy", G_CALLBACK(on_destroy), NULL);
    g_signal_connect(view, "decide-policy", G_CALLBACK(on_decide_policy), NULL);
    g_signal_connect(view, "load-changed", G_CALLBACK(on_load_changed), NULL);
    g_signal_connect(view, "load-failed", G_CALLBACK(on_load_failed), NULL);

    if (url) {
        webkit_web_view_load_uri(view, url);
    } else if (html) {
        webkit_web_view_load_html(view, html, baseURL);
    }

    gtk_widget_show_all(window);
    gtk_main();
}
