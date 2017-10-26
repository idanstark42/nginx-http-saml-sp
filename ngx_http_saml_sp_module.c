/** 
 * Nginx SP saml module
 * 
 * This module uses the Lasso (Liberty Alliance Single Sign On) open source library
 * to implement a SAML Service Provider for Nginx 
 * 
 * Currently only supports a SP Initiated Redirect Bindings
 * 
 */ 

/* Nginx includes */ 
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* Lasso includes */ 
#include <lasso/lasso/lasso.h>
#include <stdio.h>

/* Functions definitions */
static char *       ngx_http_saml_sp_parse_configuration(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *       ngx_http_saml_sp_create_srv_conf(ngx_conf_t *cf);
static void *       ngx_http_saml_sp_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)

static ngx_int_t    ngx_http_saml_sp_init_module(ngx_conf_t *cf);
static ngx_int_t    ngx_http_saml_sp_init_process(ngx_conf_t *cf);
static ngx_int_t    ngx_http_saml_sp_exit_process(ngx_conf_t *cf);

static char *       ngx_http_saml_sp_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *       get_cookie_value(ngx_http_request_t *r);
static char *       lasso_get_redirect_url(ngx_http_saml_sp_conf_t *conf);

static ngx_int_t    write_idp_metadata_file(ngx_str_t *idp_url);
static ngx_int_t    write_sp_metadata_file(ngx_str_t *sp_url);
static ngx_int_t write_to_file(ngx_str_t *path, ngx_str_t *contents);

static ngx_command_t ngx_http_saml_sp_commands[] = {
    {
        ngx_string("saml_sp_redirect"),
        NGX_HTTP_SRV_CONF|NGX_CONF_TAKE12,
        ngx_http_saml_sp_parse_configuration,
        NGX_HTTP_SRV_CONF_OFFSET,
        0,
        NULL
    },
    ngx_null_command
};

/* Module context */ 
static ngx_http_module_t ngx_http_saml_sp_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_saml_sp_init_module,          /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_saml_sp_create_srv_conf,      /* create server configuration */
    ngx_http_saml_sp_merge_srv_conf,       /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

/* Module */ 
ngx_module_t ngx_http_saml_sp_module = {
    NGX_MODULE_V1,
    &ngx_http_saml_sp_module_ctx,          /* module context */
    ngx_http_saml_sp_commands,             /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_saml_sp_init_process,         /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_http_saml_sp_exit_process,         /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

/* Functions handling different phases of the process */

/* Parses the directive in the Nginx config file. Called upon configuration reading */ 
static char *ngx_http_saml_sp_parse_configuration(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_array_t *args = cf->args->elts;

    ngx_str_t idp_url = args[0];
    ngx_str_t sp_url = args[1];

    ngx_int_t sp_write_success = write_idp_metadata_file(&sp_url);
    ngx_int_t idp_write_success = write_sp_metadata_file(&sp_url);

    if(sp_write_success < 0 || idp_write_success < 0) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/* Initiates the module. Called after configuration load */
static ngx_int_t ngx_http_saml_sp_init_module(ngx_conf_t *cf) {
    /* Loading Main context configuration */
    ngx_http_core_main_conf_t  *cmcf;
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    /* Adding the request handler to the Access Phase */
    ngx_http_handler_pt        *handler;
    handler = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);

    if (handler == NULL) {
        return NGX_ERROR;
    }

    *handler = ngx_saml_sp_request_handler;

    return NGX_OK;
}

/* Allocates the values for the configuration object */
static void *ngx_http_saml_sp_create_srv_conf(ngx_conf_t *cf) {
    /* Allocate memort for configuration */
    ngx_http_saml_sp_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_saml_sp_conf_t));
    if(conf == NULL) {
        return NGX_CONF_ERROR;
    }

    return conf;
}

/* Merges two configuration objects */
static void *ngx_http_saml_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_saml_sp_conf_t *prev = parent;
    ngx_http_saml_sp_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->sp_url, prev->sp_url, "");
    ngx_conf_merge_str_value(conf->idp_url, prev->idp_url, "");

    return NGX_CONF_OK;
}

/* Called upon process init */
static ngx_int_t ngx_http_saml_sp_init_process(ngx_conf_t *cf) {
    int success = lasso_init();
    if(success < 0) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* Called upon process exit */
static ngx_int_t ngx_http_saml_sp_exit_process(ngx_conf_t *cf) {
    int success = lasso_shutdown();
    if(success < 0) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* Handles the redirection process at realtime. Called during the Access-Phase of the request. */ 
static ngx_int_t ngx_saml_sp_request_handler(ngx_http_request_t *r) {

    /* Loading cookie value */
    ngx_int_t location;
    ngx_str_t cookie = ngx_string("auth_token");
    ngx_str_t cookie_value;
    location = ngx_http_multi_header_lines(&r->headers_in.cookies, &cookie, &cookie_value);

    /* If there's no cookie */
    if(location == NGX_DECLINED) {
        /* Load SAML response from the URL */
        ngx_str_t arg_name = ngx_string("SAMLResponse");
        ngx_int_t arg_key = ngx_hash_key(arg_name.data, arg_name.len);
        ngx_http_variable_value_t *param;
        param = ngx_http_get_variable(&r, &arg_name, arg_key);

        /* If there's no SAML response */
        if(param == NULL) {
            /* Redirect to SAML IdP */
            char *url = ngx_get_redirect_url();
            ngx_set_response_header(&r, "Location", url);
            return NGX_HTTP_MOVED_TEMPORARILY;
        } else {
            /* Adding cookie to response */
            cookie_value = get_cookie_value(param->data);
            ngx_set_response_header(&r, "Set-Cookie", cookie_value);
        }
    } else {
        /* Continue without interruption */
        return NGX_OK;
    }
}

/* Utility functions */

/* Returns a string containing the redirect URL to the IdP, as calculated by Lasso. */
static char *lasso_get_redirect_url() {
    /* Creating Lasso server */
    LassoServer *server;
    server = lasso_server_new("sp.md", "privkey.crt", NULL, "cert.crt");
    lasso_server_add_provider(server, LASSO_PROVIDER_ROLE_IDP,
                "idp.md", "pubkey.key", "cacert.crt");

    /* Creating Lasso login-request */
    LassoLogin *login;
    login = lasso_login_new(server);
    lasso_login_init_authn_request(login, idpProviderId, LASSO_HTTP_METHOD_REDIRECT);

    LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE(login)->request)->ForceAuthn = TRUE;
    LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE(login)->request)->IsPassive = FALSE;
    LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE(login)->request)->NameIDPolicy = strdup(LASSO_LIB_NAMEID_POLICY_TYPE_FEDERATED);
    LASSO_LIB_AUTHN_REQUEST(LASSO_PROFILE(login)->request)->consent = strdup(LASSO_LIB_CONSENT_OBTAINED);
    lasso_login_build_authn_request_msg(login);

    return LASSO_PROFILE(login)->msg_url;
}

static char *get_cookie_value(ngx_str_t *saml_response) {
    LassoLogin *login;

    login = lasso_login_new(server);
    lasso_login_init_request(login, saml_response->data, LASSO_HTTP_METHOD_REDIRECT);
    lasso_login_build_request_msg(login);
}

/* Writes a SP metadata file */
static ngx_int_t write_sp_metadata_file(ngx_str_t *sp_url) {
    ngx_str_t *path;
    ngx_str_t *content;
    path = "/sp.md";
    content = ngx_string("<?xml version=\"1.0\"?>
        <EntityDescriptor providerID=\"service-provider\" xmlns=\"urn:liberty:metadata:2003-08\">
        <SPDescriptor>
            <AssertionConsumerServiceURL id=\"DefaultAssertionConsumerServiceURL\" isDefault=\"true\">
                " + sp_url->data + "
            </AssertionConsumerServiceURL>
        </SPDescriptor>
    </EntityDescriptor>");

    return write_to_file(&path, &content);
}

/* Writes a IdP metadata file */
static ngx_int_t write_idp_metadata_file(ngx_str_t *idp_url) {
    ngx_str_t *path;
    ngx_str_t *content;
    path = "/idp.md";
    content = ngx_string("<?xml version=\"1.0\"?>
      <EntityDescriptor providerID=\"identity-provider\" xmlns=\"urn:liberty:metadata:2003-08\">
        <IDPDescriptor>
          <SingleSignOnServiceURL>
            " + idp_url->data + "
          </SingleSignOnServiceURL>
        </IDPDescriptor>
    </EntityDescriptor>");

    return write_to_file(&path, &content);
}

/* Generic write to a file file */
static ngx_int_t write_to_file(ngx_str_t *path, ngx_str_t *contents) {
    FILE *file_pointer;
    file_pointer = fopen(path.data, "w");

    if(file_pointer == NULL) {
        return NGX_ERROR;
    }

    fprintf(file_pointer, "");
    fclose(file_pointer);

    return NGX_OK;
}

/* Generic response header setter */
static ngx_int_t set_response_header(ngx_http_request_t *r, char *name, char *value) {
    ngx_table_elt_t *header;
    header = ngx_list_push(&r->headers_out.headers);
    header->hash = 1;
    
    ngx_string_set(&header->key, name);
    ngx_string_set(&header->value, value);

    return NGX_OK;
}